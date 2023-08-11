use crate::aggregator::{http_handlers::aggregator_handler, Config};
use janus_aggregator_core::{
    datastore::{
        models::{
            AggregationJob, AggregationJobState, Batch, BatchAggregation, BatchAggregationState,
            BatchState, CollectionJobState, LeaderStoredReport, ReportAggregation,
            ReportAggregationState,
        },
        test_util::{ephemeral_datastore, EphemeralDatastore},
        Datastore,
    },
    task::{test_util::TaskBuilder, QueryType, Task},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{
        self, aggregate_share_aad, test_util::generate_test_hpke_config_and_private_key,
        HpkeApplicationInfo, HpkeKeypair, Label,
    },
    task::{AuthenticationToken, VdafInstance},
    test_util::{
        dummy_vdaf::{self, AggregationParam},
        install_test_trace_subscriber,
    },
    time::{Clock, MockClock},
};
use janus_messages::{
    query_type::{FixedSize, QueryType as QueryTypeTrait, TimeInterval},
    BatchId, BatchSelector, CollectReq, CollectResp, Duration, Interval, Query, ReportIdChecksum,
    Role,
};
use prio::codec::{Decode, Encode};
use rand::random;
use std::sync::Arc;
use trillium::{Handler, KnownHeaderName, Status};
use trillium_testing::{
    prelude::{get, post},
    TestConn,
};

pub(crate) struct CollectionJobTestCase {
    pub(super) task: Task,
    clock: MockClock,
    pub(super) collector_hpke_keypair: HpkeKeypair,
    pub(super) handler: Box<dyn Handler>,
    pub(super) datastore: Arc<Datastore<MockClock>>,
    _ephemeral_datastore: EphemeralDatastore,
}

impl CollectionJobTestCase {
    pub(super) async fn post_collection_job_with_auth_token<Q: QueryTypeTrait>(
        &self,
        request: &CollectReq<Q>,
        auth_token: Option<&AuthenticationToken>,
    ) -> TestConn {
        let mut test_conn = post(self.task.collect_uri().unwrap().path());
        if let Some(auth) = auth_token {
            let (header, value) = auth.request_authentication();
            test_conn = test_conn.with_request_header(header, value);
        }

        test_conn
            .with_request_header(
                KnownHeaderName::ContentType,
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&self.handler)
            .await
    }

    pub(super) async fn post_collection_job<Q: QueryTypeTrait>(
        &self,
        request: &CollectReq<Q>,
    ) -> TestConn {
        self.post_collection_job_with_auth_token(
            request,
            Some(self.task.primary_collector_auth_token()),
        )
        .await
    }

    pub(super) async fn get_collection_job_with_auth_token(
        &self,
        collection_location: &str,
        auth_token: Option<&AuthenticationToken>,
    ) -> TestConn {
        let mut test_conn = get(self
            .task
            .collection_job_uri(collection_location)
            .unwrap()
            .path());
        if let Some(auth) = auth_token {
            let (header, value) = auth.request_authentication();
            test_conn = test_conn.with_request_header(header, value);
        }
        test_conn.run_async(&self.handler).await
    }

    pub(super) async fn get_collection_job(&self, collection_location: &str) -> TestConn {
        self.get_collection_job_with_auth_token(
            collection_location,
            Some(self.task.primary_collector_auth_token()),
        )
        .await
    }
}

pub(crate) async fn setup_collection_job_test_case(
    role: Role,
    query_type: QueryType,
) -> CollectionJobTestCase {
    install_test_trace_subscriber();

    let collector_hpke_keypair = generate_test_hpke_config_and_private_key();
    let task = TaskBuilder::new(query_type, VdafInstance::Fake, role)
        .with_collector_hpke_config(collector_hpke_keypair.config().clone())
        .build();
    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    datastore.put_task(&task).await.unwrap();

    let handler = aggregator_handler(
        Arc::clone(&datastore),
        clock.clone(),
        &noop_meter(),
        Config {
            batch_aggregation_shard_count: 32,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    CollectionJobTestCase {
        task,
        clock,
        collector_hpke_keypair,
        handler: Box::new(handler),
        datastore,
        _ephemeral_datastore: ephemeral_datastore,
    }
}

async fn setup_fixed_size_current_batch_collection_job_test_case(
) -> (CollectionJobTestCase, BatchId, BatchId) {
    let test_case = setup_collection_job_test_case(
        Role::Leader,
        QueryType::FixedSize {
            max_batch_size: 10,
            batch_time_window_size: None,
        },
    )
    .await;

    // Fill the datastore with the necessary data so that there is are two outstanding batches to be
    // collected.
    let batch_id_1 = random();
    let batch_id_2 = random();
    let time = test_case.clock.now();
    let interval = Interval::new(
        time,
        Duration::from_seconds(test_case.task.time_precision().as_seconds() / 2),
    )
    .unwrap();

    test_case
        .datastore
        .run_tx(|tx| {
            let task = test_case.task.clone();
            Box::pin(async move {
                for batch_id in [batch_id_1, batch_id_2] {
                    let aggregation_job_id = random();
                    tx.put_aggregation_job::<0, FixedSize, dummy_vdaf::Vdaf>(&AggregationJob::new(
                        *task.id(),
                        aggregation_job_id,
                        AggregationParam::default(),
                        batch_id,
                        interval,
                        AggregationJobState::Finished,
                    ))
                    .await
                    .unwrap();

                    for ord in 0..task.min_batch_size() + 1 {
                        let report = LeaderStoredReport::new_dummy(*task.id(), time);
                        tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report)
                            .await
                            .unwrap();

                        tx.put_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report.metadata().id(),
                            time,
                            ord,
                            ReportAggregationState::Finished,
                        ))
                        .await
                        .unwrap();
                    }

                    tx.put_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &BatchAggregation::new(
                            *task.id(),
                            batch_id,
                            AggregationParam::default(),
                            0,
                            BatchAggregationState::Aggregating,
                            Some(dummy_vdaf::AggregateShare(0)),
                            task.min_batch_size() + 1,
                            interval,
                            ReportIdChecksum::default(),
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_batch::<0, FixedSize, dummy_vdaf::Vdaf>(&Batch::new(
                        *task.id(),
                        batch_id,
                        AggregationParam::default(),
                        BatchState::Closed,
                        0,
                        interval,
                    ))
                    .await
                    .unwrap();

                    tx.put_outstanding_batch(task.id(), &batch_id, &None)
                        .await
                        .unwrap();
                }

                Ok(())
            })
        })
        .await
        .unwrap();

    (test_case, batch_id_1, batch_id_2)
}

#[tokio::test]
async fn collection_job_success_fixed_size() {
    // This test drives two current batch collection jobs to completion, verifying that distinct
    // batch IDs are collected each time. Then, we attempt to collect another current batch, which
    // must fail as there are no more outstanding batches.
    let (test_case, batch_id_1, batch_id_2) =
        setup_fixed_size_current_batch_collection_job_test_case().await;

    let mut saw_batch_id_1 = false;
    let mut saw_batch_id_2 = false;
    let leader_aggregate_share = dummy_vdaf::AggregateShare(0);
    let helper_aggregate_share = dummy_vdaf::AggregateShare(1);

    for batch_id in [batch_id_1, batch_id_2] {
        let test_conn = test_case
            .post_collection_job(&CollectReq::new(
                *test_case.task.id(),
                Query::new_fixed_size(batch_id),
                AggregationParam::default().get_encoded(),
            ))
            .await;
        assert_eq!(test_conn.status(), Some(Status::SeeOther));
        let collection_location = test_conn
            .response_headers()
            .get_str(KnownHeaderName::Location)
            .unwrap();

        let test_conn = test_case.get_collection_job(collection_location).await;
        assert_eq!(test_conn.status(), Some(Status::Accepted));

        // Update the collection job with the aggregate shares. collection job should now be complete.
        let batch_id = test_case
            .datastore
            .run_tx(|tx| {
                let task = test_case.task.clone();
                let helper_aggregate_share_bytes = helper_aggregate_share.get_encoded();

                Box::pin(async move {
                    let collection_job_id = tx
                        .get_collection_job_id::<0, FixedSize, dummy_vdaf::Vdaf>(
                            task.id(),
                            &batch_id,
                            &AggregationParam::default(),
                        )
                        .await
                        .unwrap()
                        .unwrap();

                    let collection_job = tx
                        .get_collection_job::<0, FixedSize, dummy_vdaf::Vdaf>(&collection_job_id)
                        .await
                        .unwrap()
                        .unwrap();
                    let batch_id = *collection_job.batch_identifier();

                    let encrypted_helper_aggregate_share = hpke::seal(
                        task.collector_hpke_config().unwrap(),
                        &HpkeApplicationInfo::new(
                            &Label::AggregateShare,
                            &Role::Helper,
                            &Role::Collector,
                        ),
                        &helper_aggregate_share_bytes,
                        &aggregate_share_aad(task.id(), &BatchSelector::new_fixed_size(batch_id)),
                    )
                    .unwrap();

                    tx.update_collection_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &collection_job.with_state(CollectionJobState::Finished {
                            report_count: task.min_batch_size() + 1,
                            encrypted_helper_aggregate_share,
                            leader_aggregate_share,
                        }),
                    )
                    .await
                    .unwrap();

                    Ok(batch_id)
                })
            })
            .await
            .unwrap();

        if batch_id.eq(&batch_id_1) {
            saw_batch_id_1 = true;
        } else if batch_id.eq(&batch_id_2) {
            saw_batch_id_2 = true;
        } else {
            panic!("unexpected batch ID");
        }

        let mut test_conn = test_case.get_collection_job(collection_location).await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_eq!(
            test_conn
                .response_headers()
                .get(KnownHeaderName::ContentType)
                .unwrap(),
            CollectResp::<FixedSize>::MEDIA_TYPE
        );
        let body_bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let collect_resp = CollectResp::<FixedSize>::get_decoded(body_bytes.as_ref()).unwrap();

        assert_eq!(
            collect_resp.report_count(),
            test_case.task.min_batch_size() + 1
        );
        assert_eq!(collect_resp.encrypted_aggregate_shares().len(), 2);

        let aad = aggregate_share_aad(
            test_case.task.id(),
            &BatchSelector::new_fixed_size(batch_id),
        );

        let decrypted_leader_aggregate_share = hpke::open(
            test_case.task.collector_hpke_config().unwrap(),
            test_case.collector_hpke_keypair.private_key(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
            &collect_resp.encrypted_aggregate_shares()[0],
            &aad,
        )
        .unwrap();
        assert_eq!(
            leader_aggregate_share,
            dummy_vdaf::AggregateShare::get_decoded(decrypted_leader_aggregate_share.as_ref())
                .unwrap()
        );

        let decrypted_helper_aggregate_share = hpke::open(
            test_case.task.collector_hpke_config().unwrap(),
            test_case.collector_hpke_keypair.private_key(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            &collect_resp.encrypted_aggregate_shares()[1],
            &aad,
        )
        .unwrap();
        assert_eq!(
            helper_aggregate_share,
            dummy_vdaf::AggregateShare::get_decoded(decrypted_helper_aggregate_share.as_ref())
                .unwrap()
        );
    }

    assert!(saw_batch_id_1 && saw_batch_id_2);
}
