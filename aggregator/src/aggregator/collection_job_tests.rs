use std::sync::Arc;

use assert_matches::assert_matches;
use axum::{Router, body::Body};
use http::{Request, StatusCode};
use janus_aggregator_core::{
    datastore::{
        Datastore,
        models::{
            AggregationJob, AggregationJobState, BatchAggregation, BatchAggregationState,
            CollectionJob, CollectionJobState, LeaderStoredReport, ReportAggregation,
            ReportAggregationState,
        },
        test_util::{EphemeralDatastore, ephemeral_datastore},
    },
    task::{
        AggregationMode, BatchMode,
        test_util::{Task, TaskBuilder},
    },
    test_util::noop_meter,
};
use janus_core::{
    auth_tokens::{AuthenticationToken, test_util::WithAuthenticationToken},
    hpke::{self, HpkeApplicationInfo, Label},
    retries::HeaderMapExt,
    test_util::{install_test_trace_subscriber, runtime::TestRuntime},
    time::{Clock, DateTimeExt, MockClock},
    vdaf::VdafInstance,
};
use janus_messages::{
    AggregateShareAad, AggregationJobStep, BatchId, CollectionJobId, CollectionJobReq,
    CollectionJobResp, Interval, MediaType, Query, Role, TaskId, Time, TimePrecision,
    batch_mode::{
        BatchMode as BatchModeTrait, LeaderSelected, LeaderSelectedQueryConfig, TimeInterval,
    },
};
use prio::{
    codec::{Decode, Encode},
    vdaf::dummy,
};
use rand::random;
use serde_json::json;
use tower::ServiceExt;

use super::http_handlers::AggregatorHandlerBuilder;
use crate::aggregator::{
    Config,
    http_handlers::test_util::{decode_response_body, take_problem_details, take_response_body},
    test_util::BATCH_AGGREGATION_SHARD_COUNT,
};

pub(crate) struct CollectionJobTestCase {
    pub(super) task: Task,
    clock: MockClock,
    pub(super) router: Router,
    pub(super) datastore: Arc<Datastore>,
    _ephemeral_datastore: EphemeralDatastore,
}

impl CollectionJobTestCase {
    pub(super) async fn post_collection_job_with_auth_token<B: BatchModeTrait>(
        &self,
        request: &CollectionJobReq<B>,
        auth_token: Option<&AuthenticationToken>,
    ) -> http::Response<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(self.task.collection_job_creation_uri().unwrap().path())
            .header(
                http::header::CONTENT_TYPE,
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            );
        if let Some(auth) = auth_token {
            builder = builder.with_authentication_token(auth);
        }
        self.router
            .clone()
            .oneshot(
                builder
                    .body(Body::from(request.get_encoded().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    pub(super) async fn post_collection_job<B: BatchModeTrait>(
        &self,
        request: &CollectionJobReq<B>,
    ) -> http::Response<Body> {
        self.post_collection_job_with_auth_token(request, Some(self.task.collector_auth_token()))
            .await
    }

    pub(super) async fn get_collection_job_with_auth_token(
        &self,
        collection_job_id: &CollectionJobId,
        auth_token: Option<&AuthenticationToken>,
    ) -> http::Response<Body> {
        let mut builder = Request::builder().method("GET").uri(
            self.task
                .collection_job_uri(collection_job_id)
                .unwrap()
                .path(),
        );
        if let Some(auth) = auth_token {
            builder = builder.with_authentication_token(auth);
        }
        self.router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    pub(super) async fn get_collection_job(
        &self,
        collection_job_id: &CollectionJobId,
    ) -> http::Response<Body> {
        self.get_collection_job_with_auth_token(
            collection_job_id,
            Some(self.task.collector_auth_token()),
        )
        .await
    }

    /// Seed the database with reports and various aggregation artifacts from aggregating them in a
    /// leader-selected batch.
    pub(super) async fn setup_leader_selected_batch(
        &self,
        time: Time,
        report_count: u64,
    ) -> BatchId {
        let batch_id = random();
        self.datastore
            .run_unnamed_tx(|tx| {
                let task = self.task.clone();
                Box::pin(async move {
                    let client_timestamp_interval = Interval::minimal(time).unwrap();
                    let aggregation_job_id = random();
                    tx.put_aggregation_job(&AggregationJob::<0, LeaderSelected, dummy::Vdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        dummy::AggregationParam::default(),
                        batch_id,
                        client_timestamp_interval,
                        AggregationJobState::Finished,
                        AggregationJobStep::from(1),
                    ))
                    .await
                    .unwrap();
                    for ord in 0..report_count {
                        let report = LeaderStoredReport::new_dummy(*task.id(), time);
                        tx.put_client_report(&report).await.unwrap();
                        tx.scrub_client_report(report.task_id(), report.metadata().id())
                            .await
                            .unwrap();
                        tx.put_report_aggregation(&ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report.metadata().id(),
                            time,
                            ord,
                            None,
                            ReportAggregationState::<0, dummy::Vdaf>::Finished,
                        ))
                        .await
                        .unwrap();
                    }
                    let batch_aggregation = BatchAggregation::<0, LeaderSelected, dummy::Vdaf>::new(
                        *task.id(),
                        batch_id,
                        dummy::AggregationParam::default(),
                        0,
                        client_timestamp_interval,
                        BatchAggregationState::Aggregating {
                            aggregate_share: Some(dummy::AggregateShare(0)),
                            report_count,
                            checksum: Default::default(),
                            aggregation_jobs_created: 1,
                            aggregation_jobs_terminated: 1,
                        },
                    );
                    tx.put_batch_aggregation(&batch_aggregation).await.unwrap();
                    tx.put_outstanding_batch(task.id(), &batch_id, &None)
                        .await
                        .unwrap();
                    Ok(())
                })
            })
            .await
            .unwrap();
        batch_id
    }

    /// Seed the database with a report and various aggregation artifacts from aggregating it in a
    /// time interval batch.
    pub(super) async fn setup_time_interval_batch(&self, time: Time) -> Interval {
        self.datastore
            .run_unnamed_tx(|tx| {
                let task = self.task.clone();
                Box::pin(async move {
                    let report = LeaderStoredReport::new_dummy(*task.id(), time);
                    let client_timestamp_interval =
                        Interval::minimal(*report.metadata().time()).unwrap();
                    let batch_interval = client_timestamp_interval;
                    let aggregation_job_id = random();
                    tx.put_client_report(&report).await.unwrap();
                    tx.scrub_client_report(report.task_id(), report.metadata().id())
                        .await
                        .unwrap();
                    tx.put_aggregation_job(&AggregationJob::<0, TimeInterval, dummy::Vdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        dummy::AggregationParam::default(),
                        (),
                        client_timestamp_interval,
                        AggregationJobState::Finished,
                        AggregationJobStep::from(1),
                    ))
                    .await
                    .unwrap();
                    tx.put_report_aggregation(&ReportAggregation::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        time,
                        0,
                        None,
                        ReportAggregationState::<0, dummy::Vdaf>::Finished,
                    ))
                    .await
                    .unwrap();
                    let batch_aggregation = BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                        *task.id(),
                        batch_interval,
                        dummy::AggregationParam::default(),
                        0,
                        client_timestamp_interval,
                        BatchAggregationState::Aggregating {
                            aggregate_share: Some(dummy::AggregateShare(0)),
                            report_count: 1,
                            checksum: Default::default(),
                            aggregation_jobs_created: 1,
                            aggregation_jobs_terminated: 1,
                        },
                    );
                    tx.put_batch_aggregation(&batch_aggregation).await.unwrap();
                    Ok(batch_interval)
                })
            })
            .await
            .unwrap()
    }
}

/// Parse task ID and collection job ID out of response location header.
///
/// Panics if header is missing from response or value is malformed.
pub(super) fn ids_from_collection_job_response(
    response: &http::Response<Body>,
) -> (TaskId, CollectionJobId) {
    response
        .headers()
        .ids_from_collection_job_location()
        .unwrap()
        .unwrap()
}

pub(crate) async fn setup_collection_job_test_case(
    role: Role,
    batch_mode: BatchMode,
) -> CollectionJobTestCase {
    install_test_trace_subscriber();

    let task = TaskBuilder::new(
        batch_mode,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .build();
    let role_task = task.view_for_role(role).unwrap();
    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    datastore.put_aggregator_task(&role_task).await.unwrap();
    datastore.put_hpke_key().await.unwrap();

    let router = AggregatorHandlerBuilder::new(
        Arc::clone(&datastore),
        TestRuntime::default(),
        &noop_meter(),
        Config {
            batch_aggregation_shard_count: BATCH_AGGREGATION_SHARD_COUNT,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .build()
    .unwrap();

    CollectionJobTestCase {
        task,
        clock,
        router,
        datastore,
        _ephemeral_datastore: ephemeral_datastore,
    }
}

async fn setup_leader_selected_current_batch_collection_job_test_case()
-> (CollectionJobTestCase, BatchId, BatchId, Interval) {
    let test_case = setup_collection_job_test_case(
        Role::Leader,
        BatchMode::LeaderSelected {
            batch_time_window_size: None,
        },
    )
    .await;

    // Fill the datastore with the necessary data so that there are two outstanding batches to be
    // collected.
    let time = test_case
        .clock
        .now()
        .to_time(test_case.task.time_precision());
    let batch_id_1 = test_case
        .setup_leader_selected_batch(time, test_case.task.min_batch_size() + 1)
        .await;
    let batch_id_2 = test_case
        .setup_leader_selected_batch(time, test_case.task.min_batch_size() + 1)
        .await;
    let client_timestamp_interval = Interval::minimal(time).unwrap();

    (test_case, batch_id_1, batch_id_2, client_timestamp_interval)
}

#[tokio::test]
async fn collection_job_success_leader_selected() {
    // This test drives two current batch collection jobs to completion, verifying that distinct
    // collection job IDs are minted and distinct batch IDs are collected each time. Then, we
    // attempt to collect another current batch, which must fail as there are no more outstanding
    // batches.
    let (test_case, batch_id_1, batch_id_2, spanned_interval) =
        setup_leader_selected_current_batch_collection_job_test_case().await;

    let mut saw_batch_id_1 = false;
    let mut saw_batch_id_2 = false;
    let mut collection_job_ids = vec![];
    let vdaf = dummy::Vdaf::new(1);
    let leader_aggregate_share = dummy::AggregateShare(0);
    let helper_aggregate_share = dummy::AggregateShare(1);
    let aggregation_param = dummy::AggregationParam::default();

    for _ in 0..2 {
        let request = CollectionJobReq::new(
            Query::new_leader_selected(random()),
            aggregation_param.get_encoded().unwrap(),
        );
        let mut response = test_case.post_collection_job(&request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let (task_id, collection_job_id) = ids_from_collection_job_response(&response);
        collection_job_ids.push(collection_job_id);
        assert_eq!(test_case.task.id(), &task_id);
        assert!(take_response_body(&mut response).await.is_empty());

        let mut response = test_case.get_collection_job(&collection_job_id).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(http::header::CONTENT_TYPE).is_none());
        assert!(take_response_body(&mut response).await.is_empty());

        // Update the collection job with the aggregate shares. collection job should now be
        // complete.
        let batch_id = test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task = test_case.task.clone();
                let vdaf = vdaf.clone();
                let helper_aggregate_share_bytes = helper_aggregate_share.get_encoded().unwrap();
                let request = request.clone();
                Box::pin(async move {
                    let collection_job = tx
                        .get_collection_job::<0, LeaderSelected, dummy::Vdaf>(
                            &vdaf,
                            task.id(),
                            &collection_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    let batch_id = *collection_job.batch_identifier();

                    let encrypted_helper_aggregate_share = hpke::seal(
                        task.collector_hpke_keypair().config(),
                        &HpkeApplicationInfo::new(
                            &Label::AggregateShare,
                            &Role::Helper,
                            &Role::Collector,
                        ),
                        &helper_aggregate_share_bytes,
                        &AggregateShareAad::new(*task.id(), task.task_configuration(), request)
                            .get_encoded()
                            .unwrap(),
                    )
                    .unwrap();

                    tx.update_collection_job::<0, LeaderSelected, dummy::Vdaf>(
                        &collection_job.with_state(CollectionJobState::Finished {
                            report_count: task.min_batch_size() + 1,
                            client_timestamp_interval: spanned_interval,
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

        let mut response = test_case.get_collection_job(&collection_job_id).await;
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            CollectionJobResp::MEDIA_TYPE,
        );

        let collect_resp: CollectionJobResp = decode_response_body(&mut response).await;
        let (
            report_count,
            interval,
            leader_encrypted_aggregate_share,
            helper_encrypted_aggregate_share,
        ) = assert_matches!(
            collect_resp,
            CollectionJobResp {
                report_count,
                interval,
                leader_encrypted_agg_share,
                helper_encrypted_agg_share,
                ..
            } => (
                report_count,
                interval,
                leader_encrypted_agg_share,
                helper_encrypted_agg_share
            )
        );

        assert_eq!(report_count, test_case.task.min_batch_size() + 1);
        assert_eq!(interval, spanned_interval);

        let decrypted_leader_aggregate_share = hpke::open(
            test_case.task.collector_hpke_keypair(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
            &leader_encrypted_aggregate_share,
            &AggregateShareAad::new(
                *test_case.task.id(),
                test_case.task.task_configuration(),
                request.clone(),
            )
            .get_encoded()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            leader_aggregate_share,
            dummy::AggregateShare::get_decoded(decrypted_leader_aggregate_share.as_ref()).unwrap()
        );

        let decrypted_helper_aggregate_share = hpke::open(
            test_case.task.collector_hpke_keypair(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            &helper_encrypted_aggregate_share,
            &AggregateShareAad::new(
                *test_case.task.id(),
                test_case.task.task_configuration(),
                request.clone(),
            )
            .get_encoded()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            helper_aggregate_share,
            dummy::AggregateShare::get_decoded(decrypted_helper_aggregate_share.as_ref()).unwrap()
        );
    }

    assert!(saw_batch_id_1 && saw_batch_id_2);
    // Collection job IDs should be distinct
    assert_eq!(collection_job_ids.len(), 2);
    assert_ne!(collection_job_ids[0], collection_job_ids[1]);

    // We have run the two ready batches to completion. Further attempts to collect current batch
    // ought to fail.
    let mut response = test_case
        .post_collection_job(&CollectionJobReq::new(
            Query::new_leader_selected(random()),
            aggregation_param.get_encoded().unwrap(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
            "title": "The batch implied by the query is invalid.",
            "taskid": format!("{}", test_case.task.id()),
        }),
    );
}

#[tokio::test]
async fn collection_job_post_idempotence_time_interval() {
    let test_case = setup_collection_job_test_case(Role::Leader, BatchMode::TimeInterval).await;
    // Seed DB with reports, aggregations, etc. corresponding to the two time intervals used later
    // in the test
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            &TimePrecision::from_seconds(1),
        ))
        .await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            3,
            &TimePrecision::from_seconds(1),
        ))
        .await;

    // We should get the same collection job ID back both times
    let mut collection_job_id = None;
    for _ in 0..2 {
        let response = test_case
            .post_collection_job(&CollectionJobReq::new(
                Query::new_time_interval(
                    Interval::minimal(Time::from_seconds_since_epoch(
                        0,
                        test_case.task.time_precision(),
                    ))
                    .unwrap(),
                ),
                dummy::AggregationParam::default().get_encoded().unwrap(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (_, created_collection_job_id) = ids_from_collection_job_response(&response);
        if let Some(collection_job_id) = collection_job_id {
            assert_eq!(created_collection_job_id, collection_job_id);
        } else {
            collection_job_id = Some(created_collection_job_id);
        }
    }

    // Send another request, with non-overlapping time interval. We should create a distinct
    // collection job.
    let response = test_case
        .post_collection_job(&CollectionJobReq::new(
            Query::new_time_interval(
                Interval::minimal(Time::from_seconds_since_epoch(
                    3 * test_case.task.time_precision().as_seconds(),
                    test_case.task.time_precision(),
                ))
                .unwrap(),
            ),
            dummy::AggregationParam::default().get_encoded().unwrap(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, next_collection_job_id) = ids_from_collection_job_response(&response);
    assert_ne!(collection_job_id.unwrap(), next_collection_job_id);

    // There should only be two collection jobs despite three successful POSTs
    let mut expect_collection_job_ids = vec![collection_job_id.unwrap(), next_collection_job_id];
    expect_collection_job_ids.sort();

    let got_collection_job_ids = test_case
        .datastore
        .run_unnamed_tx(|tx| {
            let task_id = *test_case.task.id();
            let vdaf = dummy::Vdaf::new(1);
            Box::pin(async move {
                let mut collection_job_ids: Vec<_> = tx
                    .get_collection_jobs_for_task::<0, TimeInterval, dummy::Vdaf>(&vdaf, &task_id)
                    .await
                    .unwrap()
                    .iter()
                    .map(CollectionJob::id)
                    .cloned()
                    .collect();
                collection_job_ids.sort();

                Ok(collection_job_ids)
            })
        })
        .await
        .unwrap();

    assert_eq!(got_collection_job_ids, expect_collection_job_ids);
}

#[tokio::test]
async fn collection_job_post_idempotence_time_interval_mutate_aggregation_param() {
    // Create a collection job for some time interval, then try to create another, varying the
    // aggregation parameter. It should fail due to illegal mutation.
    let test_case = setup_collection_job_test_case(Role::Leader, BatchMode::TimeInterval).await;
    test_case
        .setup_time_interval_batch(Time::from_time_precision_units(0))
        .await;

    let request = CollectionJobReq::new(
        Query::new_time_interval(Interval::minimal(Time::from_time_precision_units(0)).unwrap()),
        dummy::AggregationParam(0).get_encoded().unwrap(),
    );

    let response = test_case.post_collection_job(&request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let mutated_request = CollectionJobReq::new(
        Query::new_time_interval(Interval::minimal(Time::from_time_precision_units(0)).unwrap()),
        dummy::AggregationParam(1).get_encoded().unwrap(),
    );

    let response = test_case.post_collection_job(&mutated_request).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn collection_job_post_idempotence_leader_selected() {
    let (test_case, batch_id_1, batch_id_2, _) =
        setup_leader_selected_current_batch_collection_job_test_case().await;

    let mut seen_batch_id = None;
    let mut collection_job_id = None;
    let idempotency_key: LeaderSelectedQueryConfig = random();

    for _ in 0..2 {
        let response = test_case
            .post_collection_job(&CollectionJobReq::new(
                Query::new_leader_selected(idempotency_key.clone()),
                dummy::AggregationParam(0).get_encoded().unwrap(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (_, created_collection_job_id) = ids_from_collection_job_response(&response);
        if let Some(collection_job_id) = collection_job_id {
            assert_eq!(created_collection_job_id, collection_job_id);
        } else {
            collection_job_id = Some(created_collection_job_id);
        }

        // Make sure that there is only ever a single collection job, and that it uses the same
        // batch ID after each PUT
        let batch_id = test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task_id = *test_case.task.id();
                Box::pin(async move {
                    let collection_jobs = tx
                        .get_collection_jobs_for_task::<0, LeaderSelected, dummy::Vdaf>(
                            &dummy::Vdaf::new(1),
                            &task_id,
                        )
                        .await
                        .unwrap();
                    assert_eq!(collection_jobs.len(), 1);
                    assert_eq!(collection_jobs[0].id(), &collection_job_id.unwrap());
                    assert!(
                        collection_jobs[0].batch_identifier().eq(&batch_id_1)
                            || collection_jobs[0].batch_identifier().eq(&batch_id_2)
                    );

                    Ok(*collection_jobs[0].batch_identifier())
                })
            })
            .await
            .unwrap();
        match seen_batch_id {
            None => seen_batch_id = Some(batch_id),
            Some(seen_batch_id) => assert_eq!(seen_batch_id, batch_id),
        }
    }

    // POST another collection job with a different idempotency key. We should create a distinct
    // collection job.
    let response = test_case
        .post_collection_job(&CollectionJobReq::new(
            Query::new_leader_selected(random()),
            dummy::AggregationParam(0).get_encoded().unwrap(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, next_collection_job_id) = ids_from_collection_job_response(&response);
    assert_ne!(next_collection_job_id, collection_job_id.unwrap());

    // There should only be two collection jobs despite three successful POSTs
    let mut expect_collection_job_ids = vec![collection_job_id.unwrap(), next_collection_job_id];
    expect_collection_job_ids.sort();

    let got_collection_job_ids = test_case
        .datastore
        .run_unnamed_tx(|tx| {
            let task_id = *test_case.task.id();
            Box::pin(async move {
                let mut collection_job_ids: Vec<_> = tx
                    .get_collection_jobs_for_task::<0, LeaderSelected, dummy::Vdaf>(
                        &dummy::Vdaf::new(1),
                        &task_id,
                    )
                    .await
                    .unwrap()
                    .iter()
                    .map(CollectionJob::id)
                    .cloned()
                    .collect();
                collection_job_ids.sort();

                Ok(collection_job_ids)
            })
        })
        .await
        .unwrap();

    assert_eq!(got_collection_job_ids, expect_collection_job_ids);
}

#[tokio::test]
async fn collection_job_post_idempotence_leader_selected_mutate_aggregation_param() {
    // Create a collection job for some idempotency key, then try to create another, varying the
    // aggregation parameter. It should fail due to illegal mutation.
    let (test_case, _, _, _) = setup_leader_selected_current_batch_collection_job_test_case().await;

    let idempotency_key: LeaderSelectedQueryConfig = random();

    let request = CollectionJobReq::new(
        Query::new_leader_selected(idempotency_key.clone()),
        dummy::AggregationParam(0).get_encoded().unwrap(),
    );

    let response = test_case.post_collection_job(&request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let mutated_request = CollectionJobReq::new(
        Query::new_leader_selected(idempotency_key),
        dummy::AggregationParam(1).get_encoded().unwrap(),
    );

    let response = test_case.post_collection_job(&mutated_request).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn collection_job_post_idempotence_leader_selected_no_extra_reports() {
    let (test_case, _batch_id_1, _batch_id_2, _) =
        setup_leader_selected_current_batch_collection_job_test_case().await;

    let request_1 = CollectionJobReq::new(
        Query::new_leader_selected(random()),
        dummy::AggregationParam(0).get_encoded().unwrap(),
    );

    // Create the first collection job.
    let response = test_case.post_collection_job(&request_1).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, collection_job_id_1) = ids_from_collection_job_response(&response);

    // Fetch the first collection job, to advance the current batch.
    let response = test_case.get_collection_job(&collection_job_id_1).await;
    assert_eq!(response.status(), StatusCode::OK);

    let request_2 = CollectionJobReq::new(
        Query::new_leader_selected(random()),
        dummy::AggregationParam(0).get_encoded().unwrap(),
    );

    // Create the second collection job.
    let response = test_case.post_collection_job(&request_2).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, collection_job_id_2) = ids_from_collection_job_response(&response);

    // Fetch the second collection job, to advance the current batch. There are now no outstanding
    // batches left.
    let response = test_case.get_collection_job(&collection_job_id_2).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Re-send the collection job creation requests to confirm they are still idempotent.
    let response = test_case.post_collection_job(&request_1).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = test_case.post_collection_job(&request_2).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn collection_job_batch_mode_misaligned() {
    let test_case = setup_collection_job_test_case(Role::Leader, BatchMode::TimeInterval).await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            &TimePrecision::from_seconds(1),
        ))
        .await;

    // LeaderSelected != TimeInterval
    let request = CollectionJobReq::new(
        Query::new_leader_selected(random()),
        dummy::AggregationParam(0).get_encoded().unwrap(),
    );

    let mut response = test_case.post_collection_job(&request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
            "title": "The message type for a response was incorrect or the payload was malformed.",
        }),
    );
}
