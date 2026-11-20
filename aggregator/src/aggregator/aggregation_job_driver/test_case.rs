use std::{sync::Arc, time::Duration as StdDuration};

use assert_matches::assert_matches;
use chrono::TimeDelta;
use futures::future::join_all;
use http::{StatusCode, header::CONTENT_TYPE};
use janus_aggregator_core::{
    batch_mode::{AccumulableBatchMode, CollectableBatchMode},
    datastore::{
        Datastore,
        models::{
            AcquiredAggregationJob, AggregationJob, AggregationJobDatastoreId, AggregationJobState,
            BatchAggregation, BatchAggregationState, LeaderStoredReport, Lease, ReportAggregation,
            ReportAggregationState, UnwrittenAggregationJob, merge_batch_aggregations_by_batch,
        },
        task_counters::TaskAggregationCounter,
        test_util::{EphemeralDatastore, ephemeral_datastore},
    },
    task::{
        AggregationMode, AggregatorTask, BatchMode, VerifyKey,
        test_util::{Task, TaskBuilder},
    },
    test_util::noop_meter,
};
use janus_core::{
    Runtime,
    hpke::HpkeKeypair,
    http::test_util::MockExt,
    initialize_rustls,
    messages::DeriveId,
    report_id::ReportIdChecksumExt,
    retries::test_util::LimitedRetryer,
    test_util::{
        VdafTranscript, install_test_trace_subscriber, run_vdaf, runtime::TestRuntimeManager,
    },
    time::{Clock, DateTimeExt, MockClock, TimeDeltaExt, TimeExt},
    vdaf::{VERIFY_KEY_LENGTH_PRIO3, VdafInstance},
};
use janus_messages::{
    AggregationJobContinueReq, AggregationJobExtension, AggregationJobId,
    AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep, Duration, Extension,
    ExtensionType, Interval, MediaType, ReportError, ReportId, ReportIdChecksum, ReportMetadata,
    ReportShare, Role, Time, TimePrecision, VerifyContinue, VerifyInit, VerifyResp,
    VerifyStepResult,
    batch_mode::{BatchMode as BatchModeTrait, LeaderSelected, TimeInterval},
    problem_type::DapProblemType,
};
use mockito::ServerGuard;
use prio::{
    codec::Encode,
    vdaf::{
        Aggregator, dummy,
        prio3::{Prio3, Prio3Count},
    },
};
use rand::random;
use tokio::time::timeout;

use crate::{
    aggregator::{
        Error,
        aggregation_job_driver::AggregationJobDriver,
        test_util::{
            BATCH_AGGREGATION_SHARD_COUNT, TASK_AGGREGATION_COUNTER_SHARD_COUNT,
            assert_task_aggregation_counter, generate_helper_report_share,
        },
    },
    binary_utils::{Stopper, job_driver::JobDriver},
    cache::HpkeKeypairCache,
};

const DEFAULT_ASYNC_POLL_INTERVAL: StdDuration = StdDuration::from_secs(1);

pub struct AggregationJobDriverTestCase {
    pub task: AggregatorTask,
    pub vdaf: dummy::Vdaf,
    pub transcript: VdafTranscript<0, dummy::Vdaf>,
    pub aggregation_job_init_req: AggregationJobInitializeReq,
    pub aggregation_job_datastore_id: AggregationJobDatastoreId,
    pub lease: Lease<AcquiredAggregationJob>,
    pub report_metadata: ReportMetadata,
    pub datastore: Arc<Datastore>,
    _ephemeral_datastore: EphemeralDatastore,
    pub mock_server: ServerGuard,
}

impl AggregationJobDriverTestCase {
    pub async fn new() -> Self {
        Self::builder().build().await
    }

    pub fn builder() -> AggregationJobDriverTestCaseBuilder {
        AggregationJobDriverTestCaseBuilder {
            task_builder: TaskBuilder::new(
                BatchMode::TimeInterval,
                AggregationMode::Synchronous,
                VdafInstance::Fake { rounds: 2 },
            ),
            role: Role::Helper,
            vdaf_rounds: 2,
        }
    }

    /// Run the aggregation job driver, returning datastore contents afterward.
    pub async fn step_driver<B: BatchModeTrait>(
        &self,
    ) -> (
        AggregationJob<0, B, dummy::Vdaf>,
        ReportAggregation<0, dummy::Vdaf>,
        Vec<BatchAggregation<0, B, dummy::Vdaf>>,
    ) {
        let aggregation_job_driver = AggregationJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            LimitedRetryer::new(1),
            &noop_meter(),
            BATCH_AGGREGATION_SHARD_COUNT,
            TASK_AGGREGATION_COUNTER_SHARD_COUNT,
            HpkeKeypairCache::DEFAULT_REFRESH_INTERVAL,
            DEFAULT_ASYNC_POLL_INTERVAL,
        );
        aggregation_job_driver
            .step_aggregation_job(
                self.datastore.clone(),
                aggregation_job_driver
                    .make_keypair_cache(&self.datastore)
                    .await,
                self.lease.clone(),
            )
            .await
            .unwrap();

        self.datastore
            .run_unnamed_tx(|tx| {
                let vdaf = self.vdaf.clone();
                let task_id = *self.task.id();
                let role = *self.task.role();
                let aggregation_job_datastore_id = self.aggregation_job_datastore_id;
                let report_id = *self.report_metadata.id();

                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<0, B, dummy::Vdaf>(
                            &task_id,
                            aggregation_job_datastore_id,
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation_by_report_id(
                            &vdaf,
                            &role,
                            &task_id,
                            aggregation_job_datastore_id,
                            &report_id,
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    let batch_aggregations = merge_batch_aggregations_by_batch(
                        tx.get_batch_aggregations_for_task::<0, B, dummy::Vdaf>(&vdaf, &task_id)
                            .await
                            .unwrap(),
                    );

                    Ok((aggregation_job, report_aggregation, batch_aggregations))
                })
            })
            .await
            .unwrap()
    }
}

pub struct AggregationJobDriverTestCaseBuilder {
    task_builder: TaskBuilder,
    role: Role,
    vdaf_rounds: u32,
}

impl AggregationJobDriverTestCaseBuilder {
    pub async fn build(self) -> AggregationJobDriverTestCase {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut mock_server = mockito::Server::new_async().await;
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let hpke_keypair = datastore.put_hpke_key().await.unwrap();

        let vdaf = dummy::Vdaf::new(self.vdaf_rounds);
        let task = self
            .task_builder
            .with_vdaf(VdafInstance::Fake {
                rounds: self.vdaf_rounds,
            })
            .with_helper_aggregator_endpoint(mock_server.url().parse().unwrap())
            .with_aggregator_auth_token(random())
            .build();
        let role_task = match self.role {
            Role::Leader => task.leader_view().unwrap(),
            Role::Helper => task.helper_view().unwrap(),
            _ => panic!("unexpected role"),
        };

        let verify_key: VerifyKey<0> = task.vdaf_verify_key().unwrap();
        let aggregation_param = dummy::AggregationParam(7);
        let time = clock.now().to_time(task.time_precision());
        let batch_identifier = TimeInterval::to_batch_identifier(&(), &time).unwrap();
        let report_metadata = ReportMetadata::new(random(), time, Vec::new());

        let transcript = run_vdaf(
            &vdaf,
            task.id(),
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata.id(),
            &13,
        );

        let helper_hpke_keypair = HpkeKeypair::test();
        let report = LeaderStoredReport::generate(
            *task.id(),
            task.task_configuration(),
            report_metadata,
            helper_hpke_keypair.config(),
            Vec::new(),
            &transcript,
        );

        let (aggregation_job_datastore_id, lease) = datastore
            .run_unnamed_tx(|tx| {
                let role_task = role_task.clone();
                let report = report.clone();

                Box::pin(async move {
                    tx.put_aggregator_task(&role_task).await.unwrap();

                    tx.put_scrubbed_report(
                        role_task.id(),
                        report.metadata().id(),
                        report.metadata().time(),
                    )
                    .await
                    .unwrap();

                    let aggregation_job_datastore_id = tx
                        .put_aggregation_job(&UnwrittenAggregationJob::new(
                            *role_task.id(),
                            aggregation_param,
                            (),
                            Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
                            AggregationJobState::LeaderInit,
                            AggregationJobStep::from(0),
                        ))
                        .await
                        .unwrap();

                    tx.put_report_aggregation(
                        &report.as_leader_init_report_aggregation(aggregation_job_datastore_id, 0),
                    )
                    .await
                    .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                            *role_task.id(),
                            batch_identifier,
                            aggregation_param,
                            0,
                            Interval::minimal(time).unwrap(),
                            BatchAggregationState::Aggregating {
                                aggregate_share: None,
                                report_count: 0,
                                checksum: ReportIdChecksum::default(),
                                aggregation_jobs_created: 1,
                                aggregation_jobs_terminated: 0,
                            },
                        ),
                    )
                    .await
                    .unwrap();

                    let lease = tx
                        .acquire_incomplete_aggregation_jobs(&StdDuration::from_secs(60), 1)
                        .await
                        .unwrap()
                        .remove(0);

                    Ok((aggregation_job_datastore_id, lease))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id(), role_task.id());
        assert_eq!(
            lease.leased().aggregation_job_datastore_id(),
            aggregation_job_datastore_id
        );

        let aggregation_job_init_req = AggregationJobInitializeReq::new(
            0,
            aggregation_param.get_encoded().unwrap(),
            Vec::new(),
            Vec::from([VerifyInit::new(
                ReportShare::new(
                    report.metadata().clone(),
                    report.public_share().get_encoded().unwrap(),
                    report.helper_encrypted_input_share().clone(),
                ),
                transcript.leader_verify_transitions[0]
                    .message()
                    .unwrap()
                    .clone(),
            )]),
        );

        AggregationJobDriverTestCase {
            datastore,
            _ephemeral_datastore: ephemeral_datastore,
            aggregation_job_init_req,
            mock_server,
            task: role_task,
            vdaf,
            aggregation_job_datastore_id,
            lease,
            report_metadata: report.metadata().clone(),
            transcript,
        }
    }

    pub fn with_role(self, role: Role) -> Self {
        Self { role, ..self }
    }

    pub fn with_vdaf_rounds(self, vdaf_rounds: u32) -> Self {
        Self {
            vdaf_rounds,
            ..self
        }
    }

    pub fn build_task<F: FnMut(TaskBuilder) -> TaskBuilder>(self, mut f: F) -> Self {
        Self {
            task_builder: f(self.task_builder),
            ..self
        }
    }
}
