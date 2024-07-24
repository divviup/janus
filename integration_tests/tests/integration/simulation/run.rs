use std::{
    collections::HashMap,
    ops::ControlFlow,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
    time::Duration as StdDuration,
};

use backoff::ExponentialBackoff;
use derivative::Derivative;
use divviup_client::{Decode, Encode};
use http::header::CONTENT_TYPE;
use janus_aggregator_core::{
    datastore::models::AggregatorRole,
    task::{test_util::Task, AggregatorTask},
    test_util::noop_meter,
};
use janus_collector::{Collection, CollectionJob, PollResult};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label},
    http::HttpErrorResponse,
    retries::retry_http_request,
    test_util::runtime::TestRuntimeManager,
    time::{MockClock, TimeExt},
    vdaf::VdafInstance,
};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    CollectionJobId, Duration, FixedSizeQuery, HpkeConfig, HpkeConfigList, InputShareAad,
    PlaintextInputShare, Report, ReportId, ReportMetadata, Role, Time,
};
use opentelemetry::metrics::Meter;
use prio::vdaf::{
    prio3::{optimal_chunk_length, Prio3, Prio3Histogram},
    Client as _,
};
use quickcheck::TestResult;
use tokio::time::timeout;
use tracing::{debug, error, info, info_span, warn, Instrument};
use trillium_tokio::Stopper;
use url::Url;

use crate::simulation::{
    model::{Input, Op, Query},
    setup::Components,
    START_TIME,
};

const MAX_REPORTS: usize = 1_000;

pub(super) struct Simulation {
    state: State,
    components: Components,
    task: Task,
    leader_task: Arc<AggregatorTask>,
}

impl Simulation {
    async fn new(input: &Input) -> Self {
        let mut state = State::new();
        let (components, task) = Components::setup(input, &mut state).await;
        let leader_task = Arc::new(task.leader_view().unwrap());
        Self {
            state,
            components,
            task,
            leader_task,
        }
    }

    pub(super) fn run(input: Input) -> TestResult {
        let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        tokio_runtime.block_on(async {
            let mut simulation = Self::new(&input).await;
            for op in input.ops.iter() {
                let span = info_span!("operation", op = ?op);
                let timeout_result = timeout(StdDuration::from_secs(15), async {
                    info!("starting operation");
                    let result = match op {
                        Op::AdvanceTime { amount } => simulation.execute_advance_time(amount).await,
                        Op::Upload { report_time } => simulation.execute_upload(report_time).await,
                        Op::UploadReplay { report_time } => {
                            simulation.execute_upload_replay(report_time).await
                        }
                        Op::LeaderGarbageCollector => {
                            simulation
                                .execute_garbage_collector(AggregatorRole::Leader)
                                .await
                        }
                        Op::HelperGarbageCollector => {
                            simulation
                                .execute_garbage_collector(AggregatorRole::Helper)
                                .await
                        }
                        Op::AggregationJobCreator => {
                            simulation.execute_aggregation_job_creator().await
                        }
                        Op::AggregationJobDriver => {
                            simulation.execute_aggregation_job_driver().await
                        }
                        Op::AggregationJobDriverRequestError => {
                            simulation
                                .execute_aggregation_job_driver_request_error()
                                .await
                        }
                        Op::AggregationJobDriverResponseError => {
                            simulation
                                .execute_aggregation_job_driver_response_error()
                                .await
                        }
                        Op::CollectionJobDriver => simulation.execute_collection_job_driver().await,
                        Op::CollectionJobDriverRequestError => {
                            simulation
                                .execute_collection_job_driver_request_error()
                                .await
                        }
                        Op::CollectionJobDriverResponseError => {
                            simulation
                                .execute_collection_job_driver_response_error()
                                .await
                        }
                        Op::CollectorStart {
                            collection_job_id,
                            query,
                        } => {
                            simulation
                                .execute_collector_start(collection_job_id, query)
                                .await
                        }
                        Op::CollectorPoll { collection_job_id } => {
                            simulation.execute_collector_poll(collection_job_id).await
                        }
                    };
                    info!("finished operation");
                    result
                })
                .instrument(span)
                .await;
                match timeout_result {
                    Ok(ControlFlow::Break(test_result)) => return test_result,
                    Ok(ControlFlow::Continue(())) => {}
                    Err(error) => return TestResult::error(error.to_string()),
                }

                if simulation.components.leader.inspect_monitor.has_failed()
                    || simulation.components.helper.inspect_monitor.has_failed()
                {
                    return TestResult::failed();
                }
            }

            if !check_aggregate_results_valid(
                &simulation.state.aggregate_results_time_interval,
                &simulation.state,
            ) {
                return TestResult::failed();
            }

            if !check_aggregate_results_valid(
                &simulation.state.aggregate_results_fixed_size,
                &simulation.state,
            ) {
                return TestResult::failed();
            }

            // `TestRuntimeManager` will panic on drop if any asynchronous task spawned via its
            // labeled runtimes panicked. Drop the `Simulation` struct, which includes this manager,
            // inside `catch_unwind` so we can report failure.
            if catch_unwind(AssertUnwindSafe(move || drop(simulation))).is_err() {
                return TestResult::failed();
            }

            TestResult::passed()
        })
    }

    async fn execute_advance_time(&mut self, amount: &Duration) -> ControlFlow<TestResult> {
        self.state.clock.advance(amount);
        ControlFlow::Continue(())
    }

    async fn execute_upload(&mut self, report_time: &Time) -> ControlFlow<TestResult> {
        if let Some(measurement) = self.state.next_measurement() {
            if let Err(error) = self
                .components
                .client
                .upload_with_time(&measurement, *report_time)
                .await
            {
                warn!(?error, "client error");
                // We expect to receive an error if the report timestamp is too far away from the
                // current time, so we'll allow errors for now.
            }
        }
        ControlFlow::Continue(())
    }

    async fn execute_upload_replay(&mut self, report_time: &Time) -> ControlFlow<TestResult> {
        if let Some(measurement) = self.state.next_measurement() {
            if let Err(error) = upload_replay_report(
                measurement,
                &self.task,
                &self.state.vdaf,
                report_time,
                &self.components.http_client,
            )
            .await
            {
                warn!(?error, "client error");
                // We expect to receive an error if the report timestamp is too far away from the
                // current time, so we'll allow errors for now.
            }
        }
        ControlFlow::Continue(())
    }

    async fn execute_garbage_collector(&mut self, role: AggregatorRole) -> ControlFlow<TestResult> {
        let garbage_collector = match role {
            AggregatorRole::Leader => &self.components.leader_garbage_collector,
            AggregatorRole::Helper => &self.components.helper_garbage_collector,
        };
        if let Err(error) = garbage_collector.run().await {
            error!(?error, "garbage collector error");
            return ControlFlow::Break(TestResult::error(format!("{error:?}")));
        }
        ControlFlow::Continue(())
    }

    async fn execute_aggregation_job_creator(&mut self) -> ControlFlow<TestResult> {
        let aggregation_job_creator = Arc::clone(&self.components.aggregation_job_creator);
        let task = Arc::clone(&self.leader_task);
        if let Err(error) = aggregation_job_creator
            .create_aggregation_jobs_for_task(task)
            .await
        {
            error!(?error, "aggregation job creator error");
            return ControlFlow::Break(TestResult::error(format!("{error:?}")));
        }
        ControlFlow::Continue(())
    }

    async fn execute_aggregation_job_driver(&mut self) -> ControlFlow<TestResult> {
        let leases = match (self.components.aggregation_job_driver_acquirer_cb)(10).await {
            Ok(leases) => leases,
            Err(error) => {
                error!(?error, "aggregation job driver error");
                return ControlFlow::Break(TestResult::error(format!("{error:?}")));
            }
        };
        for lease in leases {
            if let Err(error) = (self.components.aggregation_job_driver_stepper_cb)(lease).await {
                error!(?error, "aggregation job driver error");
                return ControlFlow::Break(TestResult::error(format!("{error:?}")));
            }
        }
        ControlFlow::Continue(())
    }

    async fn execute_aggregation_job_driver_request_error(&mut self) -> ControlFlow<TestResult> {
        self.components.helper.fault_injector.error_before();
        let result = self.execute_aggregation_job_driver().await;
        self.components.helper.fault_injector.reset();
        result
    }

    async fn execute_aggregation_job_driver_response_error(&mut self) -> ControlFlow<TestResult> {
        self.components.helper.fault_injector.error_after();
        let result = self.execute_aggregation_job_driver().await;
        self.components.helper.fault_injector.reset();
        result
    }

    async fn execute_collection_job_driver(&mut self) -> ControlFlow<TestResult> {
        let leases = match (self.components.collection_job_driver_acquirer_cb)(10).await {
            Ok(leases) => leases,
            Err(error) => {
                error!(?error, "collection job driver error");
                return ControlFlow::Break(TestResult::error(format!("{error:?}")));
            }
        };
        for lease in leases {
            if let Err(error) = (self.components.collection_job_driver_stepper_cb)(lease).await {
                error!(?error, "collection job driver error");
                return ControlFlow::Break(TestResult::error(format!("{error:?}")));
            }
        }
        ControlFlow::Continue(())
    }

    async fn execute_collection_job_driver_request_error(&mut self) -> ControlFlow<TestResult> {
        self.components.helper.fault_injector.error_before();
        let result = self.execute_collection_job_driver().await;
        self.components.helper.fault_injector.reset();
        result
    }

    async fn execute_collection_job_driver_response_error(&mut self) -> ControlFlow<TestResult> {
        self.components.helper.fault_injector.error_after();
        let result = self.execute_collection_job_driver().await;
        self.components.helper.fault_injector.reset();
        result
    }

    async fn execute_collector_start(
        &mut self,
        collection_job_id: &CollectionJobId,
        query: &Query,
    ) -> ControlFlow<TestResult> {
        match query {
            Query::TimeInterval(interval) => {
                let query = janus_messages::Query::new_time_interval(*interval);
                match self
                    .components
                    .collector
                    .start_collection_with_id(*collection_job_id, query, &())
                    .await
                {
                    Ok(collection_job) => {
                        self.state
                            .collection_jobs_time_interval
                            .insert(*collection_job_id, collection_job);
                    }
                    Err(error) => info!(?error, "collector error"),
                }
            }
            Query::FixedSizeCurrentBatch => {
                let query = janus_messages::Query::new_fixed_size(FixedSizeQuery::CurrentBatch);
                match self
                    .components
                    .collector
                    .start_collection_with_id(*collection_job_id, query, &())
                    .await
                {
                    Ok(collection_job) => {
                        self.state
                            .collection_jobs_fixed_size
                            .insert(*collection_job_id, collection_job);
                    }
                    Err(error) => info!(?error, "collector error"),
                }
            }
            Query::FixedSizeByBatchId(previous_collection_job_id) => {
                if let Some(collection) = self
                    .state
                    .aggregate_results_fixed_size
                    .get(previous_collection_job_id)
                {
                    let query = janus_messages::Query::new_fixed_size(FixedSizeQuery::ByBatchId {
                        batch_id: *collection.partial_batch_selector().batch_id(),
                    });
                    match self
                        .components
                        .collector
                        .start_collection_with_id(*collection_job_id, query, &())
                        .await
                    {
                        Ok(collection_job) => {
                            self.state
                                .collection_jobs_fixed_size
                                .insert(*collection_job_id, collection_job);

                            // Store a copy of the collection results from the previous collection
                            // job under this new collection job as well. When we get results from
                            // pollng the "by batch ID" job, we will then compare results from the
                            // two jobs to ensure they are the same.
                            self.state.aggregate_results_fixed_size.insert(
                                *collection_job_id,
                                Collection::new(
                                    collection.partial_batch_selector().clone(),
                                    collection.report_count(),
                                    *collection.interval(),
                                    collection.aggregate_result().clone(),
                                ),
                            );
                        }
                        Err(error) => info!(?error, "collector error"),
                    }
                }
            }
        }
        ControlFlow::Continue(())
    }

    async fn execute_collector_poll(
        &mut self,
        collection_job_id: &CollectionJobId,
    ) -> ControlFlow<TestResult> {
        if let Some(collection_job) = self
            .state
            .collection_jobs_time_interval
            .get(collection_job_id)
        {
            let result = self.components.collector.poll_once(collection_job).await;
            match result {
                Ok(PollResult::CollectionResult(collection)) => {
                    let report_count = collection.report_count();
                    let interval = *collection.interval();
                    let aggregate_result = collection.aggregate_result().clone();
                    let old_opt = self
                        .state
                        .aggregate_results_time_interval
                        .insert(*collection_job_id, collection);
                    if let Some(old_collection) = old_opt {
                        if report_count != old_collection.report_count()
                            || &interval != old_collection.interval()
                            || &aggregate_result != old_collection.aggregate_result()
                        {
                            error!("repeated collection did not match");
                            return ControlFlow::Break(TestResult::failed());
                        }
                    }
                }
                Ok(PollResult::NotReady(_)) => {}
                Err(error) => info!(?error, "collector error"),
            }
        } else if let Some(collection_job) =
            self.state.collection_jobs_fixed_size.get(collection_job_id)
        {
            let result = self.components.collector.poll_once(collection_job).await;
            match result {
                Ok(PollResult::CollectionResult(collection)) => {
                    let partial_batch_selector = collection.partial_batch_selector().clone();
                    let report_count = collection.report_count();
                    let interval = *collection.interval();
                    let aggregate_result = collection.aggregate_result().clone();
                    let old_opt = self
                        .state
                        .aggregate_results_fixed_size
                        .insert(*collection_job_id, collection);
                    if let Some(old_collection) = old_opt {
                        if &partial_batch_selector != old_collection.partial_batch_selector()
                            || report_count != old_collection.report_count()
                            || &interval != old_collection.interval()
                            || &aggregate_result != old_collection.aggregate_result()
                        {
                            error!("repeated collection did not match");
                            return ControlFlow::Break(TestResult::failed());
                        }
                    }
                }
                Ok(PollResult::NotReady(_)) => {}
                Err(error) => info!(?error, "collector error"),
            }
        }
        ControlFlow::Continue(())
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub(super) struct State {
    pub(super) stopper: Stopper,
    pub(super) clock: MockClock,
    pub(super) meter: Meter,
    #[derivative(Debug = "ignore")]
    pub(super) runtime_manager: TestRuntimeManager<&'static str>,
    pub(super) vdaf_instance: VdafInstance,
    pub(super) vdaf: Prio3Histogram,
    pub(super) collection_jobs_time_interval:
        HashMap<CollectionJobId, CollectionJob<(), TimeInterval>>,
    pub(super) collection_jobs_fixed_size: HashMap<CollectionJobId, CollectionJob<(), FixedSize>>,
    pub(super) aggregate_results_time_interval:
        HashMap<CollectionJobId, Collection<Vec<u128>, TimeInterval>>,
    pub(super) aggregate_results_fixed_size:
        HashMap<CollectionJobId, Collection<Vec<u128>, FixedSize>>,
    pub(super) next_measurement: usize,
}

impl State {
    fn new() -> Self {
        let chunk_length = optimal_chunk_length(MAX_REPORTS);
        Self {
            stopper: Stopper::new(),
            clock: MockClock::new(START_TIME),
            meter: noop_meter(),
            runtime_manager: TestRuntimeManager::new(),
            vdaf_instance: VdafInstance::Prio3Histogram {
                length: MAX_REPORTS,
                chunk_length,
            },
            vdaf: Prio3::new_histogram(2, MAX_REPORTS, chunk_length).unwrap(),
            collection_jobs_time_interval: HashMap::new(),
            collection_jobs_fixed_size: HashMap::new(),
            aggregate_results_time_interval: HashMap::new(),
            aggregate_results_fixed_size: HashMap::new(),
            next_measurement: 0,
        }
    }

    fn next_measurement(&mut self) -> Option<usize> {
        if self.next_measurement < MAX_REPORTS {
            let output = self.next_measurement;
            self.next_measurement += 1;
            Some(output)
        } else {
            debug!("Too many reports, skipping upload operation");
            None
        }
    }
}

/// Shard and upload a report, but with a fixed ReportId.
async fn upload_replay_report(
    measurement: usize,
    task: &Task,
    vdaf: &Prio3Histogram,
    report_time: &Time,
    http_client: &reqwest::Client,
) -> Result<(), janus_client::Error> {
    // This encodes to "replayreplayreplayrepl".
    let report_id = ReportId::from([
        173, 234, 101, 107, 42, 222, 166, 86, 178, 173, 234, 101, 107, 42, 222, 166,
    ]);
    let task_id = *task.id();
    let (public_share, input_shares) = vdaf.shard(&measurement, report_id.as_ref())?;
    let rounded_time = report_time
        .to_batch_interval_start(task.time_precision())
        .unwrap();
    let report_metadata = ReportMetadata::new(report_id, rounded_time);
    let encoded_public_share = public_share.get_encoded();

    let leader_hpke_config =
        aggregator_hpke_config(task.leader_aggregator_endpoint(), http_client).await?;
    let helper_hpke_config =
        aggregator_hpke_config(task.helper_aggregator_endpoint(), http_client).await?;

    let aad = InputShareAad::new(
        task_id,
        report_metadata.clone(),
        encoded_public_share.clone(),
    )
    .get_encoded();
    let leader_encrypted_input_share = hpke::seal(
        &leader_hpke_config,
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
        &PlaintextInputShare::new(Vec::new(), input_shares[0].get_encoded()).get_encoded(),
        &aad,
    )?;
    let helper_encrypted_input_share = hpke::seal(
        &helper_hpke_config,
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
        &PlaintextInputShare::new(Vec::new(), input_shares[1].get_encoded()).get_encoded(),
        &aad,
    )?;

    let report = Report::new(
        report_metadata,
        encoded_public_share,
        leader_encrypted_input_share,
        helper_encrypted_input_share,
    );

    let url = task
        .leader_aggregator_endpoint()
        .join(&format!("tasks/{task_id}/reports"))
        .unwrap();
    retry_http_request(http_request_exponential_backoff(), || async {
        http_client
            .put(url.clone())
            .header(CONTENT_TYPE, Report::MEDIA_TYPE)
            .body(report.get_encoded())
            .send()
            .await
    })
    .await
    .unwrap();

    Ok(())
}

async fn aggregator_hpke_config(
    endpoint: &Url,
    http_client: &reqwest::Client,
) -> Result<HpkeConfig, janus_client::Error> {
    let response = retry_http_request(http_request_exponential_backoff(), || async {
        http_client
            .get(endpoint.join("hpke_config").unwrap())
            .send()
            .await
    })
    .await
    .unwrap();
    let status = response.status();
    if !status.is_success() {
        return Err(janus_client::Error::Http(Box::new(
            HttpErrorResponse::from(status),
        )));
    }

    let list = HpkeConfigList::get_decoded(response.bytes().await.unwrap().as_ref())?;

    Ok(list.hpke_configs()[0].clone())
}

fn check_aggregate_results_valid<Q: janus_messages::query_type::QueryType>(
    map: &HashMap<CollectionJobId, Collection<Vec<u128>, Q>>,
    state: &State,
) -> bool {
    for collection in map.values() {
        let result = collection.aggregate_result();
        if result.iter().any(|value| *value != 0 && *value != 1) {
            error!(?result, "bad aggregate result");
            return false;
        }
        if result[state.next_measurement..]
            .iter()
            .any(|value| *value != 0)
        {
            error!(
                ?result,
                num_measurements = state.next_measurement,
                "bad aggregate result, unexpected 1 with no corresponding report"
            );
            return false;
        }
    }
    true
}

/// Aggressive exponential backoff parameters for this local-only test. Due to fault injection
/// operations, we will often be hitting `max_elapsed_time`, so this value needs to be very low.
pub(super) fn http_request_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        initial_interval: StdDuration::from_millis(10),
        max_interval: StdDuration::from_millis(50),
        multiplier: 2.0,
        max_elapsed_time: Some(StdDuration::from_millis(250)),
        ..Default::default()
    }
}
