use std::{
    collections::HashMap,
    ops::ControlFlow,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};

use derivative::Derivative;
use futures::future::join_all;
use janus_aggregator::aggregator;
use janus_aggregator_core::{
    datastore::models::AggregatorRole,
    task::{test_util::Task, AggregatorTask},
    test_util::noop_meter,
};
use janus_collector::{Collection, CollectionJob, PollResult};
use janus_core::{
    test_util::runtime::TestRuntimeManager,
    time::{Clock, MockClock},
    vdaf::{vdaf_dp_strategies, VdafInstance},
};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    CollectionJobId, Duration, FixedSizeQuery, Time,
};
use opentelemetry::metrics::Meter;
use prio::vdaf::prio3::{optimal_chunk_length, Prio3, Prio3Histogram};
use quickcheck::TestResult;
use tokio::time::timeout;
use tracing::{debug, error, info, info_span, warn, Instrument};
use trillium_tokio::Stopper;

use crate::simulation::{
    bad_client::{
        upload_replay_report, upload_report_invalid_measurement, upload_report_not_rounded,
    },
    model::{Input, Op, Query},
    setup::Components,
    START_TIME,
};

pub(super) const MAX_REPORTS: usize = 400;

pub(super) struct Simulation {
    state: State,
    components: Components,
    task: Task,
    leader_task: Arc<AggregatorTask>,
}

impl Simulation {
    async fn new(input: &Input) -> Self {
        let mut state = State::new();
        let start = Instant::now();
        let (components, task) = Components::setup(input, &mut state).await;
        info!(elapsed = ?start.elapsed(), "setup done");
        let leader_task = Arc::new(task.leader_view().unwrap());
        Self {
            state,
            components,
            task,
            leader_task,
        }
    }

    pub(super) fn run(input: Input) -> TestResult {
        if input.ops.is_empty() {
            return TestResult::discard();
        }
        let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = tokio_runtime.block_on(async {
            let mut simulation = Self::new(&input).await;
            for op in input.ops.iter() {
                let span = info_span!("operation", op = ?op);
                let timeout_result = timeout(StdDuration::from_secs(15), async {
                    let start = Instant::now();
                    info!(time = ?simulation.state.clock.now(), "starting operation");
                    let result = match op {
                        Op::AdvanceTime { amount } => simulation.execute_advance_time(amount).await,
                        Op::Upload { report_time, count } => {
                            simulation.execute_upload(report_time, *count).await
                        }
                        Op::UploadReplay { report_time } => {
                            simulation.execute_upload_replay(report_time).await
                        }
                        Op::UploadNotRounded { report_time } => {
                            simulation.execute_upload_not_rounded(report_time).await
                        }
                        Op::UploadInvalid { report_time } => {
                            simulation.execute_upload_invalid(report_time).await
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
                        Op::LeaderKeyRotator => {
                            simulation.execute_key_rotator(AggregatorRole::Leader).await
                        }
                        Op::HelperKeyRotator => {
                            simulation.execute_key_rotator(AggregatorRole::Helper).await
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
                    info!(elapsed = ?start.elapsed(), "finished operation");
                    result
                })
                .instrument(span)
                .await;
                match timeout_result {
                    Ok(ControlFlow::Break(test_result)) => return test_result,
                    Ok(ControlFlow::Continue(())) => {}
                    Err(error) => {
                        error!("operation timed out");
                        return TestResult::error(error.to_string());
                    }
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
        });
        if result.is_failure() {
            error!(?input, "failure");
        } else {
            info!(?input, "success");
        }
        result
    }

    async fn execute_advance_time(&mut self, amount: &Duration) -> ControlFlow<TestResult> {
        self.state.clock.advance(amount);
        ControlFlow::Continue(())
    }

    async fn execute_upload(&mut self, report_time: &Time, count: u8) -> ControlFlow<TestResult> {
        let report_time = *report_time;
        let client = self.components.client.clone();
        let results = join_all((0..count).flat_map(|_| self.state.next_measurement()).map(
            move |measurement| {
                let client = client.clone();
                async move { client.upload_with_time(&measurement, report_time).await }
            },
        ))
        .await;
        for result in results {
            if let Err(error) = result {
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

    async fn execute_upload_not_rounded(&mut self, report_time: &Time) -> ControlFlow<TestResult> {
        if let Some(measurement) = self.state.next_measurement() {
            if let Err(error) = upload_report_not_rounded(
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

    async fn execute_upload_invalid(&mut self, report_time: &Time) -> ControlFlow<TestResult> {
        if let Err(error) = upload_report_invalid_measurement(
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

    async fn execute_key_rotator(&mut self, role: AggregatorRole) -> ControlFlow<TestResult> {
        let key_rotator = match role {
            AggregatorRole::Leader => &self.components.leader_key_rotator,
            AggregatorRole::Helper => &self.components.helper_key_rotator,
        };
        if let Err(error) = key_rotator.run().await {
            error!(?error, "key rotator error");
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
        debug!(count = leases.len(), "acquired aggregation jobs");
        for lease in leases {
            if let Err(error) = (self.components.aggregation_job_driver_stepper_cb)(lease).await {
                if let aggregator::Error::Http(_) = error {
                    warn!(?error, "aggregation job driver error");
                    return ControlFlow::Continue(());
                }
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
        debug!(count = leases.len(), "acquired collection jobs");
        for lease in leases {
            if let Err(error) = (self.components.collection_job_driver_stepper_cb)(lease).await {
                if let aggregator::Error::Http(_) = error {
                    warn!(?error, "collection job driver error");
                    return ControlFlow::Continue(());
                }
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
                dp_strategy: vdaf_dp_strategies::Prio3Histogram::NoDifferentialPrivacy,
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
