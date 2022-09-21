use crate::{
    datastore::models::{
        AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
    },
    datastore::{self, Datastore},
    task::{Task, VdafInstance, PRIO3_AES128_VERIFY_KEY_LENGTH},
};
use anyhow::Result;
use futures::future::try_join_all;
use itertools::Itertools;
use janus_core::{
    message::{Nonce, Role, TaskId, Time},
    time::Clock,
};
use opentelemetry::{
    metrics::{Unit, ValueRecorder},
    KeyValue,
};
use prio::vdaf;
use prio::vdaf::prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum};
use prio::{codec::Encode, vdaf::prio3::Prio3Aes128CountVecMultithreaded};
use rand::{random, thread_rng, Rng};
use std::collections::HashMap;
#[cfg(test)]
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::{
    sync::oneshot::{self, Receiver, Sender},
    time::{self, Instant, MissedTickBehavior},
};
use tracing::{debug, error, info};

/// A marker trait for VDAFs that have an aggregation parameter other than the unit type.
pub trait VdafHasAggregationParameter: private::Sealed {}

impl<I, P, const L: usize> VdafHasAggregationParameter for prio::vdaf::poplar1::Poplar1<I, P, L> {}

#[cfg(test)]
impl VdafHasAggregationParameter for janus_core::test_util::dummy_vdaf::Vdaf {}

mod private {
    pub trait Sealed {}

    impl<I, P, const L: usize> Sealed for prio::vdaf::poplar1::Poplar1<I, P, L> {}

    #[cfg(test)]
    impl Sealed for janus_core::test_util::dummy_vdaf::Vdaf {}
}

pub struct AggregationJobCreator<C: Clock> {
    // Dependencies.
    datastore: Datastore<C>,
    clock: C,

    // Configuration values.
    /// How frequently we look for new tasks to start creating aggregation jobs for.
    tasks_update_frequency: Duration,
    /// How frequently we attempt to create new aggregation jobs for each task.
    aggregation_job_creation_interval: Duration,
    /// The minimum number of client reports to include in an aggregation job. Applies to the
    /// "current" batch unit only; historical batch units will create aggregation jobs of any size,
    /// on the theory that almost all reports will have be received for these batch units already.
    min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    max_aggregation_job_size: usize,
}

impl<C: Clock + 'static> AggregationJobCreator<C> {
    pub fn new(
        datastore: Datastore<C>,
        clock: C,
        tasks_update_frequency: Duration,
        aggregation_job_creation_interval: Duration,
        min_aggregation_job_size: usize,
        max_aggregation_job_size: usize,
    ) -> AggregationJobCreator<C> {
        AggregationJobCreator {
            datastore,
            clock,
            tasks_update_frequency,
            aggregation_job_creation_interval,
            min_aggregation_job_size,
            max_aggregation_job_size,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn run(self: Arc<Self>) -> ! {
        // TODO(#224): add support for handling only a subset of tasks in a single job (i.e. sharding).

        // Create metric recorders.
        let meter = opentelemetry::global::meter("aggregation_job_creator");
        let task_update_time_recorder = meter
            .f64_value_recorder("janus_task_update_time")
            .with_description("Time spent updating tasks.")
            .with_unit(Unit::new("seconds"))
            .init();
        let job_creation_time_recorder = meter
            .f64_value_recorder("janus_job_creation_time")
            .with_description("Time spent creating aggregation jobs.")
            .with_unit(Unit::new("seconds"))
            .init();

        // Set up an interval to occasionally update our view of tasks in the DB.
        // (This will fire immediately, so we'll immediately load tasks from the DB when we enter
        // the loop.)
        let mut tasks_update_ticker = time::interval(self.tasks_update_frequency);
        tasks_update_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // This tracks the "shutdown handle" (i.e. oneshot sender) used to shut down the per-task
        // worker by task ID.
        let mut job_creation_task_shutdown_handles: HashMap<TaskId, Sender<()>> = HashMap::new();

        loop {
            tasks_update_ticker.tick().await;
            info!("Updating tasks");
            let start = Instant::now();
            let tasks = self
                .datastore
                .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
                .await;
            let tasks = match tasks {
                Ok(tasks) => tasks
                    .into_iter()
                    .filter_map(|task| match task.role {
                        Role::Leader => Some((task.id, task)),
                        _ => None,
                    })
                    .collect::<HashMap<_, _>>(),

                Err(error) => {
                    error!(%error, "Couldn't update tasks");
                    task_update_time_recorder.record(
                        start.elapsed().as_secs_f64(),
                        &[KeyValue::new("status", "error")],
                    );
                    continue;
                }
            };

            // Stop job creation tasks for no-longer-existing tasks.
            job_creation_task_shutdown_handles.retain(|task_id, _| {
                if tasks.contains_key(task_id) {
                    return true;
                }
                // We don't need to send on the channel: dropping the sender is enough to cause the
                // receiver future to resolve with a RecvError, which will trigger shutdown.
                info!(?task_id, "Stopping job creation worker");
                false
            });

            // Start job creation tasks for newly-discovered tasks.
            for (task_id, task) in tasks {
                if job_creation_task_shutdown_handles.contains_key(&task_id) {
                    continue;
                }
                info!(?task_id, "Starting job creation worker");
                let (tx, rx) = oneshot::channel();
                job_creation_task_shutdown_handles.insert(task_id, tx);
                tokio::task::spawn({
                    let (this, job_creation_time_recorder) =
                        (Arc::clone(&self), job_creation_time_recorder.clone());
                    async move {
                        this.run_for_task(rx, job_creation_time_recorder, task)
                            .await
                    }
                });
            }

            task_update_time_recorder.record(
                start.elapsed().as_secs_f64(),
                &[KeyValue::new("status", "success")],
            );
        }
    }

    #[tracing::instrument(skip(self, shutdown, job_creation_time_recorder))]
    async fn run_for_task(
        &self,
        mut shutdown: Receiver<()>,
        job_creation_time_recorder: ValueRecorder<f64>,
        task: Task,
    ) {
        debug!(task_id = ?task.id, "Job creation worker started");
        let first_tick_instant = Instant::now()
            + Duration::from_secs(
                thread_rng().gen_range(0..self.aggregation_job_creation_interval.as_secs()),
            );
        let mut aggregation_job_creation_ticker =
            time::interval_at(first_tick_instant, self.aggregation_job_creation_interval);

        loop {
            select! {
                _ = aggregation_job_creation_ticker.tick() => {
                    info!(task_id = ?task.id, "Creating aggregation jobs for task");
                    let (start, mut status) = (Instant::now(), "success");
                    if let Err(error) = self.create_aggregation_jobs_for_task(&task).await {
                        error!(task_id = ?task.id, %error, "Couldn't create aggregation jobs for task");
                        status = "error";
                    }
                    job_creation_time_recorder.record(start.elapsed().as_secs_f64(), &[KeyValue::new("status", status)]);
                }

                _ = &mut shutdown => {
                    debug!(task_id = ?task.id, "Job creation worker stopped");
                    return;
                }
            }
        }
    }

    #[tracing::instrument(skip(self), err)]
    async fn create_aggregation_jobs_for_task(&self, task: &Task) -> anyhow::Result<()> {
        match task.vdaf {
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
                self.create_aggregation_jobs_for_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task)
                    .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.create_aggregation_jobs_for_task_no_param::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128CountVecMultithreaded
                >(task).await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { .. }) => {
                self.create_aggregation_jobs_for_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Sum>(task)
                    .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.create_aggregation_jobs_for_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Histogram>(task)
                    .await
            }

            _ => {
                error!(vdaf = ?task.vdaf, "VDAF is not yet supported");
                panic!("VDAF {:?} is not yet supported", task.vdaf);
            }
        }
    }

    #[tracing::instrument(skip(self), err)]
    async fn create_aggregation_jobs_for_task_no_param<
        const L: usize,
        A: vdaf::Aggregator<L, AggregationParam = ()>,
    >(
        &self,
        task: &Task,
    ) -> anyhow::Result<()>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let task_id = task.id;
        let min_batch_duration = task.min_batch_duration;
        let current_batch_unit_start = self
            .clock
            .now()
            .to_batch_unit_interval_start(min_batch_duration)?;

        let min_aggregation_job_size = self.min_aggregation_job_size;
        let max_aggregation_job_size = self.max_aggregation_job_size;

        Ok(self
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    // Find some unaggregated client reports, and group them by their batch unit.
                    let nonces_by_batch_unit = tx
                        .get_unaggregated_client_report_nonces_for_task(task_id)
                        .await?
                        .into_iter()
                        .map(|(time, nonce)| {
                            time.to_batch_unit_interval_start(min_batch_duration)
                                .map(|rounded_time| (rounded_time, (time, nonce)))
                                .map_err(datastore::Error::from)
                        })
                        .collect::<Result<Vec<(Time, (Time, Nonce))>, _>>()?
                        .into_iter()
                        .into_group_map();

                    // Generate aggregation jobs & report aggregations based on the reports we read.
                    let mut agg_jobs = Vec::new();
                    let mut report_aggs = Vec::new();
                    for (batch_unit_start, report_times_and_nonces) in nonces_by_batch_unit {
                        for agg_job_nonces in
                            report_times_and_nonces.chunks(max_aggregation_job_size)
                        {
                            if batch_unit_start >= current_batch_unit_start
                                && agg_job_nonces.len() < min_aggregation_job_size
                            {
                                continue;
                            }

                            let aggregation_job_id = random();
                            debug!(
                                ?task_id,
                                ?aggregation_job_id,
                                report_count = agg_job_nonces.len(),
                                "Creating aggregation job"
                            );
                            agg_jobs.push(AggregationJob::<L, A> {
                                aggregation_job_id,
                                task_id,
                                aggregation_param: (),
                                state: AggregationJobState::InProgress,
                            });

                            for (ord, (report_time, report_nonce)) in
                                agg_job_nonces.iter().enumerate()
                            {
                                report_aggs.push(ReportAggregation::<L, A> {
                                    aggregation_job_id,
                                    task_id,
                                    time: *report_time,
                                    nonce: *report_nonce,
                                    ord: i64::try_from(ord)?,
                                    state: ReportAggregationState::Start,
                                });
                            }
                        }
                    }

                    // Write the aggregation jobs & report aggregations we created.
                    try_join_all(
                        agg_jobs
                            .iter()
                            .map(|agg_job| tx.put_aggregation_job(agg_job)),
                    )
                    .await?;
                    try_join_all(
                        report_aggs
                            .iter()
                            .map(|report_agg| tx.put_report_aggregation(report_agg)),
                    )
                    .await?;

                    Ok(())
                })
            })
            .await?)
    }

    /// Look for combinations of client reports and collect job aggregation parameters that do not
    /// yet have a report aggregation, and batch them into new aggregation jobs. This should only
    /// be used with VDAFs that have non-unit type aggregation parameters.
    // This is only used in tests thus far.
    #[cfg(test)]
    #[tracing::instrument(skip(self), err)]
    async fn create_aggregation_jobs_for_task_with_param<const L: usize, A>(
        &self,
        task: &Task,
    ) -> anyhow::Result<()>
    where
        A: vdaf::Aggregator<L> + VdafHasAggregationParameter,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::AggregationParam: Send + Sync + Eq + Hash,
    {
        let task_id = task.id;
        let min_batch_duration = task.min_batch_duration;
        let max_aggregation_job_size = self.max_aggregation_job_size;

        self.datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    // Find some client reports that are covered by a collect request,
                    // but haven't been aggregated yet, and group them by their batch unit.
                    let result_vec = tx
                        .get_unaggregated_client_report_nonces_by_collect_for_task::<L, A>(task_id)
                        .await?
                        .into_iter()
                        .map(|(report_time, report_nonce, aggregation_param)| {
                            report_time
                                .to_batch_unit_interval_start(min_batch_duration)
                                .map(|rounded_time| {
                                    (
                                        (rounded_time, aggregation_param),
                                        (report_time, report_nonce),
                                    )
                                })
                                .map_err(datastore::Error::from)
                        })
                        .collect::<Result<Vec<((Time, _), (Time, Nonce))>, _>>()?;
                    let report_count = result_vec.len();
                    let result_map = result_vec.into_iter().into_group_map();

                    // Generate aggregation jobs and report aggregations.
                    let mut agg_jobs = Vec::new();
                    let mut report_aggs = Vec::with_capacity(report_count);
                    for ((_batch_unit_start, aggregation_param), report_times_and_nonces) in
                        result_map
                    {
                        for agg_job_nonces in
                            report_times_and_nonces.chunks(max_aggregation_job_size)
                        {
                            let aggregation_job_id = random();
                            debug!(
                                ?task_id,
                                ?aggregation_job_id,
                                report_count = agg_job_nonces.len(),
                                "Creating aggregation job"
                            );
                            agg_jobs.push(AggregationJob::<L, A> {
                                aggregation_job_id,
                                task_id,
                                aggregation_param: aggregation_param.clone(),
                                state: AggregationJobState::InProgress,
                            });

                            for (ord, (time, nonce)) in agg_job_nonces.iter().enumerate() {
                                report_aggs.push(ReportAggregation::<L, A> {
                                    aggregation_job_id,
                                    task_id,
                                    time: *time,
                                    nonce: *nonce,
                                    ord: i64::try_from(ord)?,
                                    state: ReportAggregationState::Start,
                                });
                            }
                        }
                    }

                    // Write the aggregation jobs & report aggregations we created.
                    try_join_all(
                        agg_jobs
                            .iter()
                            .map(|agg_job| tx.put_aggregation_job(agg_job)),
                    )
                    .await?;
                    try_join_all(
                        report_aggs
                            .iter()
                            .map(|report_agg| tx.put_report_aggregation(report_agg)),
                    )
                    .await?;

                    Ok(())
                })
            })
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AggregationJobCreator;
    use crate::{
        datastore::{test_util::ephemeral_datastore, Transaction},
        message::AggregationJobId,
        task::{Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    };
    use futures::{future::try_join_all, TryFutureExt};
    use janus_core::{
        message::{Interval, Nonce, Report, Role, TaskId, Time},
        task::VdafInstance,
        test_util::{
            dummy_vdaf::{self, AggregationParam},
            install_test_trace_subscriber,
        },
        time::{Clock, MockClock},
    };
    use prio::{
        codec::ParameterizedDecode,
        vdaf::{
            prio3::{Prio3, Prio3Aes128Count},
            Aggregator, Vdaf,
        },
    };
    use rand::random;
    use std::{
        collections::{HashMap, HashSet},
        iter,
        sync::Arc,
        time::Duration,
    };
    use tokio::{task, time};

    #[tokio::test]
    async fn aggregation_job_creator() {
        // This is a minimal test that AggregationJobCreator::run() will successfully find tasks &
        // trigger creation of aggregation jobs. More detailed tests of the aggregation job creation
        // logic are contained in other tests which do not exercise the task-lookup code.

        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        // TODO(#234): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing, calling time::pause() breaks interaction with the
        // database -- the job-acquiry transaction deadlocks on attempting to start a transaction,
        // even if the main test loops on calling yield_now().

        let report_time = Time::from_seconds_since_epoch(0);

        let leader_task_id = random();
        let leader_task = Task::new_dummy(
            leader_task_id,
            VdafInstance::Prio3Aes128Count.into(),
            Role::Leader,
        );
        let leader_report = Report::new_dummy(leader_task_id, report_time);

        let helper_task_id = random();
        let helper_task = Task::new_dummy(
            helper_task_id,
            VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
        );
        let helper_report = Report::new_dummy(helper_task_id, report_time);

        ds.run_tx(|tx| {
            let (leader_task, helper_task) = (leader_task.clone(), helper_task.clone());
            let (leader_report, helper_report) = (leader_report.clone(), helper_report.clone());
            Box::pin(async move {
                tx.put_task(&leader_task).await?;
                tx.put_task(&helper_task).await?;

                tx.put_client_report(&leader_report).await?;
                tx.put_client_report(&helper_report).await
            })
        })
        .await
        .unwrap();

        // Create & run the aggregation job creator, give it long enough to create tasks, and then
        // kill it.
        const AGGREGATION_JOB_CREATION_INTERVAL: Duration = Duration::from_secs(1);
        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
            clock,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: AGGREGATION_JOB_CREATION_INTERVAL,
            min_aggregation_job_size: 0,
            max_aggregation_job_size: 100,
        });
        let task_handle = task::spawn({
            let job_creator = job_creator.clone();
            async move { job_creator.run().await }
        });
        time::sleep(5 * AGGREGATION_JOB_CREATION_INTERVAL).await;
        task_handle.abort();

        // Inspect database state to verify that the expected aggregation jobs were created.
        let (leader_agg_jobs, helper_agg_jobs) =
            job_creator
                .datastore
                .run_tx(|tx| {
                    Box::pin(async move {
                        let leader_agg_jobs = read_aggregate_jobs_for_task_prio3_count::<
                            HashSet<_>,
                            _,
                        >(tx, leader_task_id)
                        .await;
                        let helper_agg_jobs = read_aggregate_jobs_for_task_prio3_count::<
                            HashSet<_>,
                            _,
                        >(tx, helper_task_id)
                        .await;
                        Ok((leader_agg_jobs, helper_agg_jobs))
                    })
                })
                .await
                .unwrap();
        assert!(helper_agg_jobs.is_empty());
        assert_eq!(leader_agg_jobs.len(), 1);
        let nonces = leader_agg_jobs.into_iter().next().unwrap().1;
        assert_eq!(
            nonces,
            HashSet::from([(
                *leader_report.metadata().time(),
                *leader_report.metadata().nonce()
            )])
        );
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_task() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const MIN_AGGREGATION_JOB_SIZE: usize = 50;
        const MAX_AGGREGATION_JOB_SIZE: usize = 60;

        // Sanity check the constant values provided.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(1 < MIN_AGGREGATION_JOB_SIZE); // we can subtract 1 safely
            assert!(MIN_AGGREGATION_JOB_SIZE < MAX_AGGREGATION_JOB_SIZE);
            assert!(MAX_AGGREGATION_JOB_SIZE < usize::MAX); // we can add 1 safely
        }

        let task_id = random();
        let task = Task::new_dummy(task_id, VdafInstance::Prio3Aes128Count.into(), Role::Leader);
        let current_batch_unit = clock
            .now()
            .to_batch_unit_interval_start(task.min_batch_duration)
            .unwrap();

        // In the current batch unit, create MIN_AGGREGATION_JOB_SIZE reports. We expect an
        // aggregation job to be created containing these reports.
        let report_time = clock.now();
        let cur_batch_unit_reports: Vec<Report> =
            iter::repeat_with(|| Report::new_dummy(task_id, report_time))
                .take(MIN_AGGREGATION_JOB_SIZE)
                .collect();

        // In a previous "small" batch unit, create fewer than MIN_AGGREGATION_JOB_SIZE reports.
        // Since the minimum aggregation job size applies only to the current batch window, we
        // expect an aggregation job to be created for these reports.
        let report_time = report_time.sub(task.min_batch_duration).unwrap();
        let small_batch_unit_reports: Vec<Report> =
            iter::repeat_with(|| Report::new_dummy(task_id, report_time))
                .take(MIN_AGGREGATION_JOB_SIZE - 1)
                .collect();

        // In a (separate) previous "big" batch unit, create more than MAX_AGGREGATION_JOB_SIZE
        // reports. We expect these reports will be split into more than one aggregation job.
        let report_time = report_time.sub(task.min_batch_duration).unwrap();
        let big_batch_unit_reports: Vec<Report> =
            iter::repeat_with(|| Report::new_dummy(task_id, report_time))
                .take(MAX_AGGREGATION_JOB_SIZE + 1)
                .collect();

        let all_nonces: HashSet<Nonce> = cur_batch_unit_reports
            .iter()
            .chain(&small_batch_unit_reports)
            .chain(&big_batch_unit_reports)
            .map(|report| *report.metadata().nonce())
            .collect();

        ds.run_tx(|tx| {
            let task = task.clone();
            let (cur_batch_unit_reports, small_batch_unit_reports, big_batch_unit_reports) = (
                cur_batch_unit_reports.clone(),
                small_batch_unit_reports.clone(),
                big_batch_unit_reports.clone(),
            );
            Box::pin(async move {
                tx.put_task(&task).await?;
                for report in cur_batch_unit_reports
                    .iter()
                    .chain(&small_batch_unit_reports)
                    .chain(&big_batch_unit_reports)
                {
                    tx.put_client_report(report).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = AggregationJobCreator {
            datastore: ds,
            clock,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: MIN_AGGREGATION_JOB_SIZE,
            max_aggregation_job_size: MAX_AGGREGATION_JOB_SIZE,
        };
        job_creator
            .create_aggregation_jobs_for_task(&task)
            .await
            .unwrap();

        // Verify.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task_prio3_count::<Vec<_>, _>(tx, task_id).await)
                })
            })
            .await
            .unwrap();
        let mut seen_nonces = HashSet::new();
        for (_, times_and_nonces) in agg_jobs {
            // All nonces for aggregation job are in the same batch unit.
            let batch_units: HashSet<Time> = times_and_nonces
                .iter()
                .map(|(time, _)| {
                    time.to_batch_unit_interval_start(task.min_batch_duration)
                        .unwrap()
                })
                .collect();
            assert_eq!(batch_units.len(), 1);
            let batch_unit = batch_units.into_iter().next().unwrap();

            // The batch is at most MAX_AGGREGATION_JOB_SIZE in size.
            assert!(times_and_nonces.len() <= MAX_AGGREGATION_JOB_SIZE);

            // If we are in the current batch unit, the batch is at least MIN_AGGREGATION_JOB_SIZE in size.
            assert!(
                batch_unit < current_batch_unit
                    || times_and_nonces.len() >= MIN_AGGREGATION_JOB_SIZE
            );

            // Nonces are non-repeated across or inside aggregation jobs.
            for (_, nonce) in times_and_nonces {
                assert!(!seen_nonces.contains(&nonce));
                seen_nonces.insert(nonce);
            }
        }

        // Every client report was added to some aggregation job.
        assert_eq!(all_nonces, seen_nonces);
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_task_not_enough_reports() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let task_id = random();
        let task = Task::new_dummy(task_id, VdafInstance::Prio3Aes128Count.into(), Role::Leader);
        let first_report = Report::new_dummy(task_id, clock.now());
        let second_report = Report::new_dummy(task_id, clock.now());

        ds.run_tx(|tx| {
            let (task, first_report) = (task.clone(), first_report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&first_report).await
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = AggregationJobCreator {
            datastore: ds,
            clock,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: 2,
            max_aggregation_job_size: 100,
        };
        job_creator
            .create_aggregation_jobs_for_task(&task)
            .await
            .unwrap();

        // Verify -- we haven't received enough reports yet, so we don't create anything.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(
                        read_aggregate_jobs_for_task_prio3_count::<HashSet<_>, _>(tx, task_id)
                            .await,
                    )
                })
            })
            .await
            .unwrap();
        assert!(agg_jobs.is_empty());

        // Setup again -- add another report.
        job_creator
            .datastore
            .run_tx(|tx| {
                let second_report = second_report.clone();
                Box::pin(async move { tx.put_client_report(&second_report).await })
            })
            .await
            .unwrap();

        // Run.
        job_creator
            .create_aggregation_jobs_for_task(&task)
            .await
            .unwrap();

        // Verify -- the additional report we wrote allows an aggregation job to be created.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(
                        read_aggregate_jobs_for_task_prio3_count::<HashSet<_>, _>(tx, task_id)
                            .await,
                    )
                })
            })
            .await
            .unwrap();
        assert_eq!(agg_jobs.len(), 1);
        let nonces = agg_jobs.into_iter().next().unwrap().1;
        assert_eq!(
            nonces,
            HashSet::from([
                (
                    *first_report.metadata().time(),
                    *first_report.metadata().nonce()
                ),
                (
                    *second_report.metadata().time(),
                    *second_report.metadata().nonce()
                )
            ])
        );
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_task_with_param() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const MAX_AGGREGATION_JOB_SIZE: usize = 10;

        // Note that the minimum aggregation job size setting has no effect here, because we always
        // wait for a collect job before scheduling any aggregation jobs, and DAP requires that no
        // more reports are accepted for a time interval after that interval already has a collect
        // job.

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
        let vdaf = dummy_vdaf::Vdaf::new();

        let task_id = random();
        let task = Task::new_dummy(task_id, crate::task::VdafInstance::Fake, Role::Leader);

        // Create MAX_AGGREGATION_JOB_SIZE reports in one batch unit. This should result in
        // one aggregation job per overlapping collect job for these reports. (and there is
        // one such collect job)
        let report_time = clock.now().sub(task.min_batch_duration).unwrap();
        let batch_1_reports: Vec<Report> =
            iter::repeat_with(|| Report::new_dummy(task_id, report_time))
                .take(MAX_AGGREGATION_JOB_SIZE)
                .collect();

        // Create more than MAX_AGGREGATION_JOB_SIZE reports in another batch unit. This should result
        // in two aggregation jobs per overlapping collect job. (and there are two such collect jobs)
        let report_time = report_time.sub(task.min_batch_duration).unwrap();
        let batch_2_reports: Vec<Report> =
            iter::repeat_with(|| Report::new_dummy(task_id, report_time))
                .take(MAX_AGGREGATION_JOB_SIZE + 1)
                .collect();

        ds.run_tx(|tx| {
            let task = task.clone();
            let batch_1_reports = batch_1_reports.clone();
            let batch_2_reports = batch_2_reports.clone();

            Box::pin(async move {
                tx.put_task(&task).await?;
                for report in batch_1_reports {
                    tx.put_client_report(&report).await?;
                }
                for report in batch_2_reports {
                    tx.put_client_report(&report).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        let job_creator = AggregationJobCreator {
            datastore: ds,
            clock,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: 1,
            max_aggregation_job_size: MAX_AGGREGATION_JOB_SIZE,
        };
        job_creator
            .create_aggregation_jobs_for_task_with_param::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(
                &task,
            )
            .await
            .unwrap();

        // Verify, there should be no aggregation jobs yet, because there are no collect jobs to
        // provide aggregation parameters.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let vdaf = vdaf.clone();
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task_generic::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                        Vec<_>,
                        _,
                    >(tx, task_id, vdaf)
                    .await)
                })
            })
            .await
            .unwrap();
        assert!(agg_jobs.count() == 0);

        job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    // This will encompass the members of batch_2_reports.
                    tx.put_collect_job(
                        task_id,
                        Interval::new(report_time, task.min_batch_duration).unwrap(),
                        &[7],
                    )
                    .await?;
                    // This will encompass the members of both batch_1_reports and batch_2_reports.
                    tx.put_collect_job(
                        task_id,
                        Interval::new(
                            report_time,
                            janus_core::message::Duration::from_seconds(
                                task.min_batch_duration.as_seconds() * 2,
                            ),
                        )
                        .unwrap(),
                        &[11],
                    )
                    .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

        // Run again, this time it should create some aggregation jobs.
        job_creator
            .create_aggregation_jobs_for_task_with_param::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(
                &task,
            )
            .await
            .unwrap();

        // Verify.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let vdaf = vdaf.clone();
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task_generic::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                        Vec<_>,
                        _,
                    >(tx, task_id, vdaf)
                    .await)
                })
            })
            .await
            .unwrap()
            .collect::<Vec<(
                AggregationJobId,
                Vec<(Time, Nonce)>,
                <dummy_vdaf::Vdaf as Vdaf>::AggregationParam,
            )>>();

        let mut seen_pairs = Vec::new();
        let mut aggregation_jobs_per_aggregation_param = HashMap::new();
        for (_aggregation_job_id, times_and_nonces, aggregation_param) in agg_jobs.iter() {
            // Check that all nonces for an aggregation job are in the same batch unit.
            let batch_units: HashSet<Time> = times_and_nonces
                .iter()
                .map(|(time, _)| {
                    time.to_batch_unit_interval_start(task.min_batch_duration)
                        .unwrap()
                })
                .collect();
            assert_eq!(batch_units.len(), 1);

            assert!(times_and_nonces.len() <= MAX_AGGREGATION_JOB_SIZE);

            *aggregation_jobs_per_aggregation_param
                .entry(*aggregation_param)
                .or_default() += 1;

            for (_, nonce) in times_and_nonces {
                seen_pairs.push((*nonce, *aggregation_param));
            }
        }
        assert_eq!(agg_jobs.len(), 5);
        assert_eq!(
            aggregation_jobs_per_aggregation_param,
            HashMap::from([(AggregationParam(7), 2), (AggregationParam(11), 3)])
        );
        let mut expected_pairs = Vec::with_capacity(MAX_AGGREGATION_JOB_SIZE * 3 + 2);
        for report in batch_1_reports.iter() {
            expected_pairs.push((*report.metadata().nonce(), AggregationParam(11)));
        }
        for report in batch_2_reports.iter() {
            expected_pairs.push((*report.metadata().nonce(), AggregationParam(7)));
            expected_pairs.push((*report.metadata().nonce(), AggregationParam(11)));
        }
        seen_pairs.sort();
        expected_pairs.sort();
        assert_eq!(seen_pairs, expected_pairs);

        // Run once more, and confirm that no further aggregation jobs are created.
        // Run again, this time it should create some aggregation jobs.
        job_creator
            .create_aggregation_jobs_for_task_with_param::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(
                &task,
            )
            .await
            .unwrap();

        // We should see the same aggregation jobs as before, because the newly created aggregation
        // jobs should have satisfied all the collect jobs.
        let mut quiescent_check_agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let vdaf = vdaf.clone();
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task_generic::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                        Vec<_>,
                        _,
                    >(tx, task_id, vdaf)
                    .await)
                })
            })
            .await
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(agg_jobs.len(), quiescent_check_agg_jobs.len());
        let mut agg_jobs = agg_jobs;
        agg_jobs.sort();
        quiescent_check_agg_jobs.sort();
        assert_eq!(agg_jobs, quiescent_check_agg_jobs);
    }

    /// Test helper function that reads all aggregation jobs for a given task ID, with VDAF
    /// Prio3Aes128Count, returning a map from aggregation job ID to the report nonces included in
    /// the aggregation job. The container used to store the nonces is up to the caller; ordered
    /// containers will store nonces in the order they are included in the aggregate job.
    async fn read_aggregate_jobs_for_task_prio3_count<T: FromIterator<(Time, Nonce)>, C: Clock>(
        tx: &Transaction<'_, C>,
        task_id: TaskId,
    ) -> HashMap<AggregationJobId, T> {
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        read_aggregate_jobs_for_task_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count, T, C>(
            tx, task_id, vdaf,
        )
        .await
        .map(|(agg_job_id, nonces, _aggregation_param)| (agg_job_id, nonces))
        .collect()
    }

    /// Test helper function that reads all aggregation jobs for a given task ID, returning an iterator
    /// of tuples containing aggregation job IDs, the report nonces included in the aggregation job, and
    /// aggregation parameters. The container used to store the nonces is up to the caller; ordered
    /// containers will store nonces in the order they are included in the aggregate job.
    async fn read_aggregate_jobs_for_task_generic<const L: usize, A, T, C: Clock>(
        tx: &Transaction<'_, C>,
        task_id: TaskId,
        vdaf: A,
    ) -> impl Iterator<Item = (AggregationJobId, T, A::AggregationParam)>
    where
        T: FromIterator<(Time, Nonce)>,
        A: Aggregator<L>,
        for<'a> Vec<u8>: From<&'a <A as Vdaf>::AggregateShare>,
        <A as Aggregator<L>>::PrepareState: for<'a> ParameterizedDecode<(&'a A, usize)>,
        for<'a> <A as Vdaf>::OutputShare: TryFrom<&'a [u8]>,
    {
        try_join_all(
            tx.get_aggregation_jobs_for_task_id::<L, A>(task_id)
                .await
                .unwrap()
                .into_iter()
                .map(|agg_job| {
                    tx.get_report_aggregations_for_aggregation_job(
                        &vdaf,
                        Role::Leader,
                        task_id,
                        agg_job.aggregation_job_id,
                    )
                    .map_ok(move |report_aggs| {
                        (
                            agg_job.aggregation_job_id,
                            report_aggs,
                            agg_job.aggregation_param,
                        )
                    })
                }),
        )
        .await
        .unwrap()
        .into_iter()
        .map(|(agg_job_id, report_aggs, aggregation_param)| {
            (
                agg_job_id,
                report_aggs
                    .into_iter()
                    .map(|ra| (ra.time, ra.nonce))
                    .collect::<T>(),
                aggregation_param,
            )
        })
    }
}
