use crate::aggregator::aggregation_job_writer::AggregationJobWriter;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{
    types::extra::{U15, U31, U63},
    FixedI16, FixedI32, FixedI64,
};
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::models::{
        AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
    },
    datastore::{self, models::OutstandingBatch, Datastore},
    task::{self, Task},
};
use janus_core::{
    task::{VdafInstance, PRIO3_VERIFY_KEY_LENGTH},
    time::{Clock, DurationExt as _, TimeExt as _},
};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    AggregationJobRound, Duration as DurationMsg, Interval, Role, TaskId,
};
use opentelemetry::{
    metrics::{Histogram, Unit},
    Context, KeyValue,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded;
use prio::{
    codec::Encode,
    vdaf::{
        self,
        prio3::{Prio3, Prio3Count, Prio3Histogram, Prio3Sum, Prio3SumVecMultithreaded},
    },
};
use rand::{random, thread_rng, Rng};
use std::{
    cmp::{max, min},
    collections::HashMap,
    convert::Infallible,
    iter,
    num::TryFromIntError,
    ops::RangeInclusive,
    sync::Arc,
    time::Duration,
};
use tokio::{
    select,
    sync::oneshot::{self, Receiver, Sender},
    time::{self, sleep_until, Instant, MissedTickBehavior},
    try_join,
};
use tracing::{debug, error, info};

// TODO(#680): add metrics to aggregation job creator.
pub struct AggregationJobCreator<C: Clock> {
    // Dependencies.
    datastore: Datastore<C>,

    // Configuration values.
    /// How frequently we look for new tasks to start creating aggregation jobs for.
    tasks_update_frequency: Duration,
    /// How frequently we attempt to create new aggregation jobs for each task.
    aggregation_job_creation_interval: Duration,
    /// The minimum number of client reports to include in an aggregation job. For time-interval
    /// tasks, applies to the "current" batch only; historical batches will create aggregation jobs
    /// of any size, on the theory that almost all reports will have be received for these batches
    /// already. For fixed-size tasks, a single small aggregation job per batch will be created if
    /// necessary to meet the batch size requirements.
    min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    max_aggregation_job_size: usize,
}

impl<C: Clock + 'static> AggregationJobCreator<C> {
    pub fn new(
        datastore: Datastore<C>,
        tasks_update_frequency: Duration,
        aggregation_job_creation_interval: Duration,
        min_aggregation_job_size: usize,
        max_aggregation_job_size: usize,
    ) -> AggregationJobCreator<C> {
        AggregationJobCreator {
            datastore,
            tasks_update_frequency,
            aggregation_job_creation_interval,
            min_aggregation_job_size,
            max_aggregation_job_size,
        }
    }

    pub async fn run(self: Arc<Self>) -> Infallible {
        // TODO(#224): add support for handling only a subset of tasks in a single job (i.e. sharding).

        // Create metric instruments.
        let meter = opentelemetry::global::meter("aggregation_job_creator");
        let task_update_time_histogram = meter
            .f64_histogram("janus_task_update_time")
            .with_description("Time spent updating tasks.")
            .with_unit(Unit::new("seconds"))
            .init();
        let job_creation_time_histogram = meter
            .f64_histogram("janus_job_creation_time")
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
            let start = Instant::now();

            let result = self
                .update_tasks(
                    &mut job_creation_task_shutdown_handles,
                    &job_creation_time_histogram,
                )
                .await;

            let status = match result {
                Ok(()) => "success",
                Err(error) => {
                    error!(?error, "Couldn't update tasks");
                    "error"
                }
            };

            task_update_time_histogram.record(
                &Context::current(),
                start.elapsed().as_secs_f64(),
                &[KeyValue::new("status", status)],
            );
        }
    }

    #[tracing::instrument(skip_all, err)]
    async fn update_tasks(
        self: &Arc<Self>,
        job_creation_task_shutdown_handles: &mut HashMap<TaskId, Sender<()>>,
        job_creation_time_histogram: &Histogram<f64>,
    ) -> Result<(), datastore::Error> {
        debug!("Updating tasks");
        let tasks = self
            .datastore
            .run_tx_with_name("aggregation_job_creator_get_tasks", |tx| {
                Box::pin(async move { tx.get_tasks().await })
            })
            .await?;
        let tasks = tasks
            .into_iter()
            .filter_map(|task| match task.role() {
                Role::Leader => Some((*task.id(), task)),
                _ => None,
            })
            .collect::<HashMap<_, _>>();

        // Stop job creation tasks for no-longer-existing tasks.
        job_creation_task_shutdown_handles.retain(|task_id, _| {
            if tasks.contains_key(task_id) {
                return true;
            }
            // We don't need to send on the channel: dropping the sender is enough to cause the
            // receiver future to resolve with a RecvError, which will trigger shutdown.
            info!(%task_id, "Stopping job creation worker");
            false
        });

        // Start job creation tasks for newly-discovered tasks.
        for (task_id, task) in tasks {
            if job_creation_task_shutdown_handles.contains_key(&task_id) {
                continue;
            }
            info!(%task_id, "Starting job creation worker");
            let (tx, rx) = oneshot::channel();
            job_creation_task_shutdown_handles.insert(task_id, tx);
            tokio::task::spawn({
                let (this, job_creation_time_histogram) =
                    (Arc::clone(self), job_creation_time_histogram.clone());
                async move {
                    this.run_for_task(rx, job_creation_time_histogram, Arc::new(task))
                        .await
                }
            });
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, shutdown, job_creation_time_histogram))]
    async fn run_for_task(
        self: Arc<Self>,
        mut shutdown: Receiver<()>,
        job_creation_time_histogram: Histogram<f64>,
        task: Arc<Task>,
    ) {
        debug!(task_id = %task.id(), "Job creation worker started");
        let mut next_run_instant = Instant::now();
        if !self.aggregation_job_creation_interval.is_zero() {
            next_run_instant +=
                thread_rng().gen_range(Duration::ZERO..self.aggregation_job_creation_interval);
        }

        loop {
            select! {
                _ = sleep_until(next_run_instant) => {
                    debug!(task_id = %task.id(), "Creating aggregation jobs for task");
                    let (start, mut status) = (Instant::now(), "success");
                    match Arc::clone(&self).create_aggregation_jobs_for_task(Arc::clone(&task)).await {
                        Ok(true) => next_run_instant = Instant::now(),

                        Ok(false) =>
                            next_run_instant = Instant::now() + self.aggregation_job_creation_interval,

                        Err(err) => {
                            error!(task_id = %task.id(), %err, "Couldn't create aggregation jobs for task");
                            status = "error";
                            next_run_instant = Instant::now() + self.aggregation_job_creation_interval;
                        }
                    }
                    job_creation_time_histogram.record(&Context::current(), start.elapsed().as_secs_f64(), &[KeyValue::new("status", status)]);
                }

                _ = &mut shutdown => {
                    debug!(task_id = %task.id(), "Job creation worker stopped");
                    return;
                }
            }
        }
    }

    // Returns true if at least one aggregation job was created.
    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    async fn create_aggregation_jobs_for_task(
        self: Arc<Self>,
        task: Arc<Task>,
    ) -> anyhow::Result<bool> {
        match (task.query_type(), task.vdaf()) {
            (task::QueryType::TimeInterval, VdafInstance::Prio3Count) => {
                let vdaf = Arc::new(Prio3::new_count(2)?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3Count>(task, vdaf)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3CountVec { length }) => {
                let vdaf = Arc::new(Prio3::new_sum_vec_multithreaded(2, 1, *length)?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<
                    PRIO3_VERIFY_KEY_LENGTH,
                    Prio3SumVecMultithreaded
                >(task, vdaf).await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Sum { bits }) => {
                let vdaf = Arc::new(Prio3::new_sum(2, *bits)?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3Sum>(task, vdaf)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3SumVec { bits, length }) => {
                let vdaf = Arc::new(Prio3::new_sum_vec_multithreaded(2, *bits, *length)?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3SumVecMultithreaded>(task, vdaf)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Histogram { buckets }) => {
                let vdaf = Arc::new(Prio3::new_histogram(2, buckets)?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3Histogram>(task, vdaf)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::TimeInterval,
                VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length },
            ) => {
                let vdaf: Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>>> =
                    Arc::new(Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>>>(task, vdaf)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::TimeInterval,
                VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length },
            ) => {
                let vdaf: Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>>> =
                    Arc::new(Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>>>(task, vdaf)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::TimeInterval,
                VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length },
            ) => {
                let vdaf: Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>>> =
                    Arc::new(Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?);
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>>>(task, vdaf)
                    .await
            }

            (task::QueryType::FixedSize { max_batch_size }, VdafInstance::Prio3Count) => {
                let vdaf = Arc::new(Prio3::new_count(2)?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3Count>(task, vdaf, max_batch_size)
                    .await
            }

            (
                task::QueryType::FixedSize { max_batch_size },
                VdafInstance::Prio3CountVec { length },
            ) => {
                let vdaf = Arc::new(Prio3::new_sum_vec_multithreaded(2, 1, *length)?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<
                    PRIO3_VERIFY_KEY_LENGTH,
                    Prio3SumVecMultithreaded
                >(task, vdaf, max_batch_size).await
            }

            (task::QueryType::FixedSize { max_batch_size }, VdafInstance::Prio3Sum { bits }) => {
                let vdaf = Arc::new(Prio3::new_sum(2, *bits)?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3Sum>(task, vdaf, max_batch_size)
                    .await
            }

            (
                task::QueryType::FixedSize { max_batch_size },
                VdafInstance::Prio3SumVec { bits, length },
            ) => {
                let vdaf = Arc::new(Prio3::new_sum_vec_multithreaded(2, *bits, *length)?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<
                    PRIO3_VERIFY_KEY_LENGTH,
                    Prio3SumVecMultithreaded,
                >(task, vdaf, max_batch_size).await
            }

            (
                task::QueryType::FixedSize { max_batch_size },
                VdafInstance::Prio3Histogram { buckets },
            ) => {
                let vdaf = Arc::new(Prio3::new_histogram(2, buckets)?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3Histogram>(task, vdaf, max_batch_size)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::FixedSize { max_batch_size },
                VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length },
            ) => {
                let vdaf: Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>>> =
                    Arc::new(Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>>>(task, vdaf, max_batch_size)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::FixedSize { max_batch_size },
                VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length },
            ) => {
                let vdaf: Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>>> =
                    Arc::new(Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>>>(task, vdaf, max_batch_size)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::FixedSize { max_batch_size },
                VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length },
            ) => {
                let vdaf: Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>>> =
                    Arc::new(Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?);
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_VERIFY_KEY_LENGTH, Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>>>(task, vdaf, max_batch_size)
                    .await
            }

            _ => {
                error!(vdaf = ?task.vdaf(), "VDAF is not yet supported");
                panic!("VDAF {:?} is not yet supported", task.vdaf());
            }
        }
    }

    async fn create_aggregation_jobs_for_time_interval_task_no_param<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE, 16, AggregationParam = ()>,
    >(
        self: Arc<Self>,
        task: Arc<Task>,
        vdaf: Arc<A>,
    ) -> anyhow::Result<bool>
    where
        A: Send + Sync + 'static,
        A::AggregateShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::PrepareShare: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
    {
        Ok(self
            .datastore
            .run_tx_with_name("aggregation_job_creator_time_no_param", |tx| {
                let this = Arc::clone(&self);
                let task = Arc::clone(&task);
                let vdaf = Arc::clone(&vdaf);

                Box::pin(async move {
                    // Find some unaggregated client reports.
                    let report_ids_and_times = tx
                        .get_unaggregated_client_report_ids_for_task(task.id())
                        .await?;

                    // Generate aggregation jobs & report aggregations based on the reports we read.
                    let mut aggregation_job_writer = AggregationJobWriter::new(Arc::clone(&task));
                    for agg_job_reports in
                        report_ids_and_times.chunks(this.max_aggregation_job_size)
                    {
                        if agg_job_reports.len() < this.min_aggregation_job_size {
                            if !agg_job_reports.is_empty() {
                                let report_ids: Vec<_> = agg_job_reports
                                    .iter()
                                    .map(|(report_id, _)| *report_id)
                                    .collect();
                                tx.mark_reports_unaggregated(task.id(), &report_ids).await?;
                            }
                            continue;
                        }

                        let aggregation_job_id = random();
                        debug!(
                            task_id = %task.id(),
                            %aggregation_job_id,
                            report_count = %agg_job_reports.len(),
                            "Creating aggregation job"
                        );

                        let min_client_timestamp =
                            agg_job_reports.iter().map(|(_, time)| time).min().unwrap(); // unwrap safety: agg_job_reports is non-empty
                        let max_client_timestamp =
                            agg_job_reports.iter().map(|(_, time)| time).max().unwrap(); // unwrap safety: agg_job_reports is non-empty
                        let client_timestamp_interval = Interval::new(
                            *min_client_timestamp,
                            max_client_timestamp
                                .difference(min_client_timestamp)?
                                .add(&DurationMsg::from_seconds(1))?,
                        )?;

                        let aggregation_job = AggregationJob::<SEED_SIZE, TimeInterval, A>::new(
                            *task.id(),
                            aggregation_job_id,
                            (),
                            (),
                            client_timestamp_interval,
                            AggregationJobState::InProgress,
                            AggregationJobRound::from(0),
                        );

                        let report_aggregations = agg_job_reports
                            .iter()
                            .enumerate()
                            .map(|(ord, (report_id, time))| {
                                Ok(ReportAggregation::<SEED_SIZE, A>::new(
                                    *task.id(),
                                    aggregation_job_id,
                                    *report_id,
                                    *time,
                                    ord.try_into()?,
                                    None,
                                    ReportAggregationState::Start,
                                ))
                            })
                            .collect::<Result<_, datastore::Error>>()?;

                        aggregation_job_writer.put(aggregation_job, report_aggregations)?;
                    }

                    // Write the aggregation jobs & report aggregations we created.
                    aggregation_job_writer.write(tx, vdaf).await?;
                    Ok(!aggregation_job_writer.is_empty())
                })
            })
            .await?)
    }

    async fn create_aggregation_jobs_for_fixed_size_task_no_param<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE, 16, AggregationParam = ()>,
    >(
        self: Arc<Self>,
        task: Arc<Task>,
        vdaf: Arc<A>,
        task_max_batch_size: u64,
    ) -> anyhow::Result<bool>
    where
        A: Send + Sync + 'static,
        A::AggregateShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::PrepareShare: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
    {
        let (task_min_batch_size, task_max_batch_size) = (
            usize::try_from(task.min_batch_size())?,
            usize::try_from(task_max_batch_size)?,
        );
        Ok(self
            .datastore
            .run_tx_with_name("aggregation_job_creator_fixed_no_param", |tx| {
                let this = Arc::clone(&self);
                let task = Arc::clone(&task);
                let vdaf = Arc::clone(&vdaf);

                Box::pin(async move {
                    // Find unaggregated client reports & existing unfilled batches.
                    let (mut unaggregated_report_ids, outstanding_batches) = try_join!(
                        tx.get_unaggregated_client_report_ids_for_task(task.id()),
                        tx.get_outstanding_batches_for_task(task.id())
                    )?;

                    // First attempt to allocate unaggregated reports to existing unfilled batches,
                    // then generate new batches as necessary. This iterator has no end and
                    // therefore it is safe to unwrap the result of a call to `next`.
                    let mut batch_iter = outstanding_batches
                        .into_iter()
                        .map(|outstanding_batch| (false, outstanding_batch))
                        .chain(iter::repeat_with(|| {
                            (
                                true,
                                OutstandingBatch::new(
                                    *task.id(),
                                    random(),
                                    RangeInclusive::new(0, 0),
                                ),
                            )
                        }));

                    // Main loop: repeatedly consume some of the unaggregated report IDs to generate
                    // an aggregation job, assigning it to an existing batch which has need of
                    // reports, or a new batch if no existing batch needs reports.
                    let mut aggregation_job_writer =
                        AggregationJobWriter::<SEED_SIZE, FixedSize, A>::new(Arc::clone(&task));
                    let mut new_batches = Vec::new();
                    let (mut is_batch_new, mut batch) = batch_iter.next().unwrap(); // unwrap safety: infinite iterator
                    let mut batch_max_size = *batch.size().end();
                    loop {
                        // Figure out desired aggregation job size:
                        //  * It can't be larger than the number of reports available.
                        //  * It can't be larger than the configured maximum aggregation job size.
                        //  * It can't be larger than the difference between the maximum batch size
                        //    & the maximum number of reports that may end up aggregated into this
                        //    batch based on already-existing aggregation jobs; otherwise, we risk
                        //    aggregating more than max_batch_size reports together.
                        // Choose the maximal size meeting all of these requirements.
                        let aggregation_job_size = [
                            unaggregated_report_ids.len(),
                            this.max_aggregation_job_size,
                            task_max_batch_size - batch_max_size,
                        ]
                        .into_iter()
                        .min()
                        .unwrap(); // unwrap safety: iterator is non-empty, so result is Some

                        if aggregation_job_size < this.min_aggregation_job_size {
                            if batch_max_size < task_min_batch_size
                                && batch_max_size + aggregation_job_size >= task_min_batch_size
                            {
                                // This batch is short of the minimum batch size, and requires an
                                // unusually small aggregation job (smaller than the normal minimum
                                // aggregation job size) for it to be ever completed. Go ahead and
                                // generate one. (We also wait until the size of the aggregation job
                                // we can generate will meet the minimum configured batch size, in
                                // an attempt to minimize the number of "small" aggregation jobs we
                                // create.)
                            } else if !is_batch_new {
                                // Move on to the next unfilled batch to see if we can allocate
                                // reports to it.
                                (is_batch_new, batch) = batch_iter.next().unwrap(); // unwrap safety: infinite iterator
                                batch_max_size = *batch.size().end();
                                continue;
                            } else {
                                // We have run out of preexisting batches to evaluate adding reports
                                // to. Trying additional new batches won't help (since all of the
                                // relevant parameters will be the same as in this iteration), so
                                // stop generating aggregation jobs.
                                break;
                            }
                        }

                        // Generate an aggregation job, then update batch metadata & continue.
                        let aggregation_job_id = random();
                        debug!(
                            task_id = %task.id(),
                            batch_id = %batch.id(),
                            %aggregation_job_id,
                            report_count = aggregation_job_size,
                            "Creating aggregation job"
                        );

                        let mut min_client_timestamp = None;
                        let mut max_client_timestamp = None;
                        let report_aggregations = unaggregated_report_ids
                            .drain(..aggregation_job_size)
                            .enumerate()
                            .map(|(ord, (report_id, client_timestamp))| {
                                min_client_timestamp = Some(
                                    min_client_timestamp
                                        .map_or(client_timestamp, |ts| min(ts, client_timestamp)),
                                );
                                max_client_timestamp = Some(
                                    max_client_timestamp
                                        .map_or(client_timestamp, |ts| max(ts, client_timestamp)),
                                );
                                Ok(ReportAggregation::new(
                                    *task.id(),
                                    aggregation_job_id,
                                    report_id,
                                    client_timestamp,
                                    ord.try_into()?,
                                    None,
                                    ReportAggregationState::Start,
                                ))
                            })
                            .collect::<Result<_, TryFromIntError>>()?;

                        let min_client_timestamp = min_client_timestamp.unwrap(); // unwrap safety: aggregation_job_size > 0
                        let max_client_timestamp = max_client_timestamp.unwrap(); // unwrap safety: aggregation_job_size > 0
                        let client_timestamp_interval = Interval::new(
                            min_client_timestamp,
                            max_client_timestamp
                                .difference(&min_client_timestamp)?
                                .add(&DurationMsg::from_seconds(1))?,
                        )?;
                        let aggregation_job = AggregationJob::new(
                            *task.id(),
                            aggregation_job_id,
                            (),
                            *batch.id(),
                            client_timestamp_interval,
                            AggregationJobState::InProgress,
                            AggregationJobRound::from(0),
                        );
                        aggregation_job_writer.put(aggregation_job, report_aggregations)?;

                        if is_batch_new {
                            new_batches.push(*batch.id())
                        }
                        is_batch_new = false;
                        batch_max_size += aggregation_job_size;
                    }

                    // Write the outstanding batches, aggregation jobs, & report aggregations we
                    // created.
                    try_join!(
                        aggregation_job_writer.write(tx, vdaf),
                        try_join_all(
                            new_batches
                                .iter()
                                .map(|batch_id| tx.put_outstanding_batch(task.id(), batch_id)),
                        ),
                        {
                            let task_id = *task.id();
                            async move {
                                if !unaggregated_report_ids.is_empty() {
                                    let report_ids: Vec<_> = unaggregated_report_ids
                                        .iter()
                                        .map(|(report_id, _)| *report_id)
                                        .collect();
                                    tx.mark_reports_unaggregated(&task_id, &report_ids).await?;
                                }
                                Ok(())
                            }
                        },
                    )?;
                    Ok(!aggregation_job_writer.is_empty())
                })
            })
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::AggregationJobCreator;
    use futures::{future::try_join_all, TryFutureExt};
    use janus_aggregator_core::{
        datastore::{
            models::{AggregationJob, AggregationJobState, Batch, BatchState, LeaderStoredReport},
            test_util::ephemeral_datastore,
            Transaction,
        },
        query_type::AccumulableQueryType,
        task::{test_util::TaskBuilder, QueryType as TaskQueryType},
    };
    use janus_core::{
        task::{VdafInstance, PRIO3_VERIFY_KEY_LENGTH},
        test_util::{
            dummy_vdaf::{self},
            install_test_trace_subscriber,
        },
        time::{Clock, MockClock},
    };
    use janus_messages::{
        query_type::{FixedSize, TimeInterval},
        AggregationJobRound, ReportId, Role, TaskId, Time,
    };
    use prio::vdaf::{self, prio3::Prio3Count};
    use std::{collections::HashSet, iter, sync::Arc, time::Duration};
    use tokio::{task, time, try_join};

    #[tokio::test]
    async fn aggregation_job_creator() {
        // This is a minimal test that AggregationJobCreator::run() will successfully find tasks &
        // trigger creation of aggregation jobs. More detailed tests of the aggregation job creation
        // logic are contained in other tests which do not exercise the task-lookup code.

        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone()).await;

        // TODO(#234): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing, calling time::pause() breaks interaction with the
        // database -- the job-acquiry transaction deadlocks on attempting to start a transaction,
        // even if the main test loops on calling yield_now().

        let report_time = Time::from_seconds_since_epoch(0);
        let leader_task = TaskBuilder::new(
            TaskQueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .build();
        let batch_identifier =
            TimeInterval::to_batch_identifier(&leader_task, &(), &report_time).unwrap();
        let leader_report = LeaderStoredReport::new_dummy(*leader_task.id(), report_time);

        let helper_task = TaskBuilder::new(
            TaskQueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Helper,
        )
        .build();
        let helper_report = LeaderStoredReport::new_dummy(*helper_task.id(), report_time);

        ds.run_tx(|tx| {
            let (leader_task, helper_task) = (leader_task.clone(), helper_task.clone());
            let (leader_report, helper_report) = (leader_report.clone(), helper_report.clone());
            Box::pin(async move {
                tx.put_task(&leader_task).await?;
                tx.put_task(&helper_task).await?;

                let vdaf = dummy_vdaf::Vdaf::new();
                tx.put_client_report(&vdaf, &leader_report).await?;
                tx.put_client_report(&vdaf, &helper_report).await
            })
        })
        .await
        .unwrap();

        // Create & run the aggregation job creator, give it long enough to create tasks, and then
        // kill it.
        const AGGREGATION_JOB_CREATION_INTERVAL: Duration = Duration::from_secs(1);
        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
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

        // Inspect database state to verify that the expected aggregation jobs & batches were
        // created.
        let (leader_aggregations, leader_batches, helper_aggregations, helper_batches) =
            job_creator
                .datastore
                .run_tx(|tx| {
                    let (leader_task, helper_task) = (leader_task.clone(), helper_task.clone());
                    Box::pin(async move {
                        let (leader_aggregations, leader_batches) =
                            read_aggregate_info_for_task::<
                                PRIO3_VERIFY_KEY_LENGTH,
                                TimeInterval,
                                Prio3Count,
                                _,
                            >(tx, leader_task.id())
                            .await;
                        let (helper_aggregations, helper_batches) =
                            read_aggregate_info_for_task::<
                                PRIO3_VERIFY_KEY_LENGTH,
                                TimeInterval,
                                Prio3Count,
                                _,
                            >(tx, helper_task.id())
                            .await;
                        Ok((
                            leader_aggregations,
                            leader_batches,
                            helper_aggregations,
                            helper_batches,
                        ))
                    })
                })
                .await
                .unwrap();

        assert_eq!(leader_aggregations.len(), 1);
        let leader_aggregation = leader_aggregations.into_iter().next().unwrap();
        assert_eq!(leader_aggregation.0.partial_batch_identifier(), &());
        assert_eq!(leader_aggregation.0.round(), AggregationJobRound::from(0));
        assert_eq!(
            leader_aggregation.1,
            Vec::from([*leader_report.metadata().id()])
        );

        assert_eq!(
            leader_batches,
            Vec::from([Batch::new(
                *leader_task.id(),
                batch_identifier,
                (),
                BatchState::Open,
                1
            )])
        );

        assert!(helper_aggregations.is_empty());
        assert!(helper_batches.is_empty());
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_time_interval_task() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone()).await;
        const MIN_AGGREGATION_JOB_SIZE: usize = 50;
        const MAX_AGGREGATION_JOB_SIZE: usize = 60;

        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::TimeInterval,
                VdafInstance::Prio3Count,
                Role::Leader,
            )
            .build(),
        );

        // Create 2 max-size batches, a min-size batch, one extra report (which will be added to the
        // min-size batch).
        let report_time = clock.now();
        let batch_identifier = TimeInterval::to_batch_identifier(&task, &(), &report_time).unwrap();
        let reports: Vec<_> =
            iter::repeat_with(|| LeaderStoredReport::new_dummy(*task.id(), report_time))
                .take(2 * MAX_AGGREGATION_JOB_SIZE + MIN_AGGREGATION_JOB_SIZE + 1)
                .collect();
        let all_report_ids: HashSet<ReportId> = reports
            .iter()
            .map(|report| *report.metadata().id())
            .collect();

        ds.run_tx(|tx| {
            let (task, reports) = (Arc::clone(&task), reports.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                for report in reports.iter() {
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), report)
                        .await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: MIN_AGGREGATION_JOB_SIZE,
            max_aggregation_job_size: MAX_AGGREGATION_JOB_SIZE,
        });
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (agg_jobs, batches) = job_creator
            .datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    Ok(read_aggregate_info_for_task::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                        _,
                    >(tx, task.id())
                    .await)
                })
            })
            .await
            .unwrap();
        let mut seen_report_ids = HashSet::new();
        for (agg_job, report_ids) in &agg_jobs {
            // Jobs are created in round 0
            assert_eq!(agg_job.round(), AggregationJobRound::from(0));

            // The batch is at most MAX_AGGREGATION_JOB_SIZE in size.
            assert!(report_ids.len() <= MAX_AGGREGATION_JOB_SIZE);

            // The batch is at least MIN_AGGREGATION_JOB_SIZE in size.
            assert!(report_ids.len() >= MIN_AGGREGATION_JOB_SIZE);

            // Report IDs are non-repeated across or inside aggregation jobs.
            for report_id in report_ids {
                assert!(!seen_report_ids.contains(report_id));
                seen_report_ids.insert(*report_id);
            }
        }

        // Every client report was added to some aggregation job.
        assert_eq!(all_report_ids, seen_report_ids);

        // Batches are created appropriately.
        assert_eq!(
            batches,
            Vec::from([Batch::new(
                *task.id(),
                batch_identifier,
                (),
                BatchState::Open,
                agg_jobs.len().try_into().unwrap(),
            )])
        );
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_time_interval_task_not_enough_reports() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone()).await;
        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::TimeInterval,
                VdafInstance::Prio3Count,
                Role::Leader,
            )
            .build(),
        );
        let report_time = clock.now();
        let batch_identifier = TimeInterval::to_batch_identifier(&task, &(), &report_time).unwrap();
        let first_report = LeaderStoredReport::new_dummy(*task.id(), report_time);
        let second_report = LeaderStoredReport::new_dummy(*task.id(), report_time);

        ds.run_tx(|tx| {
            let (task, first_report) = (Arc::clone(&task), first_report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &first_report)
                    .await
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: 2,
            max_aggregation_job_size: 100,
        });
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify -- we haven't received enough reports yet, so we don't create anything.
        let (agg_jobs, batches) = job_creator
            .datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    Ok(read_aggregate_info_for_task::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                        _,
                    >(tx, task.id())
                    .await)
                })
            })
            .await
            .unwrap();
        assert!(agg_jobs.is_empty());
        assert!(batches.is_empty());

        // Setup again -- add another report.
        job_creator
            .datastore
            .run_tx(|tx| {
                let second_report = second_report.clone();
                Box::pin(async move {
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), &second_report)
                        .await
                })
            })
            .await
            .unwrap();

        // Run.
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify -- the additional report we wrote allows an aggregation job to be created.
        let (agg_jobs, batches) = job_creator
            .datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    Ok(read_aggregate_info_for_task::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                        _,
                    >(tx, task.id())
                    .await)
                })
            })
            .await
            .unwrap();
        assert_eq!(agg_jobs.len(), 1);
        let report_ids: HashSet<_> = agg_jobs.into_iter().next().unwrap().1.into_iter().collect();
        assert_eq!(
            report_ids,
            HashSet::from([
                *first_report.metadata().id(),
                *second_report.metadata().id()
            ])
        );

        assert_eq!(
            batches,
            Vec::from([Batch::new(
                *task.id(),
                batch_identifier,
                (),
                BatchState::Open,
                1
            )])
        );
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_time_interval_task_batch_closed() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone()).await;
        const MIN_AGGREGATION_JOB_SIZE: usize = 50;
        const MAX_AGGREGATION_JOB_SIZE: usize = 60;

        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::TimeInterval,
                VdafInstance::Prio3Count,
                Role::Leader,
            )
            .build(),
        );

        // Create a min-size batch.
        let report_time = clock.now();
        let batch_identifier = TimeInterval::to_batch_identifier(&task, &(), &report_time).unwrap();
        let reports: Vec<_> =
            iter::repeat_with(|| LeaderStoredReport::new_dummy(*task.id(), report_time))
                .take(2 * MAX_AGGREGATION_JOB_SIZE + MIN_AGGREGATION_JOB_SIZE + 1)
                .collect();
        let all_report_ids: HashSet<ReportId> = reports
            .iter()
            .map(|report| *report.metadata().id())
            .collect();

        ds.run_tx(|tx| {
            let (task, reports) = (Arc::clone(&task), reports.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                for report in reports.iter() {
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), report)
                        .await?;
                }
                tx.put_batch(
                    &Batch::<PRIO3_VERIFY_KEY_LENGTH, TimeInterval, Prio3Count>::new(
                        *task.id(),
                        batch_identifier,
                        (),
                        BatchState::Closed,
                        0,
                    ),
                )
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: MIN_AGGREGATION_JOB_SIZE,
            max_aggregation_job_size: MAX_AGGREGATION_JOB_SIZE,
        });
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (agg_jobs, batches) = job_creator
            .datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    Ok(read_aggregate_info_for_task::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                        _,
                    >(tx, task.id())
                    .await)
                })
            })
            .await
            .unwrap();
        let mut seen_report_ids = HashSet::new();
        for (agg_job, report_ids) in &agg_jobs {
            // Job immediately finished since all reports are in a closed batch.
            assert_eq!(agg_job.state(), &AggregationJobState::Finished);

            // Jobs are created in round 0.
            assert_eq!(agg_job.round(), AggregationJobRound::from(0));

            // The batch is at most MAX_AGGREGATION_JOB_SIZE in size.
            assert!(report_ids.len() <= MAX_AGGREGATION_JOB_SIZE);

            // The batch is at least MIN_AGGREGATION_JOB_SIZE in size.
            assert!(report_ids.len() >= MIN_AGGREGATION_JOB_SIZE);

            // Report IDs are non-repeated across or inside aggregation jobs.
            for report_id in report_ids {
                assert!(!seen_report_ids.contains(report_id));
                seen_report_ids.insert(*report_id);
            }
        }

        // Every client report was added to some aggregation job.
        assert_eq!(all_report_ids, seen_report_ids);

        // Batches are created appropriately.
        assert_eq!(
            batches,
            Vec::from([Batch::new(
                *task.id(),
                batch_identifier,
                (),
                BatchState::Closed,
                0,
            )])
        );
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_fixed_size_task() {
        // Setup.
        install_test_trace_subscriber();
        let clock: MockClock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds: janus_aggregator_core::datastore::Datastore<MockClock> =
            ephemeral_datastore.datastore(clock.clone()).await;

        const MIN_AGGREGATION_JOB_SIZE: usize = 50;
        const MAX_AGGREGATION_JOB_SIZE: usize = 60;
        const MIN_BATCH_SIZE: usize = 200;
        const MAX_BATCH_SIZE: usize = 300;

        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::FixedSize {
                    max_batch_size: MAX_BATCH_SIZE as u64,
                },
                VdafInstance::Prio3Count,
                Role::Leader,
            )
            .with_min_batch_size(MIN_BATCH_SIZE as u64)
            .build(),
        );

        // Create MIN_BATCH_SIZE + MAX_BATCH_SIZE reports. We expect aggregation jobs to be created
        // containing these reports.
        let report_time = clock.now();
        let reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>> =
            iter::repeat_with(|| LeaderStoredReport::new_dummy(*task.id(), report_time))
                .take(MIN_BATCH_SIZE + MAX_BATCH_SIZE)
                .collect();

        let report_ids: HashSet<ReportId> = reports
            .iter()
            .map(|report| *report.metadata().id())
            .collect();

        ds.run_tx(|tx| {
            let (task, reports) = (task.clone(), reports.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                let vdaf = dummy_vdaf::Vdaf::new();
                for report in &reports {
                    tx.put_client_report(&vdaf, report).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: MIN_AGGREGATION_JOB_SIZE,
            max_aggregation_job_size: MAX_AGGREGATION_JOB_SIZE,
        });
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (outstanding_batches, (agg_jobs, batches)) = job_creator
            .datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    Ok((
                        tx.get_outstanding_batches_for_task(task.id()).await?,
                        read_aggregate_info_for_task::<
                            PRIO3_VERIFY_KEY_LENGTH,
                            FixedSize,
                            Prio3Count,
                            _,
                        >(tx, task.id())
                        .await,
                    ))
                })
            })
            .await
            .unwrap();

        // Verify outstanding batches.
        let mut total_max_size = 0;
        let mut min_size_batch_id = None;
        let mut max_size_batch_id = None;
        for outstanding_batch in &outstanding_batches {
            assert_eq!(outstanding_batch.size().start(), &0);
            assert!(&MIN_BATCH_SIZE <= outstanding_batch.size().end());
            assert!(outstanding_batch.size().end() <= &MAX_BATCH_SIZE);
            total_max_size += *outstanding_batch.size().end();

            if outstanding_batch.size().end() == &MIN_BATCH_SIZE {
                min_size_batch_id = Some(*outstanding_batch.id());
            }
            if outstanding_batch.size().end() == &MAX_BATCH_SIZE {
                max_size_batch_id = Some(*outstanding_batch.id());
            }
        }
        assert_eq!(total_max_size, report_ids.len());
        let batch_ids: HashSet<_> = outstanding_batches
            .iter()
            .map(|outstanding_batch| *outstanding_batch.id())
            .collect();

        // Verify aggregation jobs.
        let mut seen_report_ids = HashSet::new();
        let mut batches_with_small_agg_jobs = HashSet::new();
        for (agg_job, report_ids) in agg_jobs {
            // Aggregation jobs are created in round 0.
            assert_eq!(agg_job.round(), AggregationJobRound::from(0));

            // Every batch corresponds to one of the outstanding batches.
            assert!(batch_ids.contains(agg_job.batch_id()));

            // At most one aggregation job per batch will be smaller than the normal minimum
            // aggregation job size.
            if report_ids.len() < MIN_AGGREGATION_JOB_SIZE {
                assert!(!batches_with_small_agg_jobs.contains(agg_job.batch_id()));
                batches_with_small_agg_jobs.insert(*agg_job.batch_id());
            }

            // The aggregation job is at most MAX_AGGREGATION_JOB_SIZE in size.
            assert!(report_ids.len() <= MAX_AGGREGATION_JOB_SIZE);

            // Report IDs are non-repeated across or inside aggregation jobs.
            for report_id in report_ids {
                assert!(!seen_report_ids.contains(&report_id));
                seen_report_ids.insert(report_id);
            }
        }

        // Every client report was added to some aggregation job.
        assert_eq!(report_ids, seen_report_ids);

        assert_eq!(
            batches.into_iter().collect::<HashSet<_>>(),
            HashSet::from([
                Batch::new(
                    *task.id(),
                    max_size_batch_id.unwrap(),
                    (),
                    BatchState::Open,
                    5,
                ),
                Batch::new(
                    *task.id(),
                    min_size_batch_id.unwrap(),
                    (),
                    BatchState::Open,
                    4,
                ),
            ])
        );
    }

    /// Test helper function that reads all aggregation jobs & batches for a given task ID,
    /// returning the aggregation jobs, the report IDs included in the aggregation job, and the
    /// batches. Report IDs are returned in the order they are included in the aggregation job.
    async fn read_aggregate_info_for_task<
        const SEED_SIZE: usize,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16>,
        C: Clock,
    >(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
    ) -> (
        Vec<(AggregationJob<SEED_SIZE, Q, A>, Vec<ReportId>)>,
        Vec<Batch<SEED_SIZE, Q, A>>,
    ) {
        try_join!(
            try_join_all(
                tx.get_aggregation_jobs_for_task(task_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg_job| async {
                        let agg_job_id = *agg_job.id();
                        tx.get_report_aggregations_for_aggregation_job(
                            &dummy_vdaf::Vdaf::new(),
                            &Role::Leader,
                            task_id,
                            &agg_job_id,
                        )
                        .map_ok(move |report_aggs| {
                            (
                                agg_job,
                                report_aggs.into_iter().map(|ra| *ra.report_id()).collect(),
                            )
                        })
                        .await
                    }),
            ),
            tx.get_batches_for_task(task_id),
        )
        .unwrap()
    }
}
