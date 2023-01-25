use crate::{
    datastore::models::{
        AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
    },
    datastore::{gather_errors, models::OutstandingBatch, Datastore},
    messages::{DurationExt as _, TimeExt as _},
    task::{self, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    try_join,
};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31, U63};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32, FixedI64};
use futures::{future::join_all, FutureExt};
use janus_core::{task::VdafInstance, time::Clock};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    Duration as DurationMsg, Interval, Role, TaskId,
};
use opentelemetry::{
    metrics::{Histogram, Unit},
    Context, KeyValue,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3Aes128FixedPointBoundedL2VecSum;
use prio::{
    codec::Encode,
    vdaf::{
        self,
        prio3::{
            Prio3Aes128Count, Prio3Aes128CountVecMultithreaded, Prio3Aes128Histogram,
            Prio3Aes128Sum,
        },
    },
};
use rand::{random, thread_rng, Rng};
use std::{
    cmp::{max, min},
    collections::HashMap,
    convert::Infallible,
    iter,
    ops::RangeInclusive,
    sync::Arc,
    time::Duration,
};
use tokio::{
    select,
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

    #[tracing::instrument(skip(self))]
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
            info!("Updating tasks");
            let start = Instant::now();
            let tasks = self
                .datastore
                .run_tx_with_name("aggregation_job_creator_get_tasks", |tx| {
                    Box::pin(async move { tx.get_tasks().await })
                })
                .await;
            let tasks = match tasks {
                Ok(tasks) => tasks
                    .into_iter()
                    .filter_map(|task| match task.role() {
                        Role::Leader => Some((*task.id(), task)),
                        _ => None,
                    })
                    .collect::<HashMap<_, _>>(),

                Err(error) => {
                    error!(?error, "Couldn't update tasks");
                    task_update_time_histogram.record(
                        &Context::current(),
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
                        (Arc::clone(&self), job_creation_time_histogram.clone());
                    async move {
                        this.run_for_task(rx, job_creation_time_histogram, Arc::new(task))
                            .await
                    }
                });
            }

            task_update_time_histogram.record(
                &Context::current(),
                start.elapsed().as_secs_f64(),
                &[KeyValue::new("status", "success")],
            );
        }
    }

    #[tracing::instrument(skip(self, shutdown, job_creation_time_histogram))]
    async fn run_for_task(
        self: Arc<Self>,
        mut shutdown: Receiver<()>,
        job_creation_time_histogram: Histogram<f64>,
        task: Arc<Task>,
    ) {
        debug!(task_id = %task.id(), "Job creation worker started");
        let first_tick_instant = Instant::now()
            + Duration::from_secs(
                thread_rng().gen_range(0..self.aggregation_job_creation_interval.as_secs()),
            );
        let mut aggregation_job_creation_ticker =
            time::interval_at(first_tick_instant, self.aggregation_job_creation_interval);

        loop {
            select! {
                _ = aggregation_job_creation_ticker.tick() => {
                    info!(task_id = %task.id(), "Creating aggregation jobs for task");
                    let (start, mut status) = (Instant::now(), "success");
                    if let Err(error) = Arc::clone(&self).create_aggregation_jobs_for_task(Arc::clone(&task)).await {
                        error!(task_id = %task.id(), %error, "Couldn't create aggregation jobs for task");
                        status = "error";
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

    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    async fn create_aggregation_jobs_for_task(
        self: Arc<Self>,
        task: Arc<Task>,
    ) -> anyhow::Result<()> {
        match (task.query_type(), task.vdaf()) {
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Count) => {
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.create_aggregation_jobs_for_time_interval_task_no_param::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128CountVecMultithreaded
                >(task).await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Sum { .. }) => {
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Sum>(task)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Histogram>(task)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { .. }) => {
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(task)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { .. }) => {
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(task)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { .. }) => {
                self.create_aggregation_jobs_for_time_interval_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(task)
                    .await
            }

            (task::QueryType::FixedSize{max_batch_size}, VdafInstance::Prio3Aes128Count) => {
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task, max_batch_size)
                    .await
            }

            (task::QueryType::FixedSize{max_batch_size}, VdafInstance::Prio3Aes128CountVec { .. }) => {
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128CountVecMultithreaded
                >(task, max_batch_size).await
            }

            (task::QueryType::FixedSize{max_batch_size}, VdafInstance::Prio3Aes128Sum { .. }) => {
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Sum>(task, max_batch_size)
                    .await
            }

            (task::QueryType::FixedSize{max_batch_size}, VdafInstance::Prio3Aes128Histogram { .. }) => {
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Histogram>(task, max_batch_size)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{max_batch_size}, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { .. }) => {
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(task, max_batch_size)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{max_batch_size}, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { .. }) => {
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(task, max_batch_size)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{max_batch_size}, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { .. }) => {
                let max_batch_size = *max_batch_size;
                self.create_aggregation_jobs_for_fixed_size_task_no_param::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(task, max_batch_size)
                    .await
            }

            _ => {
                error!(vdaf = ?task.vdaf(), "VDAF is not yet supported");
                panic!("VDAF {:?} is not yet supported", task.vdaf());
            }
        }
    }

    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    async fn create_aggregation_jobs_for_time_interval_task_no_param<
        const L: usize,
        A: vdaf::Aggregator<L, AggregationParam = ()>,
    >(
        self: Arc<Self>,
        task: Arc<Task>,
    ) -> anyhow::Result<()>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        Ok(self
            .datastore
            .run_tx_with_name("aggregation_job_creator_time_no_param", |tx| {
                let (this, task) = (Arc::clone(&self), Arc::clone(&task));
                Box::pin(async move {
                    // Find some unaggregated client reports.
                    let report_ids_and_times = tx
                        .get_unaggregated_client_report_ids_for_task(task.id())
                        .await?;

                    // Generate aggregation jobs & report aggregations based on the reports we read.
                    let mut agg_jobs = Vec::new();
                    let mut report_aggs = Vec::new();
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

                        agg_jobs.push(AggregationJob::<L, TimeInterval, A>::new(
                            *task.id(),
                            aggregation_job_id,
                            (),
                            (),
                            client_timestamp_interval,
                            AggregationJobState::InProgress,
                        ));

                        for (ord, (report_id, time)) in agg_job_reports.iter().enumerate() {
                            report_aggs.push(ReportAggregation::<L, A>::new(
                                *task.id(),
                                aggregation_job_id,
                                *report_id,
                                *time,
                                i64::try_from(ord)?,
                                ReportAggregationState::Start,
                            ));
                        }
                    }

                    // Write the aggregation jobs & report aggregations we created.
                    gather_errors(
                        join_all(
                            agg_jobs
                                .iter()
                                .map(|agg_job| tx.put_aggregation_job(agg_job)),
                        )
                        .await,
                    )?;
                    gather_errors(
                        join_all(
                            report_aggs
                                .iter()
                                .map(|report_agg| tx.put_report_aggregation(report_agg)),
                        )
                        .await,
                    )?;

                    Ok(())
                })
            })
            .await?)
    }

    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    async fn create_aggregation_jobs_for_fixed_size_task_no_param<
        const L: usize,
        A: vdaf::Aggregator<L, AggregationParam = ()>,
    >(
        self: Arc<Self>,
        task: Arc<Task>,
        task_max_batch_size: u64,
    ) -> anyhow::Result<()>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let (task_min_batch_size, task_max_batch_size) = (
            usize::try_from(task.min_batch_size())?,
            usize::try_from(task_max_batch_size)?,
        );
        Ok(self
            .datastore
            .run_tx_with_name("aggregation_job_creator_fixed_no_param", |tx| {
                let (this, task) = (Arc::clone(&self), Arc::clone(&task));
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
                    let mut aggregation_jobs = Vec::<AggregationJob<L, FixedSize, A>>::new();
                    let mut report_aggregations = Vec::<ReportAggregation<L, A>>::new();
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
                        report_aggregations.extend(
                            unaggregated_report_ids
                                .drain(..aggregation_job_size)
                                .enumerate()
                                .map(|(ord, (report_id, client_timestamp))| {
                                    min_client_timestamp =
                                        Some(min_client_timestamp.map_or(client_timestamp, |ts| {
                                            min(ts, client_timestamp)
                                        }));
                                    max_client_timestamp =
                                        Some(max_client_timestamp.map_or(client_timestamp, |ts| {
                                            max(ts, client_timestamp)
                                        }));

                                    ReportAggregation::new(
                                        *task.id(),
                                        aggregation_job_id,
                                        report_id,
                                        client_timestamp,
                                        ord as i64,
                                        ReportAggregationState::Start,
                                    )
                                }),
                        );

                        let min_client_timestamp = min_client_timestamp.unwrap(); // unwrap safety: aggregation_job_size > 0
                        let max_client_timestamp = max_client_timestamp.unwrap(); // unwrap safety: aggregation_job_size > 0
                        let client_timestamp_interval = Interval::new(
                            min_client_timestamp,
                            max_client_timestamp
                                .difference(&min_client_timestamp)?
                                .add(&DurationMsg::from_seconds(1))?,
                        )?;
                        aggregation_jobs.push(AggregationJob::new(
                            *task.id(),
                            aggregation_job_id,
                            (),
                            *batch.id(),
                            client_timestamp_interval,
                            AggregationJobState::InProgress,
                        ));

                        if is_batch_new {
                            new_batches.push(*batch.id())
                        }
                        is_batch_new = false;
                        batch_max_size += aggregation_job_size;
                    }

                    // Write the outstanding batches, aggregation jobs, & report aggregations we
                    // created.
                    if !unaggregated_report_ids.is_empty() {
                        let report_ids: Vec<_> = unaggregated_report_ids
                            .iter()
                            .map(|(report_id, _)| *report_id)
                            .collect();
                        tx.mark_reports_unaggregated(task.id(), &report_ids).await?;
                    }

                    try_join!(
                        join_all(
                            aggregation_jobs
                                .iter()
                                .map(|agg_job| tx.put_aggregation_job(agg_job)),
                        )
                        .map(gather_errors),
                        join_all(
                            new_batches
                                .iter()
                                .map(|batch_id| tx.put_outstanding_batch(task.id(), batch_id)),
                        )
                        .map(gather_errors)
                    )?;

                    gather_errors(
                        join_all(
                            report_aggregations
                                .iter()
                                .map(|report_agg| tx.put_report_aggregation(report_agg)),
                        )
                        .await,
                    )?;

                    Ok(())
                })
            })
            .await?)
    }

    /// Look for combinations of client reports and collection job aggregation parameters that do not
    /// yet have a report aggregation, and batch them into new aggregation jobs. This should only
    /// be used with VDAFs that have non-unit type aggregation parameters.
    // This is only used in tests thus far.
    #[cfg(test)]
    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    async fn create_aggregation_jobs_for_task_with_param<const L: usize, A>(
        self: Arc<Self>,
        task: Arc<Task>,
    ) -> anyhow::Result<()>
    where
        A: vdaf::Aggregator<L> + VdafHasAggregationParameter,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::AggregationParam: Send + Sync + Eq + std::hash::Hash,
    {
        use itertools::Itertools;
        let max_aggregation_job_size = self.max_aggregation_job_size;

        self.datastore
            .run_tx_with_name("aggregation_job_creator_time_with_param", |tx| {
                let (this, task) = (Arc::clone(&self), Arc::clone(&task));
                Box::pin(async move {
                    // Find some client reports that are covered by a collect request, but haven't
                    // been aggregated yet, and group them by their batch.
                    let result_vec = tx
                        .get_unaggregated_client_report_ids_by_collect_for_task::<L, A>(task.id())
                        .await?;
                    let report_count = result_vec.len();
                    let result_map = result_vec
                        .into_iter()
                        .map(|(report_id, report_time, aggregation_param)| {
                            (aggregation_param, (report_id, report_time))
                        })
                        .into_group_map();

                    // Generate aggregation jobs and report aggregations.
                    let mut agg_jobs = Vec::new();
                    let mut report_aggs = Vec::with_capacity(report_count);
                    for (aggregation_param, report_ids_and_times) in result_map {
                        for agg_job_reports in report_ids_and_times.chunks(max_aggregation_job_size)
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

                            agg_jobs.push(AggregationJob::<L, TimeInterval, A>::new(
                                *task.id(),
                                aggregation_job_id,
                                aggregation_param.clone(),
                                (),
                                client_timestamp_interval,
                                AggregationJobState::InProgress,
                            ));

                            for (ord, (report_id, time)) in agg_job_reports.iter().enumerate() {
                                report_aggs.push(ReportAggregation::<L, A>::new(
                                    *task.id(),
                                    aggregation_job_id,
                                    *report_id,
                                    *time,
                                    i64::try_from(ord)?,
                                    ReportAggregationState::Start,
                                ));
                            }
                        }
                    }

                    // Write the aggregation jobs & report aggregations we created.
                    gather_errors(
                        join_all(
                            agg_jobs
                                .iter()
                                .map(|agg_job| tx.put_aggregation_job(agg_job)),
                        )
                        .await,
                    )?;
                    gather_errors(
                        join_all(
                            report_aggs
                                .iter()
                                .map(|report_agg| tx.put_report_aggregation(report_agg)),
                        )
                        .await,
                    )?;

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
        aggregator::query_type::AccumulableQueryType,
        datastore::{
            gather_errors,
            models::{AggregationJob, CollectionJob, CollectionJobState, LeaderStoredReport},
            test_util::ephemeral_datastore,
            Transaction,
        },
        messages::TimeExt,
        task::{
            test_util::TaskBuilder, QueryType as TaskQueryType, PRIO3_AES128_VERIFY_KEY_LENGTH,
        },
    };
    use futures::{future::join_all, TryFutureExt};
    use janus_core::{
        task::VdafInstance,
        test_util::{
            dummy_vdaf::{self, AggregationParam},
            install_test_trace_subscriber,
        },
        time::{Clock, MockClock},
    };
    use janus_messages::{
        query_type::{FixedSize, TimeInterval},
        AggregationJobId, Interval, ReportId, Role, TaskId, Time,
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
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        // TODO(#234): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing, calling time::pause() breaks interaction with the
        // database -- the job-acquiry transaction deadlocks on attempting to start a transaction,
        // even if the main test loops on calling yield_now().

        let report_time = Time::from_seconds_since_epoch(0);
        let leader_task = TaskBuilder::new(
            TaskQueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let leader_report = LeaderStoredReport::new_dummy(*leader_task.id(), report_time);

        let helper_task = TaskBuilder::new(
            TaskQueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
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
        let (leader_agg_jobs, helper_agg_jobs) = job_creator
            .datastore
            .run_tx(|tx| {
                let (leader_task, helper_task) = (leader_task.clone(), helper_task.clone());
                Box::pin(async move {
                    let leader_agg_jobs = read_aggregate_jobs_for_task_prio3_count::<
                        TimeInterval,
                        HashSet<_>,
                        _,
                    >(tx, leader_task.id())
                    .await;
                    let helper_agg_jobs = read_aggregate_jobs_for_task_prio3_count::<
                        TimeInterval,
                        HashSet<_>,
                        _,
                    >(tx, helper_task.id())
                    .await;
                    Ok((leader_agg_jobs, helper_agg_jobs))
                })
            })
            .await
            .unwrap();
        assert!(helper_agg_jobs.is_empty());
        assert_eq!(leader_agg_jobs.len(), 1);
        assert_eq!(
            leader_agg_jobs
                .iter()
                .next()
                .unwrap()
                .1
                 .0
                .partial_batch_identifier(),
            &()
        );
        let report_times_and_ids = leader_agg_jobs.into_iter().next().unwrap().1 .1;
        assert_eq!(
            report_times_and_ids,
            HashSet::from([(
                *leader_report.metadata().time(),
                *leader_report.metadata().id()
            )])
        );
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_time_interval_task() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        const MIN_AGGREGATION_JOB_SIZE: usize = 50;
        const MAX_AGGREGATION_JOB_SIZE: usize = 60;

        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::TimeInterval,
                VdafInstance::Prio3Aes128Count,
                Role::Leader,
            )
            .build(),
        );

        // Create 2 max-size batches, a min-size batch, one extra report (which will be added to the
        // min-size batch).
        let report_time = clock.now();
        let reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>> =
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
                    tx.put_client_report(report).await?;
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
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    Ok(
                        read_aggregate_jobs_for_task_prio3_count::<TimeInterval, Vec<_>, _>(
                            tx,
                            task.id(),
                        )
                        .await,
                    )
                })
            })
            .await
            .unwrap();
        let mut seen_report_ids = HashSet::new();
        for (_, (_, times_and_ids)) in agg_jobs {
            // The batch is at most MAX_AGGREGATION_JOB_SIZE in size.
            assert!(times_and_ids.len() <= MAX_AGGREGATION_JOB_SIZE);

            // The batch is at least MIN_AGGREGATION_JOB_SIZE in size.
            assert!(times_and_ids.len() >= MIN_AGGREGATION_JOB_SIZE);

            // Report IDs are non-repeated across or inside aggregation jobs.
            for (_, report_id) in times_and_ids {
                assert!(!seen_report_ids.contains(&report_id));
                seen_report_ids.insert(report_id);
            }
        }

        // Every client report was added to some aggregation job.
        assert_eq!(all_report_ids, seen_report_ids);
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_time_interval_task_not_enough_reports() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());
        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::TimeInterval,
                VdafInstance::Prio3Aes128Count,
                Role::Leader,
            )
            .build(),
        );
        let first_report = LeaderStoredReport::new_dummy(*task.id(), clock.now());
        let second_report = LeaderStoredReport::new_dummy(*task.id(), clock.now());

        ds.run_tx(|tx| {
            let (task, first_report) = (Arc::clone(&task), first_report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&first_report).await
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
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    Ok(
                        read_aggregate_jobs_for_task_prio3_count::<TimeInterval, HashSet<_>, _>(
                            tx,
                            task.id(),
                        )
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
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify -- the additional report we wrote allows an aggregation job to be created.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    Ok(
                        read_aggregate_jobs_for_task_prio3_count::<TimeInterval, HashSet<_>, _>(
                            tx,
                            task.id(),
                        )
                        .await,
                    )
                })
            })
            .await
            .unwrap();
        assert_eq!(agg_jobs.len(), 1);
        let report_ids = agg_jobs.into_iter().next().unwrap().1 .1;
        assert_eq!(
            report_ids,
            HashSet::from([
                (
                    *first_report.metadata().time(),
                    *first_report.metadata().id()
                ),
                (
                    *second_report.metadata().time(),
                    *second_report.metadata().id()
                )
            ])
        );
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_fixed_size_task() {
        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        const MIN_AGGREGATION_JOB_SIZE: usize = 50;
        const MAX_AGGREGATION_JOB_SIZE: usize = 60;
        const MIN_BATCH_SIZE: usize = 200;
        const MAX_BATCH_SIZE: usize = 300;

        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::FixedSize {
                    max_batch_size: MAX_BATCH_SIZE as u64,
                },
                VdafInstance::Prio3Aes128Count,
                Role::Leader,
            )
            .with_min_batch_size(MIN_BATCH_SIZE as u64)
            .build(),
        );

        // Create MIN_BATCH_SIZE + MAX_BATCH_SIZE reports. We expect aggregation jobs to be created
        // containing these reports.
        let reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>> =
            iter::repeat_with(|| LeaderStoredReport::new_dummy(*task.id(), clock.now()))
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
                for report in &reports {
                    tx.put_client_report(report).await?;
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
        let (outstanding_batches, agg_jobs) = job_creator
            .datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    Ok((
                        tx.get_outstanding_batches_for_task(task.id()).await?,
                        read_aggregate_jobs_for_task_prio3_count::<FixedSize, Vec<_>, _>(
                            tx,
                            task.id(),
                        )
                        .await,
                    ))
                })
            })
            .await
            .unwrap();

        // Verify outstanding batches.
        let mut total_max_size = 0;
        for outstanding_batch in outstanding_batches {
            assert_eq!(outstanding_batch.size().start(), &0);
            assert!(&MIN_BATCH_SIZE <= outstanding_batch.size().end());
            assert!(outstanding_batch.size().end() <= &MAX_BATCH_SIZE);
            total_max_size += *outstanding_batch.size().end();
        }
        assert_eq!(total_max_size, report_ids.len());

        // Verify aggregation jobs.
        let mut seen_report_ids = HashSet::new();
        let mut batches_with_small_agg_jobs = HashSet::new();
        for (_, (agg_job, times_and_ids)) in agg_jobs {
            // At most one aggregation job per batch will be smaller than the normal minimum
            // aggregation job size.
            if times_and_ids.len() < MIN_AGGREGATION_JOB_SIZE {
                assert!(!batches_with_small_agg_jobs.contains(agg_job.batch_id()));
                batches_with_small_agg_jobs.insert(*agg_job.batch_id());
            }

            // The aggregation job is at most MAX_AGGREGATION_JOB_SIZE in size.
            assert!(times_and_ids.len() <= MAX_AGGREGATION_JOB_SIZE);

            // Report IDs are non-repeated across or inside aggregation jobs.
            for (_, report_id) in times_and_ids {
                assert!(!seen_report_ids.contains(&report_id));
                seen_report_ids.insert(report_id);
            }
        }

        // Every client report was added to some aggregation job.
        assert_eq!(report_ids, seen_report_ids);
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_time_interval_task_with_param() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = ephemeral_datastore.datastore(clock.clone());

        const MAX_AGGREGATION_JOB_SIZE: usize = 10;

        // Note that the minimum aggregation job size setting has no effect here, because we always
        // wait for a collection job before scheduling any aggregation jobs, and DAP requires that no
        // more reports are accepted for a time interval after that interval already has a collect
        // job.

        let vdaf = dummy_vdaf::Vdaf::new();
        let task = Arc::new(
            TaskBuilder::new(
                TaskQueryType::TimeInterval,
                VdafInstance::Fake,
                Role::Leader,
            )
            .build(),
        );

        // Create MAX_AGGREGATION_JOB_SIZE reports in one batch. This should result in one
        // aggregation job per overlapping collection job for these reports. (and there is one such
        // collection job)
        let report_time = clock.now().sub(task.time_precision()).unwrap();
        let batch_1_reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>> =
            iter::repeat_with(|| LeaderStoredReport::new_dummy(*task.id(), report_time))
                .take(MAX_AGGREGATION_JOB_SIZE)
                .collect();

        // Create more than MAX_AGGREGATION_JOB_SIZE reports in another batch. This should result in
        // two aggregation jobs per overlapping collection job. (and there are two such collection jobs)
        let report_time = report_time.sub(task.time_precision()).unwrap();
        let batch_2_reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>> =
            iter::repeat_with(|| LeaderStoredReport::new_dummy(*task.id(), report_time))
                .take(MAX_AGGREGATION_JOB_SIZE + 1)
                .collect();

        ds.run_tx(|tx| {
            let (task, batch_1_reports, batch_2_reports) = (
                Arc::clone(&task),
                batch_1_reports.clone(),
                batch_2_reports.clone(),
            );
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

        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
            min_aggregation_job_size: 1,
            max_aggregation_job_size: MAX_AGGREGATION_JOB_SIZE,
        });
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task_with_param::<0, dummy_vdaf::Vdaf>(Arc::clone(&task))
            .await
            .unwrap();

        // Verify, there should be no aggregation jobs yet, because there are no collection jobs to
        // provide aggregation parameters.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task_generic::<
                        0,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                        Vec<_>,
                        _,
                    >(tx, task.id(), &vdaf)
                    .await)
                })
            })
            .await
            .unwrap();
        assert!(agg_jobs.count() == 0);

        job_creator
            .datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    // This will encompass the members of batch_2_reports.
                    tx.put_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &CollectionJob::new(
                            *task.id(),
                            random(),
                            Interval::new(report_time, *task.time_precision()).unwrap(),
                            AggregationParam(7),
                            CollectionJobState::Start,
                        ),
                    )
                    .await?;
                    // This will encompass the members of both batch_1_reports and batch_2_reports.
                    tx.put_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &CollectionJob::new(
                            *task.id(),
                            random(),
                            Interval::new(
                                report_time,
                                janus_messages::Duration::from_seconds(
                                    task.time_precision().as_seconds() * 2,
                                ),
                            )
                            .unwrap(),
                            AggregationParam(11),
                            CollectionJobState::Start,
                        ),
                    )
                    .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

        // Run again, this time it should create some aggregation jobs.
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task_with_param::<0, dummy_vdaf::Vdaf>(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let mut agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task_generic::<
                        0,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                        Vec<_>,
                        _,
                    >(tx, task.id(), &vdaf)
                    .await)
                })
            })
            .await
            .unwrap()
            .collect::<Vec<_>>();

        let mut seen_pairs = Vec::new();
        let mut aggregation_jobs_per_aggregation_param = HashMap::new();
        for (aggregation_job, times_and_ids) in agg_jobs.iter() {
            assert!(times_and_ids.len() <= MAX_AGGREGATION_JOB_SIZE);

            *aggregation_jobs_per_aggregation_param
                .entry(*aggregation_job.aggregation_parameter())
                .or_default() += 1;

            for (_, report_id) in times_and_ids {
                seen_pairs.push((*report_id, *aggregation_job.aggregation_parameter()));
            }
        }
        assert_eq!(agg_jobs.len(), 5);
        assert_eq!(
            aggregation_jobs_per_aggregation_param,
            HashMap::from([(AggregationParam(7), 2), (AggregationParam(11), 3)])
        );
        let mut expected_pairs = Vec::with_capacity(MAX_AGGREGATION_JOB_SIZE * 3 + 2);
        for report in batch_1_reports.iter() {
            expected_pairs.push((*report.metadata().id(), AggregationParam(11)));
        }
        for report in batch_2_reports.iter() {
            expected_pairs.push((*report.metadata().id(), AggregationParam(7)));
            expected_pairs.push((*report.metadata().id(), AggregationParam(11)));
        }
        seen_pairs.sort();
        expected_pairs.sort();
        assert_eq!(seen_pairs, expected_pairs);

        // Run once more, and confirm that no further aggregation jobs are created.
        // Run again, this time it should create some aggregation jobs.
        Arc::clone(&job_creator)
            .create_aggregation_jobs_for_task_with_param::<0, dummy_vdaf::Vdaf>(Arc::clone(&task))
            .await
            .unwrap();

        // We should see the same aggregation jobs as before, because the newly created aggregation
        // jobs should have satisfied all the collection jobs.
        let mut quiescent_check_agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task_generic::<
                        0,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                        Vec<_>,
                        _,
                    >(tx, task.id(), &vdaf)
                    .await)
                })
            })
            .await
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(agg_jobs.len(), quiescent_check_agg_jobs.len());
        agg_jobs.sort_by_key(|(agg_job, _)| *agg_job.id());
        quiescent_check_agg_jobs.sort_by_key(|(agg_job, _)| *agg_job.id());
        assert_eq!(agg_jobs, quiescent_check_agg_jobs);
    }

    /// Test helper function that reads all aggregation jobs for a given task ID, with VDAF
    /// Prio3Aes128Count, returning a map from aggregation job ID to the report IDs included in
    /// the aggregation job. The container used to store the report IDs is up to the caller; ordered
    /// containers will store report IDs in the order they are included in the aggregate job.
    async fn read_aggregate_jobs_for_task_prio3_count<
        Q: AccumulableQueryType,
        T: FromIterator<(Time, ReportId)>,
        C: Clock,
    >(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
    ) -> HashMap<
        AggregationJobId,
        (
            AggregationJob<PRIO3_AES128_VERIFY_KEY_LENGTH, Q, Prio3Aes128Count>,
            T,
        ),
    > {
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        read_aggregate_jobs_for_task_generic::<
            PRIO3_AES128_VERIFY_KEY_LENGTH,
            Q,
            Prio3Aes128Count,
            T,
            C,
        >(tx, task_id, &vdaf)
        .await
        .map(|(agg_job, report_id)| (*agg_job.id(), (agg_job, report_id)))
        .collect()
    }

    /// Test helper function that reads all aggregation jobs for a given task ID, returning an
    /// iterator of tuples containing aggregation job IDs, the report IDs included in the
    /// aggregation job, and aggregation parameters. The container used to store the report IDs is
    /// up to the caller; ordered containers will store report IDs in the order they are included in
    /// the aggregate job.
    async fn read_aggregate_jobs_for_task_generic<
        const L: usize,
        Q: AccumulableQueryType,
        A,
        T,
        C: Clock,
    >(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
        vdaf: &A,
    ) -> impl Iterator<Item = (AggregationJob<L, Q, A>, T)>
    where
        T: FromIterator<(Time, ReportId)>,
        A: Aggregator<L>,
        for<'a> Vec<u8>: From<&'a <A as Vdaf>::AggregateShare>,
        <A as Aggregator<L>>::PrepareState: for<'a> ParameterizedDecode<(&'a A, usize)>,
        for<'a> <A as Vdaf>::OutputShare: TryFrom<&'a [u8]>,
    {
        gather_errors(
            join_all(
                tx.get_aggregation_jobs_for_task::<L, Q, A>(task_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg_job| async {
                        let agg_job_id = *agg_job.id();
                        tx.get_report_aggregations_for_aggregation_job(
                            vdaf,
                            &Role::Leader,
                            task_id,
                            &agg_job_id,
                        )
                        .map_ok(move |report_aggs| {
                            (
                                agg_job,
                                report_aggs
                                    .into_iter()
                                    .map(|ra| (*ra.time(), *ra.report_id()))
                                    .collect::<T>(),
                            )
                        })
                        .await
                    }),
            )
            .await,
        )
        .unwrap()
        .into_iter()
    }
}
