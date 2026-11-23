//! In-memory accumulation of aggregation job (& report aggregation) writes, along with related
//! batch aggregation writes.

use std::{collections::HashMap, fmt::Debug};

use async_trait::async_trait;
use futures::future::try_join_all;
use janus_aggregator_core::{
    AsyncAggregator,
    batch_mode::AccumulableBatchMode,
    datastore::{
        Error, Transaction,
        models::{
            AggregationJob, AggregationJobDatastoreId, AggregationJobState, BatchAggregation,
            BatchAggregationState, ReportAggregation, ReportAggregationMetadata,
            ReportAggregationMetadataState, ReportAggregationState, UnwrittenAggregationJob,
        },
        task_counters::TaskAggregationCounter,
    },
};
use janus_core::{report_id::ReportIdChecksumExt as _, vdaf::VdafInstance};
use janus_messages::{
    AggregationJobId, Interval, ReportError, ReportId, ReportIdChecksum, TaskId, Time, VerifyResp,
    VerifyStepResult, batch_mode::TimeInterval,
};
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram},
};
use rand::{RngExt, rng};
use tokio::try_join;
use tracing::{Level, warn};

use crate::{Operation, metrics::aggregate_step_failure_types::ACCUMULATE_FAILURE};

/// [`AggregationJobWriter`] specialized for [`TimeInterval`] batch mode.
///
/// This lets us refer to this commonly instantiated type more concisely in contexts where the
/// `SEED_SIZE`, `Aggregator`, and `Arguments` generic parameters can be inferred, but not
/// `BatchMode`. i.e., we can write `let foo = TimeIntervalAggregationJobWriter::new(...)` instead
/// of the messier `let foo = AggregationJobWriter::<_, TimeInterval, _>::new(...)`.
// TODO(timg): review if this is still actually useful
pub type TimeIntervalAggregationJobWriter<const SEED_SIZE: usize, A> =
    AggregationJobWriter<SEED_SIZE, TimeInterval, A>;

/// Buffers pending writes to aggregation jobs and their report aggregations.
///
/// At write time, the state of aggregation jobs is updated based on the state of the constituent
/// report aggregations, and the relevant batch aggregations are updated as appropriate without
/// output shares from finished report aggregations.
///
/// There are three settings where this is used, each of which uses different representations of
/// aggregation jobs and report aggregations:
///
/// When the leader is creating aggregation jobs in the aggregation job creator, we are writing new
/// `aggregation_jobs` rows and writing new `report_aggregations` rows corresponding to existing
/// `client_reports` rows, which get scrubbed.
///
/// When the helper is creating an aggregation job while handling an aggregation job initialization
/// request, we are writing a new `aggregation_jobs` row, new `report_aggregations` rows
/// corresponding to the report shares in the request and new `client_reports` rows containing
/// scrubbed reports for those same shares.
///
/// When either aggregator is updating an aggregation job based on the most recent message from its
/// peer, we are updating existing `aggregation_job` and `report_aggregations` rows.
///
/// Each of these cases uses a different pair of types to represent aggregation jobs and report
/// aggregations. Not all possible combinations of `WritableAggregationJob` and
/// `WritableReportAggregation` implementations are valid, so we use implementations of the
/// `AggregationJobWriterInputs` trait to restrict which combinations are supported.
#[derive(Clone)]
pub struct AggregationJobWriter<const SEED_SIZE: usize, B, A>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    task_id: TaskId,
    batch_aggregation_shard_count: u64,
    aggregation_parameter: Option<A::AggregationParam>,
    /// Generator for keys in aggregation job hashmaps.
    ///
    /// Ultimately, an [`AggregationJobDatastoreID`] represents a DB primary key value, but this
    /// structure's job is to buffer writes to the database, meaning that it can't yet know what
    /// `id` will be assigned to some job. But we still need to be able to distinguish aggregation
    /// jobs and map report aggregations to them. So we use synthetic datastore IDs gnerated from
    /// this counter, which are used purely within this module. When aggregation jobs and report
    /// aggregations are written to storage, they get updated with a real ID value.
    aggregation_job_datastore_id_counter: AggregationJobDatastoreId,
    aggregation_jobs:
        HashMap<AggregationJobDatastoreId, AggregationJobWriterInputs<SEED_SIZE, B, A>>,
    by_batch_identifier_index:
        HashMap<B::BatchIdentifier, HashMap<AggregationJobDatastoreId, Vec<usize>>>,
    metrics: Option<AggregationJobWriterMetrics>,
    task_aggregation_counters: TaskAggregationCounter,
}

impl<const SEED_SIZE: usize, B, A> AggregationJobWriter<SEED_SIZE, B, A>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    /// Create a new, empty aggregation job writer.
    pub fn new(
        task_id: TaskId,
        batch_aggregation_shard_count: u64,
        metrics: Option<AggregationJobWriterMetrics>,
        task_aggregation_counters: TaskAggregationCounter,
    ) -> Self {
        Self {
            task_id,
            batch_aggregation_shard_count,
            aggregation_parameter: None,
            aggregation_job_datastore_id_counter: AggregationJobDatastoreId::from(0),
            aggregation_jobs: HashMap::new(),
            by_batch_identifier_index: HashMap::new(),
            metrics,
            task_aggregation_counters,
        }
    }

    /// Internal helper to optionally update the aggregation parameter.
    ///
    /// # Panics
    ///
    /// Panics if a different aggregation parameter is provided than what was previously stored.
    fn update_aggregation_parameter(&mut self, aggregation_parameter: &A::AggregationParam) {
        // We don't currently have (or need, at time of writing) logic to allow writing aggregation
        // jobs across different aggregation parameters. Verify that our caller is not trying to do
        // so.
        if let Some(existing_aggregation_parameter) = self.aggregation_parameter.as_ref() {
            assert_eq!(aggregation_parameter, existing_aggregation_parameter);
        } else {
            self.aggregation_parameter = Some(aggregation_parameter.clone());
        }
    }

    /// Add a single aggregation job and write it to storage right away.
    ///
    /// This is equivalent to calling [`Self::put`] once and then [`Self::write`], except that this
    /// also returns [`VerifyResp`]s for the job's reports.
    ///
    /// # Panics
    ///
    /// Panics if the aggregation parameter of the aggregation job does not match that of previous
    /// aggregation jobs.
    #[tracing::instrument(
        name = "AggregationJobWriter::put_and_write",
        skip(batch_aggregation_shard_count, metrics, task_aggregation_counters, vdaf, tx, report_aggregations),
        err(level = Level::DEBUG),
    )]
    pub async fn put_and_write(
        task_id: TaskId,
        batch_aggregation_shard_count: u64,
        vdaf: &A,
        tx: &Transaction<'_>,
        inputs: AggregationJobWriterInputs<SEED_SIZE, B, A>,
        metrics: Option<AggregationJobWriterMetrics>,
        task_aggregation_counters: TaskAggregationCounter,
    ) -> Result<Vec<VerifyResp>, Error> {
        let mut writer = Self::new(
            task_id,
            batch_aggregation_shard_count,
            metrics,
            task_aggregation_counters,
        );

        writer.put(inputs)?;
        let agg_job_infos = writer.write_inner(vdaf, tx).await?;

        assert_eq!(
            agg_job_infos.len(),
            1,
            "write state should contain exactly one aggregation job",
        );
        // Unwrap safety: we just checked the length of the HashMap
        let (_, agg_job_info) = agg_job_infos.into_iter().next().unwrap();
        Ok(agg_job_info
            .report_aggregations
            .iter()
            .filter_map(|ra| ra.last_verify_resp().cloned())
            .collect())
    }

    /// Add an aggregation job to be written.
    ///
    /// # Panics
    ///
    /// Panics if the aggregation parameter of the aggregation job does not match that of previous
    /// aggregation jobs.
    pub fn put(
        &mut self,
        mut inputs: AggregationJobWriterInputs<SEED_SIZE, B, A>,
    ) -> Result<(), Error> {
        self.update_aggregation_parameter(inputs.aggregation_job.aggregation_parameter());

        report_aggregations.sort_unstable_by_key(|ra| ra.ord());

        // Compute batch identifiers first, since computing the batch identifier is fallible and
        // it's nicer to not have to unwind state modifications if we encounter an error.
        let batch_identifiers = report_aggregations
            .iter()
            .map(|ra| B::to_batch_identifier(aggregation_job.partial_batch_identifier(), ra.time()))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(batch_identifiers.len(), report_aggregations.len());

        // Modify our state to record this aggregation job. (starting here, failure is not allowed)
        let datastore_id = self.aggregation_job_datastore_id_counter.successor();

        for (idx, batch_identifier) in batch_identifiers.into_iter().enumerate() {
            self.by_batch_identifier_index
                .entry(batch_identifier)
                .or_default()
                .entry(datastore_id)
                .or_default()
                .push(idx);
        }

        self.aggregation_jobs.insert(
            datastore_id,
            AggregationJobWriterInputs {
                aggregation_job,
                report_aggregations,
            },
        );
        Ok(())
    }

    /// Writes all queued aggregation jobs to the datastore.
    ///
    /// Some report aggregations may turn out to be unaggregatable due to a concurrent collection
    /// operation (aggregation into a collected batch is not allowed). These report aggregations
    /// will be written with a `Failed(BatchCollected)` state.
    ///
    /// A map from aggregation job ID to the associated verification responses (if any) will be
    /// returned, along with aggregation counters indicating occurrences of aggregation-related
    /// events. In the case that a report aggregation was unaggregatable, these verification
    /// responses will be updated from the verification responses originally included in the given
    /// report aggregations.
    #[tracing::instrument(
        name = "AggregationJobWriter::write",
        skip(self, tx),
        err(level = Level::DEBUG),
    )]
    pub async fn write(self, vdaf: &A, tx: &Transaction<'_>) -> Result<usize, Error> {
        let written = self.write_inner(vdaf, tx).await?;
        Ok(written.len())
    }

    async fn write_inner(
        self,
        vdaf: &A,
        tx: &Transaction<'_>,
    ) -> Result<
        HashMap<AggregationJobDatastoreId, AggregationJobWriterInputs<SEED_SIZE, B, A, I>>,
        Error,
    > {
        let Self {
            task_id,
            batch_aggregation_shard_count,
            aggregation_parameter,
            mut aggregation_jobs,
            by_batch_identifier_index,
            metrics,
            mut task_aggregation_counters,
            ..
        } = self;

        // No aggregation parameter means no aggregation jobs to write and we can short-circuit.
        let aggregation_parameter = if let Some(ap) = aggregation_parameter {
            ap
        } else {
            return Ok(HashMap::new());
        };

        // Read & update state based on the aggregation jobs to be written. We will read batch
        // aggregations, then update aggregation jobs/report aggregations/batch aggregations based
        // on the state we read.
        // Read all relevant batch aggregations from the datastore.
        let batch_aggregation_ord = rng().random_range(0..batch_aggregation_shard_count);
        let mut batch_aggregations: HashMap<_, _> =
            try_join_all(by_batch_identifier_index.keys().map(|batch_identifier| {
                tx.get_batch_aggregation::<SEED_SIZE, B, A>(
                    vdaf,
                    &task_id,
                    batch_identifier,
                    &aggregation_parameter,
                    batch_aggregation_ord,
                )
            }))
            .await?
            .into_iter()
            .flatten()
            .map(|ba| (ba.batch_identifier().clone(), (Operation::Update, ba)))
            .collect();

        Self::fail_report_aggregations_for_collected_batches(
            &mut aggregation_jobs,
            &by_batch_identifier_index,
            &batch_aggregations,
        );
        Self::update_batch_aggregations_from_report_aggregations(
            task_id,
            aggregation_parameter.clone(),
            &mut aggregation_jobs,
            &by_batch_identifier_index,
            batch_aggregation_ord,
            &mut batch_aggregations,
            metrics.as_ref(),
            &mut task_aggregation_counters,
        )?;
        Self::update_aggregation_job_state_from_report_aggregations(&mut aggregation_jobs);
        Self::update_batch_aggregations_from_aggregation_jobs(
            task_id,
            aggregation_parameter,
            &mut aggregation_jobs,
            &by_batch_identifier_index,
            batch_aggregation_ord,
            &mut batch_aggregations,
        )?;

        // Write aggregation jobs, report aggregations, and batch aggregations back to the
        // datastore.
        let write_agg_jobs_future = try_join_all(aggregation_jobs.values().map(
            |AggregationJobWriterInputs {
                 aggregation_job,
                 report_aggregations,
             }| async move {
                I::write(tx, aggregation_job, report_aggregations.as_slice()).await
            },
        ));

        // Prevent deadlocks when inserting into shards by providing a deterministic order to shard
        // updates. Suppose two concurrent processes are attempting to update a batch aggregation.
        // We want to avoid this situation:
        //
        // A> BEGIN;
        // A> UPDATE batch_aggregations WHERE ord = 1 ... -- Row with ord 1 is locked for update.
        // B> BEGIN;
        // B> UPDATE batch_aggregations WHERE ord = 2 ... -- Row with ord 2 is locked for update.
        // A> UPDATE batch_aggregations WHERE ord = 2 ... -- A is now blocked waiting for B
        // to finish.
        // B> UPDATE batch_aggregations WHERE ord = 1 ... -- Kaboom!
        //
        // To avoid this, we sort by `batch_identifier` and `ord`.
        //
        // However, `try_join_all` executes futures concurrently thus there's no guarantee that the
        // order will be respected, so there remains the possibility of deadlock. This is rare--in
        // testing we have noticed that the probability of deadlock is drastically lower with a
        // sorted list than with an unsorted list.
        //
        // There could be changes in the `AggregationJobWriter`'s usage patterns or changes in the
        // tokio scheduler that cause this to regress, in which case the next possible solution is
        // to execute batch aggregation updates serially.
        let mut batch_aggregations: Vec<_> = batch_aggregations.values().collect();
        batch_aggregations.sort_unstable_by_key(|(_, ba)| (ba.batch_identifier(), ba.ord()));
        let write_batch_aggs_future =
            try_join_all(batch_aggregations.iter().map(|(op, ba)| async move {
                match op {
                    Operation::Put => tx.put_batch_aggregation(ba).await,
                    Operation::Update => tx.update_batch_aggregation(ba).await,
                }
            }));
        try_join!(write_agg_jobs_future, write_batch_aggs_future)?;

        Ok(aggregation_jobs)
    }

    /// Update report aggregations with failure states if they land in already-collected batches.
    /// Returns the set of report IDs which were found to be unwritable.
    fn fail_report_aggregations_for_collected_batches(
        aggregation_jobs: &mut HashMap<
            AggregationJobDatastoreId,
            AggregationJobWriterInputs<SEED_SIZE, B, A, I>,
        >,
        by_batch_identifier_index: &HashMap<
            B::BatchIdentifier,
            HashMap<AggregationJobDatastoreId, Vec<usize>>,
        >,
        batch_aggregations: &HashMap<
            B::BatchIdentifier,
            (Operation, BatchAggregation<SEED_SIZE, B, A>),
        >,
    ) {
        // Update in-memory state of report aggregations: any report aggregations applying to a
        // batch which is not still accepting aggregations (i.e. not in the Aggregating state)
        // instead fail with a BatchCollected error (unless they were already in an failed state).
        for (batch_identifier, by_aggregation_job_index) in by_batch_identifier_index {
            if batch_aggregations
                .get(batch_identifier)
                .map(|(_, b)| b.state().is_accepting_aggregations())
                .unwrap_or(true)
            {
                continue;
            }

            for (aggregation_job_id, report_aggregation_idxs) in by_aggregation_job_index {
                // If we are abandoning this aggregation job, don't modify any of the report
                // aggregations.
                //
                // Unwrap safety: index lookup.
                let aggregation_job = &aggregation_jobs
                    .get(aggregation_job_id)
                    .unwrap()
                    .aggregation_job;
                if aggregation_job.state().abandoned() {
                    continue;
                }

                for idx in report_aggregation_idxs {
                    // unwrap safety: index lookup
                    let report_aggregation = aggregation_jobs
                        .get_mut(aggregation_job_id)
                        .unwrap()
                        .report_aggregations
                        .get_mut(*idx)
                        .unwrap();
                    if report_aggregation.is_failed() {
                        continue;
                    }

                    *report_aggregation = report_aggregation
                        .clone()
                        .with_failure(ReportError::BatchCollected);
                }
            }
        }
    }

    /// Update batch aggregations to reflect the report aggregations that will be written.
    fn update_batch_aggregations_from_report_aggregations(
        task_id: TaskId,
        aggregation_parameter: A::AggregationParam,
        aggregation_jobs: &mut HashMap<
            AggregationJobDatastoreId,
            AggregationJobWriterInputs<SEED_SIZE, B, A, I>,
        >,
        by_batch_identifier_index: &HashMap<
            B::BatchIdentifier,
            HashMap<AggregationJobDatastoreId, Vec<usize>>,
        >,
        batch_aggregation_ord: u64,
        batch_aggregations: &mut HashMap<
            B::BatchIdentifier,
            (Operation, BatchAggregation<SEED_SIZE, B, A>),
        >,
        metrics: Option<&AggregationJobWriterMetrics>,
        task_aggregation_counters: &mut TaskAggregationCounter,
    ) -> Result<(), Error> {
        for (batch_identifier, by_aggregation_job_index) in by_batch_identifier_index {
            // Grab the batch aggregation we read for this batch identifier, or create a new empty
            // one to aggregate into.
            let (_, batch_aggregation) = batch_aggregations
                .entry(batch_identifier.clone())
                .or_insert_with(|| {
                    (
                        Operation::Put,
                        BatchAggregation::new(
                            task_id,
                            batch_identifier.clone(),
                            aggregation_parameter.clone(),
                            batch_aggregation_ord,
                            Interval::EMPTY,
                            BatchAggregationState::Aggregating {
                                aggregate_share: None,
                                report_count: 0,
                                checksum: ReportIdChecksum::default(),
                                aggregation_jobs_created: 0,
                                aggregation_jobs_terminated: 0,
                            },
                        ),
                    )
                });

            // Never update a batch aggregation which is no longer aggregating (because it has been
            // collected or scrubbed).
            if !batch_aggregation.state().is_accepting_aggregations() {
                continue;
            }

            for (aggregation_job_id, report_aggregation_idxs) in by_aggregation_job_index {
                // unwrap safety: index lookup
                let aggregation_job_info = aggregation_jobs.get_mut(aggregation_job_id).unwrap();

                // Update the batch aggregation based on the state of each finished report
                // aggregation.
                for ra_idx in report_aggregation_idxs {
                    // unwrap safety: index lookup
                    let report_aggregation = aggregation_job_info
                        .report_aggregations
                        .get_mut(*ra_idx)
                        .unwrap();

                    let mut is_finished = false;
                    let ra_batch_aggregation = BatchAggregation::new(
                        task_id,
                        batch_identifier.clone(),
                        aggregation_parameter.clone(),
                        batch_aggregation_ord,
                        Interval::minimal(*report_aggregation.time())?,
                        if let Some(output_share) = report_aggregation.is_finished() {
                            is_finished = true;
                            BatchAggregationState::Aggregating {
                                aggregate_share: Some(output_share.clone().into()),
                                report_count: 1,
                                checksum: ReportIdChecksum::for_report_id(
                                    report_aggregation.report_id(),
                                ),
                                aggregation_jobs_created: 0,
                                aggregation_jobs_terminated: 0,
                            }
                        } else {
                            BatchAggregationState::Aggregating {
                                aggregate_share: None,
                                report_count: 0,
                                checksum: ReportIdChecksum::default(),
                                aggregation_jobs_created: 0,
                                aggregation_jobs_terminated: 0,
                            }
                        },
                    );

                    match ra_batch_aggregation.merged_with(batch_aggregation) {
                        Ok(merged_batch_aggregation) => {
                            if is_finished {
                                task_aggregation_counters.increment_success();
                                if let Some(metrics) = &metrics {
                                    metrics.record();
                                }
                            }
                            *batch_aggregation = merged_batch_aggregation
                        }
                        Err(err) => {
                            warn!(
                                report_id = %report_aggregation.report_id(),
                                ?err,
                                "Couldn't update batch aggregation",
                            );
                            if let Some(metrics) = &metrics {
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", ACCUMULATE_FAILURE)]);
                            }
                            task_aggregation_counters
                                .increment_with_report_error(ReportError::VdafVerifyError);
                            *report_aggregation = report_aggregation
                                .clone()
                                .with_failure(ReportError::VdafVerifyError);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Update aggregation job states if all their report aggregations have reached a terminal
    /// state.
    fn update_aggregation_job_state_from_report_aggregations(
        aggregation_jobs: &mut HashMap<
            AggregationJobDatastoreId,
            AggregationJobWriterInputs<SEED_SIZE, B, A, I>,
        >,
    ) {
        // Update in-memory state of aggregation jobs: any aggregation jobs whose report
        // aggregations are all in a terminal state should be considered Finished (unless the
        // aggregation job was already in a terminal state).
        for AggregationJobWriterInputs {
            aggregation_job,
            report_aggregations,
        } in aggregation_jobs.values_mut()
        {
            if aggregation_job.state().terminal() {
                continue;
            }

            let helper_aggregation_job_id = *aggregation_job
                .dap_id()
                .expect("job transitioning to finished must have aggregation job ID assigned");

            if report_aggregations.iter().all(|ra| ra.is_terminal()) {
                *aggregation_job =
                    aggregation_job
                        .clone()
                        .with_state(AggregationJobState::Finished {
                            helper_aggregation_job_id,
                        });
            }
        }
    }

    /// Update batch aggregation state based on aggregation job state.
    fn update_batch_aggregations_from_aggregation_jobs(
        task_id: TaskId,
        aggregation_parameter: A::AggregationParam,
        aggregation_jobs: &mut HashMap<
            AggregationJobDatastoreId,
            AggregationJobWriterInputs<SEED_SIZE, B, A, I>,
        >,
        by_batch_identifier_index: &HashMap<
            B::BatchIdentifier,
            HashMap<AggregationJobDatastoreId, Vec<usize>>,
        >,
        batch_aggregation_ord: u64,
        batch_aggregations: &mut HashMap<
            B::BatchIdentifier,
            (Operation, BatchAggregation<SEED_SIZE, B, A>),
        >,
    ) -> Result<(), Error> {
        for (batch_identifier, by_aggregation_job_index) in by_batch_identifier_index {
            // Grab the batch aggregation we read for this batch identifier, or create a new empty
            // one to aggregate into.
            let (_, batch_aggregation) = batch_aggregations
                .entry(batch_identifier.clone())
                .or_insert_with(|| {
                    (
                        Operation::Put,
                        BatchAggregation::new(
                            task_id,
                            batch_identifier.clone(),
                            aggregation_parameter.clone(),
                            batch_aggregation_ord,
                            Interval::EMPTY,
                            BatchAggregationState::Aggregating {
                                aggregate_share: None,
                                report_count: 0,
                                checksum: ReportIdChecksum::default(),
                                aggregation_jobs_created: 0,
                                aggregation_jobs_terminated: 0,
                            },
                        ),
                    )
                });

            // Never update a batch aggregation which is no longer aggregating (because it has been
            // collected or scrubbed).
            if !batch_aggregation.state().is_accepting_aggregations() {
                continue;
            }

            for aggregation_job_id in by_aggregation_job_index.keys() {
                // Update the batch aggregation based on the aggregation job & the write type.
                // unwrap safety: index lookup
                I::update_batch_aggregation(
                    batch_aggregation,
                    &aggregation_jobs
                        .get(aggregation_job_id)
                        .unwrap()
                        .aggregation_job,
                )?;
            }
        }
        Ok(())
    }
}

/// Aggregation jobs and report aggregations input to an [`AggregationJobWriter`].
///
/// Implementations of this struct define supported pairs of aggregation job and report aggregation
/// representations, as well as specialized logic for writing them to the datastore.
///
/// For example, if we are creating a new row in the `aggregation_jobs` table, then we can't yet
/// know what [`AggregationJobDatastoreId`] will be assigned, so we would use
/// [`UnwrittenAggregationJob`]. But if we're updating a row that already exists, then we use an
/// [`AggregationJob`] value.
/// An aggregation job and its accompanying report aggregations.
#[derive(Clone)]
pub enum AggregationJobWriterInputs<
    const SEED_SIZE: usize,
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
> {
    LeaderCreate {
        aggregation_job: UnwrittenAggregationJob<SEED_SIZE, B, A>,
        report_aggregations: Vec<ReportAggregationMetadata>,
    },
    HelperCreate {
        aggregation_job: UnwrittenAggregationJob<SEED_SIZE, B, A>,
        report_aggregations: Vec<ReportAggregationMetadata>,
    },
    Update {
        aggregation_job: AggregationJob<SEED_SIZE, B, A>,
        report_aggregations: Vec<WritableReportAggregation<SEED_SIZE, A>>,
    },
}

impl<const SEED_SIZE: usize, B, A> AggregationJobWriterInputs<SEED_SIZE, B, A>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    async fn write<'a>(&self, tx: &Transaction<'_>) -> Result<(), Error> {
        match self {
            Self::LeaderCreate {
                aggregation_job,
                report_aggregations,
            } => {
                let job_id = tx.put_aggregation_job(aggregation_job).await?;

                // We must write the aggregation job first since report aggregation rows have a
                // foreign-key constraint on the related aggregation job existing. We could speed
                // things up for initial writes by switching to DEFERRED constraints:
                // https://www.postgresql.org/docs/current/sql-set-constraints.html
                try_join_all(
                    report_aggregations
                        .iter()
                        .map(|ra| tx.put_leader_report_aggregation(job_id, ra)),
                )
                .await?;

                // Scrub the reports we just created report aggregations for.
                // Report scrubbing must wait until after report aggregations have been created,
                // because they have a write-after-read antidependency on the report shares.
                try_join_all(
                    report_aggregations.iter().map(|ra| {
                        tx.scrub_client_report(aggregation_job.task_id(), ra.report_id())
                    }),
                )
                .await?;
            }
            Self::HelperCreate {
                aggregation_job,
                report_aggregations,
            } => todo!(),
            Self::Update {
                aggregation_job,
                report_aggregations,
            } => {
                try_join!(
                    tx.update_aggregation_job(aggregation_job),
                    try_join_all(
                        report_aggregations
                            .iter()
                            .map(|ra| tx.update_report_aggregation(&ra.report_aggregation)),
                    )
                )
                .await?
            }
        }

        Ok(())
    }

    fn update_batch_aggregation(
        &self,
        batch_aggregation: &mut BatchAggregation<SEED_SIZE, B, A>,
    ) -> Result<(), Error> {
        match self {
            // For new writes (inserts) of aggregation jobs in a non-terminal state, increment
            // aggregation_jobs_created.
            Self::LeaderCreate {
                aggregation_job, ..
            } => {
                if !aggregation_job.state().terminal() {
                    *batch_aggregation = BatchAggregation::new(
                        *batch_aggregation.task_id(),
                        batch_aggregation.batch_identifier().clone(),
                        batch_aggregation.aggregation_parameter().clone(),
                        batch_aggregation.ord(),
                        Interval::EMPTY,
                        BatchAggregationState::Aggregating {
                            aggregate_share: None,
                            report_count: 0,
                            checksum: ReportIdChecksum::default(),
                            aggregation_jobs_created: 1,
                            aggregation_jobs_terminated: 0,
                        },
                    )
                    .merged_with(batch_aggregation)?;
                }
            }
            // TODO(timg): same as leader create case?
            Self::HelperCreate {
                aggregation_job, ..
            } => todo!(),
            // For updates of aggregation jobs into a terminal state, increment
            // aggregation_jobs_terminated. (This is safe to do since we will not process a terminal
            // aggregation job again.)
            Self::Update {
                aggregation_job,
                report_aggregations,
            } => {
                if aggregation_job.state().terminal() {
                    *batch_aggregation = BatchAggregation::new(
                        *batch_aggregation.task_id(),
                        batch_aggregation.batch_identifier().clone(),
                        batch_aggregation.aggregation_parameter().clone(),
                        batch_aggregation.ord(),
                        Interval::EMPTY,
                        BatchAggregationState::Aggregating {
                            aggregate_share: None,
                            report_count: 0,
                            checksum: ReportIdChecksum::default(),
                            aggregation_jobs_created: 0,
                            aggregation_jobs_terminated: 1,
                        },
                    )
                    .merged_with(batch_aggregation)?;
                }
            }
        }

        Ok(())
    }
}

/// A report aggregation and possibly an output share.
///
/// We do not store individual report output shares in the `report_aggregations` table, preferring
/// instead to immediately accumulate them into a `batch_aggregations` row. For that reason,
/// `ReportAggregationState::Finished` does not include an `A::OutputShare`, and we instead define
/// this struct.
#[derive(Clone)]
pub struct WritableReportAggregation<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>> {
    report_aggregation: ReportAggregation<SEED_SIZE, A>,
    output_share: Option<A::OutputShare>,
}

impl<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>
    WritableReportAggregation<SEED_SIZE, A>
{
    /// Creates a new WritableReportAggregation.
    ///
    /// # Panics
    ///
    /// Panics if the report aggregation is Finished but no output share is provided, or if the
    /// report aggregation is not Finished but an output share is provided.
    pub fn new(
        report_aggregation: ReportAggregation<SEED_SIZE, A>,
        output_share: Option<A::OutputShare>,
    ) -> Self {
        assert!(
            output_share.is_some()
                == matches!(report_aggregation.state(), ReportAggregationState::Finished)
        );
        Self {
            report_aggregation,
            output_share,
        }
    }

    /// Retrieves the report aggregation to be written.
    pub fn report_aggregation(&self) -> &ReportAggregation<SEED_SIZE, A> {
        &self.report_aggregation
    }
}

/// Abstracts over representations of an aggregation job used in `AggregationJobWriterInputs`.
///
/// Implemented by [`AggregationJob`] (for updating existing jobs) and [`UnwrittenAggregationJob`]
/// (for inserting new jobs).
#[async_trait]
pub trait AggregationJobWrite<
    const SEED_SIZE: usize,
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
>: Clone + Debug
{
    fn dap_id(&self) -> Option<&AggregationJobId>;

    fn aggregation_parameter(&self) -> &A::AggregationParam;

    fn partial_batch_identifier(&self) -> &B::PartialBatchIdentifier;

    fn state(&self) -> &AggregationJobState;

    fn with_state(self, state: AggregationJobState) -> Self;
}

#[async_trait]
impl<const SEED_SIZE: usize, B, A> AggregationJobWrite<SEED_SIZE, B, A>
    for UnwrittenAggregationJob<SEED_SIZE, B, A>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    fn dap_id(&self) -> Option<&AggregationJobId> {
        self.dap_id()
    }

    fn aggregation_parameter(&self) -> &A::AggregationParam {
        self.aggregation_parameter()
    }

    fn partial_batch_identifier(&self) -> &B::PartialBatchIdentifier {
        self.partial_batch_identifier()
    }

    fn state(&self) -> &AggregationJobState {
        self.state()
    }

    fn with_state(self, state: AggregationJobState) -> Self {
        self.with_state(state)
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, B, A> AggregationJobWrite<SEED_SIZE, B, A>
    for AggregationJob<SEED_SIZE, B, A>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    fn dap_id(&self) -> Option<&AggregationJobId> {
        self.dap_id()
    }

    fn aggregation_parameter(&self) -> &A::AggregationParam {
        self.aggregation_parameter()
    }

    fn partial_batch_identifier(&self) -> &B::PartialBatchIdentifier {
        self.partial_batch_identifier()
    }

    fn state(&self) -> &AggregationJobState {
        self.state()
    }

    fn with_state(self, state: AggregationJobState) -> Self {
        self.with_state(state)
    }
}

/// Abstracts over multiple representations of a report aggregation.
///
/// See [`ReportAggregation`] and [`ReportAggregationMetadata`].
pub trait ReportAggregationUpdate<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>:
    Clone + Send + Sync
{
    /// Returns the order of this report aggregation in its aggregation job.
    fn ord(&self) -> u64;

    /// Returns the report ID associated with this report aggregation.
    fn report_id(&self) -> &ReportId;

    /// Returns the client timestamp associated with this report aggregation.
    fn time(&self) -> &Time;

    /// Returns whether this report aggregation is (successfully) finished; if so, returns a
    /// reference to the output share.
    fn is_finished(&self) -> Option<&A::OutputShare>;

    /// Returns whether this report aggregation is failed.
    fn is_failed(&self) -> bool;

    /// Returns a new report aggregation corresponding to this report aggregation updated to have
    /// the "Failed" state, with the given [`ReportError`].
    fn with_failure(self, report_error: ReportError) -> Self;

    /// Returns the last verification response from this report aggregation, if any.
    fn last_verify_resp(&self) -> Option<&VerifyResp>;

    /// Returns whether this report aggregation is in a terminal state ("Finished" or "Failed").
    fn is_terminal(&self) -> bool {
        self.is_finished().is_some() || self.is_failed()
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>> ReportAggregationUpdate<SEED_SIZE, A>
    for WritableReportAggregation<SEED_SIZE, A>
{
    fn ord(&self) -> u64 {
        self.report_aggregation.ord()
    }

    fn report_id(&self) -> &ReportId {
        self.report_aggregation.report_id()
    }

    fn time(&self) -> &Time {
        self.report_aggregation.time()
    }

    fn is_finished(&self) -> Option<&A::OutputShare> {
        self.output_share.as_ref()
    }

    fn is_failed(&self) -> bool {
        matches!(
            self.report_aggregation.state(),
            ReportAggregationState::Failed { .. }
        )
    }

    fn with_failure(self, report_error: ReportError) -> Self {
        let mut report_aggregation = self
            .report_aggregation
            .with_state(ReportAggregationState::Failed { report_error });

        // This check effectively checks if we are the Helper. (The Helper will always set
        // last_verify_resp for all non-failed report aggregations, and most failed report
        // aggregations [everything but ReportDropped].)
        if report_aggregation.last_verify_resp().is_some() {
            let report_id = *report_aggregation.report_id();
            report_aggregation = report_aggregation.with_last_verify_resp(Some(VerifyResp::new(
                report_id,
                VerifyStepResult::Reject(report_error),
            )));
        }

        Self {
            report_aggregation,
            output_share: None,
        }
    }

    /// Returns the last verification response from this report aggregation, if any.
    fn last_verify_resp(&self) -> Option<&VerifyResp> {
        self.report_aggregation.last_verify_resp()
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, A> ReportAggregationUpdate<SEED_SIZE, A> for ReportAggregationMetadata
where
    A: AsyncAggregator<SEED_SIZE>,
{
    fn ord(&self) -> u64 {
        self.ord()
    }

    fn report_id(&self) -> &ReportId {
        self.report_id()
    }

    fn time(&self) -> &Time {
        self.time()
    }

    fn is_finished(&self) -> Option<&A::OutputShare> {
        None
    }

    fn is_failed(&self) -> bool {
        matches!(self.state(), ReportAggregationMetadataState::Failed { .. })
    }

    fn with_failure(self, report_error: ReportError) -> Self {
        self.with_state(ReportAggregationMetadataState::Failed { report_error })
    }

    /// Returns the last verification response from this report aggregation, if any.
    fn last_verify_resp(&self) -> Option<&VerifyResp> {
        None
    }
}

/// Metrics for the aggregation job writer.
#[derive(Clone)]
pub struct AggregationJobWriterMetrics {
    pub vdaf_instance: VdafInstance,
    pub report_aggregation_success_counter: Counter<u64>,
    pub aggregate_step_failure_counter: Counter<u64>,
    pub aggregated_report_share_dimension_histogram: Histogram<u64>,
}

impl AggregationJobWriterMetrics {
    fn record(&self) {
        self.report_aggregation_success_counter.add(1, &[]);
        // Bucket written reports by the size of their encoded
        // measurement in field elements.
        match self.vdaf_instance {
            VdafInstance::Prio3Count => self
                .aggregated_report_share_dimension_histogram
                .record(1, &[KeyValue::new("type", "Prio3Count")]),

            VdafInstance::Prio3Sum { max_measurement } => {
                self.aggregated_report_share_dimension_histogram.record(
                    max_measurement
                        .checked_ilog2()
                        .map(|v| v as u64 + 1)
                        .unwrap_or(0),
                    &[KeyValue::new("type", "Prio3Sum")],
                )
            }

            VdafInstance::Prio3SumVec {
                length,
                max_measurement,
                ..
            } => self.aggregated_report_share_dimension_histogram.record(
                (length
                    * max_measurement
                        .checked_ilog2()
                        .map(|v| v as usize + 1)
                        .unwrap_or(0)) as u64,
                &[KeyValue::new("type", "Prio3SumVec")],
            ),

            VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                length,
                max_measurement,
                ..
            } => self.aggregated_report_share_dimension_histogram.record(
                (length
                    * max_measurement
                        .checked_ilog2()
                        .map(|v| v as usize + 1)
                        .unwrap_or(0)) as u64,
                &[KeyValue::new(
                    "type",
                    "Prio3SumVecField64MultiproofHmacSha256Aes128",
                )],
            ),

            VdafInstance::Prio3Histogram { length, .. } => {
                self.aggregated_report_share_dimension_histogram.record(
                    u64::try_from(length).unwrap_or(u64::MAX),
                    &[KeyValue::new("type", "Prio3Histogram")],
                )
            }

            #[cfg(feature = "test-util")]
            VdafInstance::Fake { rounds: _ }
            | VdafInstance::FakeFailsVerifyInit
            | VdafInstance::FakeFailsVerifyStep => self
                .aggregated_report_share_dimension_histogram
                .record(0, &[KeyValue::new("type", "Fake")]),
            _ => self
                .aggregated_report_share_dimension_histogram
                .record(0, &[KeyValue::new("type", "unknown")]),
        }
    }
}
