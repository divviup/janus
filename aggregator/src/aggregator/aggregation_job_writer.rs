//! In-memory accumulation of aggregation job (& report aggregation) writes, along with related
//! batch aggregation writes.

use std::{borrow::Cow, collections::HashMap, marker::PhantomData, sync::Arc};

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
    task::AggregatorTask,
};
use janus_core::{report_id::ReportIdChecksumExt as _, vdaf::VdafInstance};
use janus_messages::{
    Interval, ReportError, ReportId, ReportIdChecksum, Time, VerifyResp, VerifyStepResult,
};
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram},
};
use rand::{RngExt, rng};
use tokio::try_join;
use tracing::{Level, warn};

use crate::{Operation, metrics::aggregate_step_failure_types::ACCUMULATE_FAILURE};

/// Buffers pending writes to aggregation jobs and their report aggregations.
pub struct AggregationJobWriter<'a, const SEED_SIZE: usize, B, A, AJ>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
    AJ: WritableAggregationJob<SEED_SIZE, B, A>,
{
    task: Arc<AggregatorTask>,
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
        HashMap<AggregationJobDatastoreId, AggregationJobInfo<'a, SEED_SIZE, B, A, AJ>>,
    by_batch_identifier_index:
        HashMap<B::BatchIdentifier, HashMap<AggregationJobDatastoreId, Vec<usize>>>,
    metrics: Option<AggregationJobWriterMetrics>,
    task_aggregation_counters: TaskAggregationCounter,
}

/// Metrics for the aggregation job writer.
#[derive(Clone)]
pub struct AggregationJobWriterMetrics {
    pub report_aggregation_success_counter: Counter<u64>,
    pub aggregate_step_failure_counter: Counter<u64>,
    pub aggregated_report_share_dimension_histogram: Histogram<u64>,
}

#[allow(private_bounds)]
impl<'a, const SEED_SIZE: usize, B, A, AJ> AggregationJobWriter<'a, SEED_SIZE, B, A, AJ>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
    AJ: WritableAggregationJob<SEED_SIZE, B, A>,
{
    /// Create a new, empty aggregation job writer.
    pub fn new(
        task: Arc<AggregatorTask>,
        batch_aggregation_shard_count: u64,
        metrics: Option<AggregationJobWriterMetrics>,
        task_aggregation_counters: TaskAggregationCounter,
    ) -> Self {
        Self {
            task,
            batch_aggregation_shard_count,
            aggregation_parameter: None,
            aggregation_job_datastore_id_counter: AggregationJobDatastoreId::from(0),
            aggregation_jobs: HashMap::new(),
            by_batch_identifier_index: HashMap::new(),
            metrics,
            task_aggregation_counters,
        }
    }

    /// Returns true if this aggregation job writer does not contain any aggregation jobs.
    pub fn is_empty(&self) -> bool {
        self.aggregation_jobs.is_empty()
    }

    /// Returns the aggregation parameter of the aggregation jobs, if known.
    ///
    /// All aggregation jobs written at once must have the same aggregation parameter. If at least
    /// one aggregation job has been stored, then its aggregation parameter will be returned.
    /// Otherwise, this writer is empty, and `None` will be returned.
    fn aggregation_parameter(&self) -> &Option<A::AggregationParam> {
        &self.aggregation_parameter
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
    pub async fn put_and_write(
        &mut self,
        vdaf: &A,
        tx: &Transaction<'_>,
        aggregation_job: AJ,
        report_aggregations: Vec<AJ::WritableReportAggregation>,
    ) -> Result<Vec<VerifyResp>, Error> {
        self.put(aggregation_job, report_aggregations)?;
        let state = self.write_inner(vdaf, tx).await?;

        assert_eq!(
            state.by_aggregation_job.len(),
            1,
            "write state should contain exactly one aggregation job",
        );
        // Unwrap safety: we just checked the length of the HashMap
        let (_, agg_job_info) = state.by_aggregation_job.into_iter().next().unwrap();
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
        aggregation_job: AJ,
        mut report_aggregations: Vec<AJ::WritableReportAggregation>,
    ) -> Result<(), Error> {
        self.update_aggregation_parameter(aggregation_job.aggregation_parameter());

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
            AggregationJobInfo {
                aggregation_job: Cow::Owned(aggregation_job),
                report_aggregations: report_aggregations.into_iter().map(Cow::Owned).collect(),
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
    pub async fn write(&self, vdaf: &A, tx: &Transaction<'_>) -> Result<(), Error> {
        self.write_inner(vdaf, tx).await?;
        Ok(())
    }

    async fn write_inner(
        &self,
        vdaf: &A,
        tx: &Transaction<'_>,
    ) -> Result<WriteState<'_, SEED_SIZE, B, A, AJ>, Error> {
        // Read & update state based on the aggregation jobs to be written. We will read batch
        // aggregations, then update aggregation jobs/report aggregations/batch aggregations based
        // on the state we read.
        let mut state = WriteState::new(tx, vdaf, self).await?;
        state.fail_report_aggregations_for_collected_batches();
        state.update_batch_aggregations_from_report_aggregations()?;
        state.update_aggregation_job_state_from_report_aggregations();
        state.update_batch_aggregations_from_aggregation_jobs()?;

        // Write aggregation jobs, report aggregations, and batch aggregations back to the
        // datastore.
        let write_agg_jobs_future = try_join_all(state.by_aggregation_job.values().map(
            |AggregationJobInfo {
                 aggregation_job,
                 report_aggregations,
             }| async move { aggregation_job.write(tx, report_aggregations.iter()).await },
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
        let mut batch_aggregations: Vec<_> = state.batch_aggregations.values().collect();
        batch_aggregations.sort_unstable_by_key(|(_, ba)| (ba.batch_identifier(), ba.ord()));
        let write_batch_aggs_future =
            try_join_all(batch_aggregations.iter().map(|(op, ba)| async move {
                match op {
                    Operation::Put => tx.put_batch_aggregation(ba).await,
                    Operation::Update => tx.update_batch_aggregation(ba).await,
                }
            }));
        try_join!(write_agg_jobs_future, write_batch_aggs_future)?;

        Ok(state)
    }

    fn update_metrics<F: FnOnce(&AggregationJobWriterMetrics)>(&self, f: F) {
        if let Some(metrics) = self.metrics.as_ref() {
            f(metrics)
        }
    }
}

/// An aggregation job and its accompanying report aggregations.
///
/// The contents are wrapped in `Cow` because `WriteState` may rarely need to update the contents in
/// order to retry.
struct AggregationJobInfo<'a, const SEED_SIZE: usize, B, A, AJ>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
    AJ: WritableAggregationJob<SEED_SIZE, B, A>,
{
    aggregation_job: Cow<'a, AJ>,
    report_aggregations: Vec<Cow<'a, AJ::WritableReportAggregation>>,
}

/// Internal state of a write, abstracted over whether we are writing a new job or updating an
/// existing one.
///
/// This tracks in-memory adjustments to aggregation jobs and report aggregations behind
/// copy-on-write smart pointers, and maintains indices to efficiently look up aggregation jobs,
/// report aggregations, and batch aggregations.
struct WriteState<'a, const SEED_SIZE: usize, B, A, AJ>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
    AJ: WritableAggregationJob<SEED_SIZE, B, A>,
{
    writer: &'a AggregationJobWriter<'a, SEED_SIZE, B, A, AJ>,
    batch_aggregation_ord: u64,
    by_aggregation_job:
        &'a HashMap<AggregationJobDatastoreId, AggregationJobInfo<'a, SEED_SIZE, B, A, AJ>>,
    batch_aggregations: HashMap<B::BatchIdentifier, (Operation, BatchAggregation<SEED_SIZE, B, A>)>,
}

impl<'a, const SEED_SIZE: usize, B, A, AJ> WriteState<'a, SEED_SIZE, B, A, AJ>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
    AJ: WritableAggregationJob<SEED_SIZE, B, A>,
{
    /// Construct a new set of lookup maps and copy-on-write data structures, from a provided set of
    /// aggregation jobs and the current state of the datastore.
    pub async fn new(
        tx: &Transaction<'_>,
        vdaf: &A,
        writer: &'a AggregationJobWriter<'a, SEED_SIZE, B, A, AJ>,
    ) -> Result<Self, Error> {
        let aggregation_parameter = match writer.aggregation_parameter() {
            Some(aggregation_parameter) => aggregation_parameter,
            // None means no aggregation jobs to write, so we can safely short-circuit.
            None => {
                return Ok(Self {
                    writer,
                    batch_aggregation_ord: 0,
                    by_aggregation_job: HashMap::default(),
                    batch_aggregations: HashMap::default(),
                });
            }
        };

        // Create a copy-on-write instance of our state to allow efficient imperative updates with
        // the possibility of needing to retry the entire write. (Copy-on-write is used here as
        // modifying state requires cloning it to permit retry; but the common case is that most
        // pieces of state will not be modified, so using CoW avoids the cost of cloning.)
        let by_aggregation_job = writer.aggregation_jobs;

        // Read all relevant batch aggregations from the datastore.
        let batch_aggregation_ord = rng().random_range(0..writer.batch_aggregation_shard_count);
        let batch_aggregations = try_join_all(writer.by_batch_identifier_index.keys().map(
            |batch_identifier| {
                tx.get_batch_aggregation::<SEED_SIZE, B, A>(
                    vdaf,
                    writer.task.id(),
                    batch_identifier,
                    aggregation_parameter,
                    batch_aggregation_ord,
                )
            },
        ))
        .await?;

        let batch_aggregations: HashMap<_, _> = batch_aggregations
            .into_iter()
            .flatten()
            .map(|ba| (ba.batch_identifier().clone(), (Operation::Update, ba)))
            .collect();

        Ok(Self {
            writer,
            batch_aggregation_ord,
            by_aggregation_job,
            batch_aggregations,
        })
    }

    /// Update report aggregations with failure states if they land in already-collected batches.
    /// Returns the set of report IDs which were found to be unwritable.
    fn fail_report_aggregations_for_collected_batches(&mut self) {
        // Update in-memory state of report aggregations: any report aggregations applying to a
        // batch which is not still accepting aggregations (i.e. not in the Aggregating state)
        // instead fail with a BatchCollected error (unless they were already in an failed state).
        for (batch_identifier, by_aggregation_job_index) in &self.writer.by_batch_identifier_index {
            if self
                .batch_aggregations
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
                let aggregation_job = &self
                    .by_aggregation_job
                    .get(aggregation_job_id)
                    .unwrap()
                    .aggregation_job;
                if aggregation_job.state().abandoned() {
                    continue;
                }

                for idx in report_aggregation_idxs {
                    // unwrap safety: index lookup
                    let report_aggregation = self
                        .by_aggregation_job
                        .get_mut(aggregation_job_id)
                        .unwrap()
                        .report_aggregations
                        .get_mut(*idx)
                        .unwrap();
                    if report_aggregation.is_failed() {
                        continue;
                    }

                    *report_aggregation.to_mut() = report_aggregation
                        .as_ref()
                        .clone()
                        .with_failure(ReportError::BatchCollected);
                }
            }
        }
    }

    /// Update batch aggregations to reflect the report aggregations that will be written.
    fn update_batch_aggregations_from_report_aggregations(&mut self) -> Result<(), Error> {
        let aggregation_parameter = match self.writer.aggregation_parameter() {
            Some(aggregation_parameter) => aggregation_parameter,
            // None means there are no aggregation jobs to write, so we can safely short-circuit.
            None => return Ok(()),
        };

        for (batch_identifier, by_aggregation_job_index) in &self.writer.by_batch_identifier_index {
            // Grab the batch aggregation we read for this batch identifier, or create a new empty
            // one to aggregate into.
            let (_, batch_aggregation) = self
                .batch_aggregations
                .entry(batch_identifier.clone())
                .or_insert_with(|| {
                    (
                        Operation::Put,
                        BatchAggregation::new(
                            *self.writer.task.id(),
                            batch_identifier.clone(),
                            aggregation_parameter.clone(),
                            self.batch_aggregation_ord,
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
                let aggregation_job_info =
                    self.by_aggregation_job.get_mut(aggregation_job_id).unwrap();

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
                        *self.writer.task.id(),
                        batch_identifier.clone(),
                        aggregation_parameter.clone(),
                        self.batch_aggregation_ord,
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
                                self.writer.task_aggregation_counters.increment_success();
                                self.writer.update_metrics(|metrics| {
                                    metrics.report_aggregation_success_counter.add(1, &[]);

                                    // Bucket written reports by the size of their encoded
                                    // measurement in field elements.
                                    use VdafInstance::*;
                                    match self.writer.task.vdaf() {
                                        Prio3Count => metrics
                                            .aggregated_report_share_dimension_histogram
                                            .record(1, &[KeyValue::new("type", "Prio3Count")]),

                                        Prio3Sum { max_measurement } => metrics
                                            .aggregated_report_share_dimension_histogram
                                            .record(
                                                max_measurement
                                                    .checked_ilog2()
                                                    .map(|v| v as u64 + 1)
                                                    .unwrap_or(0),
                                                &[KeyValue::new("type", "Prio3Sum")],
                                            ),

                                        Prio3SumVec {
                                            length,
                                            max_measurement,
                                            ..
                                        } => metrics
                                            .aggregated_report_share_dimension_histogram
                                            .record(
                                                (length
                                                    * max_measurement
                                                        .checked_ilog2()
                                                        .map(|v| v as usize + 1)
                                                        .unwrap_or(0))
                                                    as u64,
                                                &[KeyValue::new("type", "Prio3SumVec")],
                                            ),

                                        Prio3SumVecField64MultiproofHmacSha256Aes128 {
                                            length,
                                            max_measurement,
                                            ..
                                        } => metrics
                                            .aggregated_report_share_dimension_histogram
                                            .record(
                                                (length
                                                    * max_measurement
                                                        .checked_ilog2()
                                                        .map(|v| v as usize + 1)
                                                        .unwrap_or(0))
                                                    as u64,
                                                &[KeyValue::new(
                                                    "type",
                                                    "Prio3SumVecField64MultiproofHmacSha256Aes128",
                                                )],
                                            ),

                                        Prio3Histogram { length, .. } => metrics
                                            .aggregated_report_share_dimension_histogram
                                            .record(
                                                u64::try_from(*length).unwrap_or(u64::MAX),
                                                &[KeyValue::new("type", "Prio3Histogram")],
                                            ),

                                        #[cfg(feature = "test-util")]
                                        Fake { rounds: _ }
                                        | FakeFailsVerifyInit
                                        | FakeFailsVerifyStep => metrics
                                            .aggregated_report_share_dimension_histogram
                                            .record(0, &[KeyValue::new("type", "Fake")]),
                                        _ => metrics
                                            .aggregated_report_share_dimension_histogram
                                            .record(0, &[KeyValue::new("type", "unknown")]),
                                    }
                                });
                            }
                            *batch_aggregation = merged_batch_aggregation
                        }
                        Err(err) => {
                            warn!(
                                report_id = %report_aggregation.report_id(),
                                ?err,
                                "Couldn't update batch aggregation",
                            );
                            self.writer.update_metrics(|metrics| {
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", ACCUMULATE_FAILURE)])
                            });
                            self.writer
                                .task_aggregation_counters
                                .increment_with_report_error(ReportError::VdafVerifyError);
                            *report_aggregation.to_mut() = report_aggregation
                                .as_ref()
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
    fn update_aggregation_job_state_from_report_aggregations(&mut self) {
        // Update in-memory state of aggregation jobs: any aggregation jobs whose report
        // aggregations are all in a terminal state should be considered Finished (unless the
        // aggregation job was already in a terminal state).
        for AggregationJobInfo {
            aggregation_job,
            report_aggregations,
        } in self.by_aggregation_job.values_mut()
        {
            if aggregation_job.state().terminal() {
                continue;
            }

            let helper_aggregation_job_id = *aggregation_job
                .dap_id()
                .expect("job transitioning to finished must have aggregation job ID assigned");

            if report_aggregations.iter().all(|ra| ra.is_terminal()) {
                *aggregation_job.to_mut() =
                    aggregation_job
                        .as_ref()
                        .clone()
                        .with_state(AggregationJobState::Finished {
                            helper_aggregation_job_id,
                        });
            }
        }
    }

    /// Update batch aggregation state based on aggregation job state.
    fn update_batch_aggregations_from_aggregation_jobs(&mut self) -> Result<(), Error> {
        let aggregation_parameter = match self.writer.aggregation_parameter() {
            Some(aggregation_parameter) => aggregation_parameter,
            // None means there are no aggregation jobs to write, so we can safely short-circuit.
            None => return Ok(()),
        };

        for (batch_identifier, by_aggregation_job_index) in &self.writer.by_batch_identifier_index {
            // Grab the batch aggregation we read for this batch identifier, or create a new empty
            // one to aggregate into.
            let (_, batch_aggregation) = self
                .batch_aggregations
                .entry(batch_identifier.clone())
                .or_insert_with(|| {
                    (
                        Operation::Put,
                        BatchAggregation::new(
                            *self.writer.task.id(),
                            batch_identifier.clone(),
                            aggregation_parameter.clone(),
                            self.batch_aggregation_ord,
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
                let aggregation_job = self
                    .by_aggregation_job
                    .get(aggregation_job_id)
                    .unwrap()
                    .aggregation_job
                    .as_ref();
                WT::update_batch_aggregation_for_agg_job(batch_aggregation, aggregation_job)?;
            }
        }
        Ok(())
    }
}

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

/// Abstracts over multiple representations of an aggregation job.
///
/// Implemented by [`AggregationJob`] (for updating existing jobs) and [`UnwrittenAggregationJob`]
/// (for inserting new jobs).
#[async_trait]
pub trait WritableAggregationJob<
    const SEED_SIZE: usize,
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
>: Clone
{
    type WritableReportAggregation: ReportAggregationUpdate<SEED_SIZE, A>;

    fn dap_id(&self) -> AggregationJobId;

    fn aggregation_parameter(&self) -> &A::AggregationParam;

    fn partial_batch_identifier(&self) -> &B::PartialBatchIdentifier;

    fn state(&self) -> &AggregationJobState;

    async fn write<RA: AsRef<Self::WritableReportAggregation>>(
        &self,
        tx: &Transaction<'_>,
        report_aggregations: impl Iterator<Item = RA> + Send + Sync,
    ) -> Result<(), Error>;

    async fn update_batch_aggregation(
        &self,
        batch_aggregation: &mut BatchAggregation<SEED_SIZE, B, A>,
    ) -> Result<(), Error>;
}

#[async_trait]
impl<const SEED_SIZE: usize, B, A> WritableAggregationJob<SEED_SIZE, B, A>
    for UnwrittenAggregationJob<B::PartialBatchIdentifier, A::AggregationParam>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    type WritableReportAggregation = ReportAggregationMetadata;

    fn dap_id(&self) -> AggregationJobId {
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

    async fn write<RA: AsRef<ReportAggregationMetadata>>(
        &self,
        tx: &Transaction<'_>,
        report_aggregations: impl Iterator<Item = RA> + Send + Sync,
    ) -> Result<(), Error> {
        // These operations must occur serially since report aggregation rows have a
        // foreign-key constraint on the related aggregation job existing. We could
        // speed things up for initial writes by switching to DEFERRED constraints:
        // https://www.postgresql.org/docs/current/sql-set-constraints.html
        let job_id = tx.put_aggregation_job(self).await?;
        try_join_all(
            report_aggregations.map(|ra| tx.put_leader_report_aggregation(job_id, ra.as_ref())),
        )
        .await?;
        Ok(())
    }

    async fn update_batch_aggregation(
        &self,
        batch_aggregation: &mut BatchAggregation<SEED_SIZE, B, A>,
    ) -> Result<(), Error> {
        // For new writes (inserts) of aggregation jobs in a non-terminal state, increment
        // aggregation_jobs_created.
        if !self.state().terminal() {
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
        Ok(())
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, B, A> WritableAggregationJob<SEED_SIZE, B, A>
    for AggregationJob<SEED_SIZE, B, A>
where
    B: AccumulableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    type WritableReportAggregation = WritableReportAggregation<SEED_SIZE, A>;

    fn dap_id(&self) -> AggregationJobId {
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

    async fn write<RA: AsRef<WritableReportAggregation<SEED_SIZE, A>>>(
        &self,
        tx: &Transaction<'_>,
        report_aggregations: impl Iterator<Item = RA> + Send + Sync,
    ) -> Result<(), Error> {
        try_join!(
            tx.update_aggregation_job(self),
            try_join_all(
                report_aggregations
                    .map(|ra| tx.update_report_aggregation(&ra.as_ref().report_aggregation)),
            )
        )?;
        Ok(())
    }

    async fn update_batch_aggregation(
        &self,
        batch_aggregation: &mut BatchAggregation<SEED_SIZE, B, A>,
    ) -> Result<(), Error> {
        // For updates of aggregation jobs into a terminal state, increment
        // aggregation_jobs_terminated. (This is safe to do since we will not process a terminal
        // aggregation job again.)
        if self.state().terminal() {
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
        Ok(())
    }
}

/// Abstracts over multiple representations of a report aggregation.
///
/// See [`ReportAggregation`] and [`ReportAggregationMetadata`].
pub trait ReportAggregationUpdate<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>:
    Clone + Send + Sync
{
    type Borrowed: ReportAggregationUpdate<SEED_SIZE, A>;

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

    /// Returns a borrowed `Cow` referring to this report aggregation.
    fn borrow(&self) -> Cow<'_, Self::Borrowed>;

    /// Returns whether this report aggregation is in a terminal state ("Finished" or "Failed").
    fn is_terminal(&self) -> bool {
        self.is_finished().is_some() || self.is_failed()
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>> ReportAggregationUpdate<SEED_SIZE, A>
    for WritableReportAggregation<SEED_SIZE, A>
{
    type Borrowed = Self;

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

    fn borrow(&self) -> Cow<'_, Self::Borrowed> {
        Cow::Borrowed(self)
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, A> ReportAggregationUpdate<SEED_SIZE, A> for ReportAggregationMetadata
where
    A: AsyncAggregator<SEED_SIZE>,
{
    type Borrowed = Self;

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

    fn borrow(&self) -> Cow<'_, Self::Borrowed> {
        Cow::Borrowed(self)
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, A, RA> ReportAggregationUpdate<SEED_SIZE, A> for Cow<'_, RA>
where
    A: AsyncAggregator<SEED_SIZE>,
    RA: ReportAggregationUpdate<SEED_SIZE, A>,
{
    // All methods are implemented as a fallthrough to the implementation in `RA`.
    type Borrowed = RA::Borrowed;

    fn ord(&self) -> u64 {
        self.as_ref().ord()
    }

    fn report_id(&self) -> &ReportId {
        self.as_ref().report_id()
    }

    fn time(&self) -> &Time {
        self.as_ref().time()
    }

    fn is_finished(&self) -> Option<&A::OutputShare> {
        self.as_ref().is_finished()
    }

    fn is_failed(&self) -> bool {
        self.as_ref().is_failed()
    }

    fn with_failure(self, report_error: ReportError) -> Self {
        // Since `with_failure` consumes the caller, we must own the CoW.
        Self::Owned(self.into_owned().with_failure(report_error))
    }

    /// Returns the last verification response from this report aggregation, if any.
    fn last_verify_resp(&self) -> Option<&VerifyResp> {
        self.as_ref().last_verify_resp()
    }

    fn borrow(&self) -> Cow<'_, RA::Borrowed> {
        self.as_ref().borrow()
    }
}
