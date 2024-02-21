//! In-memory accumulation of aggregation job (& report aggregation) updates.

use crate::{aggregator::query_type::CollectableQueryType, Operation};
use anyhow::anyhow;
use async_trait::async_trait;
use futures::{future::try_join_all, TryFutureExt};
use janus_aggregator_core::{
    datastore::{
        models::{
            AggregationJob, AggregationJobState, Batch, BatchState, CollectionJobState,
            ReportAggregation, ReportAggregationMetadata, ReportAggregationMetadataState,
            ReportAggregationState,
        },
        Error, Transaction,
    },
    task::AggregatorTask,
};
use janus_core::time::{Clock, IntervalExt};
use janus_messages::{AggregationJobId, Interval, PrepareError, ReportId, Time};
use prio::{codec::Encode, vdaf};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::try_join;
use tracing::{debug, error};

/// Contains logic used to write new aggregation jobs. It is used only by the leader.
pub struct NewAggregationJobWriter<
    const SEED_SIZE: usize,
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    updates: AggregationJobUpdates<SEED_SIZE, Q, A, ReportAggregationMetadata>,
}

impl<const SEED_SIZE: usize, Q, A> NewAggregationJobWriter<SEED_SIZE, Q, A>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    A::AggregationParam: PartialEq + Eq,
    A::PrepareState: Encode,
{
    /// Creates a new, empty aggregation job writer.
    pub fn new(task: Arc<AggregatorTask>) -> Self {
        Self {
            updates: AggregationJobUpdates::new(task),
        }
    }

    /// Returns true if this aggregation job writer does not contain any aggregation jobs.
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    /// Queues a new aggregation job to be written to the datastore. Nothing is actually written
    /// until [`NewAggregationJobWriter::write`] is called.
    pub fn put(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregationMetadata>,
    ) -> Result<(), Error> {
        self.updates.add(aggregation_job, report_aggregations)
    }

    /// Writes all queued aggregation jobs to the datastore.
    ///
    /// Some report aggregations may turn out to be unaggregatable due to a concurrent collection
    /// operation (aggregation into a collected batch is not allowed). These report aggregations
    /// will be written with a `Failed(BatchCollected)` state, and the associated report IDs will be
    /// returned.
    pub async fn write<'a, C: Clock>(
        &self,
        tx: &Transaction<'_, C>,
        vdaf: Arc<A>,
    ) -> Result<(), Error>
    where
        A: 'a,
    {
        self.updates
            .write(tx, vdaf, NewAggregationJobBatchUpdate)
            .await?;
        Ok(())
    }
}

/// This holds a flag and a callback used internally by [`AggregationJobUpdates`] when updating
/// batches, and is specific to creation of new aggregation jobs.
struct NewAggregationJobBatchUpdate;

impl BatchUpdateCallback for NewAggregationJobBatchUpdate {
    fn update_batch<'a, const SEED_SIZE: usize, Q, A, RA>(
        &self,
        batch: Batch<SEED_SIZE, Q, A>,
        aggregation_jobs: impl Iterator<
            Item = (
                &'a AggregationJob<SEED_SIZE, Q, A>,
                &'a [Cow<'a, RA>],
                &'a [usize],
            ),
        >,
    ) -> Result<Batch<SEED_SIZE, Q, A>, Error>
    where
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'a,
        RA: ReportAggregationUpdate + Clone + 'a,
    {
        // Increment outstanding job count by the number of new, incomplete aggregation jobs we are
        // writing. Update the time interval too.
        let mut outstanding_aggregation_jobs = batch.outstanding_aggregation_jobs();
        let mut client_timestamp_interval = *batch.client_timestamp_interval();
        for (agg_job, report_aggs, report_aggregation_ords) in aggregation_jobs {
            if let AggregationJobState::InProgress = agg_job.state() {
                outstanding_aggregation_jobs += 1;
            }
            update_client_timestamp_interval(
                &mut client_timestamp_interval,
                report_aggs,
                report_aggregation_ords,
            )?;
        }
        Ok(batch
            .with_outstanding_aggregation_jobs(outstanding_aggregation_jobs)
            .with_client_timestamp_interval(client_timestamp_interval))
    }

    fn creating_aggregation_jobs(&self) -> bool {
        true
    }
}

/// Contains logic used to write updates to aggregation jobs. It is used only by the leader.
pub struct UpdatedAggregationJobWriter<
    const SEED_SIZE: usize,
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    updates: AggregationJobUpdates<SEED_SIZE, Q, A, ReportAggregation<SEED_SIZE, A>>,
}

impl<const SEED_SIZE: usize, Q, A> UpdatedAggregationJobWriter<SEED_SIZE, Q, A>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    A::AggregationParam: PartialEq + Eq,
    A::PublicShare: Sync,
    A::InputShare: Sync,
    A::PrepareMessage: Sync,
    A::PrepareState: Encode + Sync,
{
    /// Creates a new, empty aggregation job writer.
    pub fn new(task: Arc<AggregatorTask>) -> Self {
        Self {
            updates: AggregationJobUpdates::new(task),
        }
    }

    /// Returns whether this aggregation job writer does not contain any aggregation jobs.
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    /// Queues an update to an aggregation job to be written to the datastore. Nothing is actually
    /// written until [`UpdatedAggregationJobWriter::write`] is called.
    pub fn update(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) -> Result<(), Error> {
        self.updates.add(aggregation_job, report_aggregations)
    }

    /// Writes all queued aggregation jobs to the datastore.
    ///
    /// Some report aggregations may turn out to be unaggregatable due to a concurrent collection
    /// operation (aggregation into a collected batch is not allowed). These report aggregations
    /// will be written with a `Failed(BatchCollected)` state, and the associated report IDs will be
    /// returned.
    pub async fn write<C: Clock>(
        &self,
        tx: &Transaction<'_, C>,
        vdaf: Arc<A>,
    ) -> Result<HashSet<ReportId>, Error> {
        self.updates
            .write(tx, vdaf, UpdatedAggregationJobBatchUpdate)
            .await
    }
}

/// This holds a flag and a callback used internally by [`AggregationJobUpdates`] when updating
/// batches, and is specific to updates to existing aggregation jobs.
struct UpdatedAggregationJobBatchUpdate;

impl BatchUpdateCallback for UpdatedAggregationJobBatchUpdate {
    fn update_batch<'a, const SEED_SIZE: usize, Q, A, RA>(
        &self,
        batch: Batch<SEED_SIZE, Q, A>,
        aggregation_jobs: impl Iterator<
            Item = (
                &'a AggregationJob<SEED_SIZE, Q, A>,
                &'a [Cow<'a, RA>],
                &'a [usize],
            ),
        >,
    ) -> Result<Batch<SEED_SIZE, Q, A>, Error>
    where
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'a,
        RA: ReportAggregationUpdate + Clone + 'a,
    {
        // Decrement outstanding job count by the number of updated, complete aggregation jobs we
        // are writing. (We assume any update to a terminal state is the first time we have updated
        // to a terminal state, as the system does not touch aggregation jobs once they have reached
        // a terminal state, and it would add code complexity and runtime cost to determine if we
        // are in a repeated-terminal-write case.)
        //
        // Note that it is not necessary to update the client timestamp interval, as that was
        // already done when creating the aggregation job previously.
        let mut outstanding_aggregation_jobs = batch.outstanding_aggregation_jobs();
        for (agg_job, _report_aggs, _report_aggregation_ords) in aggregation_jobs {
            if !matches!(agg_job.state(), AggregationJobState::InProgress) {
                outstanding_aggregation_jobs -= 1;
            }
        }
        Ok(batch.with_outstanding_aggregation_jobs(outstanding_aggregation_jobs))
    }

    fn creating_aggregation_jobs(&self) -> bool {
        false
    }
}

/// Expands a client timestamp interval as necessary to include a set of report aggregations.
///
/// This takes a slice of report aggregations, and a slice of offsets within that list. Only those
/// report aggregations pointed to by the offsets are considered when updating the client timestamp
/// interval.
///
/// # Panics
///
/// This will panic if any offset points outside the bounds of the slice of report aggregations.
fn update_client_timestamp_interval<RA>(
    client_timestamp_interval: &mut Interval,
    report_aggregations: &[Cow<'_, RA>],
    report_aggregation_ords: &[usize],
) -> Result<(), janus_messages::Error>
where
    RA: ReportAggregationUpdate + Clone,
{
    for ra_ord in report_aggregation_ords {
        // unwrap safety: index lookup
        let report_aggregation = report_aggregations.get(*ra_ord).unwrap();
        *client_timestamp_interval =
            client_timestamp_interval.merged_with(report_aggregation.time())?;
    }
    Ok(())
}

/// Buffers pending updates to aggregation jobs and their report aggregations. Generic storage and
/// logic for both [`NewAggregationJobWriter`] and [`UpdatedAggregationJobWriter`].
struct AggregationJobUpdates<const SEED_SIZE: usize, Q, A, RA>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
{
    task: Arc<AggregatorTask>,
    aggregation_parameter: Option<A::AggregationParam>,
    aggregation_jobs: HashMap<AggregationJobId, AggregationJobInfo<SEED_SIZE, Q, A, RA>>,
    by_batch_identifier_index: HashMap<Q::BatchIdentifier, HashMap<AggregationJobId, Vec<usize>>>,
}

impl<const SEED_SIZE: usize, A, Q, RA> AggregationJobUpdates<SEED_SIZE, Q, A, RA>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
    A::AggregationParam: PartialEq + Eq,
    RA: ReportAggregationUpdate + Clone,
{
    /// Create a new, empty set of aggregation job updates.
    fn new(task: Arc<AggregatorTask>) -> Self {
        Self {
            task,
            aggregation_parameter: None,
            aggregation_jobs: HashMap::new(),
            by_batch_identifier_index: HashMap::new(),
        }
    }

    /// Check if this set of updates is empty.
    fn is_empty(&self) -> bool {
        self.aggregation_jobs.is_empty()
    }

    /// Returns the aggregation parameter of the aggregation jobs, if known.
    ///
    /// All aggregation jobs updated at once must have the same aggregation parameter. If at least
    /// one aggregation job update has been stored, then its aggregation parameter will be returned.
    /// Otherwise, if this set of updates is empty, `None` will be returned.
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

    /// Add a new or updated aggregation and its report aggregations.
    fn add(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<RA>,
    ) -> Result<(), Error> {
        self.update_aggregation_parameter(aggregation_job.aggregation_parameter());

        // Compute batch identifiers first, since computing the batch identifier is fallible and
        // it's nicer to not have to unwind state modifications if we encounter an error.
        let batch_identifiers = report_aggregations
            .iter()
            .map(|ra| {
                Q::to_batch_identifier(
                    &self.task,
                    aggregation_job.partial_batch_identifier(),
                    ra.time(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(batch_identifiers.len(), report_aggregations.len());

        // Modify our state to record this aggregation job. (starting here, failure is not allowed)
        for (ord, batch_identifier) in batch_identifiers.into_iter().enumerate() {
            self.by_batch_identifier_index
                .entry(batch_identifier)
                .or_default()
                .entry(*aggregation_job.id())
                .or_default()
                .push(ord);
        }

        self.aggregation_jobs.insert(
            *aggregation_job.id(),
            AggregationJobInfo {
                aggregation_job,
                report_aggregations,
            },
        );
        Ok(())
    }

    /// Writes all queued aggregation job updates to the datastore. Returns report IDs of reports in
    /// batches that were already collected.
    async fn write<C>(
        &self,
        tx: &Transaction<'_, C>,
        vdaf: Arc<A>,
        batch_update_callback: impl BatchUpdateCallback,
    ) -> Result<HashSet<ReportId>, Error>
    where
        C: Clock,
        A: Send + Sync,
        A::AggregationParam: PartialEq + Eq,
        A::PrepareState: Encode,
    {
        let aggregation_parameter = if let Some(agg_param) = self.aggregation_parameter().as_ref() {
            agg_param
        } else {
            return Ok(HashSet::new()); // None means there is nothing to write.
        };

        let mut indexed =
            IndexedAggregationJobUpdates::new(tx, self, aggregation_parameter).await?;

        indexed.fail_collected_report_aggregations();

        indexed.update_aggregation_job_state_from_ra_states();

        let creating_aggregation_jobs = batch_update_callback.creating_aggregation_jobs();
        indexed.update_batches(batch_update_callback, tx.clock(), creating_aggregation_jobs)?;

        // Write batches, aggregation jobs, and report aggregations.
        let write_batches_future = try_join_all(indexed.batches.values().map(
            |(batch_op, batch)| async move {
                match (creating_aggregation_jobs, batch_op) {
                    (true, Operation::Put) => {
                        let rslt = tx.put_batch(batch).await;
                        if matches!(rslt, Err(Error::MutationTargetAlreadyExists)) {
                            // This codepath can be taken due to a quirk of how the Repeatable Read
                            // isolation level works. It cannot occur at the Serializable isolation
                            // level.
                            //
                            // For this codepath to be taken, two writers must concurrently choose
                            // to write the same batch (by task ID, batch ID, and aggregation
                            // parameter), and this batch must not already exist in the datastore.
                            //
                            // Both writers will receive `None` from the `get_batch` call, and then
                            // both will try to `put_batch`. One of the writers will succeed. The
                            // other will fail with a unique constraint violation on (task_id,
                            // batch_identifier, aggregation_param), since unique constraints are
                            // still enforced even in the presence of snapshot isolation. This
                            // unique constraint will be translated to a MutationTargetAlreadyExists
                            // error.
                            //
                            // The failing writer, in this case, can't do anything about this
                            // problem while in its current transaction: further attempts to read
                            // the batch will continue to return `None` (since all reads in the same
                            // transaction are from the same snapshot), so it can't update the
                            // now-written batch. All it can do is give up on this transaction and
                            // try again, by calling `retry` and returning an error.
                            tx.retry();
                        }
                        rslt
                    }
                    (_, Operation::Update) => tx.update_batch(batch).await,
                    (false, Operation::Put) => panic!(
                        "Unexpectedly missing batch while updating existing aggregation jobs"
                    ),
                }
            },
        ));
        let write_agg_jobs_future = try_join_all(indexed.by_aggregation_job.values().map(
            |CowAggregationJobInfo {
                 aggregation_job,
                 report_aggregations,
             }| async move {
                if creating_aggregation_jobs {
                    // These operations must occur serially since report aggregation rows have a
                    // foreign-key constraint on the related aggregation job existing. We could
                    // speed things up for initial writes by switching to DEFERRED constraints:
                    // https://www.postgresql.org/docs/current/sql-set-constraints.html
                    tx.put_aggregation_job(aggregation_job).await?;
                    try_join_all(report_aggregations.iter().map(|ra| ra.write_new(tx))).await?;
                } else {
                    try_join!(
                        tx.update_aggregation_job(aggregation_job),
                        try_join_all(report_aggregations.iter().map(|ra| ra.write_update(tx)),)
                    )?;
                };
                Ok(())
            },
        ));
        let collection_jobs_future =
            try_join_all(indexed.newly_closed_batches.iter().map(|batch_identifier| {
                Q::get_collection_jobs_including(
                    tx,
                    vdaf.as_ref(),
                    self.task.id(),
                    batch_identifier,
                )
            }))
            .map_ok(|collection_jobs| {
                collection_jobs
                    .into_iter()
                    .flatten()
                    .flat_map(|job| match job.state() {
                        CollectionJobState::Start => Some((*job.id(), job)),
                        _ => None,
                    })
                    .collect::<HashMap<_, _>>()
            });
        let (_, _, affected_collection_jobs) = try_join!(
            // Write updated batches.
            write_batches_future,
            // Write updated aggregation jobs & report aggregations.
            write_agg_jobs_future,
            // Read any collection jobs associated with a batch which just transitioned to CLOSED
            // state.
            collection_jobs_future
        )?;

        // Find all batches which are relevant to a collection job that just had a batch move into
        // CLOSED state.
        let relevant_batches: Arc<HashMap<_, _>> = Arc::new({
            let batches = Arc::new(Mutex::new(indexed.batches));
            let relevant_batch_identifiers: HashSet<_> = affected_collection_jobs
                .values()
                .flat_map(|collection_job| {
                    Q::batch_identifiers_for_collection_identifier(
                        &self.task,
                        collection_job.batch_identifier(),
                    )
                })
                .collect();
            try_join_all(
                relevant_batch_identifiers
                    .into_iter()
                    .map(|batch_identifier| {
                        let batches = Arc::clone(&batches);
                        async move {
                            // We put the lock/remove operation into its own statement to ensure the
                            // lock is dropped by the time we call `get_batch`.
                            let batch = batches.lock().unwrap().remove(&batch_identifier);
                            let batch = match batch {
                                Some((_batch_op, batch)) => Some(batch),
                                None => {
                                    tx.get_batch::<SEED_SIZE, Q, A>(
                                        self.task.id(),
                                        &batch_identifier,
                                        aggregation_parameter,
                                    )
                                    .await?
                                }
                            };
                            Ok::<_, Error>((batch_identifier, batch))
                        }
                    }),
            )
            .await?
            .into_iter()
            .collect()
        });

        // For any collection jobs for which all relevant batches are now in CLOSED state, update
        // the collection job's state to COLLECTABLE to allow the collection process to proceed.
        let relevant_batches = Arc::new(relevant_batches);
        try_join_all(
            affected_collection_jobs
                .into_values()
                .map(|collection_job| {
                    let relevant_batches = Arc::clone(&relevant_batches);
                    async move {
                        let mut is_collectable = true;
                        for batch_identifier in Q::batch_identifiers_for_collection_identifier(
                            &self.task,
                            collection_job.batch_identifier(),
                        ) {
                            let batch = match relevant_batches.get(&batch_identifier) {
                                Some(batch) => batch,
                                None => {
                                    return Err(Error::User(
                                        anyhow!(
                                        "impossible: did not attempt to read all required batches"
                                    )
                                        .into(),
                                    ))
                                }
                            };
                            let batch = match batch.as_ref() {
                                Some(batch) => batch,
                                None => {
                                    return Err(Error::User(
                                        anyhow!(
                                        "impossible: expected batch does not exist in datastore"
                                    )
                                        .into(),
                                    ));
                                }
                            };
                            if batch.state() != &BatchState::Closed {
                                is_collectable = false;
                            }
                        }
                        if is_collectable {
                            tx.update_collection_job(
                                &collection_job.with_state(CollectionJobState::Collectable),
                            )
                            .await?;
                        }
                        Ok(())
                    }
                }),
        )
        .await?;

        Ok(indexed.unwritable_report_ids)
    }
}

/// Generic callback used in the internals of aggregation job writers. Different implementations are
/// used when creating new aggregation jobs versus updating existing aggregation jobs.
trait BatchUpdateCallback {
    /// This takes one batch and an iterator of aggregation jobs, and returns that batch updated to
    /// reflect changes due to the aggregation job. Particularly, it will update the
    /// `outstanding_aggregation_jobs` counter and the `client_timestamp_interval`.
    fn update_batch<'a, const SEED_SIZE: usize, Q, A, RA>(
        &self,
        batch: Batch<SEED_SIZE, Q, A>,
        aggregation_jobs: impl Iterator<
            Item = (
                &'a AggregationJob<SEED_SIZE, Q, A>,
                &'a [Cow<'a, RA>],
                &'a [usize],
            ),
        >,
    ) -> Result<Batch<SEED_SIZE, Q, A>, Error>
    where
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'a,
        RA: ReportAggregationUpdate + Clone + 'a;

    /// Returns a flag indicating whether aggregation jobs are being created or updated.
    fn creating_aggregation_jobs(&self) -> bool;
}

/// Contains internal implementation details of [`AggregationJobUpdates::write`].
///
/// This tracks adjustments to aggregation jobs and report aggregations, before they can be written
/// to the datastore, behind copy-on-write smart pointers, and maintains multiple maps to look up
/// aggregation jobs, report aggregations, and batches.
struct IndexedAggregationJobUpdates<'a, const SEED_SIZE: usize, Q, A, RA>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
    RA: Clone,
{
    task: &'a AggregatorTask,
    aggregation_parameter: &'a A::AggregationParam,
    by_batch_identifier_index:
        &'a HashMap<Q::BatchIdentifier, HashMap<AggregationJobId, Vec<usize>>>,
    by_aggregation_job: HashMap<AggregationJobId, CowAggregationJobInfo<'a, SEED_SIZE, Q, A, RA>>,
    batches: HashMap<Q::BatchIdentifier, (Operation, Batch<SEED_SIZE, Q, A>)>,
    batches_with_unaggregated_reports: HashSet<Q::BatchIdentifier>,
    unwritable_report_ids: HashSet<ReportId>,
    newly_closed_batches: Vec<Q::BatchIdentifier>,
}

/// An aggregation job and its accompanying report aggregations.
struct AggregationJobInfo<const SEED_SIZE: usize, Q, A, RA>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
{
    aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
    report_aggregations: Vec<RA>,
}

/// Copy-on-write version of [`AggregationJobInfo`].
struct CowAggregationJobInfo<'a, const SEED_SIZE: usize, Q, A, RA>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
    RA: Clone,
{
    aggregation_job: Cow<'a, AggregationJob<SEED_SIZE, Q, A>>,
    report_aggregations: Vec<Cow<'a, RA>>,
}

impl<'a, const SEED_SIZE: usize, Q, A, RA> IndexedAggregationJobUpdates<'a, SEED_SIZE, Q, A, RA>
where
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
    RA: ReportAggregationUpdate + Clone,
{
    /// Construct a new set of lookup maps and copy-on-write data structures, from a set of
    /// aggregation job updates and the current state of the datastore.
    pub async fn new<C>(
        tx: &Transaction<'_, C>,
        updates: &'a AggregationJobUpdates<SEED_SIZE, Q, A, RA>,
        aggregation_parameter: &'a A::AggregationParam,
    ) -> Result<Self, Error>
    where
        C: Clock,
    {
        // Create a copy-on-write instance of our state to allow efficient imperative updates.
        // (Copy-on-write is used here as modifying state requires cloning it, but most pieces of
        // state will not be modified, so using CoW avoids the cost of cloning in the common case.)
        let by_aggregation_job = updates
            .aggregation_jobs
            .iter()
            .map(
                |(
                    aggregation_job_id,
                    AggregationJobInfo {
                        aggregation_job,
                        report_aggregations,
                    },
                )| {
                    (
                        *aggregation_job_id,
                        CowAggregationJobInfo {
                            aggregation_job: Cow::Borrowed(aggregation_job),
                            report_aggregations: report_aggregations
                                .iter()
                                .map(Cow::Borrowed)
                                .collect::<Vec<_>>(),
                        },
                    )
                },
            )
            .collect();

        // Read all relevant batches and report counts from the datastore.
        let (batches, batches_with_reports) = try_join!(
            try_join_all(
                updates
                    .by_batch_identifier_index
                    .keys()
                    .map(|batch_identifier| {
                        tx.get_batch::<SEED_SIZE, Q, A>(
                            updates.task.id(),
                            batch_identifier,
                            aggregation_parameter,
                        )
                    })
            ),
            try_join_all(updates.by_batch_identifier_index.keys().map(
                |batch_identifier| async move {
                    if let Some(batch_interval) = Q::to_batch_interval(batch_identifier) {
                        if tx
                            .interval_has_unaggregated_reports(updates.task.id(), batch_interval)
                            .await?
                        {
                            return Ok::<_, Error>(Some(batch_identifier.clone()));
                        }
                    }
                    Ok(None)
                },
            )),
        )?;

        let batches: HashMap<_, _> = batches
            .into_iter()
            .flat_map(|batch: Option<Batch<SEED_SIZE, Q, A>>| {
                batch.map(|b| (b.batch_identifier().clone(), (Operation::Update, b)))
            })
            .collect();

        let batches_with_unaggregated_reports: HashSet<_> =
            batches_with_reports.into_iter().flatten().collect();

        Ok(Self {
            task: &updates.task,
            aggregation_parameter,
            by_batch_identifier_index: &updates.by_batch_identifier_index,
            by_aggregation_job,
            batches,
            batches_with_unaggregated_reports,
            unwritable_report_ids: HashSet::new(),
            newly_closed_batches: Vec::new(),
        })
    }

    /// Update report aggregations with failure states if they land in previously collected batches.
    fn fail_collected_report_aggregations(&mut self) {
        // Update in-memory state of report aggregations: any report aggregations applying to a
        // closed batch instead fail with a BatchCollected error (unless they were already in an
        // failed state).
        for (batch_identifier, by_aggregation_job_index) in self.by_batch_identifier_index {
            if self.batches.get(batch_identifier).map(|(_, b)| *b.state())
                != Some(BatchState::Closed)
            {
                continue;
            }
            for (aggregation_job_id, report_aggregation_ords) in by_aggregation_job_index {
                for ord in report_aggregation_ords {
                    // unwrap safety: index lookup
                    let report_aggregation = self
                        .by_aggregation_job
                        .get_mut(aggregation_job_id)
                        .unwrap()
                        .report_aggregations
                        .get_mut(*ord)
                        .unwrap();
                    if report_aggregation.is_failed() {
                        continue;
                    }

                    self.unwritable_report_ids
                        .insert(*report_aggregation.report_id());
                    *report_aggregation = Cow::Owned(
                        report_aggregation
                            .as_ref()
                            .clone()
                            .with_failure(PrepareError::BatchCollected),
                    );
                }
            }
        }
    }

    /// Update aggregation job states if all their report aggregations have reached a terminal
    /// state.
    fn update_aggregation_job_state_from_ra_states(&mut self) {
        // Update in-memory state of aggregation jobs: any aggregation jobs whose report
        // aggregations are all in a terminal state should be considered Finished (unless the
        // aggregation job was already in a terminal state).
        for CowAggregationJobInfo {
            aggregation_job,
            report_aggregations,
        } in self.by_aggregation_job.values_mut()
        {
            if matches!(
                aggregation_job.state(),
                AggregationJobState::Finished | AggregationJobState::Abandoned
            ) {
                continue;
            }

            if report_aggregations.iter().all(|ra| ra.is_terminal()) {
                *aggregation_job = Cow::Owned(
                    aggregation_job
                        .as_ref()
                        .clone()
                        .with_state(AggregationJobState::Finished),
                );
            }
        }
    }

    /// Update batches to reflect updates to aggregation jobs.
    fn update_batches(
        &mut self,
        batch_update_callback: impl BatchUpdateCallback,
        clock: &impl Clock,
        creating_aggregation_jobs: bool,
    ) -> Result<(), Error> {
        // Update in-memory state of batches: outstanding job counts will change based on new or
        // completed aggregation jobs affecting each batch; the client timestamp interval will
        // change based on the report aggregations included in the batch.
        self.batches = self
            .by_batch_identifier_index
            .iter()
            .flat_map(|(batch_identifier, by_aggregation_job_index)| {
                let (batch_op, mut batch) = match (
                    creating_aggregation_jobs,
                    self.batches.remove(batch_identifier),
                ) {
                    (_, Some((batch_op, batch))) => (batch_op, batch),
                    (true, None) => (
                        Operation::Put,
                        Batch::new(
                            *self.task.id(),
                            batch_identifier.clone(),
                            self.aggregation_parameter.clone(),
                            BatchState::Open,
                            0,
                            Interval::EMPTY,
                        ),
                    ),
                    (false, None) => {
                        // The batch does not currently exist in the datastore. But since we first
                        // write the batch when an aggregation job referencing that batch is
                        // created, and we are stepping the aggregation job here, we must have
                        // deleted the batch at some point between creating and stepping this
                        // aggregation job. This should only be possible if the batch is GC'ed. In
                        // that case, it is acceptable to skip writing the batch entirely; and
                        // indeed, we must do so, since otherwise we might underflow the
                        // outstanding_aggregation_jobs counter.
                        //
                        // See https://github.com/divviup/janus/issues/2464 for more detail.
                        if Q::is_batch_garbage_collected(clock, batch_identifier) != Some(true) {
                            error!(
                                task_id = ?self.task.id(),
                                batch_id = ?batch_identifier,
                                "Unexpectedly missing batch while updating existing aggregation \
                                jobs"
                            );
                            panic!(
                                "Unexpectedly missing batch while updating existing aggregation \
                                jobs"
                            );
                        }

                        debug!(
                            task_id = ?self.task.id(),
                            batch_id = ?batch_identifier,
                            "Skipping batch write for GC'ed batch"
                        );
                        return None;
                    }
                };
                if batch.state() == &BatchState::Closed {
                    // Never update a closed batch.
                    return None;
                }

                let agg_job_iter = by_aggregation_job_index.iter().map(
                    |(aggregation_job_id, report_aggregation_ords)| {
                        // unwrap safety: index lookup
                        let CowAggregationJobInfo {
                            aggregation_job,
                            report_aggregations,
                        } = self.by_aggregation_job.get(aggregation_job_id).unwrap();
                        (
                            aggregation_job.as_ref(),
                            report_aggregations.as_slice(),
                            report_aggregation_ords.as_slice(),
                        )
                    },
                );
                batch = match batch_update_callback.update_batch(batch, agg_job_iter) {
                    Ok(batch) => batch,
                    Err(error) => return Some(Err(error)),
                };
                if batch.state() == &BatchState::Closing
                    && batch.outstanding_aggregation_jobs() == 0
                    && !self
                        .batches_with_unaggregated_reports
                        .contains(batch.batch_identifier())
                {
                    batch = batch.with_state(BatchState::Closed);
                    self.newly_closed_batches.push(batch_identifier.clone());
                }

                Some(Ok((batch_identifier.clone(), (batch_op, batch))))
            })
            .collect::<Result<_, _>>()?;
        Ok(())
    }
}

/// Abstracts over multiple representations of a report aggregation.
///
/// See [`ReportAggregation`] and [`ReportAggregationMetadata`].
#[async_trait]
trait ReportAggregationUpdate {
    /// Returns the report ID associated with this report aggregation.
    fn report_id(&self) -> &ReportId;

    /// Returns the client timestamp associated with this report aggregation.
    fn time(&self) -> &Time;

    /// Returns whether this report aggregation is in a terminal state ("Finished" or "Failed").
    fn is_terminal(&self) -> bool;

    /// Returns whether this report aggregation is failed.
    fn is_failed(&self) -> bool;

    /// Returns a new report aggregation corresponding to this report aggregation updated to have
    /// the "Failed" state, with the given [`PrepareError`].
    fn with_failure(self, prepare_error: PrepareError) -> Self;

    /// Write this report aggregation to the datastore. This must be used only with newly-created
    /// report aggregations.
    async fn write_new(&self, tx: &Transaction<impl Clock>) -> Result<(), Error>;

    /// Write this report aggregation to the datastore. This must be used only for updates to
    /// existing report aggregations.
    async fn write_update(&self, tx: &Transaction<impl Clock>) -> Result<(), Error>;
}

#[async_trait]
impl<const SEED_SIZE: usize, A> ReportAggregationUpdate for ReportAggregation<SEED_SIZE, A>
where
    A: vdaf::Aggregator<SEED_SIZE, 16>,
    A::PublicShare: Sync,
    A::InputShare: Sync,
    A::PrepareMessage: Sync,
    A::PrepareState: Encode + Sync,
{
    fn report_id(&self) -> &ReportId {
        self.report_id()
    }

    fn time(&self) -> &Time {
        self.time()
    }

    fn is_failed(&self) -> bool {
        matches!(self.state(), ReportAggregationState::Failed { .. })
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state(),
            ReportAggregationState::Finished { .. } | ReportAggregationState::Failed { .. }
        )
    }

    fn with_failure(self, prepare_error: PrepareError) -> Self {
        self.with_state(ReportAggregationState::Failed { prepare_error })
    }

    async fn write_new(&self, tx: &Transaction<impl Clock>) -> Result<(), Error> {
        tx.put_report_aggregation(self).await
    }

    async fn write_update(&self, tx: &Transaction<impl Clock>) -> Result<(), Error> {
        tx.update_report_aggregation(self).await
    }
}

#[async_trait]
impl ReportAggregationUpdate for ReportAggregationMetadata {
    fn report_id(&self) -> &ReportId {
        self.report_id()
    }

    fn time(&self) -> &Time {
        self.time()
    }

    fn is_failed(&self) -> bool {
        matches!(self.state(), ReportAggregationMetadataState::Failed { .. })
    }

    fn is_terminal(&self) -> bool {
        // Note that ReportAggregationMetadata can only represent the Start and Failed states, not Finished.
        self.is_failed()
    }

    fn with_failure(self, prepare_error: PrepareError) -> Self {
        self.with_state(ReportAggregationMetadataState::Failed { prepare_error })
    }

    async fn write_new(&self, tx: &Transaction<impl Clock>) -> Result<(), Error> {
        tx.create_leader_report_aggregation(self).await
    }

    async fn write_update(&self, _tx: &Transaction<impl Clock>) -> Result<(), Error> {
        panic!("tried to update an existing report aggregation via ReportAggregationMetadata")
    }
}
