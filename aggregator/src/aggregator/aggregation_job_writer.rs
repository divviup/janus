//! In-memory accumulation of aggregation job (& report aggregation) updates.

use crate::{aggregator::query_type::CollectableQueryType, Operation};
use futures::{future::try_join_all, TryFutureExt};
use janus_aggregator_core::{
    datastore::{
        models::{
            AggregationJob, AggregationJobState, Batch, BatchState, CollectionJobState,
            ReportAggregation, ReportAggregationState,
        },
        Error, Transaction,
    },
    task::Task,
};
use janus_core::time::Clock;
use janus_messages::{AggregationJobId, ReportId, ReportShareError};
use prio::{codec::Encode, vdaf};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};
use tokio::try_join;

/// AggregationJobWriter contains the logic used to write aggregation jobs, both initially &
/// on updates. It is used only by the Leader.
pub struct AggregationJobWriter<
    const SEED_SIZE: usize,
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    task: Arc<Task>,
    aggregation_jobs: HashMap<AggregationJobId, AggregationJobInfo<SEED_SIZE, Q, A>>,

    // batch identifier -> aggregation job -> ord of report aggregation; populated by all report
    // aggregations pertaining to the batch.
    by_batch_identifier_index: HashMap<Q::BatchIdentifier, HashMap<AggregationJobId, Vec<usize>>>,
}

struct AggregationJobInfo<
    const SEED_SIZE: usize,
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    operation: Operation,
    aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
    report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
}

impl<const SEED_SIZE: usize, Q: CollectableQueryType, A: vdaf::Aggregator<SEED_SIZE, 16>>
    AggregationJobWriter<SEED_SIZE, Q, A>
{
    /// Creates a new, empty aggregation job writer.
    pub fn new(task: Arc<Task>) -> Self {
        Self {
            task,
            aggregation_jobs: HashMap::new(),
            by_batch_identifier_index: HashMap::new(),
        }
    }

    /// Returns whether this aggregation job writer is empty, i.e. whether it contains any
    /// aggregation jobs.
    pub fn is_empty(&self) -> bool {
        self.aggregation_jobs.is_empty()
    }

    /// Queues a new aggregation job to be written to the datastore. Nothing is actually written
    /// until `write` is called.
    pub fn put(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: PartialEq + Eq,
    {
        self.insert_aggregation_job_info(AggregationJobInfo {
            operation: Operation::Put,
            aggregation_job,
            report_aggregations,
        })
    }

    /// Queues an existing aggregation job to be updated in the datastore. Nothing is actually
    /// written // until `write` is called.
    pub fn update(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: PartialEq + Eq,
    {
        self.insert_aggregation_job_info(AggregationJobInfo {
            operation: Operation::Update,
            aggregation_job,
            report_aggregations,
        })
    }

    fn insert_aggregation_job_info(
        &mut self,
        info: AggregationJobInfo<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: PartialEq + Eq,
    {
        // We don't currently have (or need, at time of writing) logic to allow writing aggregation
        // jobs across different aggregation parameters. Verify that our caller is not trying to do
        // so.
        assert!(self.aggregation_jobs.values().next().map_or(true, |i| {
            info.aggregation_job.aggregation_parameter()
                == i.aggregation_job.aggregation_parameter()
        }));

        // Compute batch identifiers first, since computing the batch identifier is fallible and
        // it's nicer not to have to unwind state modifications if we encounter an error.
        let batch_identifiers: Vec<_> = info
            .report_aggregations
            .iter()
            .map(|ra| {
                Q::to_batch_identifier(
                    &self.task,
                    info.aggregation_job.partial_batch_identifier(),
                    ra.report_metadata().time(),
                )
            })
            .collect::<Result<_, _>>()?;
        assert_eq!(batch_identifiers.len(), info.report_aggregations.len());

        // Modify our state to record this aggregation job. (starting here, failure is not allowed)
        for (ord, batch_identifier) in batch_identifiers.into_iter().enumerate() {
            self.by_batch_identifier_index
                .entry(batch_identifier)
                .or_default()
                .entry(*info.aggregation_job.id())
                .or_default()
                .push(ord);
        }

        self.aggregation_jobs
            .insert(*info.aggregation_job.id(), info);
        Ok(())
    }

    /// Writes all queued aggregation jobs to the datastore.
    pub async fn write<C: Clock>(
        &self,
        tx: &Transaction<'_, C>,
        vdaf: Arc<A>,
    ) -> Result<HashSet<ReportId>, Error>
    where
        A: Send + Sync,
        A::AggregationParam: PartialEq + Eq + Hash,
        A::PrepareState: Encode,
    {
        // Create a copy-on-write instance of our state to allow efficient imperative updates.
        // (Copy-on-write is used here as modifying state requires cloning it, but most pieces of
        // state will not be modified, so using CoW avoids the cost of cloning in the common case.)
        // Compute a by-batch-identifier index on the input aggregation jobs/report aggregations,
        // too.
        let aggregation_parameter = match self
            .aggregation_jobs
            .values()
            .next()
            .map(|info| info.aggregation_job.aggregation_parameter())
        {
            Some(aggregation_parameter) => aggregation_parameter,
            None => return Ok(HashSet::new()), // None means there is nothing to write.
        };

        let mut by_aggregation_job: HashMap<_, _> = self
            .aggregation_jobs
            .iter()
            .map(|(aggregation_job_id, info)| {
                (
                    *aggregation_job_id,
                    (
                        info.operation,
                        Cow::Borrowed(&info.aggregation_job),
                        info.report_aggregations
                            .iter()
                            .map(Cow::Borrowed)
                            .collect::<Vec<_>>(),
                    ),
                )
            })
            .collect();

        // Read all relevant batches from the datastore.
        let mut batches: HashMap<_, _> = try_join_all(self.by_batch_identifier_index.keys().map(
            |batch_identifier| {
                tx.get_batch::<SEED_SIZE, Q, A>(
                    self.task.id(),
                    batch_identifier,
                    aggregation_parameter,
                )
            },
        ))
        .await?
        .into_iter()
        .flat_map(|batch: Option<Batch<SEED_SIZE, Q, A>>| {
            batch.map(|b| (b.batch_identifier().clone(), b))
        })
        .collect();

        // Update in-memory state of report aggregations: any report aggregations applying to a
        // closed batch instead fail with a BatchCollected error (unless they were already in an
        // failed state).
        let mut unwritable_report_ids = HashSet::new();
        for (batch_identifier, by_aggregation_job_index) in &self.by_batch_identifier_index {
            if batches.get(batch_identifier).map(|b| *b.state()) != Some(BatchState::Closed) {
                continue;
            }
            for (aggregation_job_id, report_aggregation_ords) in by_aggregation_job_index {
                for ord in report_aggregation_ords {
                    // unwrap safety: index lookup
                    let report_aggregation = by_aggregation_job
                        .get_mut(aggregation_job_id)
                        .unwrap()
                        .2
                        .get_mut(*ord)
                        .unwrap();
                    if matches!(
                        report_aggregation.state(),
                        ReportAggregationState::Failed(_)
                    ) {
                        continue;
                    }

                    unwritable_report_ids.insert(*report_aggregation.report_id());
                    *report_aggregation =
                        Cow::Owned(report_aggregation.as_ref().clone().with_state(
                            ReportAggregationState::Failed(ReportShareError::BatchCollected),
                        ));
                }
            }
        }

        // Update in-memory state of aggregation jobs: any aggregation jobs whose report
        // aggregations are all in a terminal state should be considered Finished (unless the
        // aggregation job was already in a terminal state).
        for (_, aggregation_job, report_aggregations) in by_aggregation_job.values_mut() {
            if matches!(
                aggregation_job.state(),
                AggregationJobState::Finished | AggregationJobState::Abandoned
            ) {
                continue;
            }

            if report_aggregations.iter().all(|ra| {
                matches!(
                    ra.state(),
                    ReportAggregationState::Finished | ReportAggregationState::Failed(_)
                )
            }) {
                *aggregation_job = Cow::Owned(
                    aggregation_job
                        .as_ref()
                        .clone()
                        .with_state(AggregationJobState::Finished),
                );
            }
        }

        // Update in-memory state of batches: outstanding job counts will change based on new or
        // completed aggregation jobs affecting each batch.
        let mut newly_closed_batches = Vec::new();
        let batches: HashMap<_, _> = self
            .by_batch_identifier_index
            .iter()
            .flat_map(|(batch_identifier, by_aggregation_job_index)| {
                let (operation, mut batch) = match batches.remove(batch_identifier) {
                    Some(batch) => (Operation::Update, batch),
                    None => (
                        Operation::Put,
                        Batch::new(
                            *self.task.id(),
                            batch_identifier.clone(),
                            aggregation_parameter.clone(),
                            BatchState::Open,
                            0,
                        ),
                    ),
                };
                if batch.state() == &BatchState::Closed {
                    // Never update a closed batch.
                    return None;
                }

                // Increment outstanding job count by the number of new, incomplete aggregation jobs
                // we are writing; decrement outstanding job count by the number of updated,
                // complete aggregation jobs we are writing. (We assume any update to a terminal
                // state is the first time we have updated to a terminal state, as the system does
                // not touch aggregation jobs once they have reached a terminal state, and it would
                // add code complexity & runtime cost to determine if we are in a
                // repeated-terminal-write case.)
                let mut outstanding_aggregation_jobs = batch.outstanding_aggregation_jobs();
                for aggregation_job_id in by_aggregation_job_index.keys() {
                    // unwrap safety: index lookup
                    let (op, agg_job, _) = by_aggregation_job.get(aggregation_job_id).unwrap();
                    if op == &Operation::Put
                        && matches!(agg_job.state(), AggregationJobState::InProgress)
                    {
                        outstanding_aggregation_jobs += 1;
                    } else if op == &Operation::Update
                        && !matches!(agg_job.state(), AggregationJobState::InProgress)
                    {
                        outstanding_aggregation_jobs -= 1;
                    }
                }
                if batch.state() == &BatchState::Closing && outstanding_aggregation_jobs == 0 {
                    batch = batch.with_state(BatchState::Closed);
                    newly_closed_batches.push(batch_identifier);
                }

                Some((
                    batch_identifier,
                    (
                        operation,
                        batch.with_outstanding_aggregation_jobs(outstanding_aggregation_jobs),
                    ),
                ))
            })
            .collect();

        // Write batches, aggregation jobs, and report aggregations.
        let (_, _, affected_collection_jobs) = try_join!(
            // Write updated batches.
            try_join_all(batches.values().map(|(op, batch)| async move {
                match op {
                    Operation::Put => tx.put_batch(batch).await,
                    Operation::Update => tx.update_batch(batch).await,
                }
            })),
            // Write updated aggregation jobs & report aggregations.
            try_join_all(by_aggregation_job.values().map(
                |(op, aggregation_job, report_aggregations)| async move {
                    match op {
                        Operation::Put => {
                            // These operations must occur serially since report aggregation rows
                            // have a foreign-key contrainst on the related aggregation job
                            // existing. We could speed things up for initial writes by switching to
                            // DEFERRED constraints:
                            // https://www.postgresql.org/docs/current/sql-set-constraints.html
                            tx.put_aggregation_job(aggregation_job).await?;
                            try_join_all(
                                report_aggregations
                                    .iter()
                                    .map(|ra| tx.put_report_aggregation(ra)),
                            )
                            .await?;
                        }
                        Operation::Update => {
                            try_join!(
                                tx.update_aggregation_job(aggregation_job),
                                try_join_all(
                                    report_aggregations
                                        .iter()
                                        .map(|ra| tx.update_report_aggregation(ra)),
                                )
                            )?;
                        }
                    };
                    Ok(())
                }
            )),
            // Read any collection jobs associated with a batch which just transitioned to CLOSED
            // state.
            try_join_all(newly_closed_batches.into_iter().map(|batch_identifier| {
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
            })
        )?;

        // Find all batches which are relevant to a collection job that just had a batch move into
        // CLOSED state.
        let relevant_batches: Arc<HashMap<_, _>> = Arc::new({
            let batches = Arc::new(Mutex::new(batches));
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
                                Some((_, batch)) => Some(batch),
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
                        if Q::batch_identifiers_for_collection_identifier(
                            &self.task,
                            collection_job.batch_identifier(),
                        )
                        .all(|batch_identifier| {
                            relevant_batches
                                .get(&batch_identifier)
                                .map_or(false, |batch| {
                                    batch
                                        .as_ref()
                                        .map_or(false, |batch| batch.state() == &BatchState::Closed)
                                })
                        }) {
                            tx.update_collection_job(
                                &collection_job.with_state(CollectionJobState::Collectable),
                            )
                            .await?;
                        }
                        Ok::<_, Error>(())
                    }
                }),
        )
        .await?;

        Ok(unwritable_report_ids)
    }
}
