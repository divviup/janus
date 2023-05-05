//! In-memory accumulation of aggregation job (& report aggregation) updates.

use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::{
        models::{
            AggregationJob, AggregationJobState, Batch, BatchState, ReportAggregation,
            ReportAggregationState,
        },
        Error, Transaction,
    },
    query_type::AccumulableQueryType,
    task::Task,
};
use janus_core::time::Clock;
use janus_messages::{AggregationJobId, ReportId, ReportShareError};
use prio::{codec::Encode, vdaf};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::Arc,
};
use tokio::try_join;

// XXX: docs
pub struct AggregationJobWriter<
    const SEED_SIZE: usize,
    Q: AccumulableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    task: Arc<Task>,
    aggregation_jobs: HashMap<AggregationJobId, AggregationJobInfo<SEED_SIZE, Q, A>>,
}

struct AggregationJobInfo<
    const SEED_SIZE: usize,
    Q: AccumulableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    operation: Operation,
    aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
    report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Operation {
    Put,
    Update,
}

impl<const SEED_SIZE: usize, Q: AccumulableQueryType, A: vdaf::Aggregator<SEED_SIZE, 16>>
    AggregationJobWriter<SEED_SIZE, Q, A>
{
    pub fn new(task: Arc<Task>) -> Self {
        Self {
            task,
            aggregation_jobs: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.aggregation_jobs.is_empty()
    }

    pub fn put(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) where
        A::AggregationParam: PartialEq + Eq,
    {
        self.insert_aggregation_job_info(AggregationJobInfo {
            operation: Operation::Put,
            aggregation_job,
            report_aggregations,
        })
    }

    pub fn update(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) where
        A::AggregationParam: PartialEq + Eq,
    {
        self.insert_aggregation_job_info(AggregationJobInfo {
            operation: Operation::Update,
            aggregation_job,
            report_aggregations,
        })
    }

    fn insert_aggregation_job_info(&mut self, info: AggregationJobInfo<SEED_SIZE, Q, A>)
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

        self.aggregation_jobs
            .insert(*info.aggregation_job.id(), info);
    }

    pub async fn write<C: Clock>(&self, tx: &Transaction<'_, C>) -> Result<HashSet<ReportId>, Error>
    where
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

        let by_batch_identifier = {
            let mut by_batch_identifier = HashMap::new();
            for (aggregation_job_id, (_, aggregation_job, report_aggregations)) in
                &by_aggregation_job
            {
                for (ord, report_aggregation) in report_aggregations.iter().enumerate() {
                    let batch_identifier = Q::to_batch_identifier(
                        &self.task,
                        aggregation_job.partial_batch_identifier(),
                        report_aggregation.report_metadata().time(),
                    )?;
                    let value = by_batch_identifier
                        .entry(batch_identifier)
                        .or_insert((HashSet::new(), Vec::new()));
                    value.0.insert(*aggregation_job_id);
                    value.1.push((*aggregation_job_id, ord));
                }
            }
            by_batch_identifier
        };

        // Read all relevant batches from the datastore.
        let mut batches: HashMap<_, _> =
            try_join_all(by_batch_identifier.keys().map(|batch_identifier| {
                tx.get_batch::<SEED_SIZE, Q, A>(
                    self.task.id(),
                    batch_identifier,
                    aggregation_parameter,
                )
            }))
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
        for (batch_identifier, (_, report_aggregations)) in &by_batch_identifier {
            if batches.get(batch_identifier).map(|b| *b.state()) != Some(BatchState::Closed) {
                continue;
            }
            for (aggregation_job_id, ord) in report_aggregations {
                // unwrap safety: index lookup
                let report_aggregation = by_aggregation_job
                    .get_mut(aggregation_job_id)
                    .unwrap()
                    .2
                    .get_mut(*ord)
                    .unwrap();
                if matches!(
                    report_aggregation.state(),
                    ReportAggregationState::Failed(_) | ReportAggregationState::Invalid
                ) {
                    continue;
                }

                unwritable_report_ids.insert(*report_aggregation.report_id());
                *report_aggregation = Cow::Owned(report_aggregation.as_ref().clone().with_state(
                    ReportAggregationState::Failed(ReportShareError::BatchCollected),
                ));
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
                    ReportAggregationState::Finished
                        | ReportAggregationState::Failed(_)
                        | ReportAggregationState::Invalid
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
        let batches: Vec<_> = by_batch_identifier
            .iter()
            .flat_map(|(batch_identifier, (agg_job_ids, _))| {
                let (operation, batch) = match batches.remove(batch_identifier) {
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
                for agg_job_id in agg_job_ids {
                    // unwrap safety: index lookup
                    let (op, agg_job, _) = by_aggregation_job.get(agg_job_id).unwrap();
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

                Some((
                    operation,
                    batch.with_outstanding_aggregation_jobs(outstanding_aggregation_jobs),
                ))
            })
            .collect();

        // Write batches, aggregation jobs, and report aggregations.
        try_join!(
            try_join_all(batches.into_iter().map(|(op, batch)| async move {
                match op {
                    Operation::Put => tx.put_batch(&batch).await,
                    Operation::Update => tx.update_batch(&batch).await,
                }
            })),
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
            ))
        )?;

        Ok(unwritable_report_ids)
    }
}
