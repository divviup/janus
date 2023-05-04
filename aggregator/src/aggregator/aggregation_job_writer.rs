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
use janus_messages::{AggregationJobId, ReportShareError};
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
    task: Arc<Task>,                            // could this be a &Task instead?
    aggregation_parameter: A::AggregationParam, // could this be a &A::AggregationParam instead?
    by_aggregation_job: HashMap<
        AggregationJobId,
        (
            AggregationJob<SEED_SIZE, Q, A>,
            Vec<ReportAggregation<SEED_SIZE, A>>,
        ),
    >,
}

impl<const SEED_SIZE: usize, Q: AccumulableQueryType, A: vdaf::Aggregator<SEED_SIZE, 16>>
    AggregationJobWriter<SEED_SIZE, Q, A>
{
    pub fn new(task: Arc<Task>, aggregation_parameter: A::AggregationParam) -> Self {
        Self {
            task,
            aggregation_parameter,
            by_aggregation_job: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.by_aggregation_job.is_empty()
    }

    pub fn put(
        &mut self,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) where
        A::AggregationParam: PartialEq + Eq,
    {
        assert_eq!(
            &self.aggregation_parameter,
            aggregation_job.aggregation_parameter()
        );
        self.by_aggregation_job.insert(
            *aggregation_job.id(),
            (aggregation_job, report_aggregations),
        );
    }

    pub async fn write<C: Clock>(&self, tx: &Transaction<'_, C>) -> Result<(), Error>
    where
        A::AggregationParam: PartialEq + Eq + Hash,
        A::PrepareState: Encode,
    {
        // Create a copy-on-write instance of our state to allow efficient imperative updates.
        // (Copy-on-write is used here as modifying state requires cloning it, but most pieces of
        // state will not be modified, so using CoW avoids the cost of cloning in the common case.)
        // Compute a by-batch-identifier index on the input aggregation jobs/report aggregations,
        // too.
        let mut by_aggregation_job: HashMap<_, _> = self
            .by_aggregation_job
            .iter()
            .map(
                |(aggregation_job_id, (aggregation_job, report_aggregations))| {
                    (
                        *aggregation_job_id,
                        (
                            Cow::Borrowed(aggregation_job),
                            report_aggregations
                                .iter()
                                .map(Cow::Borrowed)
                                .collect::<Vec<_>>(),
                        ),
                    )
                },
            )
            .collect();
        let by_batch_identifier = {
            let mut by_batch_identifier = HashMap::new();
            for (aggregation_job_id, (aggregation_job, report_aggregations)) in
                &self.by_aggregation_job
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
                    &self.aggregation_parameter,
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
        for (batch_identifier, (_, report_aggregations)) in &by_batch_identifier {
            if batches.get(batch_identifier).map(|b| *b.state()) != Some(BatchState::Closed) {
                continue;
            }
            for (aggregation_job_id, ord) in report_aggregations {
                // unwrap safety: index lookup
                let report_aggregation = by_aggregation_job
                    .get_mut(aggregation_job_id)
                    .unwrap()
                    .1
                    .get_mut(*ord)
                    .unwrap();
                if matches!(
                    report_aggregation.state(),
                    ReportAggregationState::Failed(_) | ReportAggregationState::Invalid
                ) {
                    continue;
                }

                *report_aggregation = Cow::Owned(report_aggregation.as_ref().clone().with_state(
                    ReportAggregationState::Failed(ReportShareError::BatchCollected),
                ));
            }
        }

        // Update in-memory state of aggregation jobs: any aggregation jobs whose report
        // aggregations are all in a terminal state should be considered Finished (unless the
        // aggregation job was already in a terminal state).
        for (_, (aggregation_job, report_aggregations)) in &mut by_aggregation_job {
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

        // Update in-memory state of batches: counts will change based on new or completed
        // aggregation jobs affecting each batch. (the first boolean determines if this batch
        // is new or not)
        let batches: Vec<_> = by_batch_identifier
            .iter()
            .flat_map(|(batch_identifier, (agg_job_ids, _))| {
                let outstanding_agg_job_delta = match u64::try_from(
                    agg_job_ids
                        .iter()
                        .filter(|agg_job_id| {
                            // unwrap safety: index lookup
                            matches!(
                                by_aggregation_job.get(agg_job_id).unwrap().0.state(),
                                AggregationJobState::InProgress
                            )
                        })
                        .count(),
                ) {
                    Ok(delta) => delta,
                    Err(err) => return Some(Err(err)),
                };
                if outstanding_agg_job_delta == 0 {
                    return None;
                }

                let batch = match batches.remove(batch_identifier) {
                    Some(batch) => batch,
                    None => {
                        return Some(Ok((
                            /* is_new */ true,
                            Batch::new(
                                *self.task.id(),
                                batch_identifier.clone(),
                                self.aggregation_parameter.clone(),
                                BatchState::Open,
                                outstanding_agg_job_delta,
                            ),
                        )));
                    }
                };
                if batch.state() == &BatchState::Closed {
                    return None;
                }

                let outstanding_aggregation_jobs =
                    batch.outstanding_aggregation_jobs() + outstanding_agg_job_delta;
                Some(Ok((
                    /* is_new */ false,
                    batch.with_outstanding_aggregation_jobs(outstanding_aggregation_jobs),
                )))
            })
            .collect::<Result<_, _>>()?;

        // Write batches & aggregation jobs.
        try_join!(
            try_join_all(batches.into_iter().map(|(is_new, batch)| async move {
                if is_new {
                    tx.put_batch(&batch).await
                } else {
                    tx.update_batch(&batch).await
                }
            })),
            try_join_all(
                by_aggregation_job
                    .iter()
                    .map(|(_, (aggregation_job, _))| tx.put_aggregation_job(aggregation_job)),
            )
        )?;

        // Write report aggregations.
        try_join_all(
            by_aggregation_job
                .iter()
                .flat_map(|(_, (_, report_aggregations))| report_aggregations)
                .map(|report_aggregation| tx.put_report_aggregation(report_aggregation)),
        )
        .await?;

        Ok(())
    }
}
