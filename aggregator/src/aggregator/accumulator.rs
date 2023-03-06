//! In-memory accumulation of output shares.

use derivative::Derivative;
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::{self, models::BatchAggregation, Transaction},
    query_type::AccumulableQueryType,
    task::Task,
};
use janus_core::{
    report_id::ReportIdChecksumExt,
    time::{Clock, IntervalExt},
};
use janus_messages::{Interval, ReportId, ReportIdChecksum, Time};
use prio::vdaf;
use rand::{thread_rng, Rng};
use std::{collections::HashMap, sync::Arc};

/// Accumulates output shares in memory and eventually flushes accumulations to a datastore. We
/// accumulate output shares into a [`HashMap`] mapping the batch identifier at which the batch
/// interval begins to the accumulated aggregate share, report count and checksum.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Accumulator<const L: usize, Q: AccumulableQueryType, A: vdaf::Aggregator<L>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    task: Arc<Task>,
    shard_count: u64,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: A::AggregationParam,
    aggregations: HashMap<Q::BatchIdentifier, BatchAggregation<L, Q, A>>,
}

impl<'t, const L: usize, Q: AccumulableQueryType, A: vdaf::Aggregator<L>> Accumulator<L, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    /// Creates a new accumulator.
    pub fn new(
        task: Arc<Task>,
        shard_count: u64,
        aggregation_parameter: A::AggregationParam,
    ) -> Self {
        Self {
            task,
            shard_count,
            aggregation_parameter,
            aggregations: HashMap::new(),
        }
    }

    /// Update the in-memory accumulators with the provided output share and report timestamp.
    pub fn update(
        &mut self,
        partial_batch_identifier: &Q::PartialBatchIdentifier,
        report_id: &ReportId,
        client_timestamp: &Time,
        output_share: &A::OutputShare,
    ) -> Result<(), datastore::Error> {
        let batch_identifier =
            Q::to_batch_identifier(&self.task, partial_batch_identifier, client_timestamp)?;
        let client_timestamp_interval =
            Interval::from_time(client_timestamp).map_err(|e| datastore::Error::User(e.into()))?;
        let batch_aggregation_fn = || {
            BatchAggregation::new(
                *self.task.id(),
                batch_identifier.clone(),
                self.aggregation_parameter.clone(),
                thread_rng().gen_range(0..self.shard_count),
                A::AggregateShare::from(output_share.clone()),
                1,
                client_timestamp_interval,
                ReportIdChecksum::for_report_id(report_id),
            )
        };

        // This slightly-awkward usage of `rslt` is due to the Entry API not having a fallible
        // interface -- we need some way to smuggle an error out of `and_modify`.
        let mut rslt = Ok(());
        self.aggregations
            .entry(batch_identifier.clone())
            .and_modify(|agg| match batch_aggregation_fn().merged_with(agg) {
                Ok(batch_aggregation) => *agg = batch_aggregation,
                Err(err) => rslt = Err(err),
            })
            .or_insert_with(batch_aggregation_fn);
        rslt
    }

    /// Write the accumulated aggregate shares, report counts and checksums to the datastore. If a
    /// batch aggregation already exists for some accumulator, it is updated. If no batch
    /// aggregation exists, one is created and initialized with the accumulated values.
    #[tracing::instrument(skip(self, tx), err)]
    pub async fn flush_to_datastore<C: Clock>(
        &self,
        tx: &Transaction<'_, C>,
    ) -> Result<(), datastore::Error> {
        try_join_all(self.aggregations.values().map(|agg| async move {
            match tx
                .get_batch_aggregation::<L, Q, A>(
                    agg.task_id(),
                    agg.batch_identifier(),
                    agg.aggregation_parameter(),
                    agg.ord(),
                )
                .await?
            {
                Some(batch_aggregation) => {
                    tx.update_batch_aggregation(&batch_aggregation.merged_with(agg)?)
                        .await
                }
                None => {
                    let rslt = tx.put_batch_aggregation(agg).await;
                    if matches!(rslt, Err(datastore::Error::MutationTargetAlreadyExists)) {
                        // This codepath can be taken due to a quirk of how the Repeatable Read
                        // isolation level works. It cannot occur at the Serializable isolation
                        // level.
                        //
                        // For this codepath to be taken, two writers must concurrently choose to
                        // write the same batch aggregation shard (by task, batch, aggregation
                        // parameter, and shard), and this batch aggregation shard must not already
                        // exist in the datastore.
                        //
                        // Both writers will receive `None` from the `get_batch_aggregation` call,
                        // and then both will try to `put_batch_aggregation`. One of the writers
                        // will succeed. The other will fail with a unique constraint violation on
                        // (task_id, batch_identifier, aggregation_param, ord), since unique
                        // constraints are still enforced even in the presence of snapshot
                        // isolation, which will be translated to a MutationTargetAlreadyExists
                        // error.
                        //
                        // The failing writer, in this case, can't do anything about this problem
                        // while in its current transaction: further attempts to read the batch
                        // aggregation will continue to return `None` (since all reads in the same
                        // transaction are from the same snapshot), so it can't update the
                        // now-written batch aggregation. All it can do is give up on this
                        // transaction and try again, by calling `retry` and returning an error.
                        tx.retry();
                    }
                    rslt
                }
            }
        }))
        .await?;
        Ok(())
    }
}
