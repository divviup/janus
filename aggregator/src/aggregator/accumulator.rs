//! In-memory accumulation of output shares.

use derivative::Derivative;
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::{
        self,
        models::{BatchAggregation, BatchAggregationState},
        Transaction,
    },
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
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

/// Accumulates output shares in memory and eventually flushes accumulations to a datastore. We
/// accumulate output shares into a [`HashMap`] mapping the batch identifier at which the batch
/// interval begins to the accumulated aggregate share, report count and checksum.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Accumulator<
    const SEED_SIZE: usize,
    Q: AccumulableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    task: Arc<Task>,
    shard_count: u64,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: A::AggregationParam,
    aggregations: HashMap<Q::BatchIdentifier, BatchData<SEED_SIZE, Q, A>>,
}

#[derive(Debug)]
struct BatchData<
    const SEED_SIZE: usize,
    Q: AccumulableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
> {
    batch_aggregation: BatchAggregation<SEED_SIZE, Q, A>,
    included_report_ids: HashSet<ReportId>,
}

impl<const SEED_SIZE: usize, Q: AccumulableQueryType, A: vdaf::Aggregator<SEED_SIZE, 16>>
    Accumulator<SEED_SIZE, Q, A>
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
                BatchAggregationState::Aggregating,
                Some(A::AggregateShare::from(output_share.clone())),
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
            .and_modify(|data| {
                data.batch_aggregation =
                    match batch_aggregation_fn().merged_with(&data.batch_aggregation) {
                        Ok(batch_aggregation) => batch_aggregation,
                        Err(err) => {
                            rslt = Err(err);
                            return;
                        }
                    };
                data.included_report_ids.insert(*report_id);
            })
            .or_insert_with(|| BatchData {
                batch_aggregation: batch_aggregation_fn(),
                included_report_ids: HashSet::from([*report_id]),
            });
        rslt
    }

    /// Write the accumulated aggregate shares, report counts and checksums to the datastore. If a
    /// batch aggregation already exists for some accumulator, it is updated. If no batch
    /// aggregation exists, one is created and initialized with the accumulated values.
    ///
    /// This operation may discover that some batch aggregations had been concurrently collected. If
    /// so, a set of unmergeable report IDs is returned; the contribution of the reports
    /// corresponding to these IDs was not written back to the datastore because it is too late to
    /// do so.
    #[tracing::instrument(skip(self, tx), err)]
    pub async fn flush_to_datastore<C: Clock>(
        &self,
        tx: &Transaction<'_, C>,
        vdaf: &A,
    ) -> Result<HashSet<ReportId>, datastore::Error> {
        let unmergeable_report_ids = Arc::new(Mutex::new(HashSet::new()));

        try_join_all(self.aggregations.values().map(|data| {
            let unmergeable_report_ids = Arc::clone(&unmergeable_report_ids);
            async move {
                match tx
                    .get_batch_aggregation::<SEED_SIZE, Q, A>(
                        vdaf,
                        data.batch_aggregation.task_id(),
                        data.batch_aggregation.batch_identifier(),
                        data.batch_aggregation.aggregation_parameter(),
                        data.batch_aggregation.ord(),
                    )
                    .await?
                {
                    Some(batch_aggregation) => {
                        match tx
                            .update_batch_aggregation(
                                &batch_aggregation.merged_with(&data.batch_aggregation)?,
                            )
                            .await
                        {
                            Ok(()) => (),
                            Err(datastore::Error::AlreadyCollected) => {
                                // Unwrap safety: this only panics if the mutex is poisoned. If
                                // it is, one of the other futures also panicked, so we can
                                // panic too.
                                let mut unmergeable_report_ids =
                                    unmergeable_report_ids.lock().unwrap();
                                unmergeable_report_ids.extend(&data.included_report_ids);
                            }
                            Err(err) => Err(err)?,
                        };
                        Ok(())
                    }

                    None => {
                        let rslt = tx.put_batch_aggregation(&data.batch_aggregation).await;
                        if matches!(rslt, Err(datastore::Error::MutationTargetAlreadyExists)) {
                            // This codepath can be taken due to a quirk of how the Repeatable Read
                            // isolation level works. It cannot occur at the Serializable isolation
                            // level.
                            //
                            // For this codepath to be taken, two writers must concurrently choose
                            // to write the same batch aggregation shard (by task, batch,
                            // aggregation parameter, and shard), and this batch aggregation shard
                            // must not already exist in the datastore.
                            //
                            // Both writers will receive `None` from the `get_batch_aggregation`
                            // call, and then both will try to `put_batch_aggregation`. One of the
                            // writers will succeed. The other will fail with a unique constraint
                            // violation on (task_id, batch_identifier, aggregation_param, ord),
                            // since unique constraints are still enforced even in the presence of
                            // snapshot isolation, which will be translated to a
                            // MutationTargetAlreadyExists error.
                            //
                            // The failing writer, in this case, can't do anything about this
                            // problem while in its current transaction: further attempts to read
                            // the batch aggregation will continue to return `None` (since all reads
                            // in the same transaction are from the same snapshot), so it can't
                            // update the now-written batch aggregation. All it can do is give up on
                            // this transaction and try again, by calling `retry` and returning an
                            // error.
                            tx.retry();
                        }
                        rslt
                    }
                }
            }
        }))
        .await?;

        // Unwrap safety: at this point, `unmergeable_report_ids` is the only instance of this Arc,
        // so `try_unwrap().unwrap()` will succeed. `into_inner().unwrap()` can only panic if code
        // that held this mutex panicked; but in this case, we would have panicked already while
        // awaiting the above future (and if not, we do want to panic now).
        Ok(Arc::try_unwrap(unmergeable_report_ids)
            .unwrap()
            .into_inner()
            .unwrap())
    }
}
