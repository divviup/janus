//! In-memory accumulation of output shares.

use super::Error;
use crate::{
    datastore::{self, models::BatchUnitAggregation, Transaction},
    message::Interval,
};
use derivative::Derivative;
use janus::{
    message::{Duration, Nonce, NonceChecksum, TaskId, Time},
    time::Clock,
};
use prio::vdaf::{self, Aggregatable};
use std::collections::HashMap;
use tracing::debug;

#[derive(Debug)]
struct Accumulation<A: vdaf::Aggregator>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    aggregate_share: A::AggregateShare,
    report_count: u64,
    checksum: NonceChecksum,
}

impl<A: vdaf::Aggregator> Accumulation<A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    fn update(&mut self, output_share: &A::OutputShare, nonce: Nonce) -> Result<(), Error> {
        self.aggregate_share.accumulate(output_share)?;
        self.report_count += 1;
        self.checksum.update(nonce);

        Ok(())
    }
}

/// Accumulates output shares in memory and eventually flushes accumulations to a datastore. Janus'
/// leader aligns aggregate jobs with batch unit intervals, but this is not generally required for
/// DAP implementations, so we accumulate output shares into a HashMap mapping the Time at which the
/// batch unit interval begins to the accumulated aggregate share, report count and checksum.
#[derive(Derivative)]
#[derivative(Debug)]
pub(super) struct Accumulator<A: vdaf::Aggregator>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    task_id: TaskId,
    min_batch_duration: Duration,
    #[derivative(Debug = "ignore")]
    aggregation_param: A::AggregationParam,
    accumulations: HashMap<Time, Accumulation<A>>,
}

impl<A: vdaf::Aggregator> Accumulator<A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
{
    /// Create a new accumulator
    pub(super) fn new(
        task_id: TaskId,
        min_batch_duration: Duration,
        aggregation_param: &A::AggregationParam,
    ) -> Self {
        Self {
            task_id,
            min_batch_duration,
            aggregation_param: aggregation_param.clone(),
            accumulations: HashMap::new(),
        }
    }

    /// Update the in-memory accumulators with the provided output share and report nonce.
    pub(super) fn update(
        &mut self,
        output_share: &A::OutputShare,
        nonce: Nonce,
    ) -> Result<(), datastore::Error> {
        let key = nonce
            .time()
            .to_batch_unit_interval_start(self.min_batch_duration)
            .map_err(|e| datastore::Error::User(e.into()))?;
        if let Some(accumulate) = self.accumulations.get_mut(&key) {
            accumulate
                .update(output_share, nonce)
                .map_err(|e| datastore::Error::User(e.into()))?;
        } else {
            self.accumulations.insert(
                key,
                Accumulation {
                    aggregate_share: A::AggregateShare::from(output_share.clone()),
                    report_count: 1,
                    checksum: NonceChecksum::from_nonce(nonce),
                },
            );
        }

        Ok(())
    }

    /// Write the accumulated aggregate shares, report counts and checksums to the datastore. If a
    /// batch unit aggregation already exists for some accumulator, it is updated. If no batch unit
    /// aggregation exists, one is created and initialized with the accumulated values.
    #[tracing::instrument(skip(self, tx), err)]
    pub(super) async fn flush_to_datastore<C: Clock>(
        self,
        tx: &Transaction<'_, C>,
    ) -> Result<(), datastore::Error> {
        for (unit_interval_start, accumulate) in self.accumulations {
            let unit_interval = Interval::new(unit_interval_start, self.min_batch_duration)?;

            let mut batch_unit_aggregations = tx
                .get_batch_unit_aggregations_for_task_in_interval::<A>(
                    self.task_id,
                    unit_interval,
                    &self.aggregation_param,
                )
                .await?;

            if batch_unit_aggregations.len() > 1 {
                return Err(datastore::Error::DbState(format!(
                    "found {} batch unit aggregation rows for task {}, interval {unit_interval}, agg parameter {:?}",
                    batch_unit_aggregations.len(),
                    self.task_id,
                    self.aggregation_param,
                )));
            }

            if let Some(batch_unit_aggregation) = batch_unit_aggregations.first_mut() {
                debug!(
                    unit_interval_start = ?unit_interval.start(),
                    "accumulating into existing batch_unit_aggregation_row",
                );
                batch_unit_aggregation
                    .aggregate_share
                    .merge(&accumulate.aggregate_share)
                    .map_err(|e| datastore::Error::User(e.into()))?;
                batch_unit_aggregation.report_count += accumulate.report_count;
                batch_unit_aggregation.checksum.combine(accumulate.checksum);

                tx.update_batch_unit_aggregation(&batch_unit_aggregations[0])
                    .await?;
            } else {
                debug!(
                    unit_interval_start = ?unit_interval.start(),
                    "inserting new batch_unit_aggregation row",
                );
                tx.put_batch_unit_aggregation::<A>(&BatchUnitAggregation {
                    task_id: self.task_id,
                    unit_interval_start: unit_interval.start(),
                    aggregation_param: self.aggregation_param.clone(),
                    aggregate_share: accumulate.aggregate_share,
                    report_count: accumulate.report_count,
                    checksum: accumulate.checksum,
                })
                .await?;
            }
        }

        Ok(())
    }
}
