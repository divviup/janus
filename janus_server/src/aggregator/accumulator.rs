//! In-memory accumulation of output shares.

use super::Error;
use crate::datastore::{self, models::BatchUnitAggregation, Transaction};
use derivative::Derivative;
use janus_core::{
    report_id::ReportIdChecksumExt,
    time::{Clock, TimeExt},
};
use janus_messages::{Duration, Interval, ReportId, ReportIdChecksum, TaskId, Time};
use prio::vdaf::{self, Aggregatable};
use std::collections::HashMap;
use tracing::debug;

#[derive(Derivative)]
#[derivative(Debug)]
struct Accumulation<const L: usize, A: vdaf::Aggregator<L>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    #[derivative(Debug = "ignore")]
    aggregate_share: A::AggregateShare,
    report_count: u64,
    checksum: ReportIdChecksum,
}

impl<const L: usize, A: vdaf::Aggregator<L>> Accumulation<L, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    fn update(&mut self, output_share: &A::OutputShare, report_id: &ReportId) -> Result<(), Error> {
        self.aggregate_share.accumulate(output_share)?;
        self.report_count += 1;
        self.checksum = self.checksum.updated_with(report_id);

        Ok(())
    }
}

/// Accumulates output shares in memory and eventually flushes accumulations to a datastore. Janus'
/// leader aligns aggregate jobs with batch unit intervals, but this is not generally required for
/// DAP implementations, so we accumulate output shares into a HashMap mapping the Time at which the
/// batch unit interval begins to the accumulated aggregate share, report count and checksum.
#[derive(Derivative)]
#[derivative(Debug)]
pub(super) struct Accumulator<const L: usize, A: vdaf::Aggregator<L>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    task_id: TaskId,
    min_batch_duration: Duration,
    #[derivative(Debug = "ignore")]
    aggregation_param: A::AggregationParam,
    accumulations: HashMap<Time, Accumulation<L, A>>,
}

impl<const L: usize, A: vdaf::Aggregator<L>> Accumulator<L, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
{
    /// Create a new accumulator
    pub(super) fn new(
        task_id: TaskId,
        min_batch_duration: Duration,
        aggregation_param: A::AggregationParam,
    ) -> Self {
        Self {
            task_id,
            min_batch_duration,
            aggregation_param,
            accumulations: HashMap::new(),
        }
    }

    /// Update the in-memory accumulators with the provided output share and report timestamp.
    pub(super) fn update(
        &mut self,
        output_share: &A::OutputShare,
        report_time: &Time,
        report_id: &ReportId,
    ) -> Result<(), datastore::Error> {
        let key = report_time
            .to_batch_unit_interval_start(&self.min_batch_duration)
            .map_err(|e| datastore::Error::User(e.into()))?;
        if let Some(accumulation) = self.accumulations.get_mut(&key) {
            accumulation
                .update(output_share, report_id)
                .map_err(|e| datastore::Error::User(e.into()))?;
        } else {
            self.accumulations.insert(
                key,
                Accumulation {
                    aggregate_share: A::AggregateShare::from(output_share.clone()),
                    report_count: 1,
                    checksum: ReportIdChecksum::for_report_id(report_id),
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
        &self,
        tx: &Transaction<'_, C>,
    ) -> Result<(), datastore::Error> {
        for (unit_interval_start, accumulation) in &self.accumulations {
            let unit_interval = Interval::new(*unit_interval_start, self.min_batch_duration)?;

            let batch_unit_aggregations = tx
                .get_batch_unit_aggregations_for_task_in_interval::<L, A>(
                    &self.task_id,
                    &unit_interval,
                    &self.aggregation_param,
                )
                .await?;

            if batch_unit_aggregations.len() > 1 {
                return Err(datastore::Error::DbState(format!(
                    "found {} batch unit aggregation rows for task {}, interval {unit_interval}",
                    batch_unit_aggregations.len(),
                    self.task_id,
                )));
            }

            if let Some(batch_unit_aggregation) = batch_unit_aggregations.into_iter().next() {
                debug!(
                    unit_interval_start = ?unit_interval.start(),
                    "accumulating into existing batch_unit_aggregation_row",
                );
                tx.update_batch_unit_aggregation(&batch_unit_aggregation.merged_with(
                    &accumulation.aggregate_share,
                    accumulation.report_count,
                    &accumulation.checksum,
                )?)
                .await?;
            } else {
                debug!(
                    unit_interval_start = ?unit_interval.start(),
                    "inserting new batch_unit_aggregation row",
                );
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<L, A>::new(
                    self.task_id,
                    *unit_interval.start(),
                    self.aggregation_param.clone(),
                    accumulation.aggregate_share.clone(),
                    accumulation.report_count,
                    accumulation.checksum,
                ))
                .await?;
            }
        }

        Ok(())
    }
}
