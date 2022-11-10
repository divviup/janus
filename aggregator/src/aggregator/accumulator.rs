//! In-memory accumulation of output shares.

use super::{query_type::AccumulableQueryType, Error};
use crate::{
    datastore::{self, gather_errors, models::BatchAggregation, Transaction},
    task::Task,
};
use derivative::Derivative;
use futures::future::join_all;
use janus_core::{report_id::ReportIdChecksumExt, time::Clock};
use janus_messages::{ReportId, ReportIdChecksum, Time};
use prio::vdaf::{self, Aggregatable};
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
    #[derivative(Debug = "ignore")]
    aggregation_param: A::AggregationParam,
    accumulations: HashMap<Q::BatchIdentifier, Accumulation<L, A>>,
}

impl<'t, const L: usize, Q: AccumulableQueryType, A: vdaf::Aggregator<L>> Accumulator<L, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    /// Create a new accumulator
    pub fn new(task: Arc<Task>, aggregation_param: A::AggregationParam) -> Self {
        Self {
            task,
            aggregation_param,
            accumulations: HashMap::new(),
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
        // This slightly-awkward usage of `rslt` is due to the Entry API not having a fallible
        // interface -- we need some way to smuggle an error out of `and_modify`.
        let mut rslt = Ok(());
        self.accumulations
            .entry(batch_identifier)
            .and_modify(|acc| {
                rslt = acc
                    .update(report_id, output_share)
                    .map_err(|err| datastore::Error::User(err.into()))
            })
            .or_insert_with(|| Accumulation {
                aggregate_share: A::AggregateShare::from(output_share.clone()),
                report_count: 1,
                checksum: ReportIdChecksum::for_report_id(report_id),
            });
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
        gather_errors(
            join_all(self.accumulations.iter().map(
                |(batch_identifier, accumulation)| async move {
                    let batch_aggregation = tx
                        .get_batch_aggregation::<L, Q, A>(
                            self.task.id(),
                            batch_identifier,
                            &self.aggregation_param,
                        )
                        .await?;
                    match batch_aggregation {
                        Some(batch_aggregation) => {
                            tx.update_batch_aggregation(&batch_aggregation.merged_with(
                                &accumulation.aggregate_share,
                                accumulation.report_count,
                                &accumulation.checksum,
                            )?)
                            .await?;
                        }
                        None => {
                            tx.put_batch_aggregation(&BatchAggregation::<L, Q, A>::new(
                                *self.task.id(),
                                batch_identifier.clone(),
                                self.aggregation_param.clone(),
                                accumulation.aggregate_share.clone(),
                                accumulation.report_count,
                                accumulation.checksum,
                            ))
                            .await?;
                        }
                    }
                    Ok::<(), datastore::Error>(())
                },
            ))
            .await,
        )?;
        Ok(())
    }
}

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
    #[allow(clippy::result_large_err)]
    fn update(&mut self, report_id: &ReportId, output_share: &A::OutputShare) -> Result<(), Error> {
        self.aggregate_share.accumulate(output_share)?;
        self.report_count += 1;
        self.checksum = self.checksum.updated_with(report_id);
        Ok(())
    }
}
