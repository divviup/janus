//! Implements functionality for computing & validating aggregate shares.

use std::{borrow::Cow, collections::HashMap};

use itertools::iproduct;
use janus_aggregator_core::{
    AsyncAggregator,
    batch_mode::CollectableBatchMode,
    datastore::{
        self,
        models::{BatchAggregation, BatchAggregationState},
    },
    task::AggregatorTask,
};
use janus_core::{report_id::ReportIdChecksumExt, time::IntervalExt as _};
use janus_messages::{Interval, ReportIdChecksum, TaskId, batch_mode::BatchMode};
use prio::vdaf::Aggregatable;

use super::Error;

/// Computes the aggregate share over the provided batch aggregations.
///
/// The assumption is that all aggregation jobs contributing to those batch aggregations have been
/// driven to completion, and that the query count requirements have been validated for the included
/// batches.
#[derive(Clone, Debug)]
pub(crate) struct AggregateShareComputer<'a, const SEED_SIZE: usize, A>
where
    A: AsyncAggregator<SEED_SIZE>,
{
    task: &'a AggregatorTask,
    total_report_count: u64,
    client_timestamp_interval: Interval,
    total_checksum: ReportIdChecksum,
    total_aggregate_share: Option<A::AggregateShare>,
}

#[derive(Clone, Debug)]
pub(crate) struct AggregateShareComputerResult<AggregateShare> {
    pub report_count: u64,
    pub client_timestamp_interval: Interval,
    pub checksum: ReportIdChecksum,
    pub aggregate_share: AggregateShare,
}

impl<'a, const SEED_SIZE: usize, A> AggregateShareComputer<'a, SEED_SIZE, A>
where
    A: AsyncAggregator<SEED_SIZE>,
{
    /// Creates a new aggregate share computer.
    pub(crate) fn new(task: &'a AggregatorTask) -> Self {
        Self {
            task,
            total_report_count: 0,
            client_timestamp_interval: Interval::EMPTY,
            total_checksum: ReportIdChecksum::default(),
            total_aggregate_share: None,
        }
    }

    /// Compute an aggregate share over the provided batch aggregations.
    pub(crate) fn oneshot<B, I>(
        &mut self,
        batch_aggregations: I,
    ) -> Result<AggregateShareComputerResult<A::AggregateShare>, Error>
    where
        B: BatchMode,
        I: IntoIterator<Item = &'a BatchAggregation<SEED_SIZE, B, A>>,
    {
        for ba in batch_aggregations.into_iter() {
            self.update(ba)?;
        }

        self.finalize()
    }

    /// Update the computer with a single [`BatchAggregation`]. Call [`finalize`] to obtain the
    /// aggregate share.
    pub(crate) fn update<B: BatchMode>(
        &mut self,
        batch_aggregation: &BatchAggregation<SEED_SIZE, B, A>,
    ) -> Result<(), Error> {
        // At the moment we construct an aggregate share (either handling AggregateShareReq in the
        // helper or driving a collection job in the leader), there could be some incomplete
        // aggregation jobs whose results not been accumulated into the batch aggregations we just
        // queried from the datastore, meaning we will aggregate over an incomplete view of data,
        // which:
        //
        //  * reduces fidelity of the resulting aggregates,
        //  * could cause us to fail to meet the minimum batch size for the task,
        //  * or for particularly pathological timing, could cause us to aggregate a different set
        //    of reports than the leader did (though the checksum will detect this).
        //
        // There's not much the helper can do about this, because an aggregate job might be
        // unfinished because it's waiting on an aggregate sub-protocol message that is never coming
        // because the leader has abandoned that job. Thus the helper has no choice but to assume
        // that any unfinished aggregation jobs were intentionally abandoned by the leader (see
        // issue #104 for more discussion).
        //
        // On the leader side, we know/assume that we would not be stepping a collection job unless
        // we had verified that the constituent aggregation jobs were finished.
        //
        // In either case, we go ahead and service the aggregate share request with whatever batch
        // aggregations are available now.
        let (aggregate_share, report_count, checksum) = match batch_aggregation.state() {
            BatchAggregationState::Aggregating {
                aggregate_share,
                report_count,
                checksum,
                ..
            } => (aggregate_share, report_count, checksum),
            BatchAggregationState::Collected {
                aggregate_share,
                report_count,
                checksum,
                ..
            } => (aggregate_share, report_count, checksum),
            BatchAggregationState::Scrubbed => {
                return Err(Error::Datastore(datastore::Error::Scrubbed));
            }
        };

        // Merge the intervals spanned by the constituent batch aggregations into the interval
        // spanned by the collection.
        self.client_timestamp_interval = self
            .client_timestamp_interval
            .merge(batch_aggregation.client_timestamp_interval())?;

        // XOR this batch interval's checksum into the overall checksum
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.2
        self.total_checksum = self.total_checksum.combined_with(checksum);

        // Sum all the report counts
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.2
        self.total_report_count += *report_count;

        match &mut self.total_aggregate_share {
            Some(share) => {
                aggregate_share
                    .as_ref()
                    .map(|other| share.merge(other))
                    .transpose()?;
            }
            None => self.total_aggregate_share.clone_from(aggregate_share),
        }

        Ok(())
    }

    pub(crate) fn finalize(
        &self,
    ) -> Result<AggregateShareComputerResult<A::AggregateShare>, Error> {
        // Only happens if there were no batch aggregations, which would get caught by the
        // min_batch_size check below, but we have to unwrap the option.
        let aggregate_share = self
            .total_aggregate_share
            .clone()
            .ok_or_else(|| Error::InvalidBatchSize(*self.task.id(), self.total_report_count))?;

        // Validate batch size per
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
        if !self.task.validate_batch_size(self.total_report_count) {
            return Err(Error::InvalidBatchSize(
                *self.task.id(),
                self.total_report_count,
            ));
        }

        Ok(AggregateShareComputerResult {
            report_count: self.total_report_count,
            client_timestamp_interval: self.client_timestamp_interval,
            checksum: self.total_checksum,
            aggregate_share,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BatchAggregationsKey<BI> {
    batch_identifier: BI,
    ord: u64,
}

#[derive(Clone)]
pub(crate) struct BatchAggregationsIterator<
    'a,
    const SEED_SIZE: usize,
    B: CollectableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
> {
    expected_batch_aggregations: itertools::Product<B::Iter, std::ops::Range<u64>>,
    real_batch_aggregations: HashMap<
        BatchAggregationsKey<B::BatchIdentifier>,
        Cow<'a, BatchAggregation<SEED_SIZE, B, A>>,
    >,
    task_id: TaskId,
    aggregation_param: A::AggregationParam,
}

impl<'a, const SEED_SIZE: usize, B, A> BatchAggregationsIterator<'a, SEED_SIZE, B, A>
where
    B: CollectableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    pub(crate) fn new<
        InputIterator: IntoIterator<Item = Cow<'a, BatchAggregation<SEED_SIZE, B, A>>>,
    >(
        task: &AggregatorTask,
        batch_aggregation_shard_count: u64,
        batch_identifier: &B::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
        real_batch_aggregations: InputIterator,
    ) -> Self {
        // Construct iterator over all possible batch aggregations for the collection identifier.
        let expected_batch_aggregations = iproduct!(
            B::batch_identifiers_for_collection_identifier(batch_identifier),
            0..batch_aggregation_shard_count
        );

        Self {
            expected_batch_aggregations,
            real_batch_aggregations: HashMap::from_iter(real_batch_aggregations.into_iter().map(
                |ba| {
                    (
                        BatchAggregationsKey {
                            batch_identifier: ba.batch_identifier().clone(),
                            ord: ba.ord(),
                        },
                        ba,
                    )
                },
            )),
            task_id: *task.id(),
            aggregation_param: aggregation_param.clone(),
        }
    }
}

impl<'a, const SEED_SIZE: usize, B, A> Iterator for BatchAggregationsIterator<'a, SEED_SIZE, B, A>
where
    B: CollectableBatchMode,
    A: AsyncAggregator<SEED_SIZE>,
{
    // The iterator yields a tuple of the BatchAggregation and a boolean indicating whether it's
    // real or a synthetic, empty BA.
    type Item = (Cow<'a, BatchAggregation<SEED_SIZE, B, A>>, bool);

    fn next(&mut self) -> Option<Self::Item> {
        // See what the next (batch_identifier, ord) we want to yield is
        let key = self
            .expected_batch_aggregations
            .next()
            .map(|(batch_identifier, ord)| BatchAggregationsKey {
                batch_identifier,
                ord,
            })?;

        // If we have a real BA for that key, yield it, removing it from the HashMap. If the value
        // is Cow::Owned, this saves us a Clone, and as this iterator gets consumed, the value
        // can't be yielded again anyway.
        self.real_batch_aggregations
            .remove(&key)
            .map(|real_ba| (real_ba, true))
            .or_else(|| {
                // If there was no real BA, synthesize an empty one. This is why we have to yield a
                // Cow in the other case: we can't instantiate a struct BatchAggregation here and
                // return `&BatchAggregation`.
                Some((
                    Cow::Owned(BatchAggregation::<SEED_SIZE, B, A>::new(
                        self.task_id,
                        key.batch_identifier,
                        self.aggregation_param.clone(),
                        key.ord,
                        Interval::EMPTY,
                        BatchAggregationState::Collected {
                            aggregate_share: None,
                            report_count: 0,
                            checksum: ReportIdChecksum::default(),
                            aggregation_jobs_created: 0,
                            aggregation_jobs_terminated: 0,
                        },
                    )),
                    false,
                ))
            })
    }
}
