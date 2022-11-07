use crate::{
    datastore::{self, models::BatchAggregation, Transaction},
    messages::TimeExt as _,
    task::Task,
};
use async_trait::async_trait;
use futures::future::try_join_all;
use janus_core::time::{Clock, TimeExt as _};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    Duration, Interval, Time,
};
use prio::vdaf;
use std::iter;

pub trait AccumulableQueryType: QueryType {
    /// This method converts various values related to a client report into a batch identifier. The
    /// arguments are somewhat arbitrary in the sense they are what "works out" to allow the
    /// necessary functionality to be implemented for all query types.
    fn to_batch_identifier(
        _: &Task,
        _: &Self::PartialBatchIdentifier,
        client_timestamp: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error>;
}

impl AccumulableQueryType for TimeInterval {
    fn to_batch_identifier(
        task: &Task,
        _: &Self::PartialBatchIdentifier,
        client_timestamp: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error> {
        let batch_interval_start = client_timestamp
            .to_batch_interval_start(task.time_precision())
            .map_err(|e| datastore::Error::User(e.into()))?;
        Interval::new(batch_interval_start, *task.time_precision())
            .map_err(|e| datastore::Error::User(e.into()))
    }
}

impl AccumulableQueryType for FixedSize {
    fn to_batch_identifier(
        _: &Task,
        batch_id: &Self::PartialBatchIdentifier,
        _: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error> {
        Ok(*batch_id)
    }
}

/// CollectableQueryType represents a query type that can be collected by Janus. This trait extends
/// [`QueryType`] with functionality required for collection.
#[async_trait]
pub trait CollectableQueryType: QueryType {
    type Iter: Iterator<Item = Self::BatchIdentifier> + Send + Sync;

    /// Some query types (e.g. [`TimeInterval`]) can receive a batch identifier in collect requests
    /// which refers to multiple batches. This method takes a batch identifier received in a collect
    /// request and provides an iterator over the individual batches' identifiers.
    fn batch_identifiers_for_collect_identifier(
        _: &Task,
        collect_identifier: &Self::BatchIdentifier,
    ) -> Self::Iter;

    /// Retrieves batch aggregations corresponding to all batches identified by the given collect
    /// identifier.
    async fn get_batch_aggregations_for_collect_identifier<
        const L: usize,
        A: vdaf::Aggregator<L>,
        C: Clock,
    >(
        tx: &Transaction<C>,
        task: &Task,
        collect_identifier: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<Vec<BatchAggregation<L, Self, A>>, datastore::Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        let batch_aggregations = try_join_all(
            Self::batch_identifiers_for_collect_identifier(task, collect_identifier).map(
                |batch_identifier| {
                    let (task_id, aggregation_param) = (*task.id(), aggregation_param.clone());
                    async move {
                        tx.get_batch_aggregation(&task_id, &batch_identifier, &aggregation_param)
                            .await
                    }
                },
            ),
        )
        .await?;
        Ok(batch_aggregations.into_iter().flatten().collect::<Vec<_>>())
    }
}

impl CollectableQueryType for TimeInterval {
    type Iter = TimeIntervalBatchIdentifierIter;

    fn batch_identifiers_for_collect_identifier(
        task: &Task,
        batch_interval: &Self::BatchIdentifier,
    ) -> Self::Iter {
        TimeIntervalBatchIdentifierIter::new(task, batch_interval)
    }
}

// This type only exists because the CollectableQueryType trait requires specifying the type of the
// iterator explicitly (i.e. it cannot be inferred or replaced with an `impl Trait` expression), and
// the type of the iterator created via method chaining does not have a type which is expressible.
pub struct TimeIntervalBatchIdentifierIter {
    step: u64,

    total_step_count: u64,
    start: Time,
    time_precision: Duration,
}

impl TimeIntervalBatchIdentifierIter {
    fn new(task: &Task, batch_interval: &Interval) -> Self {
        // Sanity check that the given interval is of an appropriate length. We use an assert as
        // this is expected to be checked before this method is used.
        assert_eq!(
            batch_interval.duration().as_seconds() % task.time_precision().as_seconds(),
            0
        );
        let total_step_count =
            batch_interval.duration().as_seconds() / task.time_precision().as_seconds();

        Self {
            step: 0,
            total_step_count,
            start: *batch_interval.start(),
            time_precision: *task.time_precision(),
        }
    }
}

impl Iterator for TimeIntervalBatchIdentifierIter {
    type Item = Interval;

    fn next(&mut self) -> Option<Self::Item> {
        if self.step == self.total_step_count {
            return None;
        }
        // Unwrap safety: errors can only occur if the times being unwrapped cannot be represented
        // as a Time. The relevant times can always be represented since they are internal to the
        // batch interval used to create the iterator.
        let interval = Interval::new(
            self.start
                .add(&Duration::from_seconds(
                    self.step * self.time_precision.as_seconds(),
                ))
                .unwrap(),
            self.time_precision,
        )
        .unwrap();
        self.step += 1;
        Some(interval)
    }
}

impl CollectableQueryType for FixedSize {
    type Iter = iter::Once<Self::BatchIdentifier>;

    fn batch_identifiers_for_collect_identifier(
        _: &Task,
        batch_id: &Self::BatchIdentifier,
    ) -> Self::Iter {
        iter::once(*batch_id)
    }
}
