use super::Error;
use crate::{
    datastore::{
        self,
        models::{AggregateShareJob, BatchAggregation, LeaderStoredReport},
        Transaction,
    },
    messages::TimeExt as _,
    task::Task,
};
use async_trait::async_trait;
use futures::future::try_join_all;
use janus_core::time::{Clock, TimeExt as _};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    Duration, FixedSizeQuery, Interval, Query, ReportMetadata, Role, TaskId, Time,
};
use prio::vdaf;
use std::iter;

#[async_trait]
pub trait UploadableQueryType: QueryType {
    async fn validate_uploaded_report<const L: usize, C: Clock, A: vdaf::Aggregator<L>>(
        tx: &Transaction<'_, C>,
        report: &LeaderStoredReport<L, A>,
    ) -> Result<(), datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::InputShare: Send + Sync,
        A::PublicShare: Send + Sync;
}

#[async_trait]
impl UploadableQueryType for TimeInterval {
    async fn validate_uploaded_report<const L: usize, C: Clock, A: vdaf::Aggregator<L>>(
        tx: &Transaction<'_, C>,
        report: &LeaderStoredReport<L, A>,
    ) -> Result<(), datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::InputShare: Send + Sync,
        A::PublicShare: Send + Sync,
    {
        // Reject reports whose timestamps fall into a batch interval that has already been
        // collected.
        // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-03#section-4.3.2-17
        let conflicting_collect_jobs = tx
            .get_collection_jobs_including_time::<L, A>(report.task_id(), report.metadata().time())
            .await?;
        if !conflicting_collect_jobs.is_empty() {
            return Err(datastore::Error::User(
                Error::ReportRejected(
                    *report.task_id(),
                    *report.metadata().id(),
                    *report.metadata().time(),
                )
                .into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl UploadableQueryType for FixedSize {
    async fn validate_uploaded_report<const L: usize, C: Clock, A: vdaf::Aggregator<L>>(
        _: &Transaction<'_, C>,
        _: &LeaderStoredReport<L, A>,
    ) -> Result<(), datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        // Fixed-size tasks associate reports to batches at time of aggregation rather than at time
        // of upload, and there are no other relevant checks to apply here, so this method simply
        // returns Ok(()).
        Ok(())
    }
}

#[async_trait]
pub trait AccumulableQueryType: QueryType {
    /// This method converts various values related to a client report into a batch identifier. The
    /// arguments are somewhat arbitrary in the sense they are what "works out" to allow the
    /// necessary functionality to be implemented for all query types.
    fn to_batch_identifier(
        _: &Task,
        _: &Self::PartialBatchIdentifier,
        client_timestamp: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error>;

    async fn get_conflicting_aggregate_share_jobs<
        const L: usize,
        C: Clock,
        A: vdaf::Aggregator<L>,
    >(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
        partial_batch_identifier: &Self::PartialBatchIdentifier,
        report_metadata: &ReportMetadata,
    ) -> Result<Vec<AggregateShareJob<L, Self, A>>, datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>;

    /// Some query types (e.g. [`TimeInterval`]) can represent their batch identifiers as an
    /// interval. This method extracts the interval from such identifiers, or returns `None` if the
    /// query type does not represent batch identifiers as an interval.
    fn to_batch_interval(batch_identifier: &Self::BatchIdentifier) -> Option<&Interval>;

    /// Downgrade a batch identifier into a partial batch identifier.
    fn downgrade_batch_identifier(
        batch_identifier: &Self::BatchIdentifier,
    ) -> &Self::PartialBatchIdentifier;

    /// Upgrade a partial batch identifier into a batch identifier, if possible.
    fn upgrade_partial_batch_identifier(
        partial_batch_identifier: &Self::PartialBatchIdentifier,
    ) -> Option<&Self::BatchIdentifier>;

    /// Get the default value of the partial batch identifier, if applicable.
    fn default_partial_batch_identifier() -> Option<&'static Self::PartialBatchIdentifier>;
}

#[async_trait]
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

    async fn get_conflicting_aggregate_share_jobs<
        const L: usize,
        C: Clock,
        A: vdaf::Aggregator<L>,
    >(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
        _: &Self::PartialBatchIdentifier,
        report_metadata: &ReportMetadata,
    ) -> Result<Vec<AggregateShareJob<L, Self, A>>, datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        tx.get_aggregate_share_jobs_including_time::<L, A>(task_id, report_metadata.time())
            .await
    }

    fn to_batch_interval(collect_identifier: &Self::BatchIdentifier) -> Option<&Interval> {
        Some(collect_identifier)
    }

    fn downgrade_batch_identifier(
        _batch_identifier: &Self::BatchIdentifier,
    ) -> &Self::PartialBatchIdentifier {
        &()
    }

    fn upgrade_partial_batch_identifier(
        _partial_batch_identifier: &Self::PartialBatchIdentifier,
    ) -> Option<&Self::BatchIdentifier> {
        None
    }

    fn default_partial_batch_identifier() -> Option<&'static Self::PartialBatchIdentifier> {
        Some(&())
    }
}

#[async_trait]
impl AccumulableQueryType for FixedSize {
    fn to_batch_identifier(
        _: &Task,
        batch_id: &Self::PartialBatchIdentifier,
        _: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error> {
        Ok(*batch_id)
    }

    async fn get_conflicting_aggregate_share_jobs<
        const L: usize,
        C: Clock,
        A: vdaf::Aggregator<L>,
    >(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
        batch_id: &Self::PartialBatchIdentifier,
        _: &ReportMetadata,
    ) -> Result<Vec<AggregateShareJob<L, Self, A>>, datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        tx.get_aggregate_share_jobs_by_batch_identifier(task_id, batch_id)
            .await
    }

    fn to_batch_interval(_: &Self::BatchIdentifier) -> Option<&Interval> {
        None
    }

    fn downgrade_batch_identifier(
        batch_identifier: &Self::BatchIdentifier,
    ) -> &Self::PartialBatchIdentifier {
        batch_identifier
    }

    fn upgrade_partial_batch_identifier(
        partial_batch_identifier: &Self::PartialBatchIdentifier,
    ) -> Option<&Self::BatchIdentifier> {
        Some(partial_batch_identifier)
    }

    fn default_partial_batch_identifier() -> Option<&'static Self::PartialBatchIdentifier> {
        None
    }
}

/// CollectableQueryType represents a query type that can be collected by Janus. This trait extends
/// [`AccumulableQueryType`] with additional functionality required for collection.
#[async_trait]
pub trait CollectableQueryType: AccumulableQueryType {
    type Iter: Iterator<Item = Self::BatchIdentifier> + Send + Sync;

    /// Retrieves the batch identifier for a given query.
    async fn batch_identifier_for_query<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &Task,
        query: &Query<Self>,
    ) -> Result<Option<Self::BatchIdentifier>, datastore::Error>;

    /// Some query types (e.g. [`TimeInterval`]) can receive a batch identifier in collect requests
    /// which refers to multiple batches. This method takes a batch identifier received in a collect
    /// request and provides an iterator over the individual batches' identifiers.
    fn batch_identifiers_for_collect_identifier(
        _: &Task,
        collect_identifier: &Self::BatchIdentifier,
    ) -> Self::Iter;

    /// Validates a collect identifier, per the boundary checks in
    /// <https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6>.
    fn validate_collect_identifier(task: &Task, collect_identifier: &Self::BatchIdentifier)
        -> bool;

    /// Validates query count for a given batch, per the size checks in
    /// <https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6>.
    async fn validate_query_count<const L: usize, C: Clock, A: vdaf::Aggregator<L>>(
        tx: &Transaction<'_, C>,
        task: &Task,
        batch_identifier: &Self::BatchIdentifier,
    ) -> Result<(), datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>;

    /// Returns the number of client reports included in the given collect identifier, whether they
    /// have been aggregated or not.
    async fn count_client_reports<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &Task,
        collect_identifier: &Self::BatchIdentifier,
    ) -> Result<u64, datastore::Error>;

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
        Ok(try_join_all(
            Self::batch_identifiers_for_collect_identifier(task, collect_identifier).map(
                |batch_identifier| {
                    let (task_id, aggregation_param) = (*task.id(), aggregation_param.clone());
                    async move {
                        tx.get_batch_aggregations_for_batch(
                            &task_id,
                            &batch_identifier,
                            &aggregation_param,
                        )
                        .await
                    }
                },
            ),
        )
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>())
    }

    /// Acknowledges that a collection attempt has been made, allowing any query-type specific
    /// updates to be made. For exmaple, a task using fixed-size queries might remove the given
    /// batch to be removed from the list of batches ready to be returned by a `current-batch`
    /// query.
    async fn acknowledge_collection<C: Clock>(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
        batch_identifier: &Self::BatchIdentifier,
    ) -> Result<(), datastore::Error>;
}

#[async_trait]
impl CollectableQueryType for TimeInterval {
    type Iter = TimeIntervalBatchIdentifierIter;

    async fn batch_identifier_for_query<C: Clock>(
        _: &Transaction<'_, C>,
        _: &Task,
        query: &Query<Self>,
    ) -> Result<Option<Self::BatchIdentifier>, datastore::Error> {
        Ok(Some(*query.batch_interval()))
    }

    fn batch_identifiers_for_collect_identifier(
        task: &Task,
        batch_interval: &Self::BatchIdentifier,
    ) -> Self::Iter {
        TimeIntervalBatchIdentifierIter::new(task, batch_interval)
    }

    fn validate_collect_identifier(
        task: &Task,
        collect_identifier: &Self::BatchIdentifier,
    ) -> bool {
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6.1.1

        // Batch interval should be greater than task's time precision
        collect_identifier.duration().as_seconds() >= task.time_precision().as_seconds()
                // Batch interval start must be a multiple of time precision
                && collect_identifier.start().as_seconds_since_epoch() % task.time_precision().as_seconds() == 0
                // Batch interval duration must be a multiple of time precision
                && collect_identifier.duration().as_seconds() % task.time_precision().as_seconds() == 0
    }

    async fn validate_query_count<const L: usize, C: Clock, A: vdaf::Aggregator<L>>(
        tx: &Transaction<'_, C>,
        task: &Task,
        collect_interval: &Self::BatchIdentifier,
    ) -> Result<(), datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        // Check how many rows in the relevant table have an intersecting batch interval.
        // Each such row consumes one unit of query count.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
        let intersecting_intervals: Vec<_> = match task.role() {
            Role::Leader => tx
                .get_collection_jobs_intersecting_interval::<L, A>(task.id(), collect_interval)
                .await?
                .into_iter()
                .map(|job| *job.batch_interval())
                .collect(),

            Role::Helper => tx
                .get_aggregate_share_jobs_intersecting_interval::<L, A>(task.id(), collect_interval)
                .await?
                .into_iter()
                .map(|job| *job.batch_interval())
                .collect(),

            _ => panic!("Unexpected task role {:?}", task.role()),
        };

        // Check that all intersecting collect intervals are equal to this collect interval.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6-5
        if intersecting_intervals
            .iter()
            .any(|interval| interval != collect_interval)
        {
            return Err(datastore::Error::User(
                Error::BatchOverlap(*task.id(), *collect_interval).into(),
            ));
        }

        // Check that the batch query count is being consumed appropriately.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
        let max_batch_query_count: usize = task.max_batch_query_count().try_into()?;
        if intersecting_intervals.len() >= max_batch_query_count {
            return Err(datastore::Error::User(
                Error::BatchQueriedTooManyTimes(*task.id(), intersecting_intervals.len() as u64)
                    .into(),
            ));
        }
        Ok(())
    }

    async fn count_client_reports<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &Task,
        batch_interval: &Self::BatchIdentifier,
    ) -> Result<u64, datastore::Error> {
        tx.count_client_reports_for_interval(task.id(), batch_interval)
            .await
    }

    async fn acknowledge_collection<C: Clock>(
        _: &Transaction<'_, C>,
        _: &TaskId,
        _: &Self::BatchIdentifier,
    ) -> Result<(), datastore::Error> {
        Ok(()) // Purposeful no-op.
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

#[async_trait]
impl CollectableQueryType for FixedSize {
    type Iter = iter::Once<Self::BatchIdentifier>;

    async fn batch_identifier_for_query<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &Task,
        query: &Query<Self>,
    ) -> Result<Option<Self::BatchIdentifier>, datastore::Error> {
        match query.fixed_size_query() {
            FixedSizeQuery::ByBatchId { batch_id } => Ok(Some(*batch_id)),
            FixedSizeQuery::CurrentBatch => {
                tx.get_filled_outstanding_batch(task.id(), task.min_batch_size())
                    .await
            }
        }
    }

    fn batch_identifiers_for_collect_identifier(
        _: &Task,
        batch_id: &Self::BatchIdentifier,
    ) -> Self::Iter {
        iter::once(*batch_id)
    }

    fn validate_collect_identifier(_: &Task, _: &Self::BatchIdentifier) -> bool {
        true
    }

    async fn validate_query_count<const L: usize, C: Clock, A: vdaf::Aggregator<L>>(
        tx: &Transaction<'_, C>,
        task: &Task,
        batch_id: &Self::BatchIdentifier,
    ) -> Result<(), datastore::Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let query_count = match task.role() {
            Role::Leader => tx
                .get_collection_jobs_by_batch_identifier::<L, FixedSize, A>(task.id(), batch_id)
                .await?
                .len(),

            Role::Helper => tx
                .get_aggregate_share_jobs_by_batch_identifier::<L, FixedSize, A>(
                    task.id(),
                    batch_id,
                )
                .await?
                .len(),

            _ => panic!("Unexpected task role {:?}", task.role()),
        };

        // Check that the batch query count is being consumed appropriately.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
        let max_batch_query_count: usize = task.max_batch_query_count().try_into()?;
        if query_count >= max_batch_query_count {
            return Err(datastore::Error::User(
                Error::BatchQueriedTooManyTimes(*task.id(), query_count as u64).into(),
            ));
        }
        Ok(())
    }

    async fn count_client_reports<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &Task,
        batch_id: &Self::BatchIdentifier,
    ) -> Result<u64, datastore::Error> {
        tx.count_client_reports_for_batch_id(task.id(), batch_id)
            .await
    }

    async fn acknowledge_collection<C: Clock>(
        tx: &Transaction<'_, C>,
        task_id: &TaskId,
        batch_identifier: &Self::BatchIdentifier,
    ) -> Result<(), datastore::Error> {
        tx.delete_outstanding_batch(task_id, batch_identifier).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregator::query_type::CollectableQueryType,
        task::{test_util::TaskBuilder, QueryType},
    };
    use janus_core::task::VdafInstance;
    use janus_messages::{query_type::TimeInterval, Duration, Interval, Role, Time};

    #[test]
    fn validate_collect_identifier() {
        let time_precision_secs = 3600;
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
            .with_time_precision(Duration::from_seconds(time_precision_secs))
            .build();

        struct TestCase {
            name: &'static str,
            input: Interval,
            expected: bool,
        }

        for test_case in Vec::from([
            TestCase {
                name: "same duration as minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(time_precision_secs),
                    Duration::from_seconds(time_precision_secs),
                )
                .unwrap(),
                expected: true,
            },
            TestCase {
                name: "interval too short",
                input: Interval::new(
                    Time::from_seconds_since_epoch(time_precision_secs),
                    Duration::from_seconds(time_precision_secs - 1),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                name: "interval larger than minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(time_precision_secs),
                    Duration::from_seconds(time_precision_secs * 2),
                )
                .unwrap(),
                expected: true,
            },
            TestCase {
                name: "interval duration not aligned with minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(time_precision_secs),
                    Duration::from_seconds(time_precision_secs + 1800),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                name: "interval start not aligned with minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(1800),
                    Duration::from_seconds(time_precision_secs),
                )
                .unwrap(),
                expected: false,
            },
        ]) {
            assert_eq!(
                test_case.expected,
                TimeInterval::validate_collect_identifier(&task, &test_case.input),
                "test case: {}",
                test_case.name
            );
        }
    }
}
