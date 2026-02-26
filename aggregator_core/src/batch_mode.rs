use std::iter;

use async_trait::async_trait;
use futures::future::try_join_all;
use janus_core::time::Clock;
use janus_messages::{
    Interval, Query, TaskId, Time,
    batch_mode::{BatchMode, LeaderSelected, TimeInterval},
};

use crate::{
    AsyncAggregator,
    datastore::{
        self, Transaction,
        models::{BatchAggregation, CollectionJob},
    },
    task::AggregatorTask,
};

#[async_trait]
pub trait AccumulableBatchMode: BatchMode {
    /// This method converts various values related to a client report into a batch identifier. The
    /// arguments are somewhat arbitrary in the sense they are what "works out" to allow the
    /// necessary functionality to be implemented for all batch modes.
    fn to_batch_identifier(
        _: &Self::PartialBatchIdentifier,
        client_timestamp: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error>;

    /// Retrieves collection jobs which include the given batch identifier.
    async fn get_collection_jobs_including<
        const SEED_SIZE: usize,
        C: Clock,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        task_id: &TaskId,
        batch_identifier: &Self::BatchIdentifier,
    ) -> Result<Vec<CollectionJob<SEED_SIZE, Self, A>>, datastore::Error>;

    /// Some batch modes (e.g. [`TimeInterval`]) can represent their batch identifiers as an
    /// interval. This method extracts the interval from such identifiers, or returns `None` if the
    /// batch mode does not represent batch identifiers as an interval.
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
impl AccumulableBatchMode for TimeInterval {
    fn to_batch_identifier(
        _: &Self::PartialBatchIdentifier,
        client_timestamp: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error> {
        Interval::minimal(*client_timestamp).map_err(|e| datastore::Error::User(e.into()))
    }

    async fn get_collection_jobs_including<
        const SEED_SIZE: usize,
        C: Clock,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        task_id: &TaskId,
        batch_identifier: &Self::BatchIdentifier,
    ) -> Result<Vec<CollectionJob<SEED_SIZE, Self, A>>, datastore::Error> {
        tx.get_collection_jobs_intersecting_interval(vdaf, task_id, batch_identifier)
            .await
    }

    fn to_batch_interval(collection_identifier: &Self::BatchIdentifier) -> Option<&Interval> {
        Some(collection_identifier)
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
impl AccumulableBatchMode for LeaderSelected {
    fn to_batch_identifier(
        batch_id: &Self::PartialBatchIdentifier,
        _: &Time,
    ) -> Result<Self::BatchIdentifier, datastore::Error> {
        Ok(*batch_id)
    }

    async fn get_collection_jobs_including<
        const SEED_SIZE: usize,
        C: Clock,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        task_id: &TaskId,
        batch_id: &Self::BatchIdentifier,
    ) -> Result<Vec<CollectionJob<SEED_SIZE, Self, A>>, datastore::Error> {
        tx.get_collection_jobs_by_batch_id(vdaf, task_id, batch_id)
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

/// CollectableBatchMode represents a batch mode that can be collected by Janus. This trait extends
/// [`AccumulableBatchMode`] with additional functionality required for collection.
#[async_trait]
pub trait CollectableBatchMode: AccumulableBatchMode {
    type Iter: Iterator<Item = Self::BatchIdentifier> + Send + Sync + Clone;

    /// Retrieves the batch identifier for a given query.
    async fn collection_identifier_for_query<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &AggregatorTask,
        query: &Query<Self>,
    ) -> Result<Option<Self::BatchIdentifier>, datastore::Error>;

    /// Some batch modes (e.g. [`TimeInterval`]) can receive a batch identifier in collection
    /// requests which refers to multiple batches. This method takes a batch identifier received in
    /// a collection request and provides an iterator over the individual batches' identifiers.
    fn batch_identifiers_for_collection_identifier(
        collection_identifier: &Self::BatchIdentifier,
    ) -> Self::Iter;

    /// Validates a collection identifier, per the boundary checks in
    /// <https://www.ietf.org/archive/id/draft-ietf-ppm-dap-16.html#section-4.7.1>.
    fn validate_collection_identifier(collection_identifier: &Self::BatchIdentifier) -> bool;

    /// Returns the number of client reports included in the given collection identifier, whether
    /// they have been aggregated or not.
    async fn count_client_reports<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &AggregatorTask,
        collection_identifier: &Self::BatchIdentifier,
    ) -> Result<u64, datastore::Error>;

    /// Retrieves batch aggregations corresponding to all batches identified by the given collection
    /// identifier.
    async fn get_batch_aggregations_for_collection_identifier<
        const SEED_SIZE: usize,
        A: AsyncAggregator<SEED_SIZE>,
        C: Clock,
    >(
        tx: &Transaction<C>,
        task_id: &TaskId,
        vdaf: &A,
        collection_identifier: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<Vec<BatchAggregation<SEED_SIZE, Self, A>>, datastore::Error> {
        Ok(try_join_all(
            Self::batch_identifiers_for_collection_identifier(collection_identifier).map(
                |batch_identifier| {
                    let task_id = *task_id;
                    let aggregation_param = aggregation_param.clone();

                    async move {
                        tx.get_batch_aggregations_for_batch(
                            vdaf,
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

    /// Retrieves the number of aggregation jobs created & terminated for all batches identified by
    /// the given collection identifier.
    async fn get_batch_aggregation_job_count_for_collection_identifier<
        const SEED_SIZE: usize,
        A: AsyncAggregator<SEED_SIZE>,
        C: Clock,
    >(
        tx: &Transaction<C>,
        task_id: &TaskId,
        collection_identifier: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<(u64, u64), datastore::Error> {
        Ok(try_join_all(
            Self::batch_identifiers_for_collection_identifier(collection_identifier).map(
                |batch_identifier| {
                    let task_id = *task_id;
                    let aggregation_param = aggregation_param.clone();

                    async move {
                        tx.get_batch_aggregation_job_count_for_batch::<SEED_SIZE, Self, A>(
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
        .fold((0, 0), |(lc, lt), (rc, rt)| (lc + rc, lt + rt)))
    }
}

#[async_trait]
impl CollectableBatchMode for TimeInterval {
    type Iter = TimeIntervalBatchIdentifierIter;

    async fn collection_identifier_for_query<C: Clock>(
        _: &Transaction<'_, C>,
        _: &AggregatorTask,
        query: &Query<Self>,
    ) -> Result<Option<Self::BatchIdentifier>, datastore::Error> {
        Ok(Some(*query.batch_interval()))
    }

    fn batch_identifiers_for_collection_identifier(
        batch_interval: &Self::BatchIdentifier,
    ) -> Self::Iter {
        TimeIntervalBatchIdentifierIter::new(batch_interval)
    }

    fn validate_collection_identifier(collection_identifier: &Self::BatchIdentifier) -> bool {
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-16.html#section-4.7.1

        // Batch interval should be greater than task's time precision.
        collection_identifier.duration().as_time_precision_units() >= 1
    }

    async fn count_client_reports<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &AggregatorTask,
        batch_interval: &Self::BatchIdentifier,
    ) -> Result<u64, datastore::Error> {
        tx.count_client_reports_for_interval(task.id(), batch_interval)
            .await
    }
}

// This type only exists because the CollectableBatchMode trait requires specifying the type of the
// iterator explicitly (i.e. it cannot be inferred or replaced with an `impl Trait` expression), and
// the type of the iterator created via method chaining does not have a type which is expressible.
#[derive(Clone)]
pub struct TimeIntervalBatchIdentifierIter {
    step: u64,
    total_step_count: u64,
    start: Time,
}

impl TimeIntervalBatchIdentifierIter {
    fn new(batch_interval: &Interval) -> Self {
        Self {
            step: 0,
            total_step_count: batch_interval.duration().as_time_precision_units(),
            start: batch_interval.start(),
        }
    }
}

impl Iterator for TimeIntervalBatchIdentifierIter {
    type Item = Interval;

    fn next(&mut self) -> Option<Self::Item> {
        if self.step == self.total_step_count {
            return None;
        }
        let position = self.start.as_time_precision_units() + self.step;
        self.step += 1;
        Interval::minimal(Time::from_time_precision_units(position)).ok()
    }
}

#[async_trait]
impl CollectableBatchMode for LeaderSelected {
    type Iter = iter::Once<Self::BatchIdentifier>;

    async fn collection_identifier_for_query<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &AggregatorTask,
        _: &Query<Self>,
    ) -> Result<Option<Self::BatchIdentifier>, datastore::Error> {
        tx.acquire_outstanding_batch_with_report_count(task.id(), task.min_batch_size())
            .await
    }

    fn batch_identifiers_for_collection_identifier(batch_id: &Self::BatchIdentifier) -> Self::Iter {
        iter::once(*batch_id)
    }

    fn validate_collection_identifier(_: &Self::BatchIdentifier) -> bool {
        true
    }

    async fn count_client_reports<C: Clock>(
        tx: &Transaction<'_, C>,
        task: &AggregatorTask,
        batch_id: &Self::BatchIdentifier,
    ) -> Result<u64, datastore::Error> {
        tx.count_client_reports_for_batch_id(task.id(), batch_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use janus_messages::{Duration, Interval, Time, batch_mode::TimeInterval};

    use crate::batch_mode::CollectableBatchMode;

    #[test]
    fn reject_null_collection_intervals() {
        assert!(!TimeInterval::validate_collection_identifier(
            &Interval::new(Time::from_time_precision_units(0), Duration::ZERO).unwrap()
        ));

        assert!(TimeInterval::validate_collection_identifier(
            &Interval::new(
                Time::from_time_precision_units(0),
                Duration::from_time_precision_units(1)
            )
            .unwrap()
        ));
    }
}
