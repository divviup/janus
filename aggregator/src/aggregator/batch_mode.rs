use async_trait::async_trait;
use janus_aggregator_core::{
    AsyncAggregator,
    batch_mode::{AccumulableBatchMode, CollectableBatchMode as CoreCollectableBatchMode},
    datastore::{
        self, Transaction,
        models::{ExpirableAggregateShareJob, ExpirableCollectionJob, LeaderStoredReport},
    },
    task::AggregatorTask,
};
use janus_messages::{
    BatchId, Interval, Query,
    batch_mode::{BatchMode, LeaderSelected, TimeInterval},
};

use super::{
    Error,
    error::{ReportRejection, ReportRejectionReason},
};

#[async_trait]
pub trait UploadableBatchMode: BatchMode {
    async fn validate_uploaded_report<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        tx: &Transaction<'_>,
        vdaf: &A,
        report: &LeaderStoredReport<SEED_SIZE, A>,
    ) -> Result<(), Error>;
}

#[async_trait]
impl UploadableBatchMode for TimeInterval {
    async fn validate_uploaded_report<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        tx: &Transaction<'_>,
        vdaf: &A,
        report: &LeaderStoredReport<SEED_SIZE, A>,
    ) -> Result<(), Error> {
        // Reject reports whose timestamps fall into a batch interval that has already been
        // collected.
        // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-03#section-4.3.2-17
        let conflicting_collect_jobs = tx
            .get_collection_jobs_including_time::<SEED_SIZE, A>(
                vdaf,
                report.task_id(),
                report.metadata().time(),
            )
            .await?;
        if !conflicting_collect_jobs.is_empty() {
            return Err(Error::ReportRejected(ReportRejection::new(
                *report.task_id(),
                *report.metadata().id(),
                *report.metadata().time(),
                ReportRejectionReason::IntervalCollected,
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl UploadableBatchMode for LeaderSelected {
    async fn validate_uploaded_report<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        _: &Transaction<'_>,
        _: &A,
        _: &LeaderStoredReport<SEED_SIZE, A>,
    ) -> Result<(), Error> {
        // Leader-selected tasks associate reports to batches at time of aggregation rather than at
        // time of upload, and there are no other relevant checks to apply here, so this method
        // simply returns Ok(()).
        Ok(())
    }
}

/// CollectableBatchMode represents a batch mode that can be collected by Janus. This trait extends
/// [`AccumulableBatchMode`] with additional functionality required for collection.
#[async_trait]
pub trait CollectableBatchMode: CoreCollectableBatchMode + AccumulableBatchMode {
    /// Find any aggregate share jobs that intersect with the batch identifier.
    ///
    /// The iterator yields aggregate share jobs and booleans indicating whether the job is expired.
    ///
    /// For time interval batch mode, multiple aggregate share jobs could have queries that overlap
    /// with the time interval. For leader selected batch mode, the identifier is a batch ID, so
    /// only zero or one aggregate share jobs will ever be returned.
    async fn aggregate_share_jobs_intersecting_batch_identifier<const SEED_SIZE: usize, A>(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        batch_identifier: &Self::BatchIdentifier,
    ) -> Result<
        impl Iterator<Item = ExpirableAggregateShareJob<SEED_SIZE, Self, A>> + Send + Sync,
        datastore::Error,
    >
    where
        A: AsyncAggregator<SEED_SIZE>;

    /// Find any collection jobs that intersect with the query.
    ///
    /// The iterator yields collection jobs.
    ///
    /// For time interval batch mode, multiple collection jobs could have queries that overlap with
    /// the query's time interval. For leader selected batch mode, the query is a batch ID, so only
    /// zero or one collection job will ever be returned.
    async fn collection_jobs_intersecting_query<const SEED_SIZE: usize, A>(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        query: &Query<Self>,
    ) -> Result<
        impl Iterator<Item = ExpirableCollectionJob<SEED_SIZE, Self, A>> + Send + Sync,
        datastore::Error,
    >
    where
        A: AsyncAggregator<SEED_SIZE>;
}

#[async_trait]
impl CollectableBatchMode for TimeInterval {
    async fn aggregate_share_jobs_intersecting_batch_identifier<const SEED_SIZE: usize, A>(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        batch_identifier: &Interval,
    ) -> Result<
        impl Iterator<Item = ExpirableAggregateShareJob<SEED_SIZE, Self, A>> + Send + Sync,
        datastore::Error,
    >
    where
        A: AsyncAggregator<SEED_SIZE>,
    {
        Ok(tx
            .get_aggregate_share_jobs_intersecting_interval(vdaf, task.id(), batch_identifier)
            .await?
            .into_iter())
    }

    async fn collection_jobs_intersecting_query<
        const SEED_SIZE: usize,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        query: &Query<Self>,
    ) -> Result<
        impl Iterator<Item = ExpirableCollectionJob<SEED_SIZE, Self, A>> + Send + Sync,
        datastore::Error,
    > {
        Ok(tx
            .get_collection_jobs_intersecting_interval(vdaf, task.id(), query.query_body())
            .await?
            .into_iter())
    }
}

#[async_trait]
impl CollectableBatchMode for LeaderSelected {
    async fn aggregate_share_jobs_intersecting_batch_identifier<const SEED_SIZE: usize, A>(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        batch_id: &BatchId,
    ) -> Result<
        impl Iterator<Item = ExpirableAggregateShareJob<SEED_SIZE, Self, A>> + Send + Sync,
        datastore::Error,
    >
    where
        A: AsyncAggregator<SEED_SIZE>,
    {
        Ok(tx
            .get_aggregate_share_jobs_by_batch_id(vdaf, task.id(), batch_id)
            .await?
            .into_iter())
    }

    async fn collection_jobs_intersecting_query<
        const SEED_SIZE: usize,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        query: &Query<Self>,
    ) -> Result<
        impl Iterator<Item = ExpirableCollectionJob<SEED_SIZE, Self, A>> + Send + Sync,
        datastore::Error,
    > {
        Ok(tx
            .get_collection_job_by_query(vdaf, task.id(), query)
            .await?
            .into_iter())
    }
}
