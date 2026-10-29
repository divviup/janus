use async_trait::async_trait;
use janus_aggregator_core::{
    AsyncAggregator,
    batch_mode::{AccumulableBatchMode, CollectableBatchMode as CoreCollectableBatchMode},
    datastore::{
        self, Transaction,
        models::{ExpirableCollectionJob, LeaderStoredReport},
    },
    task::AggregatorTask,
};
use janus_messages::{
    Query, Role,
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
    /// Validates query count for a given batch, per the size checks in
    /// <https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6>.
    ///
    /// This method is exclusively used in the Helper's aggregate share handler. Once that moves to
    /// draft-ietf-ppm-dap-20 style, server selected identifier handling, usage of this method will
    /// be replaced with calls to a new method aggregate_share_jobs_intersecting_query and this
    /// method will be deleted.
    async fn validate_query_count<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        batch_identifier: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<(), datastore::Error>;

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
        request: &Query<Self>,
    ) -> Result<
        impl Iterator<Item = ExpirableCollectionJob<SEED_SIZE, Self, A>> + Send + Sync,
        datastore::Error,
    >
    where
        A: AsyncAggregator<SEED_SIZE>;
}

#[async_trait]
impl CollectableBatchMode for TimeInterval {
    async fn validate_query_count<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        collect_interval: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<(), datastore::Error> {
        // Compute the aggregation parameters that have already been collected for.
        let mut found_overlapping_nonequal_interval = false;
        let agg_params: Vec<_> = match task.role() {
            Role::Leader => tx
                .get_collection_jobs_intersecting_interval::<SEED_SIZE, A>(
                    vdaf,
                    task.id(),
                    collect_interval,
                )
                .await?
                .into_iter()
                .map(|job| {
                    if job.job().batch_interval() != collect_interval {
                        found_overlapping_nonequal_interval = true;
                    }
                    job.take_job().take_aggregation_parameter()
                })
                .collect(),

            Role::Helper => tx
                .get_aggregate_share_jobs_intersecting_interval::<SEED_SIZE, A>(
                    vdaf,
                    task.id(),
                    collect_interval,
                )
                .await?
                .into_iter()
                .map(|job| {
                    if job.batch_interval() != collect_interval {
                        found_overlapping_nonequal_interval = true;
                    };
                    job.take_aggregation_parameter()
                })
                .collect(),

            _ => panic!("Unexpected task role {:?}", task.role()),
        };

        // Check that all intersecting collect intervals are equal to this collect interval.
        if found_overlapping_nonequal_interval {
            return Err(datastore::Error::User(
                Error::BatchOverlap(*task.id()).into(),
            ));
        }

        // Check that the batch has not already been queried with a distinct aggregation parameter.
        if agg_params
            .iter()
            .any(|agg_param| agg_param != aggregation_param)
        {
            return Err(datastore::Error::User(
                Error::InvalidMessage(
                    Some(*task.id()),
                    "batch has already been collected with another aggregation parameter",
                )
                .into(),
            ));
        }
        Ok(())
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
    async fn validate_query_count<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        tx: &Transaction<'_>,
        vdaf: &A,
        task: &AggregatorTask,
        batch_id: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<(), datastore::Error> {
        // Compute the aggregation parameters that have already been collected for.
        let agg_params: Vec<_> = match task.role() {
            Role::Leader => tx
                .get_collection_jobs_by_batch_id::<SEED_SIZE, A>(vdaf, task.id(), batch_id)
                .await?
                .into_iter()
                .map(|job| job.take_aggregation_parameter())
                .collect(),

            Role::Helper => tx
                .get_aggregate_share_jobs_by_batch_id::<SEED_SIZE, A>(vdaf, task.id(), batch_id)
                .await?
                .into_iter()
                .map(|job| job.take_aggregation_parameter())
                .collect(),

            _ => panic!("Unexpected task role {:?}", task.role()),
        };

        // Check that the batch has not already been queried with a distinct aggregation parameter.
        if agg_params
            .iter()
            .any(|agg_param| agg_param != aggregation_param)
        {
            return Err(datastore::Error::User(
                Error::InvalidMessage(
                    Some(*task.id()),
                    "batch has already been collected with another aggregation parameter",
                )
                .into(),
            ));
        }
        Ok(())
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
