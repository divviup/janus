use super::{
    error::{ReportRejection, ReportRejectionReason},
    Error,
};
use async_trait::async_trait;
use janus_aggregator_core::{
    batch_mode::{AccumulableBatchMode, CollectableBatchMode as CoreCollectableBatchMode},
    datastore::{self, models::LeaderStoredReport, Transaction},
    task::AggregatorTask,
};
use janus_core::time::Clock;
use janus_messages::{
    batch_mode::{BatchMode, LeaderSelected, TimeInterval},
    Role,
};
use prio::vdaf;
use std::hash::Hash;

#[async_trait]
pub trait UploadableBatchMode: BatchMode {
    async fn validate_uploaded_report<
        const SEED_SIZE: usize,
        C: Clock,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        report: &LeaderStoredReport<SEED_SIZE, A>,
    ) -> Result<(), Error>
    where
        A::InputShare: Send + Sync,
        A::PublicShare: Send + Sync;
}

#[async_trait]
impl UploadableBatchMode for TimeInterval {
    async fn validate_uploaded_report<
        const SEED_SIZE: usize,
        C: Clock,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        report: &LeaderStoredReport<SEED_SIZE, A>,
    ) -> Result<(), Error>
    where
        A::InputShare: Send + Sync,
        A::PublicShare: Send + Sync,
    {
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
    async fn validate_uploaded_report<
        const SEED_SIZE: usize,
        C: Clock,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    >(
        _: &Transaction<'_, C>,
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
    async fn validate_query_count<
        const SEED_SIZE: usize,
        C: Clock,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        task: &AggregatorTask,
        batch_identifier: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<(), datastore::Error>
    where
        A::AggregationParam: Send + Sync + Eq + Hash;
}

#[async_trait]
impl CollectableBatchMode for TimeInterval {
    async fn validate_query_count<
        const SEED_SIZE: usize,
        C: Clock,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        task: &AggregatorTask,
        collect_interval: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<(), datastore::Error>
    where
        A::AggregationParam: Send + Sync + Eq + Hash,
    {
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
                    if job.batch_interval() != collect_interval {
                        found_overlapping_nonequal_interval = true;
                    }
                    job.take_aggregation_parameter()
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
                Error::BatchOverlap(*task.id(), *collect_interval).into(),
            ));
        }

        // Check that the batch has not already been queried with a distinct aggregation parameter.
        if agg_params
            .iter()
            .any(|agg_param| agg_param != aggregation_param)
        {
            return Err(datastore::Error::User(
                Error::BatchQueriedMultipleTimes(*task.id()).into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl CollectableBatchMode for LeaderSelected {
    async fn validate_query_count<
        const SEED_SIZE: usize,
        C: Clock,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync,
    >(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        task: &AggregatorTask,
        batch_id: &Self::BatchIdentifier,
        aggregation_param: &A::AggregationParam,
    ) -> Result<(), datastore::Error>
    where
        A::AggregationParam: Send + Sync + Eq + Hash,
    {
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
                Error::BatchQueriedMultipleTimes(*task.id()).into(),
            ));
        }
        Ok(())
    }
}
