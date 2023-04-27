use anyhow::{Context, Result};
use futures::future::join_all;
use janus_aggregator_core::{datastore::Datastore, task::Task};
use janus_core::time::{Clock, TimeExt};
use std::sync::Arc;
use tracing::error;

pub struct GarbageCollector<C: Clock> {
    // Dependencies.
    datastore: Arc<Datastore<C>>,
    clock: C,
}

impl<C: Clock> GarbageCollector<C> {
    pub fn new(datastore: Arc<Datastore<C>>, clock: C) -> Self {
        Self { datastore, clock }
    }

    #[tracing::instrument(skip(self))]
    pub async fn run(&self) -> Result<()> {
        // TODO(#224): add support for handling only a subset of tasks in a single job (i.e. sharding).

        // Retrieve tasks.
        let tasks = self
            .datastore
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .context("couldn't retrieve tasks")?;

        // Run GC for each task.
        join_all(tasks.into_iter().map(|task| async move {
            let task = Arc::new(task);
            if let Err(err) = self.gc_task(Arc::clone(&task)).await {
                error!(task_id = ?task.id(), ?err, "Couldn't GC task");
            }
        }))
        .await;
        Ok(())
    }

    async fn gc_task(&self, task: Arc<Task>) -> Result<()> {
        let oldest_allowed_report_timestamp =
            if let Some(report_expiry_age) = task.report_expiry_age() {
                self.clock.now().sub(report_expiry_age)?
            } else {
                // No configured report expiry age -- nothing to GC.
                return Ok(());
            };

        self.datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    // Find and delete old collection jobs.
                    tx.delete_expired_collection_artifacts(
                        task.id(),
                        oldest_allowed_report_timestamp,
                    )
                    .await?;

                    // Find and delete old aggregation jobs/report aggregations/batch aggregations.
                    tx.delete_expired_aggregation_artifacts(
                        task.id(),
                        oldest_allowed_report_timestamp,
                    )
                    .await?;

                    // Find and delete old client reports.
                    tx.delete_expired_client_reports(task.id(), oldest_allowed_report_timestamp)
                        .await?;

                    Ok(())
                })
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::garbage_collector::GarbageCollector;
    use janus_aggregator_core::{
        datastore::{
            models::{
                AggregateShareJob, AggregationJob, AggregationJobState, BatchAggregation,
                BatchAggregationState, CollectionJob, CollectionJobState, LeaderStoredReport,
                ReportAggregation, ReportAggregationState,
            },
            test_util::ephemeral_datastore,
        },
        task::{self, test_util::TaskBuilder},
    };
    use janus_core::{
        task::VdafInstance,
        test_util::{
            dummy_vdaf::{self, AggregateShare, AggregationParam},
            install_test_trace_subscriber,
        },
        time::{Clock, IntervalExt, MockClock, TimeExt},
    };
    use janus_messages::{
        query_type::{FixedSize, TimeInterval},
        AggregationJobRound, Duration, HpkeCiphertext, HpkeConfigId, Interval, ReportMetadata,
        ReportShare, Role,
    };
    use rand::random;
    use std::sync::Arc;

    #[tokio::test]
    async fn gc_task_leader_time_interval() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_tx(|tx| {
                let (clock, vdaf) = (clock.clone(), vdaf.clone());
                Box::pin(async move {
                    const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(3600);
                    let task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                    .build();
                    tx.put_task(&task).await?;

                    let client_timestamp = clock
                        .now()
                        .sub(&REPORT_EXPIRY_AGE)
                        .unwrap()
                        .sub(&Duration::from_seconds(1))
                        .unwrap();
                    let report = LeaderStoredReport::new_dummy(*task.id(), client_timestamp);
                    tx.put_client_report(&vdaf, &report).await.unwrap();

                    let batch_identifier =
                        Interval::new(client_timestamp, Duration::from_seconds(1)).unwrap();
                    let aggregation_job = AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        (),
                        batch_identifier,
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );
                    tx.put_aggregation_job(&aggregation_job).await.unwrap();

                    let report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job.id(),
                        *report.metadata().id(),
                        client_timestamp,
                        0,
                        None,
                        ReportAggregationState::Start,
                    );
                    tx.put_report_aggregation(&report_aggregation)
                        .await
                        .unwrap();

                    let batch_aggregation = BatchAggregation::new(
                        *task.id(),
                        batch_identifier,
                        AggregationParam(0),
                        0,
                        BatchAggregationState::Collected,
                        Some(AggregateShare(11)),
                        1,
                        Interval::from_time(&client_timestamp).unwrap(),
                        random(),
                    );
                    tx.put_batch_aggregation::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &batch_aggregation,
                    )
                    .await
                    .unwrap();

                    let collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        batch_identifier,
                        AggregationParam(0),
                        CollectionJobState::Start,
                    );
                    tx.put_collection_job(&collection_job).await.unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(Arc::clone(&ds), clock.clone())
            .gc_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (
            client_reports,
            aggregation_jobs,
            report_aggregations,
            batch_aggregations,
            collection_jobs,
        ) = ds
            .run_tx(|tx| {
                let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    let client_reports = tx
                        .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                        .await?;
                    let aggregation_jobs = tx
                        .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            task.id(),
                        )
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            task.id(),
                        )
                        .await?;
                    let batch_aggregations = tx
                        .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;
                    let collection_jobs = tx
                        .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;

                    Ok((
                        client_reports,
                        aggregation_jobs,
                        report_aggregations,
                        batch_aggregations,
                        collection_jobs,
                    ))
                })
            })
            .await
            .unwrap();
        assert!(client_reports.is_empty());
        assert!(aggregation_jobs.is_empty());
        assert!(report_aggregations.is_empty());
        assert!(batch_aggregations.is_empty());
        assert!(collection_jobs.is_empty());
    }

    #[tokio::test]
    async fn gc_task_helper_time_interval() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                Box::pin(async move {
                    const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(3600);
                    let task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Helper,
                    )
                    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                    .build();
                    tx.put_task(&task).await?;

                    let client_timestamp = clock
                        .now()
                        .sub(&REPORT_EXPIRY_AGE)
                        .unwrap()
                        .sub(&Duration::from_seconds(1))
                        .unwrap();
                    let report_share = ReportShare::new(
                        ReportMetadata::new(random(), client_timestamp),
                        Vec::new(),
                        HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("encapsulated_context_0"),
                            Vec::from("payload_0"),
                        ),
                    );
                    tx.put_report_share(task.id(), &report_share).await.unwrap();

                    let batch_identifier =
                        Interval::new(client_timestamp, Duration::from_seconds(1)).unwrap();
                    let aggregation_job = AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        (),
                        batch_identifier,
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );
                    tx.put_aggregation_job(&aggregation_job).await.unwrap();

                    let report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job.id(),
                        *report_share.metadata().id(),
                        client_timestamp,
                        0,
                        None,
                        ReportAggregationState::Start,
                    );
                    tx.put_report_aggregation(&report_aggregation)
                        .await
                        .unwrap();

                    let batch_aggregation = BatchAggregation::new(
                        *task.id(),
                        batch_identifier,
                        AggregationParam(0),
                        0,
                        BatchAggregationState::Collected,
                        Some(AggregateShare(11)),
                        1,
                        Interval::from_time(&client_timestamp).unwrap(),
                        random(),
                    );
                    tx.put_batch_aggregation::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &batch_aggregation,
                    )
                    .await
                    .unwrap();

                    let aggregate_share_job = AggregateShareJob::new(
                        *task.id(),
                        batch_identifier,
                        AggregationParam(0),
                        AggregateShare(11),
                        1,
                        random(),
                    );
                    tx.put_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &aggregate_share_job,
                    )
                    .await
                    .unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(Arc::clone(&ds), clock.clone())
            .gc_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (
            client_reports,
            aggregation_jobs,
            report_aggregations,
            batch_aggregations,
            aggregate_share_jobs,
        ) = ds
            .run_tx(|tx| {
                let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    let client_reports = tx
                        .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                        .await?;
                    let aggregation_jobs = tx
                        .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            task.id(),
                        )
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            task.id(),
                        )
                        .await?;
                    let batch_aggregations = tx
                        .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;
                    let aggregate_share_jobs = tx
                        .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;

                    Ok((
                        client_reports,
                        aggregation_jobs,
                        report_aggregations,
                        batch_aggregations,
                        aggregate_share_jobs,
                    ))
                })
            })
            .await
            .unwrap();
        assert!(client_reports.is_empty());
        assert!(aggregation_jobs.is_empty());
        assert!(report_aggregations.is_empty());
        assert!(batch_aggregations.is_empty());
        assert!(aggregate_share_jobs.is_empty());
    }

    #[tokio::test]
    async fn gc_task_leader_fixed_size() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_tx(|tx| {
                let (clock, vdaf) = (clock.clone(), vdaf.clone());
                Box::pin(async move {
                    const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(3600);
                    let task = TaskBuilder::new(
                        task::QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                    .build();
                    tx.put_task(&task).await?;

                    let client_timestamp = clock
                        .now()
                        .sub(&REPORT_EXPIRY_AGE)
                        .unwrap()
                        .sub(&Duration::from_seconds(1))
                        .unwrap();
                    let report = LeaderStoredReport::new_dummy(*task.id(), client_timestamp);
                    tx.put_client_report(&vdaf, &report).await.unwrap();

                    let batch_identifier = random();
                    let aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        batch_identifier,
                        Interval::new(client_timestamp, Duration::from_seconds(1)).unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );
                    tx.put_aggregation_job(&aggregation_job).await.unwrap();

                    let report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job.id(),
                        *report.metadata().id(),
                        client_timestamp,
                        0,
                        None,
                        ReportAggregationState::Start,
                    );
                    tx.put_report_aggregation(&report_aggregation)
                        .await
                        .unwrap();

                    let batch_aggregation = BatchAggregation::new(
                        *task.id(),
                        batch_identifier,
                        AggregationParam(0),
                        0,
                        BatchAggregationState::Collected,
                        Some(AggregateShare(11)),
                        1,
                        Interval::from_time(&client_timestamp).unwrap(),
                        random(),
                    );
                    tx.put_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(&batch_aggregation)
                        .await
                        .unwrap();

                    let collection_job = CollectionJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        batch_identifier,
                        AggregationParam(0),
                        CollectionJobState::Start,
                    );
                    tx.put_collection_job(&collection_job).await.unwrap();

                    tx.put_outstanding_batch(task.id(), &batch_identifier)
                        .await
                        .unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(Arc::clone(&ds), clock.clone())
            .gc_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (
            client_reports,
            aggregation_jobs,
            report_aggregations,
            batch_aggregations,
            collection_jobs,
            outstanding_batches,
        ) = ds
            .run_tx(|tx| {
                let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    let client_reports = tx
                        .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                        .await?;
                    let aggregation_jobs = tx
                        .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(task.id())
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            task.id(),
                        )
                        .await?;
                    let batch_aggregations = tx
                        .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;
                    let collection_jobs = tx
                        .get_collection_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;
                    let outstanding_batches =
                        tx.get_outstanding_batches_for_task(task.id()).await?;

                    Ok((
                        client_reports,
                        aggregation_jobs,
                        report_aggregations,
                        batch_aggregations,
                        collection_jobs,
                        outstanding_batches,
                    ))
                })
            })
            .await
            .unwrap();
        assert!(client_reports.is_empty());
        assert!(aggregation_jobs.is_empty());
        assert!(report_aggregations.is_empty());
        assert!(batch_aggregations.is_empty());
        assert!(collection_jobs.is_empty());
        assert!(outstanding_batches.is_empty());
    }

    #[tokio::test]
    async fn gc_task_helper_fixed_size() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                Box::pin(async move {
                    const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(3600);
                    let task = TaskBuilder::new(
                        task::QueryType::FixedSize { max_batch_size: 10 },
                        VdafInstance::Fake,
                        Role::Helper,
                    )
                    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                    .build();
                    tx.put_task(&task).await?;

                    let client_timestamp = clock
                        .now()
                        .sub(&REPORT_EXPIRY_AGE)
                        .unwrap()
                        .sub(&Duration::from_seconds(1))
                        .unwrap();
                    let report_share = ReportShare::new(
                        ReportMetadata::new(random(), client_timestamp),
                        Vec::new(),
                        HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("encapsulated_context_0"),
                            Vec::from("payload_0"),
                        ),
                    );
                    tx.put_report_share(task.id(), &report_share).await.unwrap();

                    let batch_identifier = random();
                    let aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        batch_identifier,
                        Interval::new(client_timestamp, Duration::from_seconds(1)).unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );
                    tx.put_aggregation_job(&aggregation_job).await.unwrap();

                    let report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job.id(),
                        *report_share.metadata().id(),
                        client_timestamp,
                        0,
                        None,
                        ReportAggregationState::Start,
                    );
                    tx.put_report_aggregation(&report_aggregation)
                        .await
                        .unwrap();

                    let batch_aggregation = BatchAggregation::new(
                        *task.id(),
                        batch_identifier,
                        AggregationParam(0),
                        0,
                        BatchAggregationState::Collected,
                        Some(AggregateShare(11)),
                        1,
                        Interval::from_time(&client_timestamp).unwrap(),
                        random(),
                    );
                    tx.put_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(&batch_aggregation)
                        .await
                        .unwrap();

                    let aggregate_share_job = AggregateShareJob::new(
                        *task.id(),
                        batch_identifier,
                        AggregationParam(0),
                        AggregateShare(11),
                        1,
                        random(),
                    );
                    tx.put_aggregate_share_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &aggregate_share_job,
                    )
                    .await
                    .unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(Arc::clone(&ds), clock.clone())
            .gc_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (
            client_reports,
            aggregation_jobs,
            report_aggregations,
            batch_aggregations,
            aggregate_share_jobs,
        ) = ds
            .run_tx(|tx| {
                let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    let client_reports = tx
                        .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                        .await?;
                    let aggregation_jobs = tx
                        .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(task.id())
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            task.id(),
                        )
                        .await?;
                    let batch_aggregations = tx
                        .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;
                    let aggregate_share_jobs = tx
                        .get_aggregate_share_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                            &vdaf,
                            task.id(),
                        )
                        .await?;

                    Ok((
                        client_reports,
                        aggregation_jobs,
                        report_aggregations,
                        batch_aggregations,
                        aggregate_share_jobs,
                    ))
                })
            })
            .await
            .unwrap();
        assert!(client_reports.is_empty());
        assert!(aggregation_jobs.is_empty());
        assert!(report_aggregations.is_empty());
        assert!(batch_aggregations.is_empty());
        assert!(aggregate_share_jobs.is_empty());
    }
}
