use anyhow::{Context, Result};
use futures::future::join_all;
use janus_aggregator_core::{datastore::Datastore, task::AggregatorTask};
use janus_core::time::Clock;
use std::sync::Arc;
use tokio::try_join;
use tracing::error;

pub struct GarbageCollector<C: Clock> {
    // Dependencies.
    datastore: Arc<Datastore<C>>,

    // Configuration.
    report_limit: u64,
    aggregation_limit: u64,
    collection_limit: u64,
}

impl<C: Clock> GarbageCollector<C> {
    pub fn new(
        datastore: Arc<Datastore<C>>,
        report_limit: u64,
        aggregation_limit: u64,
        collection_limit: u64,
    ) -> Self {
        Self {
            datastore,
            report_limit,
            aggregation_limit,
            collection_limit,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn run(&self) -> Result<()> {
        // TODO(#224): add support for handling only a subset of tasks in a single job (i.e. sharding).

        // Retrieve tasks.
        let tasks = self
            .datastore
            .run_tx("garbage_collector_get_tasks", |tx| {
                Box::pin(async move { tx.get_aggregator_tasks().await })
            })
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

    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    async fn gc_task(&self, task: Arc<AggregatorTask>) -> Result<()> {
        self.datastore
            .run_tx("garbage_collector", |tx| {
                let task = Arc::clone(&task);
                let report_limit = self.report_limit;
                let aggregation_limit = self.aggregation_limit;
                let collection_limit = self.collection_limit;

                Box::pin(async move {
                    try_join!(
                        tx.delete_expired_client_reports(task.id(), report_limit),
                        tx.delete_expired_aggregation_artifacts(task.id(), aggregation_limit),
                        tx.delete_expired_collection_artifacts(task.id(), collection_limit),
                    )?;
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
                AggregateShareJob, AggregationJob, AggregationJobState, Batch, BatchAggregation,
                BatchAggregationState, BatchState, CollectionJob, CollectionJobState,
                LeaderStoredReport, ReportAggregation, ReportAggregationState,
            },
            test_util::ephemeral_datastore,
        },
        task::{self, test_util::TaskBuilder},
    };
    use janus_core::{
        test_util::{
            dummy_vdaf::{self, AggregateShare, AggregationParam},
            install_test_trace_subscriber,
        },
        time::{Clock, IntervalExt, MockClock, TimeExt},
        vdaf::VdafInstance,
    };
    use janus_messages::{
        query_type::{FixedSize, TimeInterval},
        AggregationJobStep, Duration, FixedSizeQuery, HpkeCiphertext, HpkeConfigId, Interval,
        Query, ReportIdChecksum, ReportMetadata, ReportShare, Role, Time,
    };
    use rand::random;
    use std::sync::Arc;

    const OLDEST_ALLOWED_REPORT_TIMESTAMP: Time = Time::from_seconds_since_epoch(1000);
    const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(500);

    #[tokio::test]
    async fn gc_task_leader_time_interval() {
        install_test_trace_subscriber();

        let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_unnamed_tx(|tx| {
                let (clock, vdaf) = (clock.clone(), vdaf.clone());
                Box::pin(async move {
                    let task = TaskBuilder::new(task::QueryType::TimeInterval, VdafInstance::Fake)
                        .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                        .build()
                        .leader_view()
                        .unwrap();
                    tx.put_aggregator_task(&task).await?;

                    // Client report artifacts.
                    let client_timestamp = clock.now().sub(&Duration::from_seconds(2)).unwrap();
                    let batch_identifier = Interval::new(
                        client_timestamp
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                        *task.time_precision(),
                    )
                    .unwrap();
                    let report = LeaderStoredReport::new_dummy(*task.id(), client_timestamp);
                    tx.put_client_report(&vdaf, &report).await.unwrap();

                    // Aggregation artifacts.
                    let aggregation_job_id = random();
                    tx.put_aggregation_job(
                        &AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            aggregation_job_id,
                            AggregationParam(0),
                            (),
                            Interval::from_time(&client_timestamp).unwrap(),
                            AggregationJobState::InProgress,
                            AggregationJobStep::from(0),
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_report_aggregation(&ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        client_timestamp,
                        0,
                        None,
                        ReportAggregationState::Start,
                    ))
                    .await
                    .unwrap();

                    // Collection artifacts.
                    tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::from_time(&client_timestamp).unwrap(), // unrealistic, but induces GC
                        AggregationParam(0),
                        BatchState::Closed,
                        0,
                        Interval::from_time(&client_timestamp).unwrap(),
                    ))
                    .await
                    .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            batch_identifier,
                            AggregationParam(0),
                            0,
                            BatchAggregationState::Collected,
                            Some(AggregateShare(11)),
                            1,
                            Interval::from_time(&client_timestamp).unwrap(),
                            random(),
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_collection_job(
                        &CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            random(),
                            Query::new_time_interval(batch_identifier),
                            AggregationParam(0),
                            batch_identifier,
                            CollectionJobState::Start,
                        ),
                    )
                    .await
                    .unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Advance the clock to "enable" report expiry.
        clock.advance(&REPORT_EXPIRY_AGE);

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(
            Arc::clone(&ds),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
        )
        .gc_task(Arc::clone(&task))
        .await
        .unwrap();

        // Reset the clock to "undo" read-based expiry.
        clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

        // Reset the clock to "undo" read-based expiry.
        clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

        // Verify.
        ds.run_unnamed_tx(|tx| {
            let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
            Box::pin(async move {
                assert!(tx
                    .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Leader,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batches_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn gc_task_helper_time_interval() {
        install_test_trace_subscriber();

        let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_unnamed_tx(|tx| {
                let clock = clock.clone();
                Box::pin(async move {
                    let task = TaskBuilder::new(task::QueryType::TimeInterval, VdafInstance::Fake)
                        .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                        .build()
                        .helper_view()
                        .unwrap();
                    tx.put_aggregator_task(&task).await?;

                    // Client report artifacts.
                    let client_timestamp = clock.now().sub(&Duration::from_seconds(2)).unwrap();
                    let batch_identifier = Interval::new(
                        client_timestamp
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                        *task.time_precision(),
                    )
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

                    // Aggregation artifacts.
                    let aggregation_job_id = random();
                    tx.put_aggregation_job(
                        &AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            aggregation_job_id,
                            AggregationParam(0),
                            (),
                            Interval::from_time(&client_timestamp).unwrap(),
                            AggregationJobState::InProgress,
                            AggregationJobStep::from(0),
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_report_aggregation(&ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_share.metadata().id(),
                        client_timestamp,
                        0,
                        None,
                        ReportAggregationState::Start,
                    ))
                    .await
                    .unwrap();

                    // Collection artifacts.
                    tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::from_time(&client_timestamp).unwrap(), // unrealistic, but induces GC
                        AggregationParam(0),
                        BatchState::Closed,
                        0,
                        Interval::from_time(&client_timestamp).unwrap(),
                    ))
                    .await
                    .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            batch_identifier,
                            AggregationParam(0),
                            0,
                            BatchAggregationState::Collected,
                            Some(AggregateShare(11)),
                            1,
                            Interval::from_time(&client_timestamp).unwrap(),
                            random(),
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_aggregate_share_job(&AggregateShareJob::<
                        0,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        batch_identifier,
                        AggregationParam(0),
                        AggregateShare(11),
                        0,
                        ReportIdChecksum::default(),
                    ))
                    .await
                    .unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Advance the clock to "enable" report expiry.
        clock.advance(&REPORT_EXPIRY_AGE);

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(
            Arc::clone(&ds),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
        )
        .gc_task(Arc::clone(&task))
        .await
        .unwrap();

        // Reset the clock to "undo" read-based expiry.
        clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

        // Verify.
        ds.run_unnamed_tx(|tx| {
            let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
            Box::pin(async move {
                assert!(tx
                    .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Leader,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batches_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id()
                    )
                    .await
                    .unwrap()
                    .is_empty());
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn gc_task_leader_fixed_size() {
        install_test_trace_subscriber();

        let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_unnamed_tx(|tx| {
                let (clock, vdaf) = (clock.clone(), vdaf.clone());
                Box::pin(async move {
                    let task = TaskBuilder::new(
                        task::QueryType::FixedSize {
                            max_batch_size: 10,
                            batch_time_window_size: None,
                        },
                        VdafInstance::Fake,
                    )
                    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                    .build()
                    .leader_view()
                    .unwrap();
                    tx.put_aggregator_task(&task).await?;

                    // Client report artifacts.
                    let client_timestamp = clock
                        .now()
                        .sub(&REPORT_EXPIRY_AGE)
                        .unwrap()
                        .sub(&Duration::from_seconds(2))
                        .unwrap();
                    let report = LeaderStoredReport::new_dummy(*task.id(), client_timestamp);
                    tx.put_client_report(&vdaf, &report).await.unwrap();

                    // Aggregation artifacts.
                    let batch_id = random();
                    let aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        batch_id,
                        Interval::from_time(&client_timestamp).unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
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

                    // Collection artifacts.
                    tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        batch_id,
                        AggregationParam(0),
                        BatchState::Closed,
                        0,
                        Interval::from_time(&client_timestamp).unwrap(),
                    ))
                    .await
                    .unwrap();

                    tx.put_outstanding_batch(task.id(), &batch_id, &None)
                        .await
                        .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            batch_id,
                            AggregationParam(0),
                            0,
                            BatchAggregationState::Collected,
                            Some(AggregateShare(11)),
                            1,
                            Interval::from_time(&client_timestamp).unwrap(),
                            random(),
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_collection_job(&CollectionJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        Query::new_fixed_size(FixedSizeQuery::CurrentBatch),
                        AggregationParam(0),
                        batch_id,
                        CollectionJobState::Start,
                    ))
                    .await
                    .unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Advance the clock to "enable" report expiry.
        clock.advance(&REPORT_EXPIRY_AGE);

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(
            Arc::clone(&ds),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
        )
        .gc_task(Arc::clone(&task))
        .await
        .unwrap();

        // Reset the clock to "undo" read-based expiry.
        clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

        // Verify.
        ds.run_unnamed_tx(|tx| {
            let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
            Box::pin(async move {
                assert!(tx
                    .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Leader,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batches_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_outstanding_batches(task.id(), &None)
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_collection_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn gc_task_helper_fixed_size() {
        install_test_trace_subscriber();

        let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_unnamed_tx(|tx| {
                let clock = clock.clone();
                Box::pin(async move {
                    let task = TaskBuilder::new(
                        task::QueryType::FixedSize {
                            max_batch_size: 10,
                            batch_time_window_size: None,
                        },
                        VdafInstance::Fake,
                    )
                    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                    .build()
                    .helper_view()
                    .unwrap();
                    tx.put_aggregator_task(&task).await?;

                    // Client report artifacts.
                    let client_timestamp = clock
                        .now()
                        .sub(&REPORT_EXPIRY_AGE)
                        .unwrap()
                        .sub(&Duration::from_seconds(2))
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

                    // Aggregation artifacts.
                    let batch_id = random();
                    let aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        batch_id,
                        Interval::from_time(&client_timestamp).unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
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

                    // Collection artifacts.
                    tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        batch_id,
                        AggregationParam(0),
                        BatchState::Closed,
                        0,
                        Interval::from_time(&client_timestamp).unwrap(),
                    ))
                    .await
                    .unwrap();

                    tx.put_outstanding_batch(task.id(), &batch_id, &None)
                        .await
                        .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            batch_id,
                            AggregationParam(0),
                            0,
                            BatchAggregationState::Collected,
                            Some(AggregateShare(11)),
                            1,
                            Interval::from_time(&client_timestamp).unwrap(),
                            random(),
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_aggregate_share_job(
                        &AggregateShareJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            batch_id,
                            AggregationParam(0),
                            AggregateShare(11),
                            0,
                            ReportIdChecksum::default(),
                        ),
                    )
                    .await
                    .unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Advance the clock to "enable" report expiry.
        clock.advance(&REPORT_EXPIRY_AGE);

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(
            Arc::clone(&ds),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
            u64::try_from(i64::MAX).unwrap(),
        )
        .gc_task(Arc::clone(&task))
        .await
        .unwrap();

        // Reset the clock to "undo" read-based expiry.
        clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

        // Reset the clock to "undo" read-based expiry.
        clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

        // Verify.
        ds.run_unnamed_tx(|tx| {
            let (vdaf, task) = (vdaf.clone(), Arc::clone(&task));
            Box::pin(async move {
                assert!(tx
                    .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Leader,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batches_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(task.id())
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                assert!(tx
                    .get_aggregate_share_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        task.id(),
                    )
                    .await
                    .unwrap()
                    .is_empty());
                Ok(())
            })
        })
        .await
        .unwrap();
    }
}
