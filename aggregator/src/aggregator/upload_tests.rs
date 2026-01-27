use std::{collections::HashSet, iter, sync::Arc, time::Duration as StdDuration};

use assert_matches::assert_matches;
use futures::stream::{self, Stream};
use janus_aggregator_core::{
    datastore::{
        Datastore,
        models::{CollectionJob, CollectionJobState},
        task_counters::TaskUploadCounter,
        test_util::{EphemeralDatastore, ephemeral_datastore},
    },
    task::{
        AggregationMode, BatchMode,
        test_util::{Task, TaskBuilder},
    },
    test_util::noop_meter,
};
use janus_core::{
    Runtime,
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    initialize_rustls,
    test_util::{
        install_test_trace_subscriber,
        runtime::{TestRuntime, TestRuntimeManager},
    },
    time::{Clock, DateTimeExt, MockClock},
    vdaf::{VERIFY_KEY_LENGTH_PRIO3, VdafInstance},
};
use janus_messages::{
    Duration, Extension, ExtensionType, HpkeCiphertext, HpkeConfigId, InputShareAad, Interval,
    PlaintextInputShare, Query, Report, ReportError, Role, batch_mode::TimeInterval,
    taskprov::TimePrecision,
};
use prio::{codec::Encode, vdaf::prio3::Prio3Count};
use rand::random;

use crate::aggregator::{
    Aggregator, Config, Error,
    test_util::{create_report, create_report_custom, default_aggregator_config},
};

struct UploadTest {
    vdaf: Prio3Count,
    aggregator: Aggregator<MockClock>,
    clock: MockClock,
    task: Task,
    datastore: Arc<Datastore<MockClock>>,
    ephemeral_datastore: EphemeralDatastore,
    hpke_keypair: HpkeKeypair,
}

impl UploadTest {
    async fn new(cfg: Config) -> Self {
        Self::new_with_runtime(cfg, TestRuntime::default()).await
    }

    async fn new_with_runtime<R>(cfg: Config, runtime: R) -> Self
    where
        R: Runtime + Send + Sync + 'static,
    {
        install_test_trace_subscriber();
        initialize_rustls();

        let clock = MockClock::default();
        let vdaf = Prio3Count::new_count(2).unwrap();
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_time_precision(TimePrecision::from_seconds(100))
        .build();

        let leader_task = task.leader_view().unwrap();

        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let hpke_keypair = datastore.put_hpke_key().await.unwrap();
        datastore.put_aggregator_task(&leader_task).await.unwrap();

        let aggregator = Aggregator::new(
            Arc::clone(&datastore),
            clock.clone(),
            runtime,
            &noop_meter(),
            cfg,
        )
        .await
        .unwrap();

        Self {
            vdaf,
            aggregator,
            clock,
            task,
            datastore,
            ephemeral_datastore,
            hpke_keypair,
        }
    }
}

/// Helper to convert a single report into a Stream for testing
fn report_stream(report: Report) -> impl Stream<Item = Result<Report, Error>> {
    stream::iter(vec![Ok(report)])
}

/// Helper to convert multiple reports into a Stream for testing
fn reports_stream(reports: Vec<Report>) -> impl Stream<Item = Result<Report, Error>> {
    stream::iter(reports.into_iter().map(Ok))
}

#[tokio::test]
async fn upload() {
    let UploadTest {
        vdaf,
        aggregator,
        clock,
        task,
        datastore: ds,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new(Config {
        max_upload_batch_size: 1000,
        max_upload_batch_write_delay: StdDuration::from_millis(500),
        ..Default::default()
    })
    .await;

    let leader_task = task.leader_view().unwrap();
    let report = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();

    let got_report = ds
        .run_unnamed_tx(|tx| {
            let vdaf = vdaf.clone();
            let task_id = *task.id();
            let report_id = *report.metadata().id();
            Box::pin(async move { tx.get_client_report(&vdaf, &task_id, &report_id).await })
        })
        .await
        .unwrap()
        .unwrap();
    assert!(got_report.eq_report(&vdaf, &hpke_keypair, &report));

    // Report uploads are idempotent.
    aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();

    // Even if the report is modified, it is still reported as a duplicate. The original report
    // is stored.
    let mutated_report = create_report_custom(
        &leader_task,
        clock.now_aligned_to_precision(task.time_precision()),
        *report.metadata().id(),
        &hpke_keypair,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    aggregator
        .handle_upload(task.id(), report_stream(mutated_report))
        .await
        .unwrap();

    // Verify that the original report, rather than the modified report, is stored.
    let (got_report, got_counter) = ds
        .run_unnamed_tx(|tx| {
            let vdaf = vdaf.clone();
            let task_id = *task.id();
            let report_id = *report.metadata().id();
            Box::pin(async move {
                Ok((
                    tx.get_client_report(&vdaf, &task_id, &report_id)
                        .await
                        .unwrap(),
                    TaskUploadCounter::load(tx, &task_id).await.unwrap(),
                ))
            })
        })
        .await
        .unwrap();
    assert!(got_report.unwrap().eq_report(&vdaf, &hpke_keypair, &report));

    assert_eq!(
        got_counter,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_batch() {
    const BATCH_SIZE: usize = 100;
    let UploadTest {
        vdaf,
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new(Config {
        max_upload_batch_size: BATCH_SIZE,
        max_upload_batch_write_delay: StdDuration::from_secs(86400),
        ..Default::default()
    })
    .await;

    let reports: Vec<_> = iter::repeat_with(|| {
        create_report(
            &task.leader_view().unwrap(),
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        )
    })
    .take(BATCH_SIZE)
    .collect();
    let want_report_ids: HashSet<_> = reports.iter().map(|r| *r.metadata().id()).collect();

    aggregator
        .handle_upload(task.id(), reports_stream(reports))
        .await
        .unwrap();

    let got_report_ids = datastore
        .run_unnamed_tx(|tx| {
            let vdaf = vdaf.clone();
            let task = task.clone();
            Box::pin(async move { tx.get_client_reports_for_task(&vdaf, task.id()).await })
        })
        .await
        .unwrap()
        .iter()
        .map(|r| *r.metadata().id())
        .collect();

    assert_eq!(want_report_ids, got_report_ids);

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 100, 0, 0, 0, 0
        ))
    );
}

#[tokio::test]
async fn upload_wrong_hpke_config_id() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;
    let leader_task = task.leader_view().unwrap();
    let report = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    let unused_hpke_config_id =
        HpkeConfigId::from(u8::from(*hpke_keypair.config().id()).wrapping_add(1));

    let report = Report::new(
        report.metadata().clone(),
        report.public_share().to_vec(),
        HpkeCiphertext::new(
            unused_hpke_config_id,
            report
                .leader_encrypted_input_share()
                .encapsulated_key()
                .to_vec(),
            report.leader_encrypted_input_share().payload().to_vec(),
        ),
        report.helper_encrypted_input_share().clone(),
    );

    let result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let report_upload_status = &result.status()[0];
    assert_matches!(report_upload_status.error(), ReportError::HpkeUnknownConfigId => {
        assert_eq!(report.metadata().id(), &report_upload_status.report_id());
    });

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 1, 0, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_in_the_future_boundary_condition() {
    let UploadTest {
        vdaf,
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new(default_aggregator_config()).await;
    let report = create_report(
        &task.leader_view().unwrap(),
        &hpke_keypair,
        clock
            .now()
            .add_duration(task.tolerable_clock_skew(), task.time_precision())
            .unwrap()
            .to_time(task.time_precision()),
    );

    aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();

    let got_report = datastore
        .run_unnamed_tx(|tx| {
            let (vdaf, task_id, report_id) = (vdaf.clone(), *task.id(), *report.metadata().id());
            Box::pin(async move { tx.get_client_report(&vdaf, &task_id, &report_id).await })
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.id(), got_report.task_id());
    assert_eq!(report.metadata(), got_report.metadata());

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_in_the_future_past_clock_skew() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;
    let report = create_report(
        &task.leader_view().unwrap(),
        &hpke_keypair,
        clock
            .now()
            .add_duration(task.tolerable_clock_skew(), task.time_precision())
            .unwrap()
            .add_duration(&Duration::ONE, task.time_precision())
            .unwrap()
            .to_time(task.time_precision()),
    );

    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::ReportTooEarly => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_for_collected_batch() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;
    let report = create_report(
        &task.leader_view().unwrap(),
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    // Insert a collection job for the batch interval including our report.
    let batch_interval = Interval::minimal(*report.metadata().time()).unwrap();
    datastore
        .run_unnamed_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_collection_job(&CollectionJob::<
                    VERIFY_KEY_LENGTH_PRIO3,
                    TimeInterval,
                    Prio3Count,
                >::new(
                    *task.id(),
                    random(),
                    random(),
                    Query::new_time_interval(batch_interval),
                    (),
                    batch_interval,
                    CollectionJobState::Start,
                ))
                .await
            })
        })
        .await
        .unwrap();

    // Try to upload the report, verify that we get the expected error.
    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::ReportReplayed => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_task_not_started() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    // Set the task start time to the future, and generate & upload a report from before that time.
    let time_precision = TimePrecision::from_seconds(100);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_task_start(Some(
        clock
            .now()
            .add_duration(
                &Duration::from_seconds(3600, &time_precision),
                &time_precision,
            )
            .unwrap()
            .to_time(&time_precision),
    ))
    .build()
    .leader_view()
    .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    let report = create_report(
        &task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    // Try to upload the report, verify that we get the expected error.
    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::TaskNotStarted => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_task_ended() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let precision = TimePrecision::from_seconds(100);
    let task_end_time = clock.now_aligned_to_precision(&precision);

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(precision)
    .with_task_end(Some(task_end_time))
    .build()
    .leader_view()
    .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    // Advance the clock to end the task.
    clock.advance(task.time_precision().to_chrono().unwrap());
    // Create a report exactly at the end time
    let report = create_report(&task, &hpke_keypair, task_end_time);

    // Try to upload the report, verify that we get the expected error.
    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::TaskExpired => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_report_expired() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let time_precision = TimePrecision::from_seconds(100);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_report_expiry_age(Some(Duration::from_time_precision_units(1)))
    .build()
    .leader_view()
    .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    let report = create_report(
        &task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    // Advance the clock to expire the report.
    // We need to advance past the expiry age plus enough to move to the next time precision
    // bucket, so 2x time precision.
    clock.advance(time_precision.to_chrono().unwrap().checked_mul(2).unwrap());

    // Try to upload the report. For expired reports, the upload must succeed but the report
    // won't be stored (it's dropped asynchronously during batch write), and we want to see
    // the ReportDropped status returned.
    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::ReportDropped => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    // The expired report should not have been stored in the database.
    let stored_report = datastore
        .run_unnamed_tx(|tx| {
            let vdaf = Prio3Count::new_count(2).unwrap();
            let task_id = *task.id();
            let report_id = *report.metadata().id();
            Box::pin(async move { tx.get_client_report(&vdaf, &task_id, &report_id).await })
        })
        .await
        .unwrap();
    assert!(
        stored_report.is_none(),
        "Expired report should not be stored"
    );

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_faulty_encryption() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let task = task.leader_view().unwrap();

    // Encrypt with the wrong key.
    let report = create_report_custom(
        &task,
        clock.now_aligned_to_precision(task.time_precision()),
        random(),
        &HpkeKeypair::test_with_id(*hpke_keypair.config().id()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    // Try to upload the report, verify that we get the expected error.
    let result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::HpkeDecryptError => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 1, 0, 0, 0, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_public_share_decode_failure() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let task = task.leader_view().unwrap();

    let mut report = create_report(
        &task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );
    report = Report::new(
        report.metadata().clone(),
        // Some obviously wrong public share.
        Vec::from([0; 10]),
        report.leader_encrypted_input_share().clone(),
        report.helper_encrypted_input_share().clone(),
    );

    // Try to upload the report, verify that we get the expected error.
    let result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::InvalidMessage => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 1, 0, 0, 0, 0, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_leader_input_share_decode_failure() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let task = task.leader_view().unwrap();

    let mut report = create_report(
        &task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );
    report = Report::new(
        report.metadata().clone(),
        report.public_share().to_vec(),
        hpke::seal(
            hpke_keypair.config(),
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
            // Some obviously wrong payload.
            &PlaintextInputShare::new(Vec::new(), vec![0; 100])
                .get_encoded()
                .unwrap(),
            &InputShareAad::new(
                *task.id(),
                report.metadata().clone(),
                report.public_share().to_vec(),
            )
            .get_encoded()
            .unwrap(),
        )
        .unwrap(),
        report.helper_encrypted_input_share().clone(),
    );

    // Try to upload the report, verify that we get the expected error.
    let result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::InvalidMessage => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 1, 0, 0, 0, 0, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_duplicate_extensions() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let time_precision = TimePrecision::from_seconds(100);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_task_start(None)
    .with_report_expiry_age(Some(Duration::from_seconds(60, &time_precision)))
    .build()
    .leader_view()
    .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    // Duplicate extensions
    let report = create_report_custom(
        &task,
        clock.now_aligned_to_precision(task.time_precision()),
        random(),
        &hpke_keypair,
        /* public */ Vec::from([Extension::new(ExtensionType::Tbd, Vec::new())]),
        /* leader */ Vec::from([Extension::new(ExtensionType::Tbd, Vec::new())]),
        /* helper */ Vec::new(),
    );

    // Try to upload the report, verify that we get the expected error.
    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::InvalidMessage => {
            assert_eq!(report.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed one write task.
    runtime_manager
        .wait_for_completed_tasks("aggregator", 1)
        .await;

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ))
    )
}

#[tokio::test]
async fn upload_report_unrecognized_extension() {
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let time_precision = TimePrecision::from_seconds(100);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_task_start(None)
    .with_report_expiry_age(Some(Duration::from_seconds(60, &time_precision)))
    .build()
    .leader_view()
    .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    // Report with unrecognized extension type in public extensions
    let report_public = create_report_custom(
        &task,
        clock.now_aligned_to_precision(task.time_precision()),
        random(),
        &hpke_keypair,
        /* public */ Vec::from([Extension::new(ExtensionType::Unknown(0x1234), Vec::new())]),
        /* leader */ Vec::new(),
        /* helper */ Vec::new(),
    );

    // Try to upload the report, verify that we get the expected error.
    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report_public.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::InvalidMessage => {
            assert_eq!(report_public.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Report with unrecognized extension type in private extensions
    let report_private = create_report_custom(
        &task,
        clock.now_aligned_to_precision(task.time_precision()),
        random(),
        &hpke_keypair,
        /* public */ Vec::new(),
        /* leader */ Vec::from([Extension::new(ExtensionType::Unknown(0xABCD), Vec::new())]),
        /* helper */ Vec::new(),
    );

    let upload_result = aggregator
        .handle_upload(task.id(), report_stream(report_private.clone()))
        .await
        .unwrap();
    let result_upload_status = &upload_result.status()[0];
    assert_matches!(
        result_upload_status.error(),
        ReportError::InvalidMessage => {
            assert_eq!(report_private.metadata().id(), &result_upload_status.report_id());
        }
    );

    // Wait for the report writer to have completed the write task.
    tokio::time::timeout(
        StdDuration::from_secs(5),
        runtime_manager.wait_for_completed_tasks("aggregator", 1),
    )
    .await
    .unwrap();

    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0
        ))
    )
}

#[tokio::test]
async fn upload_report_decode_failure() {
    // This test verifies that when a Report fails to decode that the stream aborts,
    // but processes the earlier reports.

    install_test_trace_subscriber();
    let mut runtime_manager = TestRuntimeManager::new();
    let UploadTest {
        aggregator,
        clock,
        task,
        datastore,
        ephemeral_datastore: _ephemeral_datastore,
        hpke_keypair,
        ..
    } = UploadTest::new_with_runtime(
        default_aggregator_config(),
        runtime_manager.with_label("aggregator"),
    )
    .await;

    let task = task.leader_view().unwrap();

    let report = create_report(
        &task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    // Create a stream that yields this decode error (simulating what decode_reports_stream does)
    let error_stream = stream::iter(vec![
        Ok(report),
        Err(Error::MessageDecode(
            prio::codec::CodecError::UnexpectedValue,
        )),
    ]);

    let error = aggregator
        .handle_upload(task.id(), error_stream)
        .await
        .unwrap_err();

    // Should recieve a MessageDecode error
    assert_matches!(
        *error,
        Error::MessageDecode(_),
        "A decoding error should become Error::MessageDecode"
    );

    // Wait for the report writer to complete anyway
    tokio::time::timeout(
        StdDuration::from_secs(5),
        runtime_manager.wait_for_completed_tasks("aggregator", 1),
    )
    .await
    .unwrap();

    // Verify the success was recorded in counters
    let got_counters = datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
        })
        .await
        .unwrap();

    // Counter position 5 is report_success
    assert_eq!(
        got_counters,
        Some(TaskUploadCounter::new_with_values(
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0
        )),
        "Should increment report_success counter"
    );
}
