use crate::{
    datastore::{
        schema_versions_template,
        task_counters::{TaskAggregationCounter, TaskUploadCounter},
        test_util::{EphemeralDatastore, ephemeral_datastore_schema_version},
    },
    task::{self, AggregationMode, test_util::TaskBuilder},
};
use janus_core::{test_util::install_test_trace_subscriber, time::MockClock, vdaf::VdafInstance};
use rand::{Rng, random, rng};

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_task_upload_counter(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let datastore = ephemeral_datastore.datastore(clock.clone()).await;

    let task = TaskBuilder::new(
        task::BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .build()
    .leader_view()
    .unwrap();

    datastore.put_aggregator_task(&task).await.unwrap();

    datastore
        .run_unnamed_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move {
                // Returns None for non-existent task.
                let counter = TaskUploadCounter::load(tx, &random()).await.unwrap();
                assert_eq!(counter, None);

                // Returns Some for a task that has just been created and has no counters.
                let counter = TaskUploadCounter::load(tx, &task_id).await.unwrap();
                assert_eq!(counter, Some(TaskUploadCounter::default()));

                let ord = rng().random_range(0..32);
                TaskUploadCounter::new_with_values(2, 4, 6, 8, 10, 100, 25, 22, 12)
                    .flush(&task_id, tx, ord)
                    .await
                    .unwrap();

                let ord = rng().random_range(0..32);
                TaskUploadCounter::new_with_values(0, 0, 0, 0, 0, 0, 0, 0, 8)
                    .flush(&task_id, tx, ord)
                    .await
                    .unwrap();

                TaskUploadCounter::new_with_values(1, 1, 1, 1, 1, 1, 1, 1, 1)
                    // force conflict on (task_id, ord) to exercise the query's
                    // ON CONFLICT (task_id, ord) DO UPDATE SET clause
                    .flush(&task_id, tx, ord)
                    .await
                    .unwrap();

                let ord = rng().random_range(0..32);
                TaskUploadCounter::default()
                    .flush(&task_id, tx, ord)
                    .await
                    .unwrap();

                let counter = TaskUploadCounter::load(tx, &task_id).await.unwrap();
                assert_eq!(
                    counter,
                    Some(TaskUploadCounter {
                        interval_collected: 3,
                        report_decode_failure: 5,
                        report_decrypt_failure: 7,
                        report_expired: 9,
                        report_outdated_key: 11,
                        report_success: 101,
                        report_too_early: 26,
                        task_not_started: 23,
                        task_ended: 21,
                    })
                );

                Ok(())
            })
        })
        .await
        .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_task_aggregation_counter(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let datastore = ephemeral_datastore.datastore(clock.clone()).await;

    datastore
        .run_unnamed_tx(|tx| {
            Box::pin(async move {
                // Returns None for non-existent task.
                let counter = TaskAggregationCounter::load(tx, &random()).await.unwrap();
                assert_eq!(counter, None);

                // Put a task for us to increment counters for.
                let task = TaskBuilder::new(
                    task::BatchMode::LeaderSelected {
                        batch_time_window_size: None,
                    },
                    AggregationMode::Synchronous,
                    VdafInstance::Fake { rounds: 1 },
                )
                .build()
                .leader_view()
                .unwrap();

                tx.put_aggregator_task(&task).await.unwrap();

                // Returns Some for a task that has just been created and has no counters.
                let counter = TaskAggregationCounter::load(tx, task.id()).await.unwrap();
                assert_eq!(counter, Some(TaskAggregationCounter::default()));

                let ord = rng().random_range(0..32);
                TaskAggregationCounter {
                    success: 4,
                    helper_hpke_decrypt_failure: 102,
                    ..Default::default()
                }
                .flush(task.id(), tx, ord)
                .await
                .unwrap();

                TaskAggregationCounter {
                    success: 1,
                    helper_hpke_decrypt_failure: 1,
                    duplicate_extension: 1,
                    public_share_encode_failure: 1,
                    batch_collected: 1,
                    report_replayed: 1,
                    report_dropped: 1,
                    hpke_unknown_config_id: 1,
                    hpke_decrypt_failure: 1,
                    vdaf_prep_error: 1,
                    task_not_started: 1,
                    task_expired: 1,
                    invalid_message: 1,
                    report_too_early: 1,
                    helper_batch_collected: 1,
                    helper_report_replayed: 1,
                    helper_report_dropped: 1,
                    helper_hpke_unknown_config_id: 1,
                    helper_vdaf_prep_error: 1,
                    helper_task_not_started: 1,
                    helper_task_expired: 1,
                    helper_invalid_message: 1,
                    helper_report_too_early: 1,
                }
                // force conflict on (task_id, ord) to exercise the query's
                // ON CONFLICT (task_id, ord) DO UPDATE SET clause
                .flush(task.id(), tx, ord)
                .await
                .unwrap();

                let ord = rng().random_range(0..32);
                TaskAggregationCounter {
                    success: 6,
                    helper_hpke_decrypt_failure: 98,
                    helper_task_expired: 1,
                    ..Default::default()
                }
                .flush(task.id(), tx, ord)
                .await
                .unwrap();

                let ord = rng().random_range(0..32);
                TaskAggregationCounter::default()
                    .flush(task.id(), tx, ord)
                    .await
                    .unwrap();

                let counter = TaskAggregationCounter::load(tx, task.id()).await.unwrap();
                assert_eq!(
                    counter,
                    Some(TaskAggregationCounter {
                        success: 11,
                        helper_hpke_decrypt_failure: 201,
                        helper_task_expired: 2,
                        duplicate_extension: 1,
                        public_share_encode_failure: 1,
                        batch_collected: 1,
                        report_replayed: 1,
                        report_dropped: 1,
                        hpke_unknown_config_id: 1,
                        hpke_decrypt_failure: 1,
                        vdaf_prep_error: 1,
                        task_not_started: 1,
                        task_expired: 1,
                        invalid_message: 1,
                        report_too_early: 1,
                        helper_batch_collected: 1,
                        helper_report_replayed: 1,
                        helper_report_dropped: 1,
                        helper_hpke_unknown_config_id: 1,
                        helper_vdaf_prep_error: 1,
                        helper_task_not_started: 1,
                        helper_invalid_message: 1,
                        helper_report_too_early: 1
                    })
                );

                Ok(())
            })
        })
        .await
        .unwrap();
}
