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

                let ord = rng().random_range(0..32);
                TaskUploadCounter::default()
                    .flush(&task_id, tx, ord)
                    .await
                    .unwrap();

                let counter = TaskUploadCounter::load(tx, &task_id).await.unwrap();
                assert_eq!(
                    counter,
                    Some(TaskUploadCounter {
                        interval_collected: 2,
                        report_decode_failure: 4,
                        report_decrypt_failure: 6,
                        report_expired: 8,
                        report_outdated_key: 10,
                        report_success: 100,
                        report_too_early: 25,
                        task_not_started: 22,
                        task_ended: 20,
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
                        success: 10,
                        helper_hpke_decrypt_failure: 200,
                        helper_task_expired: 1,
                        duplicate_extension: 0,
                        public_share_encode_failure: 0,
                        batch_collected: 0,
                        report_replayed: 0,
                        report_dropped: 0,
                        hpke_unknown_config_id: 0,
                        hpke_decrypt_failure: 0,
                        vdaf_prep_error: 0,
                        task_not_started: 0,
                        task_expired: 0,
                        invalid_message: 0,
                        report_too_early: 0,
                        helper_batch_collected: 0,
                        helper_report_replayed: 0,
                        helper_report_dropped: 0,
                        helper_hpke_unknown_config_id: 0,
                        helper_vdaf_prep_error: 0,
                        helper_task_not_started: 0,
                        helper_invalid_message: 0,
                        helper_report_too_early: 0
                    })
                );

                Ok(())
            })
        })
        .await
        .unwrap();
}
