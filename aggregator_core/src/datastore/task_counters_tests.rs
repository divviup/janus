use janus_core::{test_util::install_test_trace_subscriber, time::MockClock, vdaf::VdafInstance};
use rand::{Rng, random, rng};

use crate::{
    datastore::{
        schema_versions_template,
        task_counters::{TaskAggregationCounter, TaskUploadCounter},
        test_util::{EphemeralDatastore, ephemeral_datastore_schema_version},
    },
    task::{self, AggregationMode, test_util::TaskBuilder},
};

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
                TaskUploadCounter::new_with_values(2, 4, 6, 8, 10, 100, 25, 22, 12, 42)
                    .flush(&task_id, tx, ord)
                    .await
                    .unwrap();

                let ord = rng().random_range(0..32);
                TaskUploadCounter::new_with_values(0, 0, 0, 0, 0, 0, 0, 0, 8, 0)
                    .flush(&task_id, tx, ord)
                    .await
                    .unwrap();

                TaskUploadCounter::new_with_values(1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
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
                    Some(TaskUploadCounter::new_with_values(
                        3, 5, 7, 9, 11, 101, 26, 23, 21, 43,
                    ))
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
                TaskAggregationCounter::default()
                    .with_success(4)
                    .with_helper_hpke_decrypt_failure(102)
                    .flush(task.id(), tx, ord)
                    .await
                    .unwrap();

                TaskAggregationCounter::new_with_values(
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                )
                // force conflict on (task_id, ord) to exercise the query's
                // ON CONFLICT (task_id, ord) DO UPDATE SET clause
                .flush(task.id(), tx, ord)
                .await
                .unwrap();

                let ord = rng().random_range(0..32);
                TaskAggregationCounter::default()
                    .with_success(6)
                    .with_helper_hpke_decrypt_failure(98)
                    .with_helper_task_expired(1)
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
                    Some(TaskAggregationCounter::new_with_values(
                        11, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 201, 1, 1, 2, 1, 1
                    ))
                );

                Ok(())
            })
        })
        .await
        .unwrap();
}
