// This function is only used when there are multiple supported versions.
#[allow(unused_imports)]
use crate::datastore::test_util::ephemeral_datastore_schema_version_by_downgrade;

use crate::{
    datastore::{
        models::{
            AcquiredAggregationJob, AcquiredCollectionJob, AggregateShareJob, AggregationJob,
            AggregationJobState, Batch, BatchAggregation, BatchAggregationState, BatchState,
            CollectionJob, CollectionJobState, GlobalHpkeKeypair, HpkeKeyState, LeaderStoredReport,
            Lease, OutstandingBatch, ReportAggregation, ReportAggregationState, SqlInterval,
        },
        schema_versions_template,
        test_util::{ephemeral_datastore_schema_version, generate_aead_key, EphemeralDatastore},
        Crypter, Datastore, Error, Transaction, SUPPORTED_SCHEMA_VERSIONS,
    },
    query_type::CollectableQueryType,
    task::{self, test_util::TaskBuilder, Task},
    taskprov::test_util::PeerAggregatorBuilder,
    test_util::noop_meter,
};

use assert_matches::assert_matches;
use async_trait::async_trait;
use chrono::NaiveDate;
use futures::future::try_join_all;
use janus_core::{
    hpke::{
        self, test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo, Label,
    },
    task::{VdafInstance, PRIO3_VERIFY_KEY_LENGTH},
    test_util::{
        dummy_vdaf::{self, AggregateShare, AggregationParam},
        install_test_trace_subscriber, run_vdaf,
    },
    time::{Clock, DurationExt, IntervalExt, MockClock, TimeExt},
};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    AggregateShareAad, AggregationJobId, AggregationJobRound, BatchId, BatchSelector,
    CollectionJobId, Duration, Extension, ExtensionType, HpkeCiphertext, HpkeConfigId, Interval,
    PrepareStep, PrepareStepResult, ReportId, ReportIdChecksum, ReportMetadata, ReportShare,
    ReportShareError, Role, TaskId, Time,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::prio3::{Prio3, Prio3Count},
};
use rand::{distributions::Standard, random, thread_rng, Rng};
use std::{
    collections::{HashMap, HashSet},
    iter,
    ops::RangeInclusive,
    sync::Arc,
    time::Duration as StdDuration,
};
use tokio::time::timeout;
use url::Url;

const OLDEST_ALLOWED_REPORT_TIMESTAMP: Time = Time::from_seconds_since_epoch(1000);
const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(1000);

#[test]
fn check_supported_versions() {
    if SUPPORTED_SCHEMA_VERSIONS[0] != *SUPPORTED_SCHEMA_VERSIONS.iter().max().unwrap() {
        panic!("the latest supported schema version must be first in the list");
    }
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn reject_unsupported_schema_version(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let error = Datastore::new_with_supported_versions(
        ephemeral_datastore.pool(),
        ephemeral_datastore.crypter(),
        MockClock::default(),
        &noop_meter(),
        &[0],
    )
    .await
    .unwrap_err();

    assert_matches!(error, Error::DbState(_));
}

#[rstest::rstest]
#[case(ephemeral_datastore_schema_version(i64::MAX))]
#[tokio::test]
async fn down_migrations(
    #[future(awt)]
    #[case]
    ephemeral_datastore: EphemeralDatastore,
) {
    ephemeral_datastore.downgrade(0).await;
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_task(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    // Insert tasks, check that they can be retrieved by ID.
    let mut want_tasks = HashMap::new();
    for (vdaf, role) in [
        (VdafInstance::Prio3Count, Role::Leader),
        (VdafInstance::Prio3CountVec { length: 8 }, Role::Leader),
        (VdafInstance::Prio3CountVec { length: 64 }, Role::Helper),
        (VdafInstance::Prio3Sum { bits: 64 }, Role::Helper),
        (VdafInstance::Prio3Sum { bits: 32 }, Role::Helper),
        (
            VdafInstance::Prio3Histogram {
                buckets: Vec::from([0, 100, 200, 400]),
            },
            Role::Leader,
        ),
        (
            VdafInstance::Prio3Histogram {
                buckets: Vec::from([0, 25, 50, 75, 100]),
            },
            Role::Leader,
        ),
        (VdafInstance::Poplar1 { bits: 8 }, Role::Helper),
        (VdafInstance::Poplar1 { bits: 64 }, Role::Helper),
    ] {
        let task = TaskBuilder::new(task::QueryType::TimeInterval, vdaf, role)
            .with_report_expiry_age(Some(Duration::from_seconds(3600)))
            .build();
        want_tasks.insert(*task.id(), task.clone());

        let err = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.delete_task(task.id()).await })
            })
            .await
            .unwrap_err();
        assert_matches!(err, Error::MutationTargetNotFound);

        let retrieved_task = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.get_task(task.id()).await })
            })
            .await
            .unwrap();
        assert_eq!(None, retrieved_task);

        ds.put_task(&task).await.unwrap();

        let retrieved_task = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.get_task(task.id()).await })
            })
            .await
            .unwrap();
        assert_eq!(Some(&task), retrieved_task.as_ref());

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.delete_task(task.id()).await })
        })
        .await
        .unwrap();

        let retrieved_task = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.get_task(task.id()).await })
            })
            .await
            .unwrap();
        assert_eq!(None, retrieved_task);

        let err = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.delete_task(task.id()).await })
            })
            .await
            .unwrap_err();
        assert_matches!(err, Error::MutationTargetNotFound);

        // Rewrite & retrieve the task again, to test that the delete is "clean" in the sense
        // that it deletes all task-related data (& therefore does not conflict with a later
        // write to the same task_id).
        ds.put_task(&task).await.unwrap();

        let retrieved_task = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.get_task(task.id()).await })
            })
            .await
            .unwrap();
        assert_eq!(Some(task), retrieved_task);
    }

    let got_tasks: HashMap<TaskId, Task> = ds
        .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
        .await
        .unwrap()
        .into_iter()
        .map(|task| (*task.id(), task))
        .collect();
    assert_eq!(want_tasks, got_tasks);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn get_task_metrics(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    const REPORT_COUNT: usize = 5;
    const REPORT_AGGREGATION_COUNT: usize = 2;

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let other_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();

                let reports: Vec<_> = iter::repeat_with(|| {
                    LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP)
                })
                .take(REPORT_COUNT)
                .collect();
                let expired_reports: Vec<_> = iter::repeat_with(|| {
                    LeaderStoredReport::new_dummy(
                        *task.id(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(2))
                            .unwrap(),
                    )
                })
                .take(REPORT_COUNT)
                .collect();
                let other_reports: Vec<_> = iter::repeat_with(|| {
                    LeaderStoredReport::new_dummy(
                        *other_task.id(),
                        Time::from_seconds_since_epoch(0),
                    )
                })
                .take(22)
                .collect();

                let aggregation_job = AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    AggregationParam(0),
                    (),
                    Interval::new(
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(1))
                            .unwrap(),
                        Duration::from_seconds(2),
                    )
                    .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobRound::from(0),
                );
                let expired_aggregation_job =
                    AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        AggregationParam(0),
                        (),
                        Interval::new(
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(2))
                                .unwrap(),
                            Duration::from_seconds(1),
                        )
                        .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );
                let other_aggregation_job =
                    AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *other_task.id(),
                        random(),
                        AggregationParam(0),
                        (),
                        Interval::new(
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(1))
                                .unwrap(),
                            Duration::from_seconds(2),
                        )
                        .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );

                let report_aggregations: Vec<_> = reports
                    .iter()
                    .take(REPORT_AGGREGATION_COUNT)
                    .enumerate()
                    .map(|(ord, report)| {
                        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            *aggregation_job.id(),
                            *report.metadata().id(),
                            *report.metadata().time(),
                            ord.try_into().unwrap(),
                            None,
                            ReportAggregationState::Start,
                        )
                    })
                    .collect();
                let expired_report_aggregations: Vec<_> = expired_reports
                    .iter()
                    .take(REPORT_AGGREGATION_COUNT)
                    .enumerate()
                    .map(|(ord, report)| {
                        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            *expired_aggregation_job.id(),
                            *report.metadata().id(),
                            *report.metadata().time(),
                            ord.try_into().unwrap(),
                            None,
                            ReportAggregationState::Start,
                        )
                    })
                    .collect();
                let other_report_aggregations: Vec<_> = other_reports
                    .iter()
                    .take(13)
                    .enumerate()
                    .map(|(ord, report)| {
                        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                            *other_task.id(),
                            *other_aggregation_job.id(),
                            *report.metadata().id(),
                            *report.metadata().time(),
                            ord.try_into().unwrap(),
                            None,
                            ReportAggregationState::Start,
                        )
                    })
                    .collect();

                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;
                try_join_all(
                    reports
                        .iter()
                        .chain(expired_reports.iter())
                        .chain(other_reports.iter())
                        .map(|report| async move {
                            tx.put_client_report(&dummy_vdaf::Vdaf::new(), report).await
                        }),
                )
                .await?;
                tx.put_aggregation_job(&aggregation_job).await?;
                tx.put_aggregation_job(&expired_aggregation_job).await?;
                tx.put_aggregation_job(&other_aggregation_job).await?;
                try_join_all(
                    report_aggregations
                        .iter()
                        .chain(expired_report_aggregations.iter())
                        .chain(other_report_aggregations.iter())
                        .map(|report_aggregation| async move {
                            tx.put_report_aggregation(report_aggregation).await
                        }),
                )
                .await?;

                Ok(*task.id())
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        Box::pin(async move {
            // Verify we get the correct results when we check metrics on our target task.
            assert_eq!(
                tx.get_task_metrics(&task_id).await.unwrap(),
                Some((
                    REPORT_COUNT.try_into().unwrap(),
                    REPORT_AGGREGATION_COUNT.try_into().unwrap()
                ))
            );

            // Verify that we get None if we ask about a task that doesn't exist.
            assert_eq!(tx.get_task_metrics(&random()).await.unwrap(), None);

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn get_task_ids(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    ds.run_tx(|tx| {
        Box::pin(async move {
            const TOTAL_TASK_ID_COUNT: usize = 20;
            let tasks: Vec<_> = iter::repeat_with(|| {
                TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build()
            })
            .take(TOTAL_TASK_ID_COUNT)
            .collect();

            let mut task_ids: Vec<_> = tasks.iter().map(Task::id).cloned().collect();
            task_ids.sort();

            try_join_all(tasks.iter().map(|task| tx.put_task(task))).await?;

            for (i, lower_bound) in iter::once(None)
                .chain(task_ids.iter().cloned().map(Some))
                .enumerate()
            {
                let got_task_ids = tx.get_task_ids(lower_bound).await?;
                assert_eq!(&got_task_ids, &task_ids[i..]);
            }

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_report(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;
    let report_expiry_age = clock
        .now()
        .difference(&OLDEST_ALLOWED_REPORT_TIMESTAMP)
        .unwrap();

    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .with_report_expiry_age(Some(report_expiry_age))
    .build();

    ds.run_tx(|tx| {
        let task = task.clone();
        Box::pin(async move { tx.put_task(&task).await })
    })
    .await
    .unwrap();

    let report_id = random();
    let report: LeaderStoredReport<0, dummy_vdaf::Vdaf> = LeaderStoredReport::new(
        *task.id(),
        ReportMetadata::new(report_id, OLDEST_ALLOWED_REPORT_TIMESTAMP),
        (), // public share
        Vec::from([
            Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
            Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
        ]),
        dummy_vdaf::InputShare::default(), // leader input share
        /* Dummy ciphertext for the helper share */
        HpkeCiphertext::new(
            HpkeConfigId::from(13),
            Vec::from("encapsulated_context_1"),
            Vec::from("payload_1"),
        ),
    );

    // Write a report twice to prove it is idempotent
    for _ in 0..2 {
        ds.run_tx(|tx| {
            let report = report.clone();
            Box::pin(async move {
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report)
                    .await
            })
        })
        .await
        .unwrap();

        let retrieved_report = ds
            .run_tx(|tx| {
                let task_id = *report.task_id();
                Box::pin(async move {
                    tx.get_client_report::<0, dummy_vdaf::Vdaf>(
                        &dummy_vdaf::Vdaf::new(),
                        &task_id,
                        &report_id,
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(report, retrieved_report);
    }

    // Try to write a different report with the same ID, and verify we get the expected error.
    let result = ds
        .run_tx(|tx| {
            let task_id = *report.task_id();
            Box::pin(async move {
                tx.put_client_report(
                    &dummy_vdaf::Vdaf::new(),
                    &LeaderStoredReport::<0, dummy_vdaf::Vdaf>::new(
                        task_id,
                        ReportMetadata::new(report_id, Time::from_seconds_since_epoch(54321)),
                        (), // public share
                        Vec::from([
                            Extension::new(ExtensionType::Tbd, Vec::from("extension_data_2")),
                            Extension::new(ExtensionType::Tbd, Vec::from("extension_data_3")),
                        ]),
                        dummy_vdaf::InputShare::default(), // leader input share
                        /* Dummy ciphertext for the helper share */
                        HpkeCiphertext::new(
                            HpkeConfigId::from(14),
                            Vec::from("encapsulated_context_2"),
                            Vec::from("payload_2"),
                        ),
                    ),
                )
                .await
            })
        })
        .await;
    assert_matches!(result, Err(Error::MutationTargetAlreadyExists));

    // Advance the clock so that the report is expired, and verify that it does not exist.
    clock.advance(&Duration::from_seconds(1));
    let retrieved_report = ds
        .run_tx(|tx| {
            let task_id = *report.task_id();
            Box::pin(async move {
                tx.get_client_report::<0, dummy_vdaf::Vdaf>(
                    &dummy_vdaf::Vdaf::new(),
                    &task_id,
                    &report_id,
                )
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(None, retrieved_report);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn report_not_found(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    let rslt = ds
        .run_tx(|tx| {
            Box::pin(async move {
                tx.get_client_report(&dummy_vdaf::Vdaf::new(), &random(), &random())
                    .await
            })
        })
        .await
        .unwrap();

    assert_eq!(rslt, None);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn get_unaggregated_client_report_ids_for_task(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;
    let report_interval = Interval::new(
        OLDEST_ALLOWED_REPORT_TIMESTAMP
            .sub(&Duration::from_seconds(1))
            .unwrap(),
        Duration::from_seconds(2),
    )
    .unwrap();
    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Prio3Count,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let unrelated_task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Prio3Count,
        Role::Leader,
    )
    .build();

    let first_unaggregated_report =
        LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let second_unaggregated_report =
        LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let expired_report = LeaderStoredReport::new_dummy(
        *task.id(),
        OLDEST_ALLOWED_REPORT_TIMESTAMP
            .sub(&Duration::from_seconds(1))
            .unwrap(),
    );
    let aggregated_report =
        LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let unrelated_report =
        LeaderStoredReport::new_dummy(*unrelated_task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);

    // Set up state.
    ds.run_tx(|tx| {
        let task = task.clone();
        let unrelated_task = unrelated_task.clone();
        let first_unaggregated_report = first_unaggregated_report.clone();
        let second_unaggregated_report = second_unaggregated_report.clone();
        let expired_report = expired_report.clone();
        let aggregated_report = aggregated_report.clone();
        let unrelated_report = unrelated_report.clone();

        Box::pin(async move {
            tx.put_task(&task).await?;
            tx.put_task(&unrelated_task).await?;

            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &first_unaggregated_report)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &second_unaggregated_report)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &expired_report)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &aggregated_report)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &unrelated_report)
                .await?;

            // Mark aggregated_report as aggregated.
            tx.mark_report_aggregated(task.id(), aggregated_report.metadata().id())
                .await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    // Verify that we can acquire both unaggregated reports.
    let got_reports = HashSet::from_iter(
        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                // At this point, first_unaggregated_report and second_unaggregated_report are
                // both unaggregated.
                assert!(
                    tx.interval_has_unaggregated_reports(task.id(), &report_interval)
                        .await?
                );

                tx.get_unaggregated_client_report_ids_for_task(task.id())
                    .await
            })
        })
        .await
        .unwrap(),
    );

    assert_eq!(
        got_reports,
        HashSet::from([
            (
                *first_unaggregated_report.metadata().id(),
                *first_unaggregated_report.metadata().time(),
            ),
            (
                *second_unaggregated_report.metadata().id(),
                *second_unaggregated_report.metadata().time(),
            ),
        ]),
    );

    // Verify that attempting to acquire again does not return the reports.
    let got_reports = HashSet::<(ReportId, Time)>::from_iter(
        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                // At this point, all reports have started aggregation.
                assert!(
                    !tx.interval_has_unaggregated_reports(task.id(), &report_interval)
                        .await?
                );

                tx.get_unaggregated_client_report_ids_for_task(task.id())
                    .await
            })
        })
        .await
        .unwrap(),
    );

    assert!(got_reports.is_empty());

    // Mark one report un-aggregated.
    ds.run_tx(|tx| {
        let (task, first_unaggregated_report) = (task.clone(), first_unaggregated_report.clone());
        Box::pin(async move {
            tx.mark_reports_unaggregated(task.id(), &[*first_unaggregated_report.metadata().id()])
                .await
        })
    })
    .await
    .unwrap();

    // Verify that we can retrieve the un-aggregated report again.
    let got_reports = HashSet::from_iter(
        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                // At this point, first_unaggregated_report is unaggregated.
                assert!(
                    tx.interval_has_unaggregated_reports(task.id(), &report_interval)
                        .await?
                );

                tx.get_unaggregated_client_report_ids_for_task(task.id())
                    .await
            })
        })
        .await
        .unwrap(),
    );

    assert_eq!(
        got_reports,
        HashSet::from([(
            *first_unaggregated_report.metadata().id(),
            *first_unaggregated_report.metadata().time(),
        ),]),
    );
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn count_client_reports_for_interval(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let unrelated_task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .build();
    let no_reports_task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .build();

    let expired_report_in_interval = LeaderStoredReport::new_dummy(
        *task.id(),
        OLDEST_ALLOWED_REPORT_TIMESTAMP
            .sub(&Duration::from_seconds(1))
            .unwrap(),
    );
    let first_report_in_interval =
        LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let second_report_in_interval = LeaderStoredReport::new_dummy(
        *task.id(),
        OLDEST_ALLOWED_REPORT_TIMESTAMP
            .add(&Duration::from_seconds(1))
            .unwrap(),
    );
    let report_outside_interval = LeaderStoredReport::new_dummy(
        *task.id(),
        OLDEST_ALLOWED_REPORT_TIMESTAMP
            .add(&Duration::from_seconds(10000))
            .unwrap(),
    );
    let report_for_other_task =
        LeaderStoredReport::new_dummy(*unrelated_task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);

    // Set up state.
    ds.run_tx(|tx| {
        let task = task.clone();
        let unrelated_task = unrelated_task.clone();
        let no_reports_task = no_reports_task.clone();
        let expired_report_in_interval = expired_report_in_interval.clone();
        let first_report_in_interval = first_report_in_interval.clone();
        let second_report_in_interval = second_report_in_interval.clone();
        let report_outside_interval = report_outside_interval.clone();
        let report_for_other_task = report_for_other_task.clone();

        Box::pin(async move {
            tx.put_task(&task).await?;
            tx.put_task(&unrelated_task).await?;
            tx.put_task(&no_reports_task).await?;

            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &expired_report_in_interval)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &first_report_in_interval)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &second_report_in_interval)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_outside_interval)
                .await?;
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_for_other_task)
                .await?;

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    let (report_count, no_reports_task_report_count) = ds
        .run_tx(|tx| {
            let (task, no_reports_task) = (task.clone(), no_reports_task.clone());
            Box::pin(async move {
                let report_count = tx
                    .count_client_reports_for_interval(
                        task.id(),
                        &Interval::new(
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(1))
                                .unwrap(),
                            Duration::from_seconds(5),
                        )
                        .unwrap(),
                    )
                    .await?;

                let no_reports_task_report_count = tx
                    .count_client_reports_for_interval(
                        no_reports_task.id(),
                        &Interval::new(
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(1))
                                .unwrap(),
                            Duration::from_seconds(5),
                        )
                        .unwrap(),
                    )
                    .await?;

                Ok((report_count, no_reports_task_report_count))
            })
        })
        .await
        .unwrap();
    assert_eq!(report_count, 2);
    assert_eq!(no_reports_task_report_count, 0);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn count_client_reports_for_batch_id(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task = TaskBuilder::new(
        task::QueryType::FixedSize {
            max_batch_size: 10,
            batch_time_window_size: None,
        },
        VdafInstance::Fake,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let unrelated_task = TaskBuilder::new(
        task::QueryType::FixedSize {
            max_batch_size: 10,
            batch_time_window_size: None,
        },
        VdafInstance::Fake,
        Role::Leader,
    )
    .build();

    // Set up state.
    let batch_id = ds
        .run_tx(|tx| {
            let (task, unrelated_task) = (task.clone(), unrelated_task.clone());

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&unrelated_task).await?;

                // Create a batch for the first task containing two reports, which has started
                // aggregation twice with two different aggregation parameters.
                let batch_id = random();
                let expired_report = LeaderStoredReport::new_dummy(
                    *task.id(),
                    OLDEST_ALLOWED_REPORT_TIMESTAMP
                        .sub(&Duration::from_seconds(2))
                        .unwrap(),
                );
                let report_0 =
                    LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);
                let report_1 = LeaderStoredReport::new_dummy(
                    *task.id(),
                    OLDEST_ALLOWED_REPORT_TIMESTAMP
                        .add(&Duration::from_seconds(1))
                        .unwrap(),
                );

                let expired_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    AggregationParam(22),
                    batch_id,
                    Interval::new(
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(2))
                            .unwrap(),
                        Duration::from_seconds(1),
                    )
                    .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobRound::from(0),
                );
                let expired_report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    *expired_aggregation_job.id(),
                    *expired_report.metadata().id(),
                    *expired_report.metadata().time(),
                    0,
                    None,
                    ReportAggregationState::Start,
                );

                let aggregation_job_0 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    AggregationParam(22),
                    batch_id,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(2))
                        .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobRound::from(0),
                );
                let aggregation_job_0_report_aggregation_0 =
                    ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        *report_0.metadata().id(),
                        *report_0.metadata().time(),
                        1,
                        None,
                        ReportAggregationState::Start,
                    );
                let aggregation_job_0_report_aggregation_1 =
                    ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_0.id(),
                        *report_1.metadata().id(),
                        *report_1.metadata().time(),
                        2,
                        None,
                        ReportAggregationState::Start,
                    );

                let aggregation_job_1 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    AggregationParam(23),
                    batch_id,
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobRound::from(0),
                );
                let aggregation_job_1_report_aggregation_0 =
                    ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        *report_0.metadata().id(),
                        *report_0.metadata().time(),
                        0,
                        None,
                        ReportAggregationState::Start,
                    );
                let aggregation_job_1_report_aggregation_1 =
                    ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job_1.id(),
                        *report_1.metadata().id(),
                        *report_1.metadata().time(),
                        1,
                        None,
                        ReportAggregationState::Start,
                    );

                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &expired_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_0)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report_1)
                    .await?;

                tx.put_aggregation_job(&expired_aggregation_job).await?;
                tx.put_report_aggregation(&expired_report_aggregation)
                    .await?;

                tx.put_aggregation_job(&aggregation_job_0).await?;
                tx.put_report_aggregation(&aggregation_job_0_report_aggregation_0)
                    .await?;
                tx.put_report_aggregation(&aggregation_job_0_report_aggregation_1)
                    .await?;

                tx.put_aggregation_job(&aggregation_job_1).await?;
                tx.put_report_aggregation(&aggregation_job_1_report_aggregation_0)
                    .await?;
                tx.put_report_aggregation(&aggregation_job_1_report_aggregation_1)
                    .await?;

                Ok(batch_id)
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    let report_count = ds
        .run_tx(|tx| {
            let task_id = *task.id();
            Box::pin(async move {
                tx.count_client_reports_for_batch_id(&task_id, &batch_id)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(report_count, 2);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_report_share(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Prio3Count,
        Role::Leader,
    )
    .build();
    let report_share = ReportShare::new(
        ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(12345),
        ),
        Vec::from("public_share"),
        HpkeCiphertext::new(
            HpkeConfigId::from(12),
            Vec::from("encapsulated_context_0"),
            Vec::from("payload_0"),
        ),
    );

    ds.run_tx(|tx| {
        let (task, report_share) = (task.clone(), report_share.clone());
        Box::pin(async move {
            tx.put_task(&task).await?;
            tx.put_report_share(task.id(), &report_share).await?;

            Ok(())
        })
    })
    .await
    .unwrap();

    let (got_task_id, got_extensions, got_leader_input_share, got_helper_input_share) = ds
        .run_tx(|tx| {
            let report_share_metadata = report_share.metadata().clone();
            Box::pin(async move {
                let row = tx
                    .query_one(
                        "SELECT
                                tasks.task_id,
                                client_reports.report_id,
                                client_reports.client_timestamp,
                                client_reports.extensions,
                                client_reports.leader_input_share,
                                client_reports.helper_encrypted_input_share
                            FROM client_reports JOIN tasks ON tasks.id = client_reports.task_id
                            WHERE report_id = $1 AND client_timestamp = $2",
                        &[
                            /* report_id */ &report_share_metadata.id().as_ref(),
                            /* client_timestamp */
                            &report_share_metadata.time().as_naive_date_time()?,
                        ],
                    )
                    .await?;

                let task_id = TaskId::get_decoded(row.get("task_id"))?;

                let maybe_extensions: Option<Vec<u8>> = row.get("extensions");
                let maybe_leader_input_share: Option<Vec<u8>> = row.get("leader_input_share");
                let maybe_helper_input_share: Option<Vec<u8>> =
                    row.get("helper_encrypted_input_share");

                Ok((
                    task_id,
                    maybe_extensions,
                    maybe_leader_input_share,
                    maybe_helper_input_share,
                ))
            })
        })
        .await
        .unwrap();

    assert_eq!(task.id(), &got_task_id);
    assert!(got_extensions.is_none());
    assert!(got_leader_input_share.is_none());
    assert!(got_helper_input_share.is_none());

    // Put the same report share again. This should not cause an error.
    ds.run_tx(|tx| {
        let (task_id, report_share) = (*task.id(), report_share.clone());
        Box::pin(async move {
            tx.put_report_share(&task_id, &report_share).await.unwrap();

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_aggregation_job(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    // We use a dummy VDAF & fixed-size task for this test, to better exercise the
    // serialization/deserialization roundtrip of the batch_identifier & aggregation_param.
    let task = TaskBuilder::new(
        task::QueryType::FixedSize {
            max_batch_size: 10,
            batch_time_window_size: None,
        },
        VdafInstance::Fake,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let batch_id = random();
    let leader_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        *task.id(),
        random(),
        AggregationParam(23),
        batch_id,
        Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1)).unwrap(),
        AggregationJobState::InProgress,
        AggregationJobRound::from(0),
    );
    let helper_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        *task.id(),
        random(),
        AggregationParam(23),
        random(),
        Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1)).unwrap(),
        AggregationJobState::InProgress,
        AggregationJobRound::from(0),
    );

    ds.run_tx(|tx| {
        let (task, leader_aggregation_job, helper_aggregation_job) = (
            task.clone(),
            leader_aggregation_job.clone(),
            helper_aggregation_job.clone(),
        );
        Box::pin(async move {
            tx.put_task(&task).await.unwrap();
            tx.put_aggregation_job(&leader_aggregation_job)
                .await
                .unwrap();
            tx.put_aggregation_job(&helper_aggregation_job)
                .await
                .unwrap();

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    let (got_leader_aggregation_job, got_helper_aggregation_job) = ds
        .run_tx(|tx| {
            let (leader_aggregation_job, helper_aggregation_job) = (
                leader_aggregation_job.clone(),
                helper_aggregation_job.clone(),
            );
            Box::pin(async move {
                Ok((
                    tx.get_aggregation_job(
                        leader_aggregation_job.task_id(),
                        leader_aggregation_job.id(),
                    )
                    .await
                    .unwrap(),
                    tx.get_aggregation_job(
                        helper_aggregation_job.task_id(),
                        helper_aggregation_job.id(),
                    )
                    .await
                    .unwrap(),
                ))
            })
        })
        .await
        .unwrap();
    assert_eq!(
        Some(&leader_aggregation_job),
        got_leader_aggregation_job.as_ref()
    );
    assert_eq!(
        Some(&helper_aggregation_job),
        got_helper_aggregation_job.as_ref()
    );

    let new_leader_aggregation_job = leader_aggregation_job
        .clone()
        .with_state(AggregationJobState::Finished);
    let new_helper_aggregation_job =
        helper_aggregation_job.with_last_continue_request_hash([3; 32]);
    ds.run_tx(|tx| {
        let (new_leader_aggregation_job, new_helper_aggregation_job) = (
            new_leader_aggregation_job.clone(),
            new_helper_aggregation_job.clone(),
        );
        Box::pin(async move {
            tx.update_aggregation_job(&new_leader_aggregation_job)
                .await
                .unwrap();
            tx.update_aggregation_job(&new_helper_aggregation_job)
                .await
                .unwrap();

            Ok(())
        })
    })
    .await
    .unwrap();

    let (got_leader_aggregation_job, got_helper_aggregation_job) = ds
        .run_tx(|tx| {
            let (new_leader_aggregation_job, new_helper_aggregation_job) = (
                new_leader_aggregation_job.clone(),
                new_helper_aggregation_job.clone(),
            );
            Box::pin(async move {
                Ok((
                    tx.get_aggregation_job(
                        new_leader_aggregation_job.task_id(),
                        new_leader_aggregation_job.id(),
                    )
                    .await
                    .unwrap(),
                    tx.get_aggregation_job(
                        new_helper_aggregation_job.task_id(),
                        new_helper_aggregation_job.id(),
                    )
                    .await
                    .unwrap(),
                ))
            })
        })
        .await
        .unwrap();
    assert_eq!(
        Some(new_leader_aggregation_job.clone()),
        got_leader_aggregation_job
    );
    assert_eq!(
        Some(new_helper_aggregation_job.clone()),
        got_helper_aggregation_job
    );

    // Trying to write an aggregation job again should fail.
    let new_leader_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        *task.id(),
        *leader_aggregation_job.id(),
        AggregationParam(24),
        batch_id,
        Interval::new(
            Time::from_seconds_since_epoch(2345),
            Duration::from_seconds(6789),
        )
        .unwrap(),
        AggregationJobState::InProgress,
        AggregationJobRound::from(0),
    );
    ds.run_tx(|tx| {
        let new_leader_aggregation_job = new_leader_aggregation_job.clone();
        Box::pin(async move {
            let error = tx
                .put_aggregation_job(&new_leader_aggregation_job)
                .await
                .unwrap_err();
            assert_matches!(error, Error::MutationTargetAlreadyExists);

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to verify that the aggregation jobs have expired & are no longer
    // returned.
    clock.advance(&Duration::from_seconds(2));
    let (got_leader_aggregation_job, got_helper_aggregation_job) = ds
        .run_tx(|tx| {
            let (new_leader_aggregation_job, new_helper_aggregation_job) = (
                new_leader_aggregation_job.clone(),
                new_helper_aggregation_job.clone(),
            );
            Box::pin(async move {
                Ok((
                    tx.get_aggregation_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                        new_leader_aggregation_job.task_id(),
                        new_leader_aggregation_job.id(),
                    )
                    .await
                    .unwrap(),
                    tx.get_aggregation_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                        new_helper_aggregation_job.task_id(),
                        new_helper_aggregation_job.id(),
                    )
                    .await
                    .unwrap(),
                ))
            })
        })
        .await
        .unwrap();
    assert_eq!(None, got_leader_aggregation_job);
    assert_eq!(None, got_helper_aggregation_job);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn aggregation_job_acquire_release(ephemeral_datastore: EphemeralDatastore) {
    // Setup: insert a few aggregation jobs.
    install_test_trace_subscriber();

    const LEASE_DURATION: StdDuration = StdDuration::from_secs(300);
    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    const AGGREGATION_JOB_COUNT: usize = 10;
    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Prio3Count,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let mut aggregation_job_ids: Vec<_> = thread_rng()
        .sample_iter(Standard)
        .take(AGGREGATION_JOB_COUNT)
        .collect();
    aggregation_job_ids.sort();

    ds.run_tx(|tx| {
        let (task, aggregation_job_ids) = (task.clone(), aggregation_job_ids.clone());
        Box::pin(async move {
            // Write a few aggregation jobs we expect to be able to retrieve with
            // acquire_incomplete_aggregation_jobs().
            tx.put_task(&task).await?;
            try_join_all(aggregation_job_ids.into_iter().map(|aggregation_job_id| {
                let task_id = *task.id();
                async move {
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                    >::new(
                        task_id,
                        aggregation_job_id,
                        (),
                        (),
                        Interval::new(
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(LEASE_DURATION.as_secs()))
                                .unwrap()
                                .add(&Duration::from_seconds(LEASE_DURATION.as_secs()))
                                .unwrap(),
                            Duration::from_seconds(1),
                        )
                        .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await
                }
            }))
            .await?;

            // Write an aggregation job that is finished. We don't want to retrieve this one.
            tx.put_aggregation_job(&AggregationJob::<
                PRIO3_VERIFY_KEY_LENGTH,
                TimeInterval,
                Prio3Count,
            >::new(
                *task.id(),
                random(),
                (),
                (),
                Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1)).unwrap(),
                AggregationJobState::Finished,
                AggregationJobRound::from(1),
            ))
            .await?;

            // Write an expired aggregation job. We don't want to retrieve this one, either.
            tx.put_aggregation_job(&AggregationJob::<
                PRIO3_VERIFY_KEY_LENGTH,
                TimeInterval,
                Prio3Count,
            >::new(
                *task.id(),
                random(),
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::InProgress,
                AggregationJobRound::from(0),
            ))
            .await?;

            // Write an aggregation job for a task that we are taking on the helper role for.
            // We don't want to retrieve this one, either.
            let helper_task = TaskBuilder::new(
                task::QueryType::TimeInterval,
                VdafInstance::Prio3Count,
                Role::Helper,
            )
            .build();
            tx.put_task(&helper_task).await?;
            tx.put_aggregation_job(&AggregationJob::<
                PRIO3_VERIFY_KEY_LENGTH,
                TimeInterval,
                Prio3Count,
            >::new(
                *helper_task.id(),
                random(),
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::InProgress,
                AggregationJobRound::from(0),
            ))
            .await
        })
    })
    .await
    .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    // Run: run several transactions that all call acquire_incomplete_aggregation_jobs
    // concurrently. (We do things concurrently in an attempt to make sure the
    // mutual-exclusivity works properly.)
    const CONCURRENT_TX_COUNT: usize = 10;
    const MAXIMUM_ACQUIRE_COUNT: usize = 4;

    // Sanity check constants: ensure we acquire jobs across multiple calls to exercise the
    // maximum-jobs-per-call functionality. Make sure we're attempting to acquire enough jobs
    // in total to cover the number of acquirable jobs we created.
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(MAXIMUM_ACQUIRE_COUNT < AGGREGATION_JOB_COUNT);
        assert!(
            MAXIMUM_ACQUIRE_COUNT
                .checked_mul(CONCURRENT_TX_COUNT)
                .unwrap()
                >= AGGREGATION_JOB_COUNT
        );
    }

    let want_expiry_time = clock.now().as_naive_date_time().unwrap()
        + chrono::Duration::from_std(LEASE_DURATION).unwrap();
    let want_aggregation_jobs: Vec<_> = aggregation_job_ids
        .iter()
        .map(|&agg_job_id| {
            (
                AcquiredAggregationJob::new(
                    *task.id(),
                    agg_job_id,
                    task::QueryType::TimeInterval,
                    VdafInstance::Prio3Count,
                ),
                want_expiry_time,
            )
        })
        .collect();

    let got_leases = timeout(StdDuration::from_secs(10), {
        let ds = Arc::clone(&ds);
        let want_lease_count = want_aggregation_jobs.len();
        async move {
            let mut got_leases = Vec::new();
            loop {
                // Rarely, due to Postgres locking semantics, an aggregation job that could be
                // returned will instead be skipped by all concurrent aggregation attempts. Retry
                // for a little while to keep this from affecting test outcome.
                let results = try_join_all(
                    iter::repeat_with(|| {
                        ds.run_tx(|tx| {
                            Box::pin(async move {
                                tx.acquire_incomplete_aggregation_jobs(
                                    &LEASE_DURATION,
                                    MAXIMUM_ACQUIRE_COUNT,
                                )
                                .await
                            })
                        })
                    })
                    .take(CONCURRENT_TX_COUNT),
                )
                .await
                .unwrap();

                for result in results {
                    assert!(result.len() <= MAXIMUM_ACQUIRE_COUNT);
                    got_leases.extend(result.into_iter());
                }

                if got_leases.len() >= want_lease_count {
                    break got_leases;
                }
            }
        }
    })
    .await
    .unwrap();

    // Verify: check that we got all of the desired aggregation jobs, with no duplication, and
    // the expected lease expiry.
    let mut got_aggregation_jobs: Vec<_> = got_leases
        .iter()
        .map(|lease| {
            assert_eq!(lease.lease_attempts(), 1);
            (lease.leased().clone(), *lease.lease_expiry_time())
        })
        .collect();
    got_aggregation_jobs.sort();

    assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

    // Run: release a few jobs, then attempt to acquire jobs again.
    const RELEASE_COUNT: usize = 2;

    // Sanity check constants: ensure we release fewer jobs than we're about to acquire to
    // ensure we can acquire them in all in a single call, while leaving headroom to acquire
    // at least one unwanted job if there is a logic bug.
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(RELEASE_COUNT < MAXIMUM_ACQUIRE_COUNT);
    }

    let leases_to_release: Vec<_> = got_leases.into_iter().take(RELEASE_COUNT).collect();
    let mut jobs_to_release: Vec<_> = leases_to_release
        .iter()
        .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
        .collect();
    jobs_to_release.sort();
    ds.run_tx(|tx| {
        let leases_to_release = leases_to_release.clone();
        Box::pin(async move {
            for lease in leases_to_release {
                tx.release_aggregation_job(&lease).await?;
            }
            Ok(())
        })
    })
    .await
    .unwrap();

    let mut got_aggregation_jobs: Vec<_> = ds
        .run_tx(|tx| {
            Box::pin(async move {
                tx.acquire_incomplete_aggregation_jobs(&LEASE_DURATION, MAXIMUM_ACQUIRE_COUNT)
                    .await
            })
        })
        .await
        .unwrap()
        .into_iter()
        .map(|lease| {
            assert_eq!(lease.lease_attempts(), 1);
            (lease.leased().clone(), *lease.lease_expiry_time())
        })
        .collect();
    got_aggregation_jobs.sort();

    // Verify: we should have re-acquired the jobs we released.
    assert_eq!(jobs_to_release, got_aggregation_jobs);

    // Run: advance time by the lease duration (which implicitly releases the jobs), and attempt
    // to acquire aggregation jobs again.
    clock.advance(&Duration::from_seconds(LEASE_DURATION.as_secs()));
    let want_expiry_time = clock.now().as_naive_date_time().unwrap()
        + chrono::Duration::from_std(LEASE_DURATION).unwrap();
    let want_aggregation_jobs: Vec<_> = aggregation_job_ids
        .iter()
        .map(|&job_id| {
            (
                AcquiredAggregationJob::new(
                    *task.id(),
                    job_id,
                    task::QueryType::TimeInterval,
                    VdafInstance::Prio3Count,
                ),
                want_expiry_time,
            )
        })
        .collect();
    let mut got_aggregation_jobs: Vec<_> = ds
        .run_tx(|tx| {
            Box::pin(async move {
                // This time, we just acquire all jobs in a single go for simplicity -- we've
                // already tested the maximum acquire count functionality above.
                tx.acquire_incomplete_aggregation_jobs(&LEASE_DURATION, AGGREGATION_JOB_COUNT)
                    .await
            })
        })
        .await
        .unwrap()
        .into_iter()
        .map(|lease| {
            let job = (lease.leased().clone(), *lease.lease_expiry_time());
            let expected_attempts = if jobs_to_release.contains(&job) { 1 } else { 2 };
            assert_eq!(lease.lease_attempts(), expected_attempts);
            job
        })
        .collect();
    got_aggregation_jobs.sort();

    // Verify: we got all the jobs.
    assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

    // Run: advance time again to release jobs, acquire a single job, modify its lease token
    // to simulate a previously-held lease, and attempt to release it. Verify that releasing
    // fails.
    clock.advance(&Duration::from_seconds(LEASE_DURATION.as_secs()));
    let lease = ds
        .run_tx(|tx| {
            Box::pin(async move {
                Ok(tx
                    .acquire_incomplete_aggregation_jobs(&LEASE_DURATION, 1)
                    .await?
                    .remove(0))
            })
        })
        .await
        .unwrap();
    let lease_with_random_token = Lease::new(
        lease.leased().clone(),
        *lease.lease_expiry_time(),
        random(),
        lease.lease_attempts(),
    );
    ds.run_tx(|tx| {
        let lease_with_random_token = lease_with_random_token.clone();
        Box::pin(async move { tx.release_aggregation_job(&lease_with_random_token).await })
    })
    .await
    .unwrap_err();

    // Replace the original lease token and verify that we can release successfully with it in
    // place.
    ds.run_tx(|tx| {
        let lease = lease.clone();
        Box::pin(async move { tx.release_aggregation_job(&lease).await })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn aggregation_job_not_found(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    let rslt = ds
        .run_tx(|tx| {
            Box::pin(async move {
                tx.get_aggregation_job::<PRIO3_VERIFY_KEY_LENGTH, TimeInterval, Prio3Count>(
                    &random(),
                    &random(),
                )
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(rslt, None);

    let rslt = ds
        .run_tx(|tx| {
            Box::pin(async move {
                tx.update_aggregation_job::<PRIO3_VERIFY_KEY_LENGTH, TimeInterval, Prio3Count>(
                    &AggregationJob::new(
                        random(),
                        random(),
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ),
                )
                .await
            })
        })
        .await;
    assert_matches!(rslt, Err(Error::MutationTargetNotFound));
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn get_aggregation_jobs_for_task(ephemeral_datastore: EphemeralDatastore) {
    // Setup.
    install_test_trace_subscriber();
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    // We use a dummy VDAF & fixed-size task for this test, to better exercise the
    // serialization/deserialization roundtrip of the batch_identifier & aggregation_param.
    let task = TaskBuilder::new(
        task::QueryType::FixedSize {
            max_batch_size: 10,
            batch_time_window_size: None,
        },
        VdafInstance::Fake,
        Role::Leader,
    )
    .build();
    let first_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        *task.id(),
        random(),
        AggregationParam(23),
        random(),
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::InProgress,
        AggregationJobRound::from(0),
    );
    let second_aggregation_job = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        *task.id(),
        random(),
        AggregationParam(42),
        random(),
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::InProgress,
        AggregationJobRound::from(0),
    );
    let aggregation_job_with_request_hash = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        *task.id(),
        random(),
        AggregationParam(42),
        random(),
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::InProgress,
        AggregationJobRound::from(0),
    )
    .with_last_continue_request_hash([3; 32]);

    let mut want_agg_jobs = Vec::from([
        first_aggregation_job,
        second_aggregation_job,
        aggregation_job_with_request_hash,
    ]);

    ds.run_tx(|tx| {
        let (task, want_agg_jobs) = (task.clone(), want_agg_jobs.clone());
        Box::pin(async move {
            tx.put_task(&task).await?;

            for agg_job in want_agg_jobs {
                tx.put_aggregation_job(&agg_job).await.unwrap();
            }

            // Also write an unrelated aggregation job with a different task ID to check that it
            // is not returned.
            let unrelated_task = TaskBuilder::new(
                task::QueryType::FixedSize {
                    max_batch_size: 10,
                    batch_time_window_size: None,
                },
                VdafInstance::Fake,
                Role::Leader,
            )
            .build();
            tx.put_task(&unrelated_task).await?;
            tx.put_aggregation_job(&AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                *unrelated_task.id(),
                random(),
                AggregationParam(82),
                random(),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::InProgress,
                AggregationJobRound::from(0),
            ))
            .await
        })
    })
    .await
    .unwrap();

    // Run.
    want_agg_jobs.sort_by_key(|agg_job| *agg_job.id());
    let mut got_agg_jobs = ds
        .run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.get_aggregation_jobs_for_task(task.id()).await })
        })
        .await
        .unwrap();
    got_agg_jobs.sort_by_key(|agg_job| *agg_job.id());

    // Verify.
    assert_eq!(want_agg_jobs, got_agg_jobs);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_report_aggregation(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let report_id = random();
    let vdaf = Arc::new(Prio3::new_count(2).unwrap());
    let verify_key: [u8; PRIO3_VERIFY_KEY_LENGTH] = random();
    let vdaf_transcript = run_vdaf(vdaf.as_ref(), &verify_key, &(), &report_id, &0);
    let leader_prep_state = vdaf_transcript.leader_prep_state(0);

    for (ord, state) in [
        ReportAggregationState::<PRIO3_VERIFY_KEY_LENGTH, Prio3Count>::Start,
        ReportAggregationState::Waiting(
            leader_prep_state.clone(),
            Some(vdaf_transcript.prepare_messages[0].clone()),
        ),
        ReportAggregationState::Waiting(leader_prep_state.clone(), None),
        ReportAggregationState::Finished,
        ReportAggregationState::Failed(ReportShareError::VdafPrepError),
    ]
    .into_iter()
    .enumerate()
    {
        let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
        let ds = ephemeral_datastore.datastore(clock.clone()).await;

        let task = TaskBuilder::new(
            task::QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
        .build();
        let aggregation_job_id = random();
        let report_id = random();

        let want_report_aggregation = ds
            .run_tx(|tx| {
                let (task, state) = (task.clone(), state.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            ReportMetadata::new(report_id, OLDEST_ALLOWED_REPORT_TIMESTAMP),
                            Vec::from("public_share"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(12),
                                Vec::from("encapsulated_context_0"),
                                Vec::from("payload_0"),
                            ),
                        ),
                    )
                    .await?;

                    let report_aggregation = ReportAggregation::new(
                        *task.id(),
                        aggregation_job_id,
                        report_id,
                        OLDEST_ALLOWED_REPORT_TIMESTAMP,
                        ord.try_into().unwrap(),
                        Some(PrepareStep::new(
                            report_id,
                            PrepareStepResult::Continued(format!("prep_msg_{ord}").into()),
                        )),
                        state,
                    );
                    tx.put_report_aggregation(&report_aggregation).await?;
                    Ok(report_aggregation)
                })
            })
            .await
            .unwrap();

        // Advance the clock to "enable" report expiry.
        clock.advance(&REPORT_EXPIRY_AGE);

        let got_report_aggregation = ds
            .run_tx(|tx| {
                let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                Box::pin(async move {
                    tx.get_report_aggregation(
                        vdaf.as_ref(),
                        &Role::Leader,
                        task.id(),
                        &aggregation_job_id,
                        &report_id,
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(want_report_aggregation, got_report_aggregation);

        let want_report_aggregation = ReportAggregation::new(
            *want_report_aggregation.task_id(),
            *want_report_aggregation.aggregation_job_id(),
            *want_report_aggregation.report_id(),
            *want_report_aggregation.time(),
            want_report_aggregation.ord(),
            Some(PrepareStep::new(
                report_id,
                PrepareStepResult::Continued(format!("updated_prep_msg_{ord}").into()),
            )),
            want_report_aggregation.state().clone(),
        );

        ds.run_tx(|tx| {
            let want_report_aggregation = want_report_aggregation.clone();
            Box::pin(async move { tx.update_report_aggregation(&want_report_aggregation).await })
        })
        .await
        .unwrap();

        let got_report_aggregation = ds
            .run_tx(|tx| {
                let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                Box::pin(async move {
                    tx.get_report_aggregation(
                        vdaf.as_ref(),
                        &Role::Leader,
                        task.id(),
                        &aggregation_job_id,
                        &report_id,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(Some(want_report_aggregation), got_report_aggregation);

        // Advance the clock again to expire relevant datastore items.
        clock.advance(&REPORT_EXPIRY_AGE);

        let got_report_aggregation = ds
            .run_tx(|tx| {
                let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                Box::pin(async move {
                    tx.get_report_aggregation(
                        vdaf.as_ref(),
                        &Role::Leader,
                        task.id(),
                        &aggregation_job_id,
                        &report_id,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(None, got_report_aggregation);
    }
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn check_other_report_aggregation_exists(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Helper,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();

    ds.put_task(&task).await.unwrap();

    let aggregation_job_id = random();
    let report_id = random();

    ds.run_tx(|tx| {
        let task_id = *task.id();
        Box::pin(async move {
            tx.put_aggregation_job(&AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                dummy_vdaf::AggregationParam(0),
                (),
                Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1)).unwrap(),
                AggregationJobState::InProgress,
                AggregationJobRound::from(0),
            ))
            .await?;
            tx.put_report_share(
                &task_id,
                &ReportShare::new(
                    ReportMetadata::new(report_id, OLDEST_ALLOWED_REPORT_TIMESTAMP),
                    Vec::from("public_share"),
                    HpkeCiphertext::new(
                        HpkeConfigId::from(12),
                        Vec::from("encapsulated_context_0"),
                        Vec::from("payload_0"),
                    ),
                ),
            )
            .await?;

            let report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                task_id,
                aggregation_job_id,
                report_id,
                OLDEST_ALLOWED_REPORT_TIMESTAMP,
                0,
                None,
                ReportAggregationState::Start,
            );
            tx.put_report_aggregation(&report_aggregation).await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let task_id = *task.id();
        Box::pin(async move {
            assert!(tx
                .check_other_report_aggregation_exists::<0, dummy_vdaf::Vdaf>(
                    &task_id,
                    &report_id,
                    &dummy_vdaf::AggregationParam(0),
                    &random(),
                )
                .await
                .unwrap());

            // Aggregation job ID matches
            assert!(!tx
                .check_other_report_aggregation_exists::<0, dummy_vdaf::Vdaf>(
                    &task_id,
                    &report_id,
                    &dummy_vdaf::AggregationParam(0),
                    &aggregation_job_id,
                )
                .await
                .unwrap());

            // Wrong task ID
            assert!(!tx
                .check_other_report_aggregation_exists::<0, dummy_vdaf::Vdaf>(
                    &random(),
                    &report_id,
                    &dummy_vdaf::AggregationParam(0),
                    &random(),
                )
                .await
                .unwrap());

            // Wrong report ID
            assert!(!tx
                .check_other_report_aggregation_exists::<0, dummy_vdaf::Vdaf>(
                    &task_id,
                    &random(),
                    &dummy_vdaf::AggregationParam(0),
                    &random(),
                )
                .await
                .unwrap());

            // Wrong aggregation param
            assert!(!tx
                .check_other_report_aggregation_exists::<0, dummy_vdaf::Vdaf>(
                    &task_id,
                    &report_id,
                    &dummy_vdaf::AggregationParam(1),
                    &random(),
                )
                .await
                .unwrap());

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock again to expire all relevant datastore items.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let task_id = *task.id();
        Box::pin(async move {
            assert!(!tx
                .check_other_report_aggregation_exists::<0, dummy_vdaf::Vdaf>(
                    &task_id,
                    &report_id,
                    &dummy_vdaf::AggregationParam(0),
                    &random(),
                )
                .await
                .unwrap());

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn report_aggregation_not_found(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    let vdaf = Arc::new(dummy_vdaf::Vdaf::default());

    let rslt = ds
        .run_tx(|tx| {
            let vdaf = Arc::clone(&vdaf);
            Box::pin(async move {
                tx.get_report_aggregation(
                    vdaf.as_ref(),
                    &Role::Leader,
                    &random(),
                    &random(),
                    &ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                )
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(rslt, None);

    let rslt = ds
        .run_tx(|tx| {
            Box::pin(async move {
                tx.update_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                    random(),
                    random(),
                    ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    Time::from_seconds_since_epoch(12345),
                    0,
                    None,
                    ReportAggregationState::Failed(ReportShareError::VdafPrepError),
                ))
                .await
            })
        })
        .await;
    assert_matches!(rslt, Err(Error::MutationTargetNotFound));
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn get_report_aggregations_for_aggregation_job(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let report_id = random();
    let vdaf = Arc::new(Prio3::new_count(2).unwrap());
    let verify_key: [u8; PRIO3_VERIFY_KEY_LENGTH] = random();
    let vdaf_transcript = run_vdaf(vdaf.as_ref(), &verify_key, &(), &report_id, &0);

    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Prio3Count,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let aggregation_job_id = random();

    let want_report_aggregations = ds
        .run_tx(|tx| {
            let (task, prep_msg, prep_state) = (
                task.clone(),
                vdaf_transcript.prepare_messages[0].clone(),
                vdaf_transcript.leader_prep_state(0).clone(),
            );
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Count,
                >::new(
                    *task.id(),
                    aggregation_job_id,
                    (),
                    (),
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobRound::from(0),
                ))
                .await?;

                let mut want_report_aggregations = Vec::new();
                for (ord, state) in [
                    ReportAggregationState::<PRIO3_VERIFY_KEY_LENGTH, Prio3Count>::Start,
                    ReportAggregationState::Waiting(prep_state.clone(), Some(prep_msg)),
                    ReportAggregationState::Finished,
                    ReportAggregationState::Failed(ReportShareError::VdafPrepError),
                ]
                .iter()
                .enumerate()
                {
                    let report_id = ReportId::from((ord as u128).to_be_bytes());
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            ReportMetadata::new(report_id, OLDEST_ALLOWED_REPORT_TIMESTAMP),
                            Vec::from("public_share"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(12),
                                Vec::from("encapsulated_context_0"),
                                Vec::from("payload_0"),
                            ),
                        ),
                    )
                    .await?;

                    let report_aggregation = ReportAggregation::new(
                        *task.id(),
                        aggregation_job_id,
                        report_id,
                        OLDEST_ALLOWED_REPORT_TIMESTAMP,
                        ord.try_into().unwrap(),
                        Some(PrepareStep::new(report_id, PrepareStepResult::Finished)),
                        state.clone(),
                    );
                    tx.put_report_aggregation(&report_aggregation).await?;
                    want_report_aggregations.push(report_aggregation);
                }
                Ok(want_report_aggregations)
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    let got_report_aggregations = ds
        .run_tx(|tx| {
            let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
            Box::pin(async move {
                tx.get_report_aggregations_for_aggregation_job(
                    vdaf.as_ref(),
                    &Role::Leader,
                    task.id(),
                    &aggregation_job_id,
                )
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(want_report_aggregations, got_report_aggregations);

    // Advance the clock again to expire relevant datastore entities.
    clock.advance(&REPORT_EXPIRY_AGE);

    let got_report_aggregations = ds
        .run_tx(|tx| {
            let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
            Box::pin(async move {
                tx.get_report_aggregations_for_aggregation_job(
                    vdaf.as_ref(),
                    &Role::Leader,
                    task.id(),
                    &aggregation_job_id,
                )
                .await
            })
        })
        .await
        .unwrap();
    assert!(got_report_aggregations.is_empty());
}

#[tokio::test]
async fn crypter() {
    let crypter = Crypter::new(Vec::from([generate_aead_key(), generate_aead_key()]));
    let bad_key = generate_aead_key();

    const TABLE: &str = "some_table";
    const ROW: &[u8] = b"12345";
    const COLUMN: &str = "some_column";
    const PLAINTEXT: &[u8] = b"This is my plaintext value.";

    // Test that roundtripping encryption works.
    let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
    let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
    assert_eq!(PLAINTEXT, &plaintext);

    // Roundtripping encryption works even if a non-primary key was used for encryption.
    let ciphertext =
        Crypter::encrypt_with_key(crypter.keys.last().unwrap(), TABLE, ROW, COLUMN, PLAINTEXT)
            .unwrap();
    let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
    assert_eq!(PLAINTEXT, &plaintext);

    // Roundtripping encryption with an unknown key fails.
    let ciphertext = Crypter::encrypt_with_key(&bad_key, TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
    assert!(crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).is_err());

    // Roundtripping encryption with a mismatched table, row, or column fails.
    let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
    assert!(crypter
        .decrypt("wrong_table", ROW, COLUMN, &ciphertext)
        .is_err());
    assert!(crypter
        .decrypt(TABLE, b"wrong_row", COLUMN, &ciphertext)
        .is_err());
    assert!(crypter
        .decrypt(TABLE, ROW, "wrong_column", &ciphertext)
        .is_err());
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn get_collection_job(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let first_batch_interval =
        Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(100)).unwrap();
    let second_batch_interval = Interval::new(
        OLDEST_ALLOWED_REPORT_TIMESTAMP
            .add(&Duration::from_seconds(100))
            .unwrap(),
        Duration::from_seconds(200),
    )
    .unwrap();
    let aggregation_param = AggregationParam(13);

    let (first_collection_job, second_collection_job) = ds
        .run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_task(&task).await.unwrap();

                let first_collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    first_batch_interval,
                    aggregation_param,
                    CollectionJobState::Start,
                );
                tx.put_collection_job(&first_collection_job).await.unwrap();

                let second_collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    random(),
                    second_batch_interval,
                    aggregation_param,
                    CollectionJobState::Start,
                );
                tx.put_collection_job(&second_collection_job).await.unwrap();

                Ok((first_collection_job, second_collection_job))
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let task = task.clone();
        let first_collection_job = first_collection_job.clone();
        let second_collection_job = second_collection_job.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let first_collection_job_again = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    first_collection_job.id(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first_collection_job, first_collection_job_again);

            let second_collection_job_again = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    second_collection_job.id(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(second_collection_job, second_collection_job_again);

            let encrypted_helper_aggregate_share = hpke::seal(
                task.collector_hpke_config().unwrap(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                &[0, 1, 2, 3, 4, 5],
                &AggregateShareAad::new(
                    *task.id(),
                    BatchSelector::new_time_interval(first_batch_interval),
                )
                .get_encoded(),
            )
            .unwrap();

            let first_collection_job =
                first_collection_job.with_state(CollectionJobState::Finished {
                    report_count: 12,
                    encrypted_helper_aggregate_share,
                    leader_aggregate_share: AggregateShare(41),
                });

            tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&first_collection_job)
                .await
                .unwrap();

            let updated_first_collection_job = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    first_collection_job.id(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first_collection_job, updated_first_collection_job);

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock again to expire everything that has been written.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let first_collection_job = first_collection_job.clone();
        let second_collection_job = second_collection_job.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let first_collection_job = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    first_collection_job.id(),
                )
                .await
                .unwrap();
            assert_eq!(first_collection_job, None);

            let second_collection_job = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    second_collection_job.id(),
                )
                .await
                .unwrap();
            assert_eq!(second_collection_job, None);

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn update_collection_jobs(ephemeral_datastore: EphemeralDatastore) {
    // Setup: write collection jobs to the datastore.
    install_test_trace_subscriber();

    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .build();
    let abandoned_batch_interval = Interval::new(
        Time::from_seconds_since_epoch(100),
        Duration::from_seconds(100),
    )
    .unwrap();
    let deleted_batch_interval = Interval::new(
        Time::from_seconds_since_epoch(200),
        Duration::from_seconds(100),
    )
    .unwrap();

    ds.run_tx(|tx| {
        let task = task.clone();
        Box::pin(async move {
            tx.put_task(&task).await?;

            let vdaf = dummy_vdaf::Vdaf::new();
            let aggregation_param = AggregationParam(10);
            let abandoned_collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                *task.id(),
                random(),
                abandoned_batch_interval,
                aggregation_param,
                CollectionJobState::Start,
            );
            tx.put_collection_job(&abandoned_collection_job).await?;

            let deleted_collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                *task.id(),
                random(),
                deleted_batch_interval,
                aggregation_param,
                CollectionJobState::Start,
            );
            tx.put_collection_job(&deleted_collection_job).await?;

            let abandoned_collection_job_again = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    abandoned_collection_job.id(),
                )
                .await?
                .unwrap();

            // Verify: initial state.
            assert_eq!(abandoned_collection_job, abandoned_collection_job_again);

            // Setup: update the collection jobs.
            let abandoned_collection_job =
                abandoned_collection_job.with_state(CollectionJobState::Abandoned);
            let deleted_collection_job =
                deleted_collection_job.with_state(CollectionJobState::Deleted);

            tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                &abandoned_collection_job,
            )
            .await?;
            tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&deleted_collection_job)
                .await?;

            let abandoned_collection_job_again = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    abandoned_collection_job.id(),
                )
                .await?
                .unwrap();

            let deleted_collection_job_again = tx
                .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    deleted_collection_job.id(),
                )
                .await?
                .unwrap();

            // Verify: collection jobs were updated.
            assert_eq!(abandoned_collection_job, abandoned_collection_job_again);
            assert_eq!(deleted_collection_job, deleted_collection_job_again);

            // Setup: try to update a job into state `Start`
            let abandoned_collection_job =
                abandoned_collection_job.with_state(CollectionJobState::Start);

            // Verify: Update should fail
            tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                &abandoned_collection_job,
            )
            .await
            .unwrap_err();
            Ok(())
        })
    })
    .await
    .unwrap();
}

#[derive(Copy, Clone)]
enum CollectionJobTestCaseState {
    Start,
    Collectable,
    Finished,
    Deleted,
    Abandoned,
}

#[derive(Clone)]
struct CollectionJobTestCase<Q: QueryType> {
    should_be_acquired: bool,
    task_id: TaskId,
    batch_identifier: Q::BatchIdentifier,
    agg_param: AggregationParam,
    collection_job_id: Option<CollectionJobId>,
    client_timestamp_interval: Interval,
    state: CollectionJobTestCaseState,
}

#[derive(Clone)]
struct CollectionJobAcquireTestCase<Q: CollectableQueryType> {
    task_ids: Vec<TaskId>,
    query_type: task::QueryType,
    reports: Vec<LeaderStoredReport<0, dummy_vdaf::Vdaf>>,
    aggregation_jobs: Vec<AggregationJob<0, Q, dummy_vdaf::Vdaf>>,
    report_aggregations: Vec<ReportAggregation<0, dummy_vdaf::Vdaf>>,
    collection_job_test_cases: Vec<CollectionJobTestCase<Q>>,
}

async fn setup_collection_job_acquire_test_case<Q: CollectableQueryType>(
    ds: &Datastore<MockClock>,
    test_case: CollectionJobAcquireTestCase<Q>,
) -> CollectionJobAcquireTestCase<Q> {
    ds.run_tx(|tx| {
        let mut test_case = test_case.clone();
        Box::pin(async move {
            for task_id in &test_case.task_ids {
                tx.put_task(
                    &TaskBuilder::new(test_case.query_type, VdafInstance::Fake, Role::Leader)
                        .with_id(*task_id)
                        .build(),
                )
                .await?;
            }

            for report in &test_case.reports {
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), report)
                    .await?;
            }

            for aggregation_job in &test_case.aggregation_jobs {
                tx.put_aggregation_job(aggregation_job).await?;
            }

            for report_aggregation in &test_case.report_aggregations {
                tx.put_report_aggregation(report_aggregation).await?;
            }

            for test_case in test_case.collection_job_test_cases.iter_mut() {
                tx.put_batch(&Batch::<0, Q, dummy_vdaf::Vdaf>::new(
                    test_case.task_id,
                    test_case.batch_identifier.clone(),
                    test_case.agg_param,
                    BatchState::Closed,
                    0,
                    test_case.client_timestamp_interval,
                ))
                .await?;

                let collection_job_id = random();
                tx.put_collection_job(&CollectionJob::<0, Q, dummy_vdaf::Vdaf>::new(
                    test_case.task_id,
                    collection_job_id,
                    test_case.batch_identifier.clone(),
                    test_case.agg_param,
                    match test_case.state {
                        CollectionJobTestCaseState::Start => CollectionJobState::Start,
                        CollectionJobTestCaseState::Collectable => CollectionJobState::Collectable,
                        CollectionJobTestCaseState::Finished => CollectionJobState::Finished {
                            report_count: 1,
                            encrypted_helper_aggregate_share: HpkeCiphertext::new(
                                HpkeConfigId::from(0),
                                Vec::new(),
                                Vec::new(),
                            ),
                            leader_aggregate_share: AggregateShare(0),
                        },
                        CollectionJobTestCaseState::Abandoned => CollectionJobState::Abandoned,
                        CollectionJobTestCaseState::Deleted => CollectionJobState::Deleted,
                    },
                ))
                .await?;

                test_case.collection_job_id = Some(collection_job_id);
            }

            Ok(test_case)
        })
    })
    .await
    .unwrap()
}

async fn run_collection_job_acquire_test_case<Q: CollectableQueryType>(
    ds: &Datastore<MockClock>,
    test_case: CollectionJobAcquireTestCase<Q>,
) -> Vec<Lease<AcquiredCollectionJob>> {
    let test_case = setup_collection_job_acquire_test_case(ds, test_case).await;

    let clock = &ds.clock;
    ds.run_tx(|tx| {
        let test_case = test_case.clone();
        let clock = clock.clone();
        Box::pin(async move {
            let leases = tx
                .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10)
                .await?;

            let mut leased_collection_jobs: Vec<_> = leases
                .iter()
                .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
                .collect();
            leased_collection_jobs.sort();

            let mut expected_collection_jobs: Vec<_> = test_case
                .collection_job_test_cases
                .iter()
                .filter(|c| c.should_be_acquired)
                .map(|c| {
                    (
                        AcquiredCollectionJob::new(
                            c.task_id,
                            c.collection_job_id.unwrap(),
                            test_case.query_type,
                            VdafInstance::Fake,
                        ),
                        clock.now().as_naive_date_time().unwrap() + chrono::Duration::seconds(100),
                    )
                })
                .collect();
            expected_collection_jobs.sort();

            assert_eq!(leased_collection_jobs, expected_collection_jobs);

            Ok(leases)
        })
    })
    .await
    .unwrap()
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn time_interval_collection_job_acquire_release_happy_path(
    ephemeral_datastore: EphemeralDatastore,
) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([LeaderStoredReport::new_dummy(
        task_id,
        Time::from_seconds_since_epoch(0),
    )]);
    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(0),
        Duration::from_seconds(100),
    )
    .unwrap();
    let aggregation_job_id = random();
    let aggregation_jobs = Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        AggregationParam(0),
        (),
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::Finished,
        AggregationJobRound::from(1),
    )]);
    let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        *reports[0].metadata().id(),
        *reports[0].metadata().time(),
        0,
        None,
        ReportAggregationState::Start, // Doesn't matter what state the report aggregation is in
    )]);

    let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
        should_be_acquired: true,
        task_id,
        batch_identifier: batch_interval,
        agg_param: AggregationParam(0),
        collection_job_id: None,
        client_timestamp_interval: Interval::EMPTY,
        state: CollectionJobTestCaseState::Collectable,
    }]);

    let collection_job_leases = run_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::TimeInterval,
            reports,
            aggregation_jobs,
            report_aggregations,
            collection_job_test_cases,
        },
    )
    .await;

    let reacquired_jobs = ds
        .run_tx(|tx| {
            let collection_job_leases = collection_job_leases.clone();
            Box::pin(async move {
                // Try to re-acquire collection jobs. Nothing should happen because the lease is still
                // valid.
                assert!(tx
                    .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10)
                    .await
                    .unwrap()
                    .is_empty());

                // Release the lease, then re-acquire it.
                tx.release_collection_job(&collection_job_leases[0])
                    .await
                    .unwrap();

                let reacquired_leases = tx
                    .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10)
                    .await
                    .unwrap();
                let reacquired_jobs: Vec<_> = reacquired_leases
                    .iter()
                    .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                    .collect();

                let collection_jobs: Vec<_> = collection_job_leases
                    .iter()
                    .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                    .collect();

                assert_eq!(reacquired_jobs.len(), 1);
                assert_eq!(reacquired_jobs, collection_jobs);

                Ok(reacquired_leases)
            })
        })
        .await
        .unwrap();

    // Advance time by the lease duration
    clock.advance(&Duration::from_seconds(100));

    ds.run_tx(|tx| {
        let reacquired_jobs = reacquired_jobs.clone();
        Box::pin(async move {
            // Re-acquire the jobs whose lease should have lapsed.
            let acquired_jobs = tx
                .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10)
                .await
                .unwrap();

            for (acquired_job, reacquired_job) in acquired_jobs.iter().zip(reacquired_jobs) {
                assert_eq!(acquired_job.leased(), reacquired_job.leased());
                assert_eq!(
                    *acquired_job.lease_expiry_time(),
                    *reacquired_job.lease_expiry_time() + chrono::Duration::seconds(100),
                );
            }

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn fixed_size_collection_job_acquire_release_happy_path(
    ephemeral_datastore: EphemeralDatastore,
) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([LeaderStoredReport::new_dummy(
        task_id,
        Time::from_seconds_since_epoch(0),
    )]);
    let batch_id = random();
    let aggregation_job_id = random();
    let aggregation_jobs = Vec::from([AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        AggregationParam(0),
        batch_id,
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::Finished,
        AggregationJobRound::from(1),
    )]);
    let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        *reports[0].metadata().id(),
        *reports[0].metadata().time(),
        0,
        None,
        ReportAggregationState::Start, // Doesn't matter what state the report aggregation is in
    )]);

    let collection_job_leases = run_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::FixedSize {
                max_batch_size: 10,
                batch_time_window_size: None,
            },
            reports,
            aggregation_jobs,
            report_aggregations,
            collection_job_test_cases: Vec::from([CollectionJobTestCase::<FixedSize> {
                should_be_acquired: true,
                task_id,
                batch_identifier: batch_id,
                agg_param: AggregationParam(0),
                collection_job_id: None,
                client_timestamp_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(1),
                )
                .unwrap(),
                state: CollectionJobTestCaseState::Collectable,
            }]),
        },
    )
    .await;

    let reacquired_jobs = ds
        .run_tx(|tx| {
            let collection_job_leases = collection_job_leases.clone();
            Box::pin(async move {
                // Try to re-acquire collection jobs. Nothing should happen because the lease is still
                // valid.
                assert!(tx
                    .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10,)
                    .await
                    .unwrap()
                    .is_empty());

                // Release the lease, then re-acquire it.
                tx.release_collection_job(&collection_job_leases[0])
                    .await
                    .unwrap();

                let reacquired_leases = tx
                    .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10)
                    .await
                    .unwrap();
                let reacquired_jobs: Vec<_> = reacquired_leases
                    .iter()
                    .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                    .collect();

                let collection_jobs: Vec<_> = collection_job_leases
                    .iter()
                    .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                    .collect();

                assert_eq!(reacquired_jobs.len(), 1);
                assert_eq!(reacquired_jobs, collection_jobs);

                Ok(reacquired_leases)
            })
        })
        .await
        .unwrap();

    // Advance time by the lease duration
    clock.advance(&Duration::from_seconds(100));

    ds.run_tx(|tx| {
        let reacquired_jobs = reacquired_jobs.clone();
        Box::pin(async move {
            // Re-acquire the jobs whose lease should have lapsed.
            let acquired_jobs = tx
                .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10)
                .await
                .unwrap();

            for (acquired_job, reacquired_job) in acquired_jobs.iter().zip(reacquired_jobs) {
                assert_eq!(acquired_job.leased(), reacquired_job.leased());
                assert_eq!(
                    *acquired_job.lease_expiry_time(),
                    *reacquired_job.lease_expiry_time() + chrono::Duration::seconds(100),
                );
            }

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn collection_job_acquire_no_aggregation_job_with_task_id(
    ephemeral_datastore: EphemeralDatastore,
) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let other_task_id = random();

    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(0),
        Duration::from_seconds(100),
    )
    .unwrap();
    let aggregation_jobs = Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
        // Aggregation job task ID does not match collection job task ID
        other_task_id,
        random(),
        AggregationParam(0),
        (),
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::Finished,
        AggregationJobRound::from(1),
    )]);

    let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
        should_be_acquired: false,
        task_id,
        batch_identifier: batch_interval,
        agg_param: AggregationParam(0),
        collection_job_id: None,
        client_timestamp_interval: Interval::EMPTY,
        state: CollectionJobTestCaseState::Start,
    }]);

    run_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase {
            task_ids: Vec::from([task_id, other_task_id]),
            query_type: task::QueryType::TimeInterval,
            reports: Vec::new(),
            aggregation_jobs,
            report_aggregations: Vec::new(),
            collection_job_test_cases,
        },
    )
    .await;
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn collection_job_acquire_no_aggregation_job_with_agg_param(
    ephemeral_datastore: EphemeralDatastore,
) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([LeaderStoredReport::new_dummy(
        task_id,
        Time::from_seconds_since_epoch(0),
    )]);

    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(0),
        Duration::from_seconds(100),
    )
    .unwrap();
    let aggregation_jobs = Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
        task_id,
        random(),
        // Aggregation job agg param does not match collection job agg param
        AggregationParam(1),
        (),
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::Finished,
        AggregationJobRound::from(1),
    )]);

    let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
        should_be_acquired: false,
        task_id,
        batch_identifier: batch_interval,
        agg_param: AggregationParam(0),
        collection_job_id: None,
        client_timestamp_interval: Interval::EMPTY,
        state: CollectionJobTestCaseState::Start,
    }]);

    run_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::TimeInterval,
            reports,
            aggregation_jobs,
            report_aggregations: Vec::new(),
            collection_job_test_cases,
        },
    )
    .await;
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn collection_job_acquire_report_shares_outside_interval(
    ephemeral_datastore: EphemeralDatastore,
) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([LeaderStoredReport::new_dummy(
        task_id,
        // Report associated with the aggregation job is outside the collection job's batch
        // interval
        Time::from_seconds_since_epoch(200),
    )]);
    let aggregation_job_id = random();
    let aggregation_jobs = Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        AggregationParam(0),
        (),
        Interval::new(
            Time::from_seconds_since_epoch(200),
            Duration::from_seconds(1),
        )
        .unwrap(),
        AggregationJobState::Finished,
        AggregationJobRound::from(1),
    )]);
    let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        *reports[0].metadata().id(),
        *reports[0].metadata().time(),
        0,
        None,
        ReportAggregationState::Start, // Shouldn't matter what state the report aggregation is in
    )]);

    run_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase::<TimeInterval> {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::TimeInterval,
            reports,
            aggregation_jobs,
            report_aggregations,
            collection_job_test_cases: Vec::from([CollectionJobTestCase::<TimeInterval> {
                should_be_acquired: false,
                task_id,
                batch_identifier: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(0),
                collection_job_id: None,
                client_timestamp_interval: Interval::EMPTY,
                state: CollectionJobTestCaseState::Start,
            }]),
        },
    )
    .await;
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn collection_job_acquire_release_job_finished(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([LeaderStoredReport::new_dummy(
        task_id,
        Time::from_seconds_since_epoch(0),
    )]);
    let aggregation_job_id = random();
    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(0),
        Duration::from_seconds(100),
    )
    .unwrap();
    let aggregation_jobs = Vec::from([AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        AggregationParam(0),
        (),
        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
        AggregationJobState::Finished,
        AggregationJobRound::from(1),
    )]);

    let report_aggregations = Vec::from([ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
        task_id,
        aggregation_job_id,
        *reports[0].metadata().id(),
        *reports[0].metadata().time(),
        0,
        None,
        ReportAggregationState::Start,
    )]);

    let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
        should_be_acquired: false,
        task_id,
        batch_identifier: batch_interval,
        agg_param: AggregationParam(0),
        collection_job_id: None,
        client_timestamp_interval: Interval::EMPTY,
        // collection job has already run to completion
        state: CollectionJobTestCaseState::Finished,
    }]);

    run_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::TimeInterval,
            reports,
            aggregation_jobs,
            report_aggregations,
            collection_job_test_cases,
        },
    )
    .await;
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn collection_job_acquire_release_aggregation_job_in_progress(
    ephemeral_datastore: EphemeralDatastore,
) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([
        LeaderStoredReport::new_dummy(task_id, Time::from_seconds_since_epoch(0)),
        LeaderStoredReport::new_dummy(task_id, Time::from_seconds_since_epoch(50)),
    ]);

    let aggregation_job_ids: [_; 2] = random();
    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(0),
        Duration::from_seconds(100),
    )
    .unwrap();
    let aggregation_jobs = Vec::from([
        AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[0],
            AggregationParam(0),
            (),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::Finished,
            AggregationJobRound::from(1),
        ),
        AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[1],
            AggregationParam(0),
            (),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            // Aggregation job included in collect request is in progress
            AggregationJobState::InProgress,
            AggregationJobRound::from(0),
        ),
    ]);

    let report_aggregations = Vec::from([
        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[0],
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            None,
            ReportAggregationState::Start,
        ),
        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[1],
            *reports[1].metadata().id(),
            *reports[1].metadata().time(),
            0,
            None,
            ReportAggregationState::Start,
        ),
    ]);

    let collection_job_test_cases = Vec::from([CollectionJobTestCase::<TimeInterval> {
        should_be_acquired: false,
        task_id,
        batch_identifier: batch_interval,
        agg_param: AggregationParam(0),
        collection_job_id: None,
        client_timestamp_interval: Interval::EMPTY,
        state: CollectionJobTestCaseState::Start,
    }]);

    run_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::TimeInterval,
            reports,
            aggregation_jobs,
            report_aggregations,
            collection_job_test_cases,
        },
    )
    .await;
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn collection_job_acquire_job_max(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([LeaderStoredReport::new_dummy(
        task_id,
        Time::from_seconds_since_epoch(0),
    )]);
    let aggregation_job_ids: [_; 2] = random();
    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(0),
        Duration::from_seconds(100),
    )
    .unwrap();
    let aggregation_jobs = Vec::from([
        AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[0],
            AggregationParam(0),
            (),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::Finished,
            AggregationJobRound::from(1),
        ),
        AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[1],
            AggregationParam(1),
            (),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::Finished,
            AggregationJobRound::from(1),
        ),
    ]);
    let report_aggregations = Vec::from([
        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[0],
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            None,
            ReportAggregationState::Start,
        ),
        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[1],
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            None,
            ReportAggregationState::Start,
        ),
    ]);

    let collection_job_test_cases = Vec::from([
        CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: true,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(0),
            collection_job_id: None,
            client_timestamp_interval: batch_interval,
            state: CollectionJobTestCaseState::Collectable,
        },
        CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: true,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(1),
            collection_job_id: None,
            client_timestamp_interval: batch_interval,
            state: CollectionJobTestCaseState::Collectable,
        },
    ]);

    let test_case = setup_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase::<TimeInterval> {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::TimeInterval,
            reports,
            aggregation_jobs,
            report_aggregations,
            collection_job_test_cases,
        },
    )
    .await;

    ds.run_tx(|tx| {
        let test_case = test_case.clone();
        let clock = clock.clone();
        Box::pin(async move {
            // Acquire a single collection job, twice. Each call should yield one job. We don't
            // care what order they are acquired in.
            let mut acquired_collection_jobs = tx
                .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 1)
                .await?;
            assert_eq!(acquired_collection_jobs.len(), 1);

            acquired_collection_jobs.extend(
                tx.acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 1)
                    .await?,
            );

            assert_eq!(acquired_collection_jobs.len(), 2);

            let mut acquired_collection_jobs: Vec<_> = acquired_collection_jobs
                .iter()
                .map(|lease| (lease.leased().clone(), *lease.lease_expiry_time()))
                .collect();
            acquired_collection_jobs.sort();

            let mut expected_collection_jobs: Vec<_> = test_case
                .collection_job_test_cases
                .iter()
                .filter(|c| c.should_be_acquired)
                .map(|c| {
                    (
                        AcquiredCollectionJob::new(
                            c.task_id,
                            c.collection_job_id.unwrap(),
                            task::QueryType::TimeInterval,
                            VdafInstance::Fake,
                        ),
                        clock.now().as_naive_date_time().unwrap() + chrono::Duration::seconds(100),
                    )
                })
                .collect();
            expected_collection_jobs.sort();

            assert_eq!(acquired_collection_jobs, expected_collection_jobs);

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn collection_job_acquire_state_filtering(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task_id = random();
    let reports = Vec::from([LeaderStoredReport::new_dummy(
        task_id,
        Time::from_seconds_since_epoch(0),
    )]);
    let aggregation_job_ids: [_; 3] = random();
    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(0),
        Duration::from_seconds(100),
    )
    .unwrap();
    let aggregation_jobs = Vec::from([
        AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[0],
            AggregationParam(0),
            (),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::Finished,
            AggregationJobRound::from(1),
        ),
        AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[1],
            AggregationParam(1),
            (),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::Finished,
            AggregationJobRound::from(1),
        ),
        AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[2],
            AggregationParam(2),
            (),
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            AggregationJobState::Finished,
            AggregationJobRound::from(1),
        ),
    ]);
    let report_aggregations = Vec::from([
        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[0],
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            None,
            ReportAggregationState::Start,
        ),
        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[1],
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            None,
            ReportAggregationState::Start,
        ),
        ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
            task_id,
            aggregation_job_ids[2],
            *reports[0].metadata().id(),
            *reports[0].metadata().time(),
            0,
            None,
            ReportAggregationState::Start,
        ),
    ]);

    let collection_job_test_cases = Vec::from([
        CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: true,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(0),
            collection_job_id: None,
            client_timestamp_interval: Interval::EMPTY,
            state: CollectionJobTestCaseState::Finished,
        },
        CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: true,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(1),
            collection_job_id: None,
            client_timestamp_interval: Interval::EMPTY,
            state: CollectionJobTestCaseState::Abandoned,
        },
        CollectionJobTestCase::<TimeInterval> {
            should_be_acquired: true,
            task_id,
            batch_identifier: batch_interval,
            agg_param: AggregationParam(2),
            collection_job_id: None,
            client_timestamp_interval: Interval::EMPTY,
            state: CollectionJobTestCaseState::Deleted,
        },
    ]);

    setup_collection_job_acquire_test_case(
        &ds,
        CollectionJobAcquireTestCase {
            task_ids: Vec::from([task_id]),
            query_type: task::QueryType::TimeInterval,
            reports,
            aggregation_jobs,
            report_aggregations,
            collection_job_test_cases,
        },
    )
    .await;

    ds.run_tx(|tx| {
        Box::pin(async move {
            // No collection jobs should be acquired because none of them are in the START state
            let acquired_collection_jobs = tx
                .acquire_incomplete_collection_jobs(&StdDuration::from_secs(100), 10)
                .await?;
            assert!(acquired_collection_jobs.is_empty());

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_batch_aggregation_time_interval(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let time_precision = Duration::from_seconds(100);
    let task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .with_time_precision(time_precision)
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let other_task = TaskBuilder::new(
        task::QueryType::TimeInterval,
        VdafInstance::Fake,
        Role::Leader,
    )
    .build();
    let aggregate_share = AggregateShare(23);
    let aggregation_param = AggregationParam(12);

    let (first_batch_aggregation, second_batch_aggregation, third_batch_aggregation) = ds
        .run_tx(|tx| {
            let task = task.clone();
            let other_task = other_task.clone();

            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;

                for when in [1000, 1100, 1200, 1300, 1400] {
                    tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(when), time_precision)
                            .unwrap(),
                        aggregation_param,
                        BatchState::Closed,
                        0,
                        Interval::new(Time::from_seconds_since_epoch(when), time_precision)
                            .unwrap(),
                    ))
                    .await
                    .unwrap();
                }

                let first_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(1100), time_precision)
                            .unwrap(),
                        aggregation_param,
                        0,
                        BatchAggregationState::Aggregating,
                        Some(aggregate_share),
                        0,
                        Interval::new(Time::from_seconds_since_epoch(1100), time_precision)
                            .unwrap(),
                        ReportIdChecksum::default(),
                    );

                let second_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(1200), time_precision)
                            .unwrap(),
                        aggregation_param,
                        1,
                        BatchAggregationState::Collected,
                        None,
                        0,
                        Interval::new(Time::from_seconds_since_epoch(1200), time_precision)
                            .unwrap(),
                        ReportIdChecksum::default(),
                    );

                let third_batch_aggregation =
                    BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(1300), time_precision)
                            .unwrap(),
                        aggregation_param,
                        2,
                        BatchAggregationState::Aggregating,
                        Some(aggregate_share),
                        0,
                        Interval::new(Time::from_seconds_since_epoch(1300), time_precision)
                            .unwrap(),
                        ReportIdChecksum::default(),
                    );

                // Start of this aggregation's interval is before the interval queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(1000), time_precision)
                            .unwrap(),
                        aggregation_param,
                        3,
                        BatchAggregationState::Collected,
                        None,
                        0,
                        Interval::new(Time::from_seconds_since_epoch(1000), time_precision)
                            .unwrap(),
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Following three batches are within the interval queried below.
                tx.put_batch_aggregation(&first_batch_aggregation).await?;
                tx.put_batch_aggregation(&second_batch_aggregation).await?;
                tx.put_batch_aggregation(&third_batch_aggregation).await?;

                assert_matches!(
                    tx.put_batch_aggregation(&first_batch_aggregation).await,
                    Err(Error::MutationTargetAlreadyExists)
                );

                // Aggregation parameter differs from the one queried below.
                tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    Interval::new(Time::from_seconds_since_epoch(1000), time_precision).unwrap(),
                    AggregationParam(13),
                    BatchState::Closed,
                    0,
                    Interval::new(Time::from_seconds_since_epoch(1000), time_precision).unwrap(),
                ))
                .await?;
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(1000), time_precision)
                            .unwrap(),
                        AggregationParam(13),
                        4,
                        BatchAggregationState::Aggregating,
                        Some(aggregate_share),
                        0,
                        Interval::new(Time::from_seconds_since_epoch(1000), time_precision)
                            .unwrap(),
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Start of this aggregation's interval is after the interval queried below.
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(1400), time_precision)
                            .unwrap(),
                        aggregation_param,
                        5,
                        BatchAggregationState::Collected,
                        None,
                        0,
                        Interval::new(Time::from_seconds_since_epoch(1400), time_precision)
                            .unwrap(),
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                // Task ID differs from that queried below.
                tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *other_task.id(),
                    Interval::new(Time::from_seconds_since_epoch(1200), time_precision).unwrap(),
                    aggregation_param,
                    BatchState::Closed,
                    0,
                    Interval::new(Time::from_seconds_since_epoch(1200), time_precision).unwrap(),
                ))
                .await?;
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *other_task.id(),
                        Interval::new(Time::from_seconds_since_epoch(1200), time_precision)
                            .unwrap(),
                        aggregation_param,
                        6,
                        BatchAggregationState::Aggregating,
                        Some(aggregate_share),
                        0,
                        Interval::new(Time::from_seconds_since_epoch(1200), time_precision)
                            .unwrap(),
                        ReportIdChecksum::default(),
                    ),
                )
                .await?;

                Ok((
                    first_batch_aggregation,
                    second_batch_aggregation,
                    third_batch_aggregation,
                ))
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let task = task.clone();
        let first_batch_aggregation = first_batch_aggregation.clone();
        let second_batch_aggregation = second_batch_aggregation.clone();
        let third_batch_aggregation = third_batch_aggregation.clone();

        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let batch_aggregations =
                TimeInterval::get_batch_aggregations_for_collection_identifier::<
                    0,
                    dummy_vdaf::Vdaf,
                    _,
                >(
                    tx,
                    &task,
                    &vdaf,
                    &Interval::new(
                        Time::from_seconds_since_epoch(1100),
                        Duration::from_seconds(3 * time_precision.as_seconds()),
                    )
                    .unwrap(),
                    &aggregation_param,
                )
                .await?;

            assert_eq!(batch_aggregations.len(), 3, "{batch_aggregations:#?}");
            for batch_aggregation in [
                &first_batch_aggregation,
                &second_batch_aggregation,
                &third_batch_aggregation,
            ] {
                assert!(
                    batch_aggregations.contains(batch_aggregation),
                    "{batch_aggregations:#?}"
                );
            }

            let first_batch_aggregation =
                BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *first_batch_aggregation.task_id(),
                    *first_batch_aggregation.batch_interval(),
                    *first_batch_aggregation.aggregation_parameter(),
                    first_batch_aggregation.ord(),
                    *first_batch_aggregation.state(),
                    Some(AggregateShare(92)),
                    1,
                    *first_batch_aggregation.client_timestamp_interval(),
                    ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
                );
            tx.update_batch_aggregation(&first_batch_aggregation)
                .await?;

            let batch_aggregations =
                TimeInterval::get_batch_aggregations_for_collection_identifier::<
                    0,
                    dummy_vdaf::Vdaf,
                    _,
                >(
                    tx,
                    &task,
                    &vdaf,
                    &Interval::new(
                        Time::from_seconds_since_epoch(1100),
                        Duration::from_seconds(3 * time_precision.as_seconds()),
                    )
                    .unwrap(),
                    &aggregation_param,
                )
                .await?;

            assert_eq!(batch_aggregations.len(), 3, "{batch_aggregations:#?}");
            for batch_aggregation in [
                &first_batch_aggregation,
                &second_batch_aggregation,
                &third_batch_aggregation,
            ] {
                assert!(
                    batch_aggregations.contains(batch_aggregation),
                    "{batch_aggregations:#?}"
                );
            }

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock again to expire all written entities.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let task = task.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let batch_aggregations: Vec<BatchAggregation<0, TimeInterval, dummy_vdaf::Vdaf>> =
                TimeInterval::get_batch_aggregations_for_collection_identifier::<
                    0,
                    dummy_vdaf::Vdaf,
                    _,
                >(
                    tx,
                    &task,
                    &vdaf,
                    &Interval::new(
                        Time::from_seconds_since_epoch(1100),
                        Duration::from_seconds(3 * time_precision.as_seconds()),
                    )
                    .unwrap(),
                    &aggregation_param,
                )
                .await?;

            assert!(batch_aggregations.is_empty());

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_batch_aggregation_fixed_size(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let task = TaskBuilder::new(
        task::QueryType::FixedSize {
            max_batch_size: 10,
            batch_time_window_size: None,
        },
        VdafInstance::Fake,
        Role::Leader,
    )
    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
    .build();
    let batch_id = random();
    let aggregate_share = AggregateShare(23);
    let aggregation_param = AggregationParam(12);
    let batch_aggregation = ds
        .run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                let other_task = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();

                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;

                tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    batch_id,
                    aggregation_param,
                    BatchState::Closed,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                ))
                .await
                .unwrap();

                let batch_aggregation = BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    batch_id,
                    aggregation_param,
                    0,
                    BatchAggregationState::Aggregating,
                    Some(aggregate_share),
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                    ReportIdChecksum::default(),
                );

                // Following batch aggregations have the batch ID queried below.
                tx.put_batch_aggregation(&batch_aggregation).await?;

                assert_matches!(
                    tx.put_batch_aggregation(&batch_aggregation).await,
                    Err(Error::MutationTargetAlreadyExists)
                );

                // Wrong batch ID.
                let other_batch_id = random();
                tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    other_batch_id,
                    aggregation_param,
                    BatchState::Closed,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                ))
                .await
                .unwrap();
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    other_batch_id,
                    aggregation_param,
                    1,
                    BatchAggregationState::Collected,
                    None,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                    ReportIdChecksum::default(),
                ))
                .await?;

                // Task ID differs from that queried below.
                tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *other_task.id(),
                    batch_id,
                    aggregation_param,
                    BatchState::Closed,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                ))
                .await
                .unwrap();
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *other_task.id(),
                    batch_id,
                    aggregation_param,
                    2,
                    BatchAggregationState::Aggregating,
                    Some(aggregate_share),
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                    ReportIdChecksum::default(),
                ))
                .await?;

                // Index differs from that queried below.
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    batch_id,
                    aggregation_param,
                    3,
                    BatchAggregationState::Collected,
                    None,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                    ReportIdChecksum::default(),
                ))
                .await?;
                Ok(batch_aggregation)
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let task = task.clone();
        let batch_aggregation = batch_aggregation.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let got_batch_aggregation = tx
                .get_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                    &vdaf,
                    task.id(),
                    &batch_id,
                    &aggregation_param,
                    0,
                )
                .await?;
            assert_eq!(got_batch_aggregation.as_ref(), Some(&batch_aggregation));

            let batch_aggregation = BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                *batch_aggregation.task_id(),
                *batch_aggregation.batch_id(),
                *batch_aggregation.aggregation_parameter(),
                batch_aggregation.ord(),
                *batch_aggregation.state(),
                None,
                1,
                Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1)).unwrap(),
                ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
            );
            tx.update_batch_aggregation(&batch_aggregation).await?;

            let got_batch_aggregation = tx
                .get_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                    &vdaf,
                    task.id(),
                    &batch_id,
                    &aggregation_param,
                    0,
                )
                .await?;
            assert_eq!(got_batch_aggregation, Some(batch_aggregation));
            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock again to expire all written entities.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let task = task.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let got_batch_aggregation = tx
                .get_batch_aggregation::<0, FixedSize, dummy_vdaf::Vdaf>(
                    &vdaf,
                    task.id(),
                    &batch_id,
                    &aggregation_param,
                    0,
                )
                .await?;
            assert!(got_batch_aggregation.is_none());

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_aggregate_share_job_time_interval(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let aggregate_share_job = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Helper,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                tx.put_task(&task).await?;

                tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(100))
                        .unwrap(),
                    AggregationParam(11),
                    BatchState::Closed,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(100))
                        .unwrap(),
                ))
                .await
                .unwrap();

                let aggregate_share_job = AggregateShareJob::new(
                    *task.id(),
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(100))
                        .unwrap(),
                    AggregationParam(11),
                    AggregateShare(42),
                    10,
                    ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
                );

                tx.put_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &aggregate_share_job,
                )
                .await
                .unwrap();

                Ok(aggregate_share_job)
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let want_aggregate_share_job = aggregate_share_job.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let got_aggregate_share_job = tx
                .get_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    want_aggregate_share_job.batch_interval(),
                    want_aggregate_share_job.aggregation_parameter(),
                )
                .await
                .unwrap()
                .unwrap();

            assert_eq!(want_aggregate_share_job, got_aggregate_share_job);

            assert!(tx
                .get_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    &Interval::new(
                        Time::from_seconds_since_epoch(500),
                        Duration::from_seconds(100),
                    )
                    .unwrap(),
                    want_aggregate_share_job.aggregation_parameter(),
                )
                .await
                .unwrap()
                .is_none());

            let want_aggregate_share_jobs = Vec::from([want_aggregate_share_job.clone()]);

            let got_aggregate_share_jobs = tx
                .get_aggregate_share_jobs_including_time::<0, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    &OLDEST_ALLOWED_REPORT_TIMESTAMP
                        .add(&Duration::from_seconds(5))
                        .unwrap(),
                )
                .await?;
            assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

            let got_aggregate_share_jobs = tx
                .get_aggregate_share_jobs_intersecting_interval::<0, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    &Interval::new(
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(5))
                            .unwrap(),
                        Duration::from_seconds(10),
                    )
                    .unwrap(),
                )
                .await?;
            assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to expire all written entities.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let want_aggregate_share_job = aggregate_share_job.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            assert_eq!(
                tx.get_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    want_aggregate_share_job.batch_interval(),
                    want_aggregate_share_job.aggregation_parameter(),
                )
                .await
                .unwrap(),
                None
            );

            assert_eq!(
                tx.get_aggregate_share_jobs_including_time::<0, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    &OLDEST_ALLOWED_REPORT_TIMESTAMP
                        .add(&Duration::from_seconds(5))
                        .unwrap(),
                )
                .await
                .unwrap(),
                Vec::new()
            );

            assert!(tx
                .get_aggregate_share_jobs_intersecting_interval::<0, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    &Interval::new(
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(5))
                            .unwrap(),
                        Duration::from_seconds(10),
                    )
                    .unwrap(),
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

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_aggregate_share_job_fixed_size(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let aggregate_share_job = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Helper,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                tx.put_task(&task).await?;

                let batch_id = random();
                tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task.id(),
                    batch_id,
                    AggregationParam(11),
                    BatchState::Closed,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                ))
                .await
                .unwrap();

                let aggregate_share_job = AggregateShareJob::new(
                    *task.id(),
                    batch_id,
                    AggregationParam(11),
                    AggregateShare(42),
                    10,
                    ReportIdChecksum::get_decoded(&[1; 32]).unwrap(),
                );

                tx.put_aggregate_share_job::<0, FixedSize, dummy_vdaf::Vdaf>(&aggregate_share_job)
                    .await
                    .unwrap();

                Ok(aggregate_share_job)
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let want_aggregate_share_job = aggregate_share_job.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            let got_aggregate_share_job = tx
                .get_aggregate_share_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    want_aggregate_share_job.batch_id(),
                    want_aggregate_share_job.aggregation_parameter(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(want_aggregate_share_job, got_aggregate_share_job);

            assert!(tx
                .get_aggregate_share_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    &random(),
                    want_aggregate_share_job.aggregation_parameter(),
                )
                .await
                .unwrap()
                .is_none());

            let want_aggregate_share_jobs = Vec::from([want_aggregate_share_job.clone()]);

            let got_aggregate_share_jobs = tx
                .get_aggregate_share_jobs_by_batch_id::<0, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    want_aggregate_share_job.batch_id(),
                )
                .await?;
            assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to expire all written entities.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let want_aggregate_share_job = aggregate_share_job.clone();
        Box::pin(async move {
            let vdaf = dummy_vdaf::Vdaf::new();

            assert_eq!(
                tx.get_aggregate_share_job::<0, FixedSize, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    want_aggregate_share_job.batch_id(),
                    want_aggregate_share_job.aggregation_parameter(),
                )
                .await
                .unwrap(),
                None
            );

            assert_eq!(
                tx.get_aggregate_share_jobs_by_batch_id::<0, dummy_vdaf::Vdaf>(
                    &vdaf,
                    want_aggregate_share_job.task_id(),
                    want_aggregate_share_job.batch_id(),
                )
                .await
                .unwrap(),
                Vec::new()
            );

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_outstanding_batch(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let batch_time_window_size = Duration::from_hours(24).unwrap();
    let time_bucket_start = clock
        .now()
        .to_batch_interval_start(&batch_time_window_size)
        .unwrap();

    let (task_id_1, batch_id_1, task_id_2, batch_id_2) = ds
        .run_tx(|tx| {
            let clock = clock.clone();
            Box::pin(async move {
                let task_1 = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                tx.put_task(&task_1).await?;
                let batch_id_1 = random();

                tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    batch_id_1,
                    AggregationParam(0),
                    BatchState::Closed,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                ))
                .await?;
                tx.put_outstanding_batch(task_1.id(), &batch_id_1, &None)
                    .await?;

                let task_2 = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: Some(batch_time_window_size),
                    },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                tx.put_task(&task_2).await?;
                let batch_id_2 = random();

                tx.put_batch(&Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task_2.id(),
                    batch_id_2,
                    AggregationParam(0),
                    BatchState::Closed,
                    0,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                ))
                .await?;
                tx.put_outstanding_batch(task_2.id(), &batch_id_2, &Some(time_bucket_start))
                    .await?;

                // Write a few aggregation jobs & report aggregations to produce useful
                // min_size/max_size values to validate later.
                let aggregation_job_0 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    random(),
                    AggregationParam(0),
                    batch_id_1,
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::Finished,
                    AggregationJobRound::from(1),
                );
                let report_aggregation_0_0 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    *aggregation_job_0.id(),
                    random(),
                    clock.now(),
                    0,
                    None,
                    ReportAggregationState::Start, // Counted among max_size.
                );
                let report_aggregation_0_1 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    *aggregation_job_0.id(),
                    random(),
                    clock.now(),
                    1,
                    None,
                    ReportAggregationState::Waiting(dummy_vdaf::PrepareState::default(), Some(())), // Counted among max_size.
                );
                let report_aggregation_0_2 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    *aggregation_job_0.id(),
                    random(),
                    clock.now(),
                    2,
                    None,
                    ReportAggregationState::Failed(ReportShareError::VdafPrepError), // Not counted among min_size or max_size.
                );

                let aggregation_job_1 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    random(),
                    AggregationParam(0),
                    batch_id_1,
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::Finished,
                    AggregationJobRound::from(1),
                );
                let report_aggregation_1_0 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    *aggregation_job_1.id(),
                    random(),
                    clock.now(),
                    0,
                    None,
                    ReportAggregationState::Finished, // Counted among min_size and max_size.
                );
                let report_aggregation_1_1 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    *aggregation_job_1.id(),
                    random(),
                    clock.now(),
                    1,
                    None,
                    ReportAggregationState::Finished, // Counted among min_size and max_size.
                );
                let report_aggregation_1_2 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    *aggregation_job_1.id(),
                    random(),
                    clock.now(),
                    2,
                    None,
                    ReportAggregationState::Failed(ReportShareError::VdafPrepError), // Not counted among min_size or max_size.
                );

                let aggregation_job_2 = AggregationJob::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task_2.id(),
                    random(),
                    AggregationParam(0),
                    batch_id_2,
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::Finished,
                    AggregationJobRound::from(1),
                );
                let report_aggregation_2_0 = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                    *task_2.id(),
                    *aggregation_job_2.id(),
                    random(),
                    clock.now(),
                    0,
                    None,
                    ReportAggregationState::Start,
                );

                for aggregation_job in &[aggregation_job_0, aggregation_job_1, aggregation_job_2] {
                    tx.put_aggregation_job(aggregation_job).await?;
                }
                for report_aggregation in &[
                    report_aggregation_0_0,
                    report_aggregation_0_1,
                    report_aggregation_0_2,
                    report_aggregation_1_0,
                    report_aggregation_1_1,
                    report_aggregation_1_2,
                    report_aggregation_2_0,
                ] {
                    tx.put_client_report(
                        &dummy_vdaf::Vdaf::new(),
                        &LeaderStoredReport::new(
                            *report_aggregation.task_id(),
                            ReportMetadata::new(
                                *report_aggregation.report_id(),
                                *report_aggregation.time(),
                            ),
                            (), // Dummy public share
                            Vec::new(),
                            dummy_vdaf::InputShare::default(), // Dummy leader input share
                            // Dummy helper encrypted input share
                            HpkeCiphertext::new(
                                HpkeConfigId::from(13),
                                Vec::from("encapsulated_context_0"),
                                Vec::from("payload_0"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation(report_aggregation).await?;
                }

                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    batch_id_1,
                    AggregationParam(0),
                    0,
                    BatchAggregationState::Aggregating,
                    Some(AggregateShare(0)),
                    1,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                    ReportIdChecksum::default(),
                ))
                .await?;
                tx.put_batch_aggregation(&BatchAggregation::<0, FixedSize, dummy_vdaf::Vdaf>::new(
                    *task_1.id(),
                    batch_id_1,
                    AggregationParam(0),
                    1,
                    BatchAggregationState::Aggregating,
                    Some(AggregateShare(0)),
                    1,
                    Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1))
                        .unwrap(),
                    ReportIdChecksum::default(),
                ))
                .await?;

                Ok((*task_1.id(), batch_id_1, *task_2.id(), batch_id_2))
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    let (
        outstanding_batches_task_1,
        outstanding_batch_1,
        outstanding_batch_2,
        outstanding_batch_3,
        outstanding_batches_task_2,
        outstanding_batches_empty_time_bucket,
    ) = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let outstanding_batches_task_1 =
                    tx.get_outstanding_batches(&task_id_1, &None).await?;
                let outstanding_batch_1 = tx.get_filled_outstanding_batch(&task_id_1, 1).await?;
                let outstanding_batch_2 = tx.get_filled_outstanding_batch(&task_id_1, 2).await?;
                let outstanding_batch_3 = tx.get_filled_outstanding_batch(&task_id_1, 3).await?;
                let outstanding_batches_task_2 = tx
                    .get_outstanding_batches(&task_id_2, &Some(time_bucket_start))
                    .await?;
                let outstanding_batches_empty_time_bucket = tx
                    .get_outstanding_batches(
                        &task_id_2,
                        &Some(time_bucket_start.add(&Duration::from_hours(24)?)?),
                    )
                    .await?;
                Ok((
                    outstanding_batches_task_1,
                    outstanding_batch_1,
                    outstanding_batch_2,
                    outstanding_batch_3,
                    outstanding_batches_task_2,
                    outstanding_batches_empty_time_bucket,
                ))
            })
        })
        .await
        .unwrap();
    assert_eq!(
        outstanding_batches_task_1,
        Vec::from([OutstandingBatch::new(
            task_id_1,
            batch_id_1,
            RangeInclusive::new(2, 4)
        )])
    );
    assert_eq!(outstanding_batch_1, Some(batch_id_1));
    assert_eq!(outstanding_batch_2, Some(batch_id_1));
    assert_eq!(outstanding_batch_3, None);
    assert_eq!(
        outstanding_batches_task_2,
        Vec::from([OutstandingBatch::new(
            task_id_2,
            batch_id_2,
            RangeInclusive::new(0, 1)
        )])
    );
    assert_eq!(outstanding_batches_empty_time_bucket, Vec::new());

    // Advance the clock further to trigger expiration of the written batches.
    clock.advance(&REPORT_EXPIRY_AGE);

    // Verify that the batch is no longer available.
    let outstanding_batches = ds
        .run_tx(|tx| Box::pin(async move { tx.get_outstanding_batches(&task_id_1, &None).await }))
        .await
        .unwrap();
    assert!(outstanding_batches.is_empty());

    // Reset the clock to "un-expire" the written batches. (...don't try this in prod.)
    clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

    // Delete the outstanding batch, then check that it is no longer available.
    ds.run_tx(|tx| {
        Box::pin(async move { tx.delete_outstanding_batch(&task_id_1, &batch_id_1).await })
    })
    .await
    .unwrap();

    let outstanding_batches = ds
        .run_tx(|tx| Box::pin(async move { tx.get_outstanding_batches(&task_id_1, &None).await }))
        .await
        .unwrap();
    assert!(outstanding_batches.is_empty());
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_batch(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    let want_batch = Batch::<0, FixedSize, dummy_vdaf::Vdaf>::new(
        random(),
        random(),
        AggregationParam(2),
        BatchState::Closing,
        1,
        Interval::new(OLDEST_ALLOWED_REPORT_TIMESTAMP, Duration::from_seconds(1)).unwrap(),
    );

    ds.run_tx(|tx| {
        let want_batch = want_batch.clone();
        Box::pin(async move {
            tx.put_task(
                &TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_id(*want_batch.task_id())
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build(),
            )
            .await?;
            tx.put_batch(&want_batch).await?;

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let want_batch = want_batch.clone();
        Box::pin(async move {
            // Try reading the batch back, and verify that modifying any of the primary key
            // attributes causes None to be returned.
            assert_eq!(
                tx.get_batch(
                    want_batch.task_id(),
                    want_batch.batch_identifier(),
                    want_batch.aggregation_parameter()
                )
                .await?
                .as_ref(),
                Some(&want_batch)
            );
            assert_eq!(
                tx.get_batch::<0, FixedSize, dummy_vdaf::Vdaf>(
                    &random(),
                    want_batch.batch_identifier(),
                    want_batch.aggregation_parameter()
                )
                .await?,
                None
            );
            assert_eq!(
                tx.get_batch::<0, FixedSize, dummy_vdaf::Vdaf>(
                    want_batch.task_id(),
                    &random(),
                    want_batch.aggregation_parameter()
                )
                .await?,
                None
            );
            assert_eq!(
                tx.get_batch::<0, FixedSize, dummy_vdaf::Vdaf>(
                    want_batch.task_id(),
                    want_batch.batch_identifier(),
                    &AggregationParam(3)
                )
                .await?,
                None
            );

            // Update the batch, then read it again, verifying that the changes are reflected.
            let want_batch = want_batch
                .with_state(BatchState::Closed)
                .with_outstanding_aggregation_jobs(0);
            tx.update_batch(&want_batch).await?;

            assert_eq!(
                tx.get_batch(
                    want_batch.task_id(),
                    want_batch.batch_identifier(),
                    want_batch.aggregation_parameter()
                )
                .await?
                .as_ref(),
                Some(&want_batch)
            );

            Ok(())
        })
    })
    .await
    .unwrap();

    // Advance the clock to expire the batch.
    clock.advance(&REPORT_EXPIRY_AGE);

    ds.run_tx(|tx| {
        let want_batch = want_batch.clone();
        Box::pin(async move {
            // Try reading the batch back, and verify it is expired.
            assert_eq!(
                tx.get_batch::<0, FixedSize, dummy_vdaf::Vdaf>(
                    want_batch.task_id(),
                    want_batch.batch_identifier(),
                    want_batch.aggregation_parameter()
                )
                .await?,
                None
            );

            Ok(())
        })
    })
    .await
    .unwrap();
}

#[async_trait]
trait ExpirationQueryTypeExt: CollectableQueryType {
    fn batch_identifier_for_client_timestamps(client_timestamps: &[Time]) -> Self::BatchIdentifier;

    fn shortened_batch_identifier(
        batch_identifier: &Self::BatchIdentifier,
    ) -> Self::BatchIdentifier;

    async fn write_outstanding_batch(
        tx: &Transaction<MockClock>,
        task_id: &TaskId,
        batch_identifier: &Self::BatchIdentifier,
        time_bucket_start: &Option<Time>,
    ) -> Option<(TaskId, BatchId)>;
}

#[async_trait]
impl ExpirationQueryTypeExt for TimeInterval {
    fn batch_identifier_for_client_timestamps(client_timestamps: &[Time]) -> Self::BatchIdentifier {
        let min_client_timestamp = *client_timestamps.iter().min().unwrap();
        let max_client_timestamp = *client_timestamps.iter().max().unwrap();
        Interval::new(
            min_client_timestamp,
            Duration::from_seconds(
                max_client_timestamp
                    .difference(&min_client_timestamp)
                    .unwrap()
                    .as_seconds()
                    + 1,
            ),
        )
        .unwrap()
    }

    fn shortened_batch_identifier(
        batch_identifier: &Self::BatchIdentifier,
    ) -> Self::BatchIdentifier {
        Interval::new(
            *batch_identifier.start(),
            Duration::from_seconds(batch_identifier.duration().as_seconds() / 2),
        )
        .unwrap()
    }

    async fn write_outstanding_batch(
        _: &Transaction<MockClock>,
        _: &TaskId,
        _: &Self::BatchIdentifier,
        _: &Option<Time>,
    ) -> Option<(TaskId, BatchId)> {
        None
    }
}

#[async_trait]
impl ExpirationQueryTypeExt for FixedSize {
    fn batch_identifier_for_client_timestamps(_: &[Time]) -> Self::BatchIdentifier {
        random()
    }

    fn shortened_batch_identifier(
        batch_identifier: &Self::BatchIdentifier,
    ) -> Self::BatchIdentifier {
        *batch_identifier
    }

    async fn write_outstanding_batch(
        tx: &Transaction<MockClock>,
        task_id: &TaskId,
        batch_identifier: &Self::BatchIdentifier,
        time_bucket_start: &Option<Time>,
    ) -> Option<(TaskId, BatchId)> {
        tx.put_outstanding_batch(task_id, batch_identifier, time_bucket_start)
            .await
            .unwrap();
        Some((*task_id, *batch_identifier))
    }
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn delete_expired_client_reports(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::default();
    let ds = ephemeral_datastore.datastore(clock.clone()).await;
    let vdaf = dummy_vdaf::Vdaf::new();

    // Setup.
    let report_expiry_age = clock
        .now()
        .difference(&OLDEST_ALLOWED_REPORT_TIMESTAMP)
        .unwrap();
    let (task_id, new_report_id, other_task_id, other_task_report_id) = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(report_expiry_age))
                .build();
                let other_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .build();
                tx.put_task(&task).await?;
                tx.put_task(&other_task).await?;

                let old_report = LeaderStoredReport::new_dummy(
                    *task.id(),
                    OLDEST_ALLOWED_REPORT_TIMESTAMP
                        .sub(&Duration::from_seconds(1))
                        .unwrap(),
                );
                let new_report =
                    LeaderStoredReport::new_dummy(*task.id(), OLDEST_ALLOWED_REPORT_TIMESTAMP);
                let other_task_report = LeaderStoredReport::new_dummy(
                    *other_task.id(),
                    OLDEST_ALLOWED_REPORT_TIMESTAMP
                        .sub(&Duration::from_seconds(1))
                        .unwrap(),
                );
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &old_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &new_report)
                    .await?;
                tx.put_client_report(&dummy_vdaf::Vdaf::new(), &other_task_report)
                    .await?;

                Ok((
                    *task.id(),
                    *new_report.metadata().id(),
                    *other_task.id(),
                    *other_task_report.metadata().id(),
                ))
            })
        })
        .await
        .unwrap();

    // Run.
    ds.run_tx(|tx| {
        Box::pin(async move {
            tx.delete_expired_client_reports(&task_id, u64::try_from(i64::MAX)?)
                .await
        })
    })
    .await
    .unwrap();

    // Verify.
    let want_report_ids = HashSet::from([new_report_id, other_task_report_id]);
    let got_report_ids = ds
        .run_tx(|tx| {
            let vdaf = vdaf.clone();
            Box::pin(async move {
                let task_client_reports = tx.get_client_reports_for_task(&vdaf, &task_id).await?;
                let other_task_client_reports = tx
                    .get_client_reports_for_task(&vdaf, &other_task_id)
                    .await?;
                Ok(HashSet::from_iter(
                    task_client_reports
                        .into_iter()
                        .chain(other_task_client_reports)
                        .map(|report| *report.metadata().id()),
                ))
            })
        })
        .await
        .unwrap();
    assert_eq!(want_report_ids, got_report_ids);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn delete_expired_aggregation_artifacts(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;
    let vdaf = dummy_vdaf::Vdaf::new();

    // Setup.
    async fn write_aggregation_artifacts<Q: ExpirationQueryTypeExt>(
        tx: &Transaction<'_, MockClock>,
        task_id: &TaskId,
        client_timestamps: &[Time],
    ) -> (
        Q::BatchIdentifier,
        AggregationJobId, // aggregation job ID
        Vec<ReportId>,    // client report IDs
    ) {
        let batch_identifier = Q::batch_identifier_for_client_timestamps(client_timestamps);

        let mut report_ids_and_timestamps = Vec::new();
        for client_timestamp in client_timestamps {
            let report = LeaderStoredReport::new_dummy(*task_id, *client_timestamp);
            tx.put_client_report(&dummy_vdaf::Vdaf::new(), &report)
                .await
                .unwrap();
            report_ids_and_timestamps.push((*report.metadata().id(), *client_timestamp));
        }

        let min_client_timestamp = client_timestamps.iter().min().unwrap();
        let max_client_timestamp = client_timestamps.iter().max().unwrap();
        let client_timestamp_interval = Interval::new(
            *min_client_timestamp,
            max_client_timestamp
                .difference(min_client_timestamp)
                .unwrap()
                .add(&Duration::from_seconds(1))
                .unwrap(),
        )
        .unwrap();

        let aggregation_job = AggregationJob::<0, Q, dummy_vdaf::Vdaf>::new(
            *task_id,
            random(),
            AggregationParam(0),
            Q::partial_batch_identifier(&batch_identifier).clone(),
            client_timestamp_interval,
            AggregationJobState::InProgress,
            AggregationJobRound::from(0),
        );
        tx.put_aggregation_job(&aggregation_job).await.unwrap();

        for (ord, (report_id, client_timestamp)) in report_ids_and_timestamps.iter().enumerate() {
            let report_aggregation = ReportAggregation::new(
                *task_id,
                *aggregation_job.id(),
                *report_id,
                *client_timestamp,
                ord.try_into().unwrap(),
                None,
                ReportAggregationState::<0, dummy_vdaf::Vdaf>::Start,
            );
            tx.put_report_aggregation(&report_aggregation)
                .await
                .unwrap();
        }

        (
            batch_identifier,
            *aggregation_job.id(),
            report_ids_and_timestamps
                .into_iter()
                .map(|(report_id, _)| report_id)
                .collect(),
        )
    }

    let (
        leader_time_interval_task_id,
        helper_time_interval_task_id,
        leader_fixed_size_task_id,
        helper_fixed_size_task_id,
        want_aggregation_job_ids,
        want_report_ids,
    ) = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let leader_time_interval_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let helper_time_interval_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Helper,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let leader_fixed_size_task = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let helper_fixed_size_task = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Helper,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                tx.put_task(&leader_time_interval_task).await?;
                tx.put_task(&helper_time_interval_task).await?;
                tx.put_task(&leader_fixed_size_task).await?;
                tx.put_task(&helper_fixed_size_task).await?;

                let mut aggregation_job_ids = HashSet::new();
                let mut all_report_ids = HashSet::new();

                // Leader, time-interval aggregation job with old reports [GC'ed].
                write_aggregation_artifacts::<TimeInterval>(
                    tx,
                    leader_time_interval_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(20))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(19))
                            .unwrap(),
                    ],
                )
                .await;

                // Leader, time-interval aggregation job with old & new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) =
                    write_aggregation_artifacts::<TimeInterval>(
                        tx,
                        leader_time_interval_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(5))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(8))
                                .unwrap(),
                        ],
                    )
                    .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                // Leader, time-interval aggregation job with new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) =
                    write_aggregation_artifacts::<TimeInterval>(
                        tx,
                        leader_time_interval_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(19))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(20))
                                .unwrap(),
                        ],
                    )
                    .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                // Helper, time-interval aggregation job with old reports [GC'ed].
                write_aggregation_artifacts::<TimeInterval>(
                    tx,
                    helper_time_interval_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(20))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(19))
                            .unwrap(),
                    ],
                )
                .await;

                // Helper, time-interval task with old & new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) =
                    write_aggregation_artifacts::<TimeInterval>(
                        tx,
                        helper_time_interval_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(5))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(8))
                                .unwrap(),
                        ],
                    )
                    .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                // Helper, time-interval task with new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) =
                    write_aggregation_artifacts::<TimeInterval>(
                        tx,
                        helper_time_interval_task.id(),
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(19))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(20))
                                .unwrap(),
                        ],
                    )
                    .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                // Leader, fixed-size aggregation job with old reports [GC'ed].
                write_aggregation_artifacts::<FixedSize>(
                    tx,
                    leader_fixed_size_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(20))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(19))
                            .unwrap(),
                    ],
                )
                .await;

                // Leader, fixed-size aggregation job with old & new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) = write_aggregation_artifacts::<FixedSize>(
                    tx,
                    leader_fixed_size_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(5))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(8))
                            .unwrap(),
                    ],
                )
                .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                // Leader, fixed-size aggregation job with new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) = write_aggregation_artifacts::<FixedSize>(
                    tx,
                    leader_fixed_size_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(19))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(20))
                            .unwrap(),
                    ],
                )
                .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                // Helper, fixed-size aggregation job with old reports [GC'ed].
                write_aggregation_artifacts::<FixedSize>(
                    tx,
                    helper_fixed_size_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(20))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(19))
                            .unwrap(),
                    ],
                )
                .await;

                // Helper, fixed-size aggregation job with old & new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) = write_aggregation_artifacts::<FixedSize>(
                    tx,
                    helper_fixed_size_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(5))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(8))
                            .unwrap(),
                    ],
                )
                .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                // Helper, fixed-size aggregation job with new reports [not GC'ed].
                let (_, aggregation_job_id, report_ids) = write_aggregation_artifacts::<FixedSize>(
                    tx,
                    helper_fixed_size_task.id(),
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(19))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(20))
                            .unwrap(),
                    ],
                )
                .await;
                aggregation_job_ids.insert(aggregation_job_id);
                all_report_ids.extend(report_ids);

                Ok((
                    *leader_time_interval_task.id(),
                    *helper_time_interval_task.id(),
                    *leader_fixed_size_task.id(),
                    *helper_fixed_size_task.id(),
                    aggregation_job_ids,
                    all_report_ids,
                ))
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    // Run.
    ds.run_tx(|tx| {
        Box::pin(async move {
            tx.delete_expired_aggregation_artifacts(
                &leader_time_interval_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await?;
            tx.delete_expired_aggregation_artifacts(
                &helper_time_interval_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await?;
            tx.delete_expired_aggregation_artifacts(
                &leader_fixed_size_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await?;
            tx.delete_expired_aggregation_artifacts(
                &helper_fixed_size_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    // Verify.
    let (got_aggregation_job_ids, got_report_ids) = ds
        .run_tx(|tx| {
            let vdaf = vdaf.clone();
            Box::pin(async move {
                let leader_time_interval_aggregation_job_ids = tx
                    .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &leader_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| *job.id());
                let helper_time_interval_aggregation_job_ids = tx
                    .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &helper_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| *job.id());
                let leader_fixed_size_aggregation_job_ids = tx
                    .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &leader_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| *job.id());
                let helper_fixed_size_aggregation_job_ids = tx
                    .get_aggregation_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &helper_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| *job.id());
                let got_aggregation_job_ids = leader_time_interval_aggregation_job_ids
                    .chain(helper_time_interval_aggregation_job_ids)
                    .chain(leader_fixed_size_aggregation_job_ids)
                    .chain(helper_fixed_size_aggregation_job_ids)
                    .collect();

                let leader_time_interval_report_aggregations = tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Leader,
                        &leader_time_interval_task_id,
                    )
                    .await
                    .unwrap();
                let helper_time_interval_report_aggregations = tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Helper,
                        &helper_time_interval_task_id,
                    )
                    .await
                    .unwrap();
                let leader_fixed_size_report_aggregations = tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Leader,
                        &leader_fixed_size_task_id,
                    )
                    .await
                    .unwrap();
                let helper_fixed_size_report_aggregations = tx
                    .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &Role::Helper,
                        &helper_fixed_size_task_id,
                    )
                    .await
                    .unwrap();
                let got_report_ids = leader_time_interval_report_aggregations
                    .into_iter()
                    .chain(helper_time_interval_report_aggregations)
                    .chain(leader_fixed_size_report_aggregations)
                    .chain(helper_fixed_size_report_aggregations)
                    .map(|report_aggregation| *report_aggregation.report_id())
                    .collect();

                Ok((got_aggregation_job_ids, got_report_ids))
            })
        })
        .await
        .unwrap();
    assert_eq!(want_aggregation_job_ids, got_aggregation_job_ids);
    assert_eq!(want_report_ids, got_report_ids);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn delete_expired_collection_artifacts(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();

    let clock = MockClock::new(OLDEST_ALLOWED_REPORT_TIMESTAMP);
    let ds = ephemeral_datastore.datastore(clock.clone()).await;

    // Setup.
    async fn write_collect_artifacts<Q: ExpirationQueryTypeExt>(
        tx: &Transaction<'_, MockClock>,
        task: &Task,
        client_timestamps: &[Time],
    ) -> (
        Option<CollectionJobId>,   // collection job ID
        Option<(TaskId, Vec<u8>)>, // aggregate share job ID (task ID, encoded batch identifier)
        Option<(TaskId, Vec<u8>)>, // batch ID (task ID, encoded batch identifier)
        Option<(TaskId, BatchId)>, // outstanding batch ID
        Option<(TaskId, Vec<u8>)>, // batch aggregation ID (task ID, encoded batch identifier)
        Option<Time>,              // time bucket start
    ) {
        let batch_identifier = Q::batch_identifier_for_client_timestamps(client_timestamps);
        let client_timestamp_interval = client_timestamps
            .iter()
            .fold(Interval::EMPTY, |left, right| {
                left.merged_with(right).unwrap()
            });

        tx.put_batch(&Batch::<0, Q, dummy_vdaf::Vdaf>::new(
            *task.id(),
            batch_identifier.clone(),
            AggregationParam(0),
            BatchState::Closed,
            0,
            client_timestamp_interval,
        ))
        .await
        .unwrap();

        let batch_aggregation = BatchAggregation::<0, Q, dummy_vdaf::Vdaf>::new(
            *task.id(),
            batch_identifier.clone(),
            AggregationParam(0),
            0,
            BatchAggregationState::Aggregating,
            None,
            0,
            client_timestamp_interval,
            ReportIdChecksum::default(),
        );
        tx.put_batch_aggregation(&batch_aggregation).await.unwrap();

        if task.role() == &Role::Leader {
            let collection_job = CollectionJob::<0, Q, dummy_vdaf::Vdaf>::new(
                *task.id(),
                random(),
                batch_identifier.clone(),
                AggregationParam(0),
                CollectionJobState::Start,
            );
            tx.put_collection_job(&collection_job).await.unwrap();

            let time_bucket_start = match task.query_type() {
                task::QueryType::TimeInterval
                | task::QueryType::FixedSize {
                    batch_time_window_size: None,
                    ..
                } => None,
                task::QueryType::FixedSize {
                    batch_time_window_size: Some(batch_time_window_size),
                    ..
                } => {
                    let time_bucket_start = client_timestamps[0]
                        .to_batch_interval_start(batch_time_window_size)
                        .unwrap();
                    let same_bucket = client_timestamps.iter().all(|ts| {
                        ts.to_batch_interval_start(batch_time_window_size).unwrap()
                            == time_bucket_start
                    });
                    assert!(
                        same_bucket,
                        "client timestamps do not all fall in the same time bucket"
                    );
                    Some(time_bucket_start)
                }
            };

            let outstanding_batch_id =
                Q::write_outstanding_batch(tx, task.id(), &batch_identifier, &time_bucket_start)
                    .await;

            return (
                Some(*collection_job.id()),
                None,
                Some((*task.id(), batch_identifier.get_encoded())),
                outstanding_batch_id,
                Some((*task.id(), batch_identifier.get_encoded())),
                time_bucket_start,
            );
        } else {
            tx.put_aggregate_share_job::<0, Q, dummy_vdaf::Vdaf>(&AggregateShareJob::new(
                *task.id(),
                batch_identifier.clone(),
                AggregationParam(0),
                AggregateShare(11),
                client_timestamps.len().try_into().unwrap(),
                random(),
            ))
            .await
            .unwrap();

            return (
                None,
                Some((*task.id(), batch_identifier.get_encoded())),
                Some((*task.id(), batch_identifier.get_encoded())),
                None,
                Some((*task.id(), batch_identifier.get_encoded())),
                None,
            );
        }
    }

    let (
        leader_time_interval_task_id,
        helper_time_interval_task_id,
        leader_fixed_size_task_id,
        helper_fixed_size_task_id,
        leader_fixed_size_time_bucketed_task_id,
        other_task_id,
        want_batch_ids,
        want_collection_job_ids,
        want_aggregate_share_job_ids,
        want_outstanding_batch_ids,
        want_batch_aggregation_ids,
        time_bucket_starts,
    ) = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let leader_time_interval_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let helper_time_interval_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Helper,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let leader_fixed_size_task = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let helper_fixed_size_task = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: None,
                    },
                    VdafInstance::Fake,
                    Role::Helper,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let leader_fixed_size_time_bucketed_task = TaskBuilder::new(
                    task::QueryType::FixedSize {
                        max_batch_size: 10,
                        batch_time_window_size: Some(Duration::from_hours(24)?),
                    },
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                let other_task = TaskBuilder::new(
                    task::QueryType::TimeInterval,
                    VdafInstance::Fake,
                    Role::Leader,
                )
                .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                .build();
                tx.put_task(&leader_time_interval_task).await?;
                tx.put_task(&helper_time_interval_task).await?;
                tx.put_task(&leader_fixed_size_task).await?;
                tx.put_task(&helper_fixed_size_task).await?;
                tx.put_task(&leader_fixed_size_time_bucketed_task).await?;
                tx.put_task(&other_task).await?;

                let mut collection_job_ids = HashSet::new();
                let mut aggregate_share_job_ids = HashSet::new();
                let mut batch_ids = HashSet::new();
                let mut outstanding_batch_ids = HashSet::new();
                let mut batch_aggregation_ids = HashSet::new();
                let mut time_bucket_starts = HashSet::new();

                // Leader, time-interval collection artifacts with old reports. [GC'ed]
                write_collect_artifacts::<TimeInterval>(
                    tx,
                    &leader_time_interval_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(10))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(9))
                            .unwrap(),
                    ],
                )
                .await;

                // Leader, time-interval collection artifacts with old & new reports. [collection job GC'ed, remainder not GC'ed]
                let (
                    _,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<TimeInterval>(
                    tx,
                    &leader_time_interval_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(5))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(5))
                            .unwrap(),
                    ],
                )
                .await;
                // collection_job_ids purposefully not changed.
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Leader, time-interval collection artifacts with new reports. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<TimeInterval>(
                    tx,
                    &leader_time_interval_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(9))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(10))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Helper, time-interval collection artifacts with old reports. [GC'ed]
                write_collect_artifacts::<TimeInterval>(
                    tx,
                    &helper_time_interval_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(10))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(9))
                            .unwrap(),
                    ],
                )
                .await;

                // Helper, time-interval collection artifacts with old & new reports. [aggregate share job job GC'ed, remainder not GC'ed]
                let (_, _, batch_id, outstanding_batch_id, batch_aggregation_id, _) =
                    write_collect_artifacts::<TimeInterval>(
                        tx,
                        &helper_time_interval_task,
                        &[
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .sub(&Duration::from_seconds(5))
                                .unwrap(),
                            OLDEST_ALLOWED_REPORT_TIMESTAMP
                                .add(&Duration::from_seconds(5))
                                .unwrap(),
                        ],
                    )
                    .await;
                // collection_job_ids purposefully not changed.
                // aggregate_share_job_ids purposefully not changed.
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Helper, time-interval collection artifacts with new reports. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<TimeInterval>(
                    tx,
                    &helper_time_interval_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(9))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(10))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Leader, fixed-size collection artifacts with old reports. [GC'ed]
                write_collect_artifacts::<FixedSize>(
                    tx,
                    &leader_fixed_size_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(10))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(9))
                            .unwrap(),
                    ],
                )
                .await;

                // Leader, fixed-size collection artifacts with old & new reports. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<FixedSize>(
                    tx,
                    &leader_fixed_size_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(5))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(5))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Leader, fixed-size collection artifacts with new reports. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<FixedSize>(
                    tx,
                    &leader_fixed_size_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(9))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(10))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Helper, fixed-size collection artifacts with old reports. [GC'ed]
                write_collect_artifacts::<FixedSize>(
                    tx,
                    &helper_fixed_size_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(10))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(9))
                            .unwrap(),
                    ],
                )
                .await;

                // Helper, fixed-size collection artifacts with old & new reports. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<FixedSize>(
                    tx,
                    &helper_fixed_size_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(5))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(5))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Helper, fixed-size collection artifacts with new reports. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<FixedSize>(
                    tx,
                    &helper_fixed_size_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(9))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(10))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                // Leader, fixed-size time bucketed collection artifacts with old reports.
                // [GC'ed]
                let (_, _, _, _, _, time_bucket_start) = write_collect_artifacts::<FixedSize>(
                    tx,
                    &leader_fixed_size_time_bucketed_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(10))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(9))
                            .unwrap(),
                    ],
                )
                .await;
                time_bucket_starts.extend(time_bucket_start);

                // Leader, fixed-size time bucketed collection artifacts with old and new
                // reports. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    time_bucket_start,
                ) = write_collect_artifacts::<FixedSize>(
                    tx,
                    &leader_fixed_size_time_bucketed_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(5))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(5))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);
                time_bucket_starts.extend(time_bucket_start);

                // Leader, fixed-size time bucketed collection artifacts with new reports [not
                // GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    time_bucket_start,
                ) = write_collect_artifacts::<FixedSize>(
                    tx,
                    &leader_fixed_size_time_bucketed_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(9))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .add(&Duration::from_seconds(10))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);
                time_bucket_starts.extend(time_bucket_start);

                // Collection artifacts for different task. [not GC'ed]
                let (
                    collection_job_id,
                    aggregate_share_job_id,
                    batch_id,
                    outstanding_batch_id,
                    batch_aggregation_id,
                    _,
                ) = write_collect_artifacts::<TimeInterval>(
                    tx,
                    &other_task,
                    &[
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(9))
                            .unwrap(),
                        OLDEST_ALLOWED_REPORT_TIMESTAMP
                            .sub(&Duration::from_seconds(8))
                            .unwrap(),
                    ],
                )
                .await;
                collection_job_ids.extend(collection_job_id);
                aggregate_share_job_ids.extend(aggregate_share_job_id);
                batch_ids.extend(batch_id);
                outstanding_batch_ids.extend(outstanding_batch_id);
                batch_aggregation_ids.extend(batch_aggregation_id);

                Ok((
                    *leader_time_interval_task.id(),
                    *helper_time_interval_task.id(),
                    *leader_fixed_size_task.id(),
                    *helper_fixed_size_task.id(),
                    *leader_fixed_size_time_bucketed_task.id(),
                    *other_task.id(),
                    batch_ids,
                    collection_job_ids,
                    aggregate_share_job_ids,
                    outstanding_batch_ids,
                    batch_aggregation_ids,
                    time_bucket_starts,
                ))
            })
        })
        .await
        .unwrap();

    // Advance the clock to "enable" report expiry.
    clock.advance(&REPORT_EXPIRY_AGE);

    // Run.
    ds.run_tx(|tx| {
        Box::pin(async move {
            tx.delete_expired_collection_artifacts(
                &leader_time_interval_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await
            .unwrap();
            tx.delete_expired_collection_artifacts(
                &helper_time_interval_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await
            .unwrap();
            tx.delete_expired_collection_artifacts(
                &leader_fixed_size_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await
            .unwrap();
            tx.delete_expired_collection_artifacts(
                &helper_fixed_size_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await
            .unwrap();
            tx.delete_expired_collection_artifacts(
                &leader_fixed_size_time_bucketed_task_id,
                u64::try_from(i64::MAX)?,
            )
            .await
            .unwrap();
            Ok(())
        })
    })
    .await
    .unwrap();

    // Reset the clock to "disable" GC-on-read.
    clock.set(OLDEST_ALLOWED_REPORT_TIMESTAMP);

    // Verify.
    let (
        got_batch_ids,
        got_collection_job_ids,
        got_aggregate_share_job_ids,
        got_outstanding_batch_ids,
        got_batch_aggregation_ids,
    ) = ds
        .run_tx(|tx| {
            let time_bucket_starts = time_bucket_starts.clone();
            Box::pin(async move {
                let vdaf = dummy_vdaf::Vdaf::new();

                let leader_time_interval_batch_ids = tx
                    .get_batches_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &leader_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), batch.batch_identifier().get_encoded()));
                let helper_time_interval_batch_ids = tx
                    .get_batches_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &helper_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), batch.batch_identifier().get_encoded()));
                let leader_fixed_size_batch_ids = tx
                    .get_batches_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &leader_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), batch.batch_identifier().get_encoded()));
                let helper_fixed_size_batch_ids = tx
                    .get_batches_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &helper_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), batch.batch_identifier().get_encoded()));
                let leader_fixed_size_time_bucketed_batch_ids = tx
                    .get_batches_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &leader_fixed_size_time_bucketed_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), batch.batch_identifier().get_encoded()));
                let other_task_batch_ids = tx
                    .get_batches_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(&other_task_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), batch.batch_identifier().get_encoded()));
                let got_batch_ids = leader_time_interval_batch_ids
                    .chain(helper_time_interval_batch_ids)
                    .chain(leader_fixed_size_batch_ids)
                    .chain(helper_fixed_size_batch_ids)
                    .chain(leader_fixed_size_time_bucketed_batch_ids)
                    .chain(other_task_batch_ids)
                    .collect();

                let leader_time_interval_collection_job_ids = tx
                    .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|collection_job| *collection_job.id());
                let helper_time_interval_collection_job_ids = tx
                    .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &helper_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|collection_job| *collection_job.id());
                let leader_fixed_size_collection_job_ids = tx
                    .get_collection_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|collection_job| *collection_job.id());
                let helper_fixed_size_collection_job_ids = tx
                    .get_collection_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &helper_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|collection_job| *collection_job.id());
                let leader_fixed_size_time_bucketed_collection_job_ids = tx
                    .get_collection_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_fixed_size_time_bucketed_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|collection_job| *collection_job.id());
                let other_task_collection_job_ids = tx
                    .get_collection_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &other_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|collection_job| *collection_job.id());
                let got_collection_job_ids = leader_time_interval_collection_job_ids
                    .chain(helper_time_interval_collection_job_ids)
                    .chain(leader_fixed_size_collection_job_ids)
                    .chain(helper_fixed_size_collection_job_ids)
                    .chain(leader_fixed_size_time_bucketed_collection_job_ids)
                    .chain(other_task_collection_job_ids)
                    .collect();

                let leader_time_interval_aggregate_share_job_ids = tx
                    .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                let helper_time_interval_aggregate_share_job_ids = tx
                    .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &helper_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                let leader_fixed_size_aggregate_share_job_ids = tx
                    .get_aggregate_share_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                let helper_fixed_size_aggregate_share_job_ids = tx
                    .get_aggregate_share_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &helper_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                let leader_fixed_size_time_bucketed_aggregate_share_job_ids = tx
                    .get_aggregate_share_jobs_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_fixed_size_time_bucketed_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                let other_task_aggregate_share_job_ids = tx
                    .get_aggregate_share_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &other_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|job| (*job.task_id(), job.batch_identifier().get_encoded()));
                let got_aggregate_share_job_ids = leader_time_interval_aggregate_share_job_ids
                    .chain(helper_time_interval_aggregate_share_job_ids)
                    .chain(leader_fixed_size_aggregate_share_job_ids)
                    .chain(helper_fixed_size_aggregate_share_job_ids)
                    .chain(leader_fixed_size_time_bucketed_aggregate_share_job_ids)
                    .chain(other_task_aggregate_share_job_ids)
                    .collect();

                let leader_time_interval_outstanding_batch_ids = tx
                    .get_outstanding_batches(&leader_time_interval_task_id, &None)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), *batch.id()));
                let helper_time_interval_outstanding_batch_ids = tx
                    .get_outstanding_batches(&helper_time_interval_task_id, &None)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), *batch.id()));
                let leader_fixed_size_outstanding_batch_ids = tx
                    .get_outstanding_batches(&leader_fixed_size_task_id, &None)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), *batch.id()));
                let helper_fixed_size_outstanding_batch_ids = tx
                    .get_outstanding_batches(&helper_fixed_size_task_id, &None)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), *batch.id()));
                let leader_fixed_size_time_bucketed_outstanding_batch_ids =
                    try_join_all(time_bucket_starts.iter().copied().map(
                        |time_bucket_start| async move {
                            tx.get_outstanding_batches(
                                &leader_fixed_size_time_bucketed_task_id,
                                &Some(time_bucket_start),
                            )
                            .await
                        },
                    ))
                    .await
                    .unwrap()
                    .into_iter()
                    .flatten()
                    .map(|batch| (*batch.task_id(), *batch.id()));
                let other_task_outstanding_batch_ids = tx
                    .get_outstanding_batches(&other_task_id, &None)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|batch| (*batch.task_id(), *batch.id()));
                let got_outstanding_batch_ids = leader_time_interval_outstanding_batch_ids
                    .chain(helper_time_interval_outstanding_batch_ids)
                    .chain(leader_fixed_size_outstanding_batch_ids)
                    .chain(helper_fixed_size_outstanding_batch_ids)
                    .chain(leader_fixed_size_time_bucketed_outstanding_batch_ids)
                    .chain(other_task_outstanding_batch_ids)
                    .collect();

                let leader_time_interval_batch_aggregation_ids = tx
                    .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg| (*agg.task_id(), agg.batch_identifier().get_encoded()));
                let helper_time_interval_batch_aggregation_ids = tx
                    .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &helper_time_interval_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg| (*agg.task_id(), agg.batch_identifier().get_encoded()));
                let leader_fixed_size_batch_aggregation_ids = tx
                    .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg| (*agg.task_id(), agg.batch_identifier().get_encoded()));
                let helper_fixed_size_batch_aggregation_ids = tx
                    .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &helper_fixed_size_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg| (*agg.task_id(), agg.batch_identifier().get_encoded()));
                let leader_fixed_size_time_bucketed_batch_aggregation_ids = tx
                    .get_batch_aggregations_for_task::<0, FixedSize, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &leader_fixed_size_time_bucketed_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg| (*agg.task_id(), agg.batch_identifier().get_encoded()));
                let other_task_batch_aggregation_ids = tx
                    .get_batch_aggregations_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &vdaf,
                        &other_task_id,
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|agg| (*agg.task_id(), agg.batch_identifier().get_encoded()));
                let got_batch_aggregation_ids = leader_time_interval_batch_aggregation_ids
                    .chain(helper_time_interval_batch_aggregation_ids)
                    .chain(leader_fixed_size_batch_aggregation_ids)
                    .chain(helper_fixed_size_batch_aggregation_ids)
                    .chain(leader_fixed_size_time_bucketed_batch_aggregation_ids)
                    .chain(other_task_batch_aggregation_ids)
                    .collect();

                Ok((
                    got_batch_ids,
                    got_collection_job_ids,
                    got_aggregate_share_job_ids,
                    got_outstanding_batch_ids,
                    got_batch_aggregation_ids,
                ))
            })
        })
        .await
        .unwrap();
    assert_eq!(want_batch_ids, got_batch_ids);
    assert_eq!(want_collection_job_ids, got_collection_job_ids);
    assert_eq!(want_aggregate_share_job_ids, got_aggregate_share_job_ids);
    assert_eq!(want_outstanding_batch_ids, got_outstanding_batch_ids);
    assert_eq!(want_batch_aggregation_ids, got_batch_aggregation_ids);
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_interval_sql(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let datastore = ephemeral_datastore.datastore(MockClock::default()).await;

    datastore
        .run_tx(|tx| {
            Box::pin(async move {
                let interval = tx
                    .query_one(
                        "SELECT '[2020-01-01 10:00, 2020-01-01 10:30)'::tsrange AS interval",
                        &[],
                    )
                    .await?
                    .get::<_, SqlInterval>("interval");
                let ref_interval = Interval::new(
                    Time::from_naive_date_time(
                        &NaiveDate::from_ymd_opt(2020, 1, 1)
                            .unwrap()
                            .and_hms_opt(10, 0, 0)
                            .unwrap(),
                    ),
                    Duration::from_minutes(30).unwrap(),
                )
                .unwrap();
                assert_eq!(interval.as_interval(), ref_interval);

                let interval = tx
                    .query_one(
                        "SELECT '[1970-02-03 23:00, 1970-02-04 00:00)'::tsrange AS interval",
                        &[],
                    )
                    .await?
                    .get::<_, SqlInterval>("interval");
                let ref_interval = Interval::new(
                    Time::from_naive_date_time(
                        &NaiveDate::from_ymd_opt(1970, 2, 3)
                            .unwrap()
                            .and_hms_opt(23, 0, 0)
                            .unwrap(),
                    ),
                    Duration::from_hours(1).unwrap(),
                )?;
                assert_eq!(interval.as_interval(), ref_interval);

                let res = tx
                    .query_one(
                        "SELECT '[1969-01-01 00:00, 1970-01-01 00:00)'::tsrange AS interval",
                        &[],
                    )
                    .await?
                    .try_get::<_, SqlInterval>("interval");
                assert!(res.is_err());

                let ok = tx
                    .query_one(
                        "SELECT (lower(interval) = '1972-07-21 05:30:00' AND
                            upper(interval) = '1972-07-21 06:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                        &[&SqlInterval::from(
                            Interval::new(
                                Time::from_naive_date_time(
                                    &NaiveDate::from_ymd_opt(1972, 7, 21)
                                        .unwrap()
                                        .and_hms_opt(5, 30, 0)
                                        .unwrap(),
                                ),
                                Duration::from_minutes(30).unwrap(),
                            )
                            .unwrap(),
                        )],
                    )
                    .await?
                    .get::<_, bool>("ok");
                assert!(ok);

                let ok = tx
                    .query_one(
                        "SELECT (lower(interval) = '2021-10-05 00:00:00' AND
                            upper(interval) = '2021-10-06 00:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                        &[&SqlInterval::from(
                            Interval::new(
                                Time::from_naive_date_time(
                                    &NaiveDate::from_ymd_opt(2021, 10, 5)
                                        .unwrap()
                                        .and_hms_opt(0, 0, 0)
                                        .unwrap(),
                                ),
                                Duration::from_hours(24).unwrap(),
                            )
                            .unwrap(),
                        )],
                    )
                    .await?
                    .get::<_, bool>("ok");
                assert!(ok);

                Ok(())
            })
        })
        .await
        .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_global_hpke_keypair(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let datastore = ephemeral_datastore.datastore(MockClock::default()).await;
    let clock = datastore.clock.clone();
    let keypair = generate_test_hpke_config_and_private_key();

    datastore
        .run_tx(|tx| {
            let keypair = keypair.clone();
            let clock = clock.clone();
            Box::pin(async move {
                assert_eq!(tx.get_global_hpke_keypairs().await?, vec![]);
                tx.put_global_hpke_keypair(&keypair).await?;

                let expected_keypair =
                    GlobalHpkeKeypair::new(keypair.clone(), HpkeKeyState::Pending, clock.now());
                assert_eq!(
                    tx.get_global_hpke_keypairs().await?,
                    vec![expected_keypair.clone()]
                );
                assert_eq!(
                    tx.get_global_hpke_keypair(keypair.config().id())
                        .await?
                        .unwrap(),
                    expected_keypair
                );

                // Try modifying state.
                clock.advance(&Duration::from_seconds(100));
                tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                    .await?;
                assert_eq!(
                    tx.get_global_hpke_keypair(keypair.config().id())
                        .await?
                        .unwrap(),
                    GlobalHpkeKeypair::new(keypair.clone(), HpkeKeyState::Active, clock.now(),)
                );

                clock.advance(&Duration::from_seconds(100));
                tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Expired)
                    .await?;
                assert_eq!(
                    tx.get_global_hpke_keypair(keypair.config().id())
                        .await?
                        .unwrap(),
                    GlobalHpkeKeypair::new(keypair.clone(), HpkeKeyState::Expired, clock.now(),)
                );

                Ok(())
            })
        })
        .await
        .unwrap();

    // Should not be able to set keypair with the same id.
    assert_matches!(
        datastore
            .run_tx(|tx| {
                let keypair = keypair.clone();
                Box::pin(async move { tx.put_global_hpke_keypair(&keypair).await })
            })
            .await,
        Err(Error::Db(_))
    );

    datastore
        .run_tx(|tx| {
            let keypair = keypair.clone();
            Box::pin(async move {
                tx.delete_global_hpke_keypair(keypair.config().id()).await?;
                assert_eq!(tx.get_global_hpke_keypairs().await?, vec![]);
                assert_matches!(
                    tx.get_global_hpke_keypair(keypair.config().id()).await?,
                    None
                );
                Ok(())
            })
        })
        .await
        .unwrap();
}

#[rstest_reuse::apply(schema_versions_template)]
#[tokio::test]
async fn roundtrip_taskprov_peer_aggregator(ephemeral_datastore: EphemeralDatastore) {
    install_test_trace_subscriber();
    let datastore = ephemeral_datastore.datastore(MockClock::default()).await;

    // Basic aggregator.
    let example_leader_peer_aggregator =
        PeerAggregatorBuilder::new().with_role(Role::Leader).build();
    let example_helper_peer_aggregator = PeerAggregatorBuilder::new()
        .with_role(Role::Helper)
        .with_aggregator_auth_tokens(vec![random(), random()])
        .with_collector_auth_tokens(vec![])
        .build();
    let another_example_leader_peer_aggregator = PeerAggregatorBuilder::new()
        .with_endpoint(Url::parse("https://another.example.com/").unwrap())
        .with_aggregator_auth_tokens(vec![])
        .with_collector_auth_tokens(vec![random(), random()])
        .build();

    datastore
        .run_tx(|tx| {
            let example_leader_peer_aggregator = example_leader_peer_aggregator.clone();
            let example_helper_peer_aggregator = example_helper_peer_aggregator.clone();
            let another_example_leader_peer_aggregator =
                another_example_leader_peer_aggregator.clone();
            Box::pin(async move {
                tx.put_taskprov_peer_aggregator(&example_leader_peer_aggregator)
                    .await?;
                tx.put_taskprov_peer_aggregator(&example_helper_peer_aggregator)
                    .await?;
                tx.put_taskprov_peer_aggregator(&another_example_leader_peer_aggregator)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

    // Should not be able to put an aggregator with the same endpoint and role.
    assert_matches!(
        datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let colliding_peer_aggregator = PeerAggregatorBuilder::new().build();
                    tx.put_taskprov_peer_aggregator(&colliding_peer_aggregator)
                        .await
                })
            })
            .await,
        Err(Error::MutationTargetAlreadyExists)
    );

    datastore
        .run_tx(|tx| {
            let example_leader_peer_aggregator = example_leader_peer_aggregator.clone();
            let example_helper_peer_aggregator = example_helper_peer_aggregator.clone();
            let another_example_leader_peer_aggregator =
                another_example_leader_peer_aggregator.clone();
            Box::pin(async move {
                assert_eq!(
                    tx.get_taskprov_peer_aggregators().await.unwrap(),
                    vec![
                        example_leader_peer_aggregator.clone(),
                        example_helper_peer_aggregator.clone(),
                        another_example_leader_peer_aggregator.clone(),
                    ]
                );
                Ok(())
            })
        })
        .await
        .unwrap();
}
