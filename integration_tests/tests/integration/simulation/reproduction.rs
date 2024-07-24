use janus_core::test_util::install_test_trace_subscriber;
use janus_messages::{Duration, Interval, Time};
use rand::random;

use crate::simulation::{
    model::{Config, Input, Op, Query},
    run::Simulation,
    START_TIME,
};

#[test]
fn successful_collection_time_interval() {
    install_test_trace_subscriber();

    let collection_job_id = random();
    let input = Input {
        is_fixed_size: false,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 4,
            max_batch_size: None,
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 10,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::CollectorStart {
                collection_job_id,
                query: Query::TimeInterval(
                    Interval::new(
                        Time::from_seconds_since_epoch(1_699_999_200),
                        Duration::from_seconds(3600),
                    )
                    .unwrap(),
                ),
            },
            Op::CollectionJobDriver,
            Op::CollectorPoll { collection_job_id },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::CollectorStart {
                collection_job_id,
                query: Query::TimeInterval(
                    Interval::new(
                        Time::from_seconds_since_epoch(1_699_999_200),
                        Duration::from_seconds(3600),
                    )
                    .unwrap(),
                ),
            },
            Op::CollectionJobDriver,
            Op::CollectorPoll { collection_job_id },
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}

#[test]
fn successful_collection_fixed_size() {
    install_test_trace_subscriber();

    let collection_job_id = random();
    let input = Input {
        is_fixed_size: true,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 4,
            max_batch_size: Some(6),
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 10,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::CollectorStart {
                collection_job_id,
                query: Query::FixedSizeCurrentBatch,
            },
            Op::CollectionJobDriver,
            Op::CollectorPoll { collection_job_id },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::CollectorStart {
                collection_job_id,
                query: Query::FixedSizeCurrentBatch,
            },
            Op::CollectionJobDriver,
            Op::CollectorPoll { collection_job_id },
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}

#[test]
#[ignore = "failing test"]
/// Reproduction of https://github.com/divviup/janus/issues/3323.
fn repro_slow_uploads_with_max_batch_size() {
    install_test_trace_subscriber();

    let collection_job_id = random();
    let input = Input {
        is_fixed_size: true,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 4,
            max_batch_size: Some(6),
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 10,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::AdvanceTime {
                amount: Duration::from_seconds(3600),
            },
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: Time::from_seconds_since_epoch(1_700_003_600),
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::AdvanceTime {
                amount: Duration::from_seconds(3600),
            },
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: Time::from_seconds_since_epoch(1_700_007_200),
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::AdvanceTime {
                amount: Duration::from_seconds(3600),
            },
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: Time::from_seconds_since_epoch(1_700_010_800),
            },
            Op::Upload {
                report_time: Time::from_seconds_since_epoch(1_700_010_800),
            },
            Op::Upload {
                report_time: Time::from_seconds_since_epoch(1_700_010_800),
            },
            Op::Upload {
                report_time: Time::from_seconds_since_epoch(1_700_010_800),
            },
            Op::AggregationJobCreator,
            Op::AggregationJobDriver,
            Op::CollectorStart {
                collection_job_id,
                query: Query::FixedSizeCurrentBatch,
            },
            Op::CollectionJobDriver,
            Op::CollectorPoll { collection_job_id },
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}
