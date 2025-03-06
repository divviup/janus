use janus_aggregator_core::task::AggregationMode;
use janus_core::{test_util::install_test_trace_subscriber, time::TimeExt};
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
        is_leader_selected: false,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 4,
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            aggregation_mode: AggregationMode::Synchronous,
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 10,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
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
                count: 4,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
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
fn successful_collection_leader_selected() {
    install_test_trace_subscriber();

    let collection_job_id = random();
    let input = Input {
        is_leader_selected: true,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 4,
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            aggregation_mode: AggregationMode::Synchronous,
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 10,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::CollectorStart {
                collection_job_id,
                query: Query::LeaderSelected,
            },
            Op::CollectionJobDriver,
            Op::CollectorPoll { collection_job_id },
            Op::Upload {
                report_time: START_TIME,
                count: 4,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::CollectorStart {
                collection_job_id,
                query: Query::LeaderSelected,
            },
            Op::CollectionJobDriver,
            Op::CollectorPoll { collection_job_id },
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}

#[test]
fn successful_collection_asynchronous() {
    install_test_trace_subscriber();

    let collection_job_id = random();
    let input = Input {
        is_leader_selected: false,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 4,
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            aggregation_mode: AggregationMode::Asynchronous,
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 10,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::HelperAggregationJobDriver,
            Op::AdvanceTime {
                amount: Duration::from_seconds(2),
            },
            Op::LeaderAggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::HelperAggregationJobDriver,
            Op::AdvanceTime {
                amount: Duration::from_seconds(2),
            },
            Op::LeaderAggregationJobDriver,
            Op::LeaderGarbageCollector,
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::HelperAggregationJobDriver,
            Op::AdvanceTime {
                amount: Duration::from_seconds(2),
            },
            Op::LeaderAggregationJobDriver,
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
                count: 4,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::HelperAggregationJobDriver,
            Op::AdvanceTime {
                amount: Duration::from_seconds(2),
            },
            Op::LeaderAggregationJobDriver,
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
/// Regression test for https://github.com/divviup/janus/issues/2442.
fn repro_gc_changes_aggregation_job_retry_time_interval() {
    install_test_trace_subscriber();

    let input = Input {
        is_leader_selected: false,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 1,
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            aggregation_mode: AggregationMode::Synchronous,
            min_aggregation_job_size: 2,
            max_aggregation_job_size: 2,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AdvanceTime {
                amount: Duration::from_seconds(3600),
            },
            Op::Upload {
                report_time: START_TIME.add(&Duration::from_seconds(3600)).unwrap(),
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriverResponseError,
            Op::AdvanceTime {
                amount: Duration::from_seconds(5400),
            },
            Op::LeaderGarbageCollector,
            Op::LeaderAggregationJobDriver,
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}

#[test]
/// Regression test for https://github.com/divviup/janus/issues/2442.
fn repro_gc_changes_aggregation_job_retry_leader_selected() {
    install_test_trace_subscriber();

    let input = Input {
        is_leader_selected: true,
        config: Config {
            time_precision: Duration::from_seconds(3600),
            min_batch_size: 1,
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(7200)),
            aggregation_mode: AggregationMode::Synchronous,
            min_aggregation_job_size: 2,
            max_aggregation_job_size: 2,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AdvanceTime {
                amount: Duration::from_seconds(3600),
            },
            Op::Upload {
                report_time: START_TIME.add(&Duration::from_seconds(3600)).unwrap(),
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriverResponseError,
            Op::AdvanceTime {
                amount: Duration::from_seconds(5400),
            },
            Op::LeaderGarbageCollector,
            Op::LeaderAggregationJobDriver,
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}

#[test]
/// Regression test for https://github.com/divviup/janus/issues/2464.
fn repro_recreate_gcd_batch_job_count_underflow() {
    install_test_trace_subscriber();

    let input = Input {
        is_leader_selected: false,
        config: Config {
            time_precision: Duration::from_seconds(1000),
            min_batch_size: 100,
            batch_time_window_size: None,
            report_expiry_age: Some(Duration::from_seconds(4000)),
            aggregation_mode: AggregationMode::Synchronous,
            min_aggregation_job_size: 2,
            max_aggregation_job_size: 2,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AdvanceTime {
                amount: Duration::from_seconds(2000),
            },
            Op::Upload {
                report_time: START_TIME.add(&Duration::from_seconds(2000)).unwrap(),
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::AdvanceTime {
                amount: Duration::from_seconds(3500),
            },
            Op::LeaderAggregationJobDriver,
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}

#[test]
#[ignore = "failing test"]
fn repro_abandoned_aggregation_job_batch_mismatch() {
    install_test_trace_subscriber();

    let collection_job_id = random();
    let input = Input {
        is_leader_selected: false,
        config: Config {
            time_precision: Duration::from_seconds(1000),
            min_batch_size: 1,
            batch_time_window_size: None,
            report_expiry_age: None,
            aggregation_mode: AggregationMode::Synchronous,
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 1,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriver,
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriverResponseError,
            Op::AdvanceTime {
                amount: Duration::from_seconds(610),
            },
            Op::LeaderAggregationJobDriverResponseError,
            Op::AdvanceTime {
                amount: Duration::from_seconds(610),
            },
            Op::LeaderAggregationJobDriver,
            Op::CollectorStart {
                collection_job_id,
                query: Query::TimeInterval(
                    Interval::new(START_TIME, Duration::from_seconds(1000)).unwrap(),
                ),
            },
            Op::CollectionJobDriver,
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}

#[test]
/// Reproduction of the issue fixed by https://github.com/divviup/janus/pull/2355.
fn repro_helper_accumulate_on_retried_request() {
    install_test_trace_subscriber();

    let input = Input {
        is_leader_selected: false,
        config: Config {
            time_precision: Duration::from_seconds(1000),
            min_batch_size: 1,
            batch_time_window_size: None,
            report_expiry_age: None,
            aggregation_mode: AggregationMode::Synchronous,
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 1,
        },
        ops: Vec::from([
            Op::Upload {
                report_time: START_TIME,
                count: 1,
            },
            Op::AggregationJobCreator,
            Op::LeaderAggregationJobDriverResponseError,
            Op::AdvanceTime {
                amount: Duration::from_seconds(700),
            },
            Op::LeaderAggregationJobDriver,
            Op::CollectorStart {
                collection_job_id: random(),
                query: Query::TimeInterval(
                    Interval::new(START_TIME, Duration::from_seconds(1000)).unwrap(),
                ),
            },
            Op::CollectionJobDriver,
        ]),
    };
    assert!(!Simulation::run(input).is_failure());
}
