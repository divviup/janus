//! This integration test attempts to implement discrete event simulation in Janus. The goal of this
//! test is to uncover more bugs around garbage collection, network errors, or other failures to
//! uphold certain DAP invariants. We will try to avoid introducing nondeterminism as much as
//! possible, given the current architecture, though we will likely fall short of complete
//! determinism. Database anomalies and other concurrency bugs are out of scope, because the
//! operation of the Postgres database is outside the control of our simulation. All operations will
//! be serialized, so that at most one database transaction may run concurrently.
//!
//! Prio3Histogram is the only VDAF used, and reports are carefully crafted to allow aggregate
//! results to be verified, even in the face of loss of reports. Each report will have a unique
//! measurement, so correct aggregate results must consist of only zeros and ones (and moreover,
//! they should be all zeros for buckets that were never submitted in reports). A two in any
//! position would indicate that a report was replayed or counted twice, while very large numbers
//! would suggest an undetected batch mismatch between the leader and helper, or incorrect
//! aggregation by one of the aggregators. There will only be one DAP task in use at a time. Both
//! TimeInterval and FixedSize query types should be supported, as their implementations are very
//! different.
//!
//! The simulation consists of multiple components making up a client, two aggregators, and a
//! collector. All components for each aggregator share a database, and all components across the
//! simulation share a `MockClock`. None of the components should run any asynchronous tasks
//! continuously throughout the simulation (except for tokio-postgres connection tasks). Some
//! components will spawn Tokio tasks to perform concurrent work, thus those will need to use
//! `TestRuntime` so that the simulation can wait for the background work to complete before
//! continuing on to the next operation. Initialization will be akin to `JanusInProcessPair`, but
//! more low-level. The simulation will be fed a list of `Op` objects, and it will execute the
//! operations described one after another. The operations are as follows:
//!
//! - AdvanceTime: Advance the `MockClock`'s time by some amount.
//! - Upload: Have the client shard a report at the given timestamp, with the next sequential
//!   measurement, and send it to the leader aggregator. The leader will handle the request and
//!   store the report to the database. Note that, as currently implemented, this will wait for the
//!   report batching timeout to expire, so the client's upload method won't return until the
//!   leader's database transaction is complete.
//! - GarbageCollector: Run the garbage collector once.
//! - AggregationJobCreator: Run the aggregation job creator once. It may be necessary to re-run the
//!   aggregation job creator multiple times per operation, or change the databas queries used,
//!   because a `SKIP LOCKED` flag in an underlying database query may otherwise introduce
//!   nondeterminism. For example, a retry loop could be used, exiting if a custom query (without
//!   `SKIP LOCKED`) finds that there are no more unaggregated reports available. However, the
//!   mapping from reports to newly created aggregation jobs may still be nondeterministic,
//! - AggregationJobDriver: Run the aggregation job driver once, and wait until it is done stepping
//!   all the jobs it acquired. Requests and responses will pass through a proxy in front of the
//!   helper that inspects them. It may be necessary to re-run the aggregation job driver multiple
//!   times per operation, or change the database queries used, because a `SKIP LOCKED` flag in an
//!   underlying database query may otherwise introduce nondeterminism. Additionally, the
//!   aggregation job driver normally steps multiple jobs in parallel, on different Tokio tasks. We
//!   want to avoid this, both because it would introduce nondeterminism in the leader's database
//!   and the helper's HTTP handler and database. A new custom implementation of the `Runtime` trait
//!   would allow serializing these operations. Extra work may be needed to ensure that aggregation
//!   jobs are stepped in a deterministic order.
//! - AggregationJobDriverRequestError: Same as above, with fault injection. Drop all requests and
//!   return some sort of error.
//! - AggregationJobDriverResponseError: Same as above, with fault injection. Forward all requests
//!   but drop the responses, and return some sort of error.
//! - CollectionJobDriver: Run the collection job driver once, and wait until it is done stepping
//!   all the jobs it acquired. Requests and responses will pass through a proxy in front of the
//!   helper that inspects them. As above, concurrent Tokio tasks will need to be serialized, and
//!   the presence of `SKIP LOCKED` in the collection job acquisition query will present
//!   nondeterminism issues.
//! - CollectionJobDriverRequestError: Same as above, with fault injection. Drop all requests and
//!   return some sort of error.
//! - CollectionJobDriverResponseError: Same as above, with fault injection. Forward all requests
//!   but drop the responses, and return some sort of error.
//! - CollectorStart: The collector sends a collection request to the leader. It remembers the
//!   collection job ID.
//! - CollectorStartRequestError: Same as above, with fault injection. Drop the request and return
//!   some sort of error.
//! - CollectorStartResponseError: Same as above, with fault injection. Forward the request but drop
//!   the response, and return some sort of error.
//! - CollectorPoll: The collector sends a request to the leader to poll an existing collection job.
//! - CollectorPollRequestError: Same as above, with fault injection. Drop the request and return
//!   some sort of error.
//! - CollectorPollResponseError: Same as above, with fault injection. Drop the response and return
//!   some sort of error.
//!
//! Given the above nondeterminism issues introduced by `SKIP LOCKED`, it might be worth adding a
//! knob to switch to more deterministic variants of these queries (removing `SKIP LOCKED` and
//! adding `ORDER BY`). Otherwise, it would be difficult to eliminate nondeterminism without
//! rewriting large parts of the respective components.
//!
//! There may also be some residual nondeterminism from stochastic behavior of Postgres's query
//! planner. Different query plans may return results in different orders, for queries that do not
//! specify an ordering.
//!
//! Similarly, Tokio's `select!` macro and async runtime both introduce sources of nondeterminism.
//! Operations that use async task concurrency will be affected. This may be mitigated by
//! serializing task execution in a chosen order, but timing of network I/O may still make the order
//! of execution nondeterministic.
//!
//! The following are possible failure conditions:
//! - The main Tokio task panics while calling into any component.
//! - Any spawned Tokio task managed by the `TestRuntime` panics.
//! - The collector gets an aggregate result that is impossible.
//!   - Any array element is greater than one.
//!   - Any array element is nonzero and none of the reports contributed to that bucket.
//! - The collector gets multiple successful responses when polling the same collection job (across
//!   multiple operations), and they are not equal.
//! - The helper sends an error response with a "batch mismatch" problem type in response to an
//!   aggregate share request from the leader.
//! - The leader sends two aggregation job initialization requests with the same ID, but different
//!   contents.
//! - An individual operation exceeds some timeout.
//!
//! The following are explicitly not failure conditions:
//! - The collector gets an error back from the leader.
//!
//! Note that, due to known issues, Janus would currently fail a liveness criteria like "if a report
//! is uploaded with a timestamp near enough the current time, and the leader's components run
//! enough times before time advances too much, and its batch was collected after the report was
//! uploaded, then it should show up in the results." In particular, it's possible for fresh reports
//! to be combined with about-to-expire reports in aggregation jobs, and in such cases the fresh
//! report would be lost if time advanced a small amount before aggregation happened.
//!
//! It may be possible to impose a collection job liveness criteria, along the lines of "if the
//! aggregation job driver runs 'enough', then collection job driver runs 'enough', then a
//! collection job request is polled, the job should either finish or fail."
//!
//! This test will require at least two ephemeral TCP servers for the aggregators. The intercepting
//! proxies that do fault injection and error response inspection could either be implemented as
//! another TCP server, or as a Trillium handler that is combined with the aggregator handler.

use std::collections::HashMap;

use janus_collector::Collection;
use janus_core::{time::MockClock, vdaf::VdafInstance};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    CollectionJobId, Duration, ReportId, Time,
};
use prio::vdaf::prio3::{optimal_chunk_length, Prio3, Prio3Histogram};
use quickcheck::{Arbitrary, QuickCheck, TestResult};

const MAX_REPORTS: usize = 1_000;

#[derive(Debug, Clone)]
enum Op {
    AdvanceTime {
        amount: Duration,
    },
    Upload {
        report_time: Time,
    },
    GarbageCollector,
    AggregationJobCreator,
    AggregationJobDriver,
    AggregationJobDriverRequestError,
    AggregationJobDriverResponseError,
    CollectionJobDriver,
    CollectionJobDriverRequestError,
    CollectionJobDriverResponseError,
    CollectorStart {
        query: Query,
    },
    CollectorStartRequestError {
        query: Query,
    },
    CollectorStartResponseError {
        query: Query,
    },
    CollectorPoll {
        // TODO: how should this refer to previous collection job IDs in an Arbitrary-friendly way?
        // Check wasm-smith for inspiration.
    },
    CollectorPollRequestError {},
    CollectorPollResponseError {},
}

#[derive(Debug, Clone)]
enum Query {
    TimeInterval(janus_messages::Query<janus_messages::query_type::TimeInterval>),
    FixedSize(janus_messages::Query<janus_messages::query_type::FixedSize>),
}

#[derive(Debug, Clone)]
struct Input {
    config: Config,
    ops: Vec<Op>,
}

#[derive(Debug, Clone)]
struct TimeIntervalInput(Input);

#[derive(Debug, Clone)]
struct FixedSizeInput(Input);

#[derive(Debug, Clone)]
struct TimeIntervalFaultInjectionInput(Input);

#[derive(Debug, Clone)]
struct FixedSizeFaultInjectionInput(Input);

impl Arbitrary for TimeIntervalInput {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        todo!()
    }
}

fn arbitrary_op_time_interval(g: &mut quickcheck::Gen, context: ()) -> Op {
    todo!()
}

impl Arbitrary for FixedSizeInput {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        todo!()
    }
}

fn arbitrary_op_fixed_size(g: &mut quickcheck::Gen, context: ()) -> Op {
    todo!()
}

impl Arbitrary for TimeIntervalFaultInjectionInput {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        todo!()
    }
}

fn arbitrary_op_time_interval_fault_injection(g: &mut quickcheck::Gen, context: ()) -> Op {
    todo!()
}

impl Arbitrary for FixedSizeFaultInjectionInput {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        todo!()
    }
}

fn arbitrary_op_fixed_size_fault_injection(g: &mut quickcheck::Gen, context: ()) -> Op {
    todo!()
}

#[derive(Debug, Clone)]
struct Config {
    time_precision: Duration,
    // etc.
}

impl Arbitrary for Config {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        todo!()
    }
}

#[derive(Debug)]
struct State {
    clock: MockClock,
    report_ids: Vec<ReportId>,
    vdaf_instance: VdafInstance,
    vdaf: Prio3Histogram,
    aggregate_results_time_interval: HashMap<CollectionJobId, Collection<Vec<u128>, TimeInterval>>,
    aggregate_results_fixed_size: HashMap<CollectionJobId, Collection<Vec<u128>, FixedSize>>,
}

impl State {
    fn new() -> Self {
        let chunk_length = optimal_chunk_length(MAX_REPORTS);
        Self {
            clock: MockClock::new(Time::from_seconds_since_epoch(1_600_000_000)),
            report_ids: Vec::new(),
            vdaf_instance: VdafInstance::Prio3Histogram {
                length: MAX_REPORTS,
                chunk_length,
            },
            vdaf: Prio3::new_histogram(2, MAX_REPORTS, chunk_length).unwrap(),
            aggregate_results_time_interval: HashMap::new(),
            aggregate_results_fixed_size: HashMap::new(),
        }
    }
}

fn run_simulation(input: Input) -> TestResult {
    let mut state = State::new();
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // TODO

    for op in input.ops.iter() {
        match op {
            Op::AdvanceTime { amount } => state.clock.advance(amount),
            Op::Upload { report_time } => todo!(),
            Op::GarbageCollector => todo!(),
            Op::AggregationJobCreator => todo!(),
            Op::AggregationJobDriver => todo!(),
            Op::AggregationJobDriverRequestError => todo!(),
            Op::AggregationJobDriverResponseError => todo!(),
            Op::CollectionJobDriver => todo!(),
            Op::CollectionJobDriverRequestError => todo!(),
            Op::CollectionJobDriverResponseError => todo!(),
            Op::CollectorStart { query } => todo!(),
            Op::CollectorStartRequestError { query } => todo!(),
            Op::CollectorStartResponseError { query } => todo!(),
            Op::CollectorPoll {} => todo!(),
            Op::CollectorPollRequestError {} => todo!(),
            Op::CollectorPollResponseError {} => todo!(),
        }
    }
    TestResult::passed()
}

#[test]
fn simulation_test_time_interval_no_fault_injection() {
    QuickCheck::new().quickcheck(
        (|TimeIntervalInput(input)| run_simulation(input)) as fn(TimeIntervalInput) -> TestResult,
    )
}
