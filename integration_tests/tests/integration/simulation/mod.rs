//! This integration test attempts to implement discrete event simulation in Janus. The goal of this
//! test is to uncover more bugs around garbage collection, network errors, runtime errors, or other
//! failures to uphold certain DAP invariants. We will try to avoid introducing nondeterminism as
//! much as possible, given the current architecture, though we will necessarily fall short of
//! complete determinism.
//!
//! The operating system, Postgres, and Rust synchronization primitives are outside the control of
//! our simulation, so nondeterminism introduced by these sources is out of scope. While this set of
//! tests may trigger bugs that involve these phenomena, it will not be able to reproduce them
//! reliably like in-scope bugs. There will be room to fix some sources of nondeterminism short of
//! these limits, in order to reproduce more bugs repeatably. For example, operations can be
//! serialized, to avoid running multiple database transactions concurrently, and parallelism in the
//! aggregation job driver and collection job driver can be eliminated.
//!
//! Prio3Histogram is the only VDAF used, and reports are carefully crafted to allow aggregate
//! results to be verified, even in the face of partial data loss. Each report will have a unique
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
//! continuously throughout the simulation (except for tokio-postgres connection tasks).
//! Initialization will be akin to `JanusInProcessPair`, but more low-level. The simulation is fed a
//! list of [`Op`](model::Op) values, and it executes the operations described one after another.
//!
//! The following are possible failure conditions:
//! - The main Tokio task panics while calling into any component.
//! - Any spawned Tokio task managed by a `TestRuntime` panics.
//! - The collector gets an aggregate result that is impossible.
//!   * Any array element is greater than one.
//!   * Any array element is nonzero and none of the reports contributed to that bucket.
//! - The collector gets multiple successful responses when polling the same collection job (across
//!   multiple operations) and they are not equal.
//! - The helper sends an error response with a "batch mismatch" problem type in response to an
//!   aggregate share request from the leader.
//! - The leader sends two aggregation job initialization requests with the same ID, but different
//!   contents.
//! - An individual operation exceeds some timeout.
//!
//! The following are explicitly not failure conditions:
//! - The client gets an error from the leader when trying to upload a report, because the timestamp
//!   is too old or too new.
//! - The collector gets an error back from the leader indicating a batch can't be collected yet.
//!
//! Note that, due to known issues, Janus would currently fail a liveness criteria like "if a report
//! is uploaded with a timestamp near enough the current time, and the leader's components run
//! enough times before time advances too much, and its batch was collected after the report was
//! uploaded, then it should show up in the results." In particular, it's possible for fresh reports
//! to be combined with about-to-expire reports in aggregation jobs, and in such cases the fresh
//! report would be lost if time advanced a small amount before aggregation happened.
//!
//! It may be possible to impose a collection job liveness criteria, along the lines of "if the
//! aggregation job driver runs 'enough', then the collection job driver runs 'enough', then a
//! collection job request is polled, the job should either finish or fail."
//!
//! ## Known sources of nondeterminism
//!
//! - Timing of network syscalls.
//! - Database anomalies allowed at REPEATABLE READ.
//! - Stochastic behavior of Postgres query planner (leading to different row orders).
//! - `SKIP LOCKED` clauses in database queries.
//! - Any parallelization of database-related futures.
//! - Randomly-selected `ord` values in tables with "sharded" rows.
//! - Timing of asynchronous tasks.
//! - Randomness used by `tokio::select!`.
//! - Application-level concurrency bugs.

use std::time::Duration;

use backoff::ExponentialBackoff;
use janus_messages::Time;

const START_TIME: Time = Time::from_seconds_since_epoch(1_700_000_000);

mod arbitrary;
mod bad_client;
mod model;
mod proxy;
mod quicktest;
mod reproduction;
mod run;
mod setup;

/// Aggressive exponential backoff parameters for this local-only test. Due to fault injection
/// operations, we will often be hitting `max_elapsed_time`, so this value needs to be very low.
pub(super) fn http_request_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        initial_interval: Duration::from_millis(10),
        max_interval: Duration::from_millis(50),
        multiplier: 2.0,
        max_elapsed_time: Some(Duration::from_millis(250)),
        ..Default::default()
    }
}
