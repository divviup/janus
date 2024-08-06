use std::sync::Arc;

use janus_aggregator_core::datastore::test_util::EphemeralDatabase;
use janus_core::test_util::install_test_trace_subscriber;
use quickcheck::{QuickCheck, TestResult};
use tokio::runtime::Runtime;

use crate::simulation::{
    arbitrary::{
        FixedSizeFaultInjectionInput, FixedSizeInput, KeyRotatorInput,
        TimeIntervalFaultInjectionInput, TimeIntervalInput,
    },
    run::Simulation,
};

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_time_interval_no_fault_injection() {
    install_test_trace_subscriber();

    let _ephemeral_database = DatabaseHandle::new();

    QuickCheck::new().quickcheck(
        (|TimeIntervalInput(input)| Simulation::run(input)) as fn(TimeIntervalInput) -> TestResult,
    );
}

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_fixed_size_no_fault_injection() {
    install_test_trace_subscriber();

    let _ephemeral_database = DatabaseHandle::new();

    QuickCheck::new().quickcheck(
        (|FixedSizeInput(input)| Simulation::run(input)) as fn(FixedSizeInput) -> TestResult,
    );
}

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_time_interval_with_fault_injection() {
    install_test_trace_subscriber();

    let _ephemeral_database = DatabaseHandle::new();

    QuickCheck::new().quickcheck(
        (|TimeIntervalFaultInjectionInput(input)| Simulation::run(input))
            as fn(TimeIntervalFaultInjectionInput) -> TestResult,
    );
}

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_fixed_size_with_fault_injection() {
    install_test_trace_subscriber();

    let _ephemeral_database = DatabaseHandle::new();

    QuickCheck::new().quickcheck(
        (|FixedSizeFaultInjectionInput(input)| Simulation::run(input))
            as fn(FixedSizeFaultInjectionInput) -> TestResult,
    );
}

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_key_rotator() {
    install_test_trace_subscriber();

    let _ephemeral_database = DatabaseHandle::new();

    QuickCheck::new().quickcheck(
        (|KeyRotatorInput(input)| Simulation::run(input)) as fn(KeyRotatorInput) -> TestResult,
    );
}

/// Handle to keep one ephemeral database container live.
struct DatabaseHandle {
    /// Ephemeral database container reference.
    database: Option<Arc<EphemeralDatabase>>,
    /// Tokio runtime used to set up the database. This must be kept live longer than the database,
    /// so that the Tokio reactor shuts down last.
    runtime: Runtime,
}

impl DatabaseHandle {
    /// Create an ephemeral datastore with a new async runtime.
    ///
    /// This is used to ensure that one ephemeral database is available throughout the duration of
    /// quickcheck tests. This avoids repeatedly starting and stopping database containers if only
    /// one quickcheck test is running, each time its ephemeral datastore goes out of scope.
    /// Starting a database container can take around five seconds, while setting up a new database
    /// and schema inside the same container can take around one second.
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let database = Some(runtime.block_on(async { EphemeralDatabase::shared().await }));
        Self { database, runtime }
    }
}

impl Drop for DatabaseHandle {
    fn drop(&mut self) {
        // The database needs to be dropped in the context of a Tokio runtime.
        self.runtime.block_on(async { drop(self.database.take()) })
    }
}
