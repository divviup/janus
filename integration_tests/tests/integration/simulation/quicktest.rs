use janus_core::test_util::install_test_trace_subscriber;
use quickcheck::{QuickCheck, TestResult};

use crate::simulation::{
    arbitrary::{
        FixedSizeFaultInjectionInput, FixedSizeInput, TimeIntervalFaultInjectionInput,
        TimeIntervalInput,
    },
    run::Simulation,
};

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_time_interval_no_fault_injection() {
    install_test_trace_subscriber();

    QuickCheck::new().quickcheck(
        (|TimeIntervalInput(input)| Simulation::run(input)) as fn(TimeIntervalInput) -> TestResult,
    );
}

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_fixed_size_no_fault_injection() {
    install_test_trace_subscriber();

    QuickCheck::new().quickcheck(
        (|FixedSizeInput(input)| Simulation::run(input)) as fn(FixedSizeInput) -> TestResult,
    );
}

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_time_interval_with_fault_injection() {
    install_test_trace_subscriber();

    QuickCheck::new().quickcheck(
        (|TimeIntervalFaultInjectionInput(input)| Simulation::run(input))
            as fn(TimeIntervalFaultInjectionInput) -> TestResult,
    );
}

#[test]
#[ignore = "slow quickcheck test"]
fn simulation_test_fixed_size_with_fault_injection() {
    install_test_trace_subscriber();

    QuickCheck::new().quickcheck(
        (|FixedSizeFaultInjectionInput(input)| Simulation::run(input))
            as fn(FixedSizeFaultInjectionInput) -> TestResult,
    );
}
