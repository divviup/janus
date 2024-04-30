#![cfg(feature = "testcontainer")]
//! These tests check interoperation between the divviup-ts client and Janus aggregators.

use crate::common::{submit_measurements_and_verify_aggregate, test_task_builder};
use janus_aggregator_core::task::QueryType;
use janus_core::{test_util::install_test_trace_subscriber, vdaf::VdafInstance};
use janus_integration_tests::{
    client::{ClientBackend, InteropClient},
    janus::JanusContainer,
};
use janus_interop_binaries::test_util::generate_network_name;
use janus_messages::Role;
use std::time::Duration;

async fn run_divviup_ts_integration_test(test_name: &str, vdaf: VdafInstance) {
    let (task_parameters, task_builder) = test_task_builder(
        vdaf,
        QueryType::TimeInterval,
        Duration::from_millis(500),
        Duration::from_secs(60),
    );
    let task = task_builder.build();
    let network = generate_network_name();
    let leader = JanusContainer::new(test_name, &network, &task, Role::Leader).await;
    let helper = JanusContainer::new(test_name, &network, &task, Role::Helper).await;

    let client_backend = ClientBackend::Container {
        container_image: InteropClient::divviup_ts(),
        network: &network,
    };
    submit_measurements_and_verify_aggregate(
        test_name,
        &task_parameters,
        (leader.port(), helper.port()),
        &client_backend,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_divviup_ts_count() {
    install_test_trace_subscriber();

    run_divviup_ts_integration_test("janus_divviup_ts_count", VdafInstance::Prio3Count).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_divviup_ts_sum() {
    install_test_trace_subscriber();

    run_divviup_ts_integration_test("janus_divviup_ts_sum", VdafInstance::Prio3Sum { bits: 8 })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_divviup_ts_histogram() {
    install_test_trace_subscriber();

    run_divviup_ts_integration_test(
        "janus_divviup_ts_histogram",
        VdafInstance::Prio3Histogram {
            length: 4,
            chunk_length: 2,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_divviup_ts_sumvec() {
    install_test_trace_subscriber();

    run_divviup_ts_integration_test(
        "janus_divviup_ts_sumvec",
        VdafInstance::Prio3SumVec {
            bits: 16,
            length: 15,
            chunk_length: 16,
        },
    )
    .await;
}
