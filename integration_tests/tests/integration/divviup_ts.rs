#![cfg(feature = "testcontainer")]
//! These tests check interoperation between the divviup-ts client and Janus aggregators.

use crate::{
    common::{build_test_task, submit_measurements_and_verify_aggregate, TestContext},
    initialize_rustls,
};
use janus_aggregator_core::task::{test_util::TaskBuilder, QueryType};
use janus_core::{
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
    vdaf::VdafInstance,
};
use janus_integration_tests::{
    client::{ClientBackend, InteropClient},
    janus::JanusContainer,
};
use janus_interop_binaries::test_util::generate_network_name;
use janus_messages::Role;
use std::time::Duration;
use testcontainers::clients::Cli;

async fn run_divviup_ts_integration_test(
    test_name: &str,
    container_client: &Cli,
    vdaf: VdafInstance,
) {
    let (task_parameters, task_builder) = build_test_task(
        TaskBuilder::new(QueryType::TimeInterval, vdaf),
        TestContext::VirtualNetwork,
        Duration::from_millis(500),
        Duration::from_secs(60),
    );
    let task = task_builder.build();
    let network = generate_network_name();
    let leader =
        JanusContainer::new(test_name, container_client, &network, &task, Role::Leader).await;
    let helper =
        JanusContainer::new(test_name, container_client, &network, &task, Role::Helper).await;

    let client_backend = ClientBackend::Container {
        container_client,
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
#[ignore = "disabled until divviup-ts supports draft-ietf-ppm-dap-09"]
async fn janus_divviup_ts_count() {
    install_test_trace_subscriber();
    initialize_rustls();

    run_divviup_ts_integration_test(
        "janus_divviup_ts_count",
        &container_client(),
        VdafInstance::Prio3Count,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "disabled until divviup-ts supports draft-ietf-ppm-dap-09"]
async fn janus_divviup_ts_sum() {
    install_test_trace_subscriber();
    initialize_rustls();

    run_divviup_ts_integration_test(
        "janus_divviup_ts_sum",
        &container_client(),
        VdafInstance::Prio3Sum { bits: 8 },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "disabled until divviup-ts supports draft-ietf-ppm-dap-09"]
async fn janus_divviup_ts_histogram() {
    install_test_trace_subscriber();
    initialize_rustls();

    run_divviup_ts_integration_test(
        "janus_divviup_ts_histogram",
        &container_client(),
        VdafInstance::Prio3Histogram {
            length: 4,
            chunk_length: 2,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "disabled until divviup-ts supports draft-ietf-ppm-dap-09"]
async fn janus_divviup_ts_sumvec() {
    install_test_trace_subscriber();
    initialize_rustls();

    run_divviup_ts_integration_test(
        "janus_divviup_ts_sumvec",
        &container_client(),
        VdafInstance::Prio3SumVec {
            bits: 16,
            length: 15,
            chunk_length: 16,
        },
    )
    .await;
}
