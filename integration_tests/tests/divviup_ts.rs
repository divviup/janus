//! These tests check interoperation between the divviup-ts client and Janus aggregators.

use common::{submit_measurements_and_verify_aggregate, test_task_builders};
use janus_aggregator_core::task::QueryType;
use janus_core::{
    task::VdafInstance,
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
};
use janus_integration_tests::{
    client::{ClientBackend, InteropClient},
    janus::Janus,
};
use janus_interop_binaries::test_util::generate_network_name;
use testcontainers::clients::Cli;

mod common;

async fn run_divviup_ts_integration_test(container_client: &Cli, vdaf: VdafInstance) {
    let (collector_private_key, leader_task, helper_task) =
        test_task_builders(vdaf, QueryType::TimeInterval);
    let leader_task = leader_task.build();
    let network = generate_network_name();
    let leader = Janus::new(container_client, &network, &leader_task).await;
    let helper = Janus::new(container_client, &network, &helper_task.build()).await;

    let client_backend = ClientBackend::Container {
        container_client,
        container_image: InteropClient::divviup_ts(),
        network: &network,
    };
    submit_measurements_and_verify_aggregate(
        (leader.port(), helper.port()),
        &leader_task,
        &collector_private_key,
        &client_backend,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_divviup_ts_count() {
    install_test_trace_subscriber();

    run_divviup_ts_integration_test(&container_client(), VdafInstance::Prio3Count).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_divviup_ts_sum() {
    install_test_trace_subscriber();

    run_divviup_ts_integration_test(&container_client(), VdafInstance::Prio3Sum { bits: 8 }).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_divviup_ts_histogram() {
    install_test_trace_subscriber();

    run_divviup_ts_integration_test(
        &container_client(),
        VdafInstance::Prio3Histogram {
            buckets: Vec::from([1, 10, 100, 1000]),
        },
    )
    .await;
}

// TODO(https://github.com/divviup/divviup-ts/issues/100): Test CountVec once it is implemented.
