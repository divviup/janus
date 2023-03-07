#![cfg(feature = "daphne")]

use common::{submit_measurements_and_verify_aggregate, test_task_builders};
use janus_aggregator_core::task::Task;
use janus_core::{
    task::VdafInstance,
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
};
use janus_integration_tests::{daphne::Daphne, janus::Janus};
use janus_interop_binaries::test_util::generate_network_name;
use janus_messages::Role;

mod common;

// TODO(timg): re-enable DAphne tests once Daphne implements DAP-04

// This test places Daphne in the leader role & Janus in the helper role.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn daphne_janus() {
    install_test_trace_subscriber();

    // Start servers.
    let network = generate_network_name();
    let (collector_private_key, leader_task, helper_task) =
        test_task_builders(VdafInstance::Prio3Count);

    // Daphne is hardcoded to serve from a path starting with /v01/.
    let [leader_task, helper_task]: [Task; 2] = [leader_task, helper_task]
        .into_iter()
        .map(|task| {
            let mut endpoints = task.aggregator_endpoints().to_vec();
            endpoints[Role::Leader.index().unwrap()].set_path("/v01/");
            task.with_aggregator_endpoints(endpoints).build()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let container_client = container_client();
    let leader = Daphne::new(&container_client, &network, &leader_task).await;
    let helper = Janus::new_in_container(&container_client, &network, &helper_task).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (leader.port(), helper.port()),
        &leader_task,
        &collector_private_key,
    )
    .await;
}

// This test places Janus in the leader role & Daphne in the helper role.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn janus_daphne() {
    install_test_trace_subscriber();

    // Start servers.
    let network = generate_network_name();
    let (collector_private_key, leader_task, helper_task) =
        test_task_builders(VdafInstance::Prio3Count);

    // Daphne is hardcoded to serve from a path starting with /v01/.
    let [leader_task, helper_task]: [Task; 2] = [leader_task, helper_task]
        .into_iter()
        .map(|task| {
            let mut endpoints = task.aggregator_endpoints().to_vec();
            endpoints[Role::Helper.index().unwrap()].set_path("/v01/");
            task.with_aggregator_endpoints(endpoints).build()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let container_client = container_client();
    let leader = Janus::new_in_container(&container_client, &network, &leader_task).await;
    let helper = Daphne::new(&container_client, &network, &helper_task).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (leader.port(), helper.port()),
        &leader_task,
        &collector_private_key,
    )
    .await;
}
