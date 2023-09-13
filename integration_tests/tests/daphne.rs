use common::{submit_measurements_and_verify_aggregate, test_task_builders};
use janus_aggregator_core::task::{QueryType, Task};
use janus_core::{
    task::VdafInstance,
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
};
use janus_integration_tests::{client::ClientBackend, daphne::Daphne, janus::Janus};
use janus_interop_binaries::test_util::generate_network_name;

mod common;

// This test places Daphne in the leader role & Janus in the helper role.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Daphne does not yet publish a leader container image"]
async fn daphne_janus() {
    install_test_trace_subscriber();

    // Start servers.
    let network = generate_network_name();
    let (mut task_parameters, leader_task, helper_task) =
        test_task_builders(VdafInstance::Prio3Count, QueryType::TimeInterval);

    // Daphne is hardcoded to serve from a path starting with /v04/.
    task_parameters.endpoint_fragments.leader_endpoint_path = "/v04/".to_string();
    let [leader_task, helper_task]: [Task; 2] = [leader_task, helper_task]
        .into_iter()
        .map(|task| {
            let mut leader_aggregator_endpoint = task.leader_aggregator_endpoint().clone();
            leader_aggregator_endpoint.set_path("/v04/");
            task.with_leader_aggregator_endpoint(leader_aggregator_endpoint)
                .build()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let container_client = container_client();
    let leader = Daphne::new(&container_client, &network, &leader_task).await;
    let helper = Janus::new(&container_client, &network, &helper_task).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        &task_parameters,
        (leader.port(), helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

// This test places Janus in the leader role & Daphne in the helper role.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Daphne does not currently support DAP-06 (issue #1669)"]
async fn janus_daphne() {
    install_test_trace_subscriber();

    // Start servers.
    let network = generate_network_name();
    let (mut task_parameters, leader_task, helper_task) =
        test_task_builders(VdafInstance::Prio3Count, QueryType::TimeInterval);

    // Daphne is hardcoded to serve from a path starting with /v04/.
    task_parameters.endpoint_fragments.helper_endpoint_path = "/v04/".to_string();
    let [leader_task, helper_task]: [Task; 2] = [leader_task, helper_task]
        .into_iter()
        .map(|task| {
            let mut helper_aggregator_endpoint = task.helper_aggregator_endpoint().clone();
            helper_aggregator_endpoint.set_path("/v04/");
            task.with_helper_aggregator_endpoint(helper_aggregator_endpoint)
                .build()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let container_client = container_client();
    let leader = Janus::new(&container_client, &network, &leader_task).await;
    let helper = Daphne::new(&container_client, &network, &helper_task).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        &task_parameters,
        (leader.port(), helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}
