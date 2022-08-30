use common::{create_test_tasks, submit_measurements_and_verify_aggregate};
use interop_binaries::test_util::generate_network_name;
use janus_core::{
    hpke::test_util::generate_test_hpke_config_and_private_key,
    message::Role,
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
};
use monolithic_integration_test::{daphne::Daphne, janus::Janus};

mod common;

// This test places Daphne in the leader role & Janus in the helper role.
#[tokio::test(flavor = "multi_thread")]
async fn daphne_janus() {
    install_test_trace_subscriber();

    // Start servers.
    let network = generate_network_name();
    let (collector_hpke_config, collector_private_key) =
        generate_test_hpke_config_and_private_key();
    let (mut leader_task, mut helper_task) = create_test_tasks(&collector_hpke_config);

    // Daphne is hardcoded to serve from a path starting with /v01/.
    for task in [&mut leader_task, &mut helper_task] {
        task.aggregator_endpoints
            .get_mut(Role::Leader.index().unwrap())
            .unwrap()
            .set_path("/v01/");
    }

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
async fn janus_daphne() {
    install_test_trace_subscriber();

    // Start servers.
    let network = generate_network_name();
    let (collector_hpke_config, collector_private_key) =
        generate_test_hpke_config_and_private_key();
    let (mut leader_task, mut helper_task) = create_test_tasks(&collector_hpke_config);

    // Daphne is hardcoded to serve from a path starting with /v01/.
    for task in [&mut leader_task, &mut helper_task] {
        task.aggregator_endpoints
            .get_mut(Role::Helper.index().unwrap())
            .unwrap()
            .set_path("/v01/");
    }

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
