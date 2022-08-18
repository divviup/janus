use common::{create_test_tasks, generate_network_name, submit_measurements_and_verify_aggregate};
use janus_core::{
    hpke::test_util::generate_test_hpke_config_and_private_key,
    test_util::install_test_trace_subscriber,
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
    let (leader_task, helper_task) = create_test_tasks(&collector_hpke_config);

    let leader = Daphne::new(&network, &leader_task).await;
    let helper = Janus::new_in_container(&network, &helper_task).await;

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
    let (leader_task, helper_task) = create_test_tasks(&collector_hpke_config);

    let leader = Janus::new_in_container(&network, &leader_task).await;
    let helper = Daphne::new(&network, &helper_task).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (leader.port(), helper.port()),
        &leader_task,
        &collector_private_key,
    )
    .await;
}
