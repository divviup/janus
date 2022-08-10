use common::{create_test_tasks, pick_two_unused_ports, submit_measurements_and_verify_aggregate};
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
    let (daphne_port, janus_port) = pick_two_unused_ports();
    let (collector_hpke_config, collector_private_key) =
        generate_test_hpke_config_and_private_key();
    let (daphne_task, janus_task) =
        create_test_tasks(daphne_port, janus_port, &collector_hpke_config);

    let _daphne = Daphne::new(daphne_port, &daphne_task);
    let _janus = Janus::new(janus_port, &janus_task).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        &daphne_task,
        &collector_hpke_config,
        &collector_private_key,
    )
    .await;
}

// This test places Janus in the leader role & Daphne in the helper role.
#[tokio::test(flavor = "multi_thread")]
async fn janus_daphne() {
    install_test_trace_subscriber();

    // Start servers.
    let (janus_port, daphne_port) = pick_two_unused_ports();
    let (collector_hpke_config, collector_private_key) =
        generate_test_hpke_config_and_private_key();
    let (janus_task, daphne_task) =
        create_test_tasks(janus_port, daphne_port, &collector_hpke_config);

    let _janus = Janus::new(janus_port, &janus_task).await;
    let _daphne = Daphne::new(daphne_port, &daphne_task);

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        &janus_task,
        &collector_hpke_config,
        &collector_private_key,
    )
    .await;
}
