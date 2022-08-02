use common::{create_test_tasks, pick_two_unused_ports, submit_measurements_and_verify_aggregate};
use janus_core::{
    hpke::test_util::generate_hpke_config_and_private_key, test_util::install_test_trace_subscriber,
};
use monolithic_integration_test::{daphne::Daphne, janus::Janus};

mod common;

// This test places Daphne in both the leader & helper roles.
#[tokio::test(flavor = "multi_thread")]
async fn daphne_daphne() {
    install_test_trace_subscriber();

    for i in 0..100 {
        println!("\n\n\n==========\n==========\n==========\nTest iteration: {}\n==========\n==========\n==========\n\n\n", i);

        // Start servers.
        let (daphne_leader_port, daphne_helper_port) = pick_two_unused_ports();
        let (collector_hpke_config, collector_private_key) = generate_hpke_config_and_private_key();
        let (daphne_leader_task, daphne_helper_task) = create_test_tasks(
            daphne_leader_port,
            daphne_helper_port,
            &collector_hpke_config,
        );

        let _daphne_leader = Daphne::new(daphne_leader_port, &daphne_leader_task);
        let _daphne_helper = Daphne::new(daphne_helper_port, &daphne_helper_task);

        // Run the behavioral test.
        submit_measurements_and_verify_aggregate(
            &daphne_leader_task,
            &collector_hpke_config,
            &collector_private_key,
        )
        .await;
    }
}

// This test places Daphne in the leader role & Janus in the helper role.
#[tokio::test(flavor = "multi_thread")]
async fn daphne_janus() {
    install_test_trace_subscriber();

    for i in 0..100 {
        println!("\n\n\n==========\n==========\n==========\nTest iteration: {}\n==========\n==========\n==========\n\n\n", i);

        // Start servers.
        let (daphne_port, janus_port) = pick_two_unused_ports();
        let (collector_hpke_config, collector_private_key) = generate_hpke_config_and_private_key();
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
}

// This test places Janus in the leader role & Daphne in the helper role.
#[tokio::test(flavor = "multi_thread")]
async fn janus_daphne() {
    // Start servers.
    let (janus_port, daphne_port) = pick_two_unused_ports();
    let (collector_hpke_config, collector_private_key) = generate_hpke_config_and_private_key();
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
