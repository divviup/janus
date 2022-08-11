use common::{create_test_tasks, pick_two_unused_ports, submit_measurements_and_verify_aggregate};
use janus_core::{
    hpke::test_util::generate_hpke_config_and_private_key, test_util::install_test_trace_subscriber,
};
use monolithic_integration_test::janus::Janus;

mod common;

// This test places Janus in both the leader & helper roles.
#[tokio::test(flavor = "multi_thread")]
async fn janus_janus() {
    install_test_trace_subscriber();

    // Start servers.
    let (janus_leader_port, janus_helper_port) = pick_two_unused_ports();
    let (collector_hpke_config, collector_private_key) = generate_hpke_config_and_private_key();
    let (mut janus_leader_task, mut janus_helper_task) =
        create_test_tasks(janus_leader_port, janus_helper_port, &collector_hpke_config);

    // Update tasks to serve out of /dap/ prefix.
    for task in [&mut janus_leader_task, &mut janus_helper_task] {
        for url in &mut task.aggregator_endpoints {
            url.set_path("/dap/");
        }
    }

    let _janus_leader = Janus::new(janus_leader_port, &janus_leader_task).await;
    let _janus_helper = Janus::new(janus_helper_port, &janus_helper_task).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        &janus_leader_task,
        &collector_hpke_config,
        &collector_private_key,
    )
    .await;
}
