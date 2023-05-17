//! Functionality for tests interacting with Janus (<https://github.com/divviup/janus>).

use crate::interop_api;
use janus_aggregator_core::task::Task;
use janus_interop_binaries::{
    log_export_path, test_util::await_http_server, testcontainer::Aggregator,
};
use janus_messages::Role;
use std::{
    process::{Command, Stdio},
    thread::panicking,
};
use testcontainers::{clients::Cli, Container, RunnableImage};

/// Represents a running Janus test instance in a container.
pub struct Janus<'a> {
    role: Role,
    container: Container<'a, Aggregator>,
}

impl<'a> Janus<'a> {
    /// Create and start a new hermetic Janus test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new(container_client: &'a Cli, network: &str, task: &Task) -> Janus<'a> {
        // Start the Janus interop aggregator container running.
        let endpoint = task.aggregator_url(task.role()).unwrap();
        let container = container_client.run(
            RunnableImage::from(Aggregator::default())
                .with_network(network)
                .with_container_name(endpoint.host_str().unwrap()),
        );
        let port = container.get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT);

        // Wait for the container to start listening on its port.
        await_http_server(port).await;

        // Write the given task to the Janus instance we started.
        interop_api::aggregator_add_task(port, task.clone()).await;

        Self {
            role: *task.role(),
            container,
        }
    }

    /// Returns the port of the aggregator on the host.
    pub fn port(&self) -> u16 {
        self.container
            .get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT)
    }
}

impl<'a> Drop for Janus<'a> {
    fn drop(&mut self) {
        // We assume that if a Janus value is dropped during a panic, we are in the middle of
        // test failure. In this case, export logs if log_export_path() suggests doing so.
        //
        // (log export is a no-op for non-containers: when running tests against a cluster, we
        // gather up logfiles with `kind export logs`)

        if !panicking() {
            return;
        }
        if let Some(mut destination_path) = log_export_path() {
            destination_path.push(format!("{}-{}", self.role, self.container.id()));
            if let Ok(docker_cp_status) = Command::new("docker")
                .args([
                    "cp",
                    &format!("{}:logs/", self.container.id()),
                    destination_path.as_os_str().to_str().unwrap(),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                if !docker_cp_status.success() {
                    println!("`docker cp` failed with status {docker_cp_status:?}");
                }
            } else {
                println!("Failed to execute `docker cp`");
            }
        }
    }
}
