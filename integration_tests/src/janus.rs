//! Functionality for tests interacting with Janus (<https://github.com/divviup/janus>).

use crate::interop_api;
use janus_aggregator_core::task::Task;
use janus_interop_binaries::{
    test_util::await_http_server, testcontainer::Aggregator, ContainerLogsDropGuard,
};
use janus_messages::Role;
use testcontainers::{clients::Cli, RunnableImage};

/// Represents a running Janus test instance in a container.
pub struct Janus<'a> {
    container: ContainerLogsDropGuard<'a, Aggregator>,
}

impl<'a> Janus<'a> {
    /// Create and start a new hermetic Janus test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new(container_client: &'a Cli, network: &str, task: &Task) -> Janus<'a> {
        // Start the Janus interop aggregator container running.
        let endpoint = match task.role() {
            Role::Leader => task.leader_aggregator_endpoint(),
            Role::Helper => task.helper_aggregator_endpoint(),
            _ => panic!("unexpected task role"),
        };
        let container = ContainerLogsDropGuard::new_janus(
            container_client.run(
                RunnableImage::from(Aggregator::default())
                    .with_network(network)
                    .with_container_name(endpoint.host_str().unwrap()),
            ),
        );
        let port = container.get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT);

        // Wait for the container to start listening on its port.
        await_http_server(port).await;

        // Write the given task to the Janus instance we started.
        interop_api::aggregator_add_task(port, task.clone()).await;

        Self { container }
    }

    /// Returns the port of the aggregator on the host.
    pub fn port(&self) -> u16 {
        self.container
            .get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT)
    }
}
