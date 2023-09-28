//! Functionality for tests interacting with Daphne (<https://github.com/cloudflare/daphne>).

use crate::interop_api;
use janus_aggregator_core::task::test_util::{Task, TaskBuilder};
use janus_interop_binaries::{
    test_util::await_http_server, ContainerLogsDropGuard, ContainerLogsSource,
};
use janus_messages::{Role, Time};
use testcontainers::{clients::Cli, images::generic::GenericImage, RunnableImage};

const DAPHNE_HELPER_IMAGE_NAME_AND_TAG: &str = "cloudflare/daphne-worker-helper:sha-f6b3ef1";

/// Represents a running Daphne test instance.
pub struct Daphne<'a> {
    daphne_container: ContainerLogsDropGuard<'a, GenericImage>,
}

impl<'a> Daphne<'a> {
    const INTERNAL_SERVING_PORT: u16 = 8080;

    /// Create and start a new hermetic Daphne test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new(
        container_client: &'a Cli,
        network: &str,
        task: &Task,
        role: Role,
    ) -> Daphne<'a> {
        let (endpoint, image_name_and_tag) = match role {
            Role::Leader => panic!("A leader container image for Daphne is not yet available"),
            Role::Helper => (
                task.helper_aggregator_endpoint(),
                DAPHNE_HELPER_IMAGE_NAME_AND_TAG,
            ),
            Role::Collector | Role::Client => unreachable!(),
        };
        let (image_name, image_tag) = image_name_and_tag.rsplit_once(':').unwrap();

        // Start the Daphne test container running.
        let runnable_image = RunnableImage::from(GenericImage::new(image_name, image_tag))
            .with_network(network)
            .with_container_name(endpoint.host_str().unwrap());
        let daphne_container = ContainerLogsDropGuard::new(
            container_client.run(runnable_image),
            ContainerLogsSource::Docker,
        );
        let port = daphne_container.get_host_port_ipv4(Self::INTERNAL_SERVING_PORT);

        // Wait for Daphne container to begin listening on the port.
        await_http_server(port).await;

        // Daphne does not support unset task expiration values. Work around this by specifying an
        // arbitrary, far-future task expiration time, instead.
        let task = if task.task_expiration().is_none() {
            TaskBuilder::from(task.clone())
                .with_task_expiration(Some(Time::from_seconds_since_epoch(2000000000)))
                .build()
        } else {
            task.clone()
        };

        // Write the given task to the Daphne instance we started.
        interop_api::aggregator_add_task(port, task, role).await;

        Self { daphne_container }
    }

    /// Returns the port of the aggregator on the host.
    pub fn port(&self) -> u16 {
        self.daphne_container
            .get_host_port_ipv4(Self::INTERNAL_SERVING_PORT)
    }
}
