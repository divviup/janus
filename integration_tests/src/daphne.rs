//! Functionality for tests interacting with Daphne (<https://github.com/cloudflare/daphne>).

use crate::interop_api;
use janus_aggregator_core::task::{test_util::TaskBuilder, Task};
use janus_interop_binaries::log_export_path;
use janus_interop_binaries::test_util::await_http_server;
use janus_messages::{Role, Time};
use std::{
    fs::{create_dir_all, File},
    process::{Command, Stdio},
    thread::panicking,
};
use testcontainers::{clients::Cli, images::generic::GenericImage, Container, RunnableImage};

const DAPHNE_HELPER_IMAGE_NAME_AND_TAG: &str = "cloudflare/daphne-worker-helper:sha-f6b3ef1";

/// Represents a running Daphne test instance.
pub struct Daphne<'a> {
    daphne_container: Container<'a, GenericImage>,
    role: Role,
}

impl<'a> Daphne<'a> {
    const INTERNAL_SERVING_PORT: u16 = 8080;

    /// Create and start a new hermetic Daphne test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new(container_client: &'a Cli, network: &str, task: &Task) -> Daphne<'a> {
        let image_name_and_tag = match task.role() {
            Role::Leader => panic!("A leader container image for Daphne is not yet available"),
            Role::Helper => DAPHNE_HELPER_IMAGE_NAME_AND_TAG,
            Role::Collector | Role::Client => unreachable!(),
        };
        let (image_name, image_tag) = image_name_and_tag.rsplit_once(':').unwrap();

        // Start the Daphne test container running.
        let endpoint = task.aggregator_url(task.role()).unwrap();
        let runnable_image = RunnableImage::from(GenericImage::new(image_name, image_tag))
            .with_network(network)
            .with_container_name(endpoint.host_str().unwrap());
        let daphne_container = container_client.run(runnable_image);
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
        let role = *task.role();

        // Write the given task to the Daphne instance we started.
        interop_api::aggregator_add_task(port, task).await;

        Self {
            daphne_container,
            role,
        }
    }

    /// Returns the port of the aggregator on the host.
    pub fn port(&self) -> u16 {
        self.daphne_container
            .get_host_port_ipv4(Self::INTERNAL_SERVING_PORT)
    }
}

impl<'a> Drop for Daphne<'a> {
    fn drop(&mut self) {
        // We assume that if a Daphne value is dropped during a panic, we are in the middle of
        // test failure. In this case, export logs if logs_path() suggests doing so.
        if !panicking() {
            return;
        }
        if let Some(mut destination_path) = log_export_path() {
            destination_path.push(format!("{}-{}", self.role, self.daphne_container.id()));
            create_dir_all(&destination_path).unwrap();
            let docker_logs_status = Command::new("docker")
                .args(["logs", "--timestamps", self.daphne_container.id()])
                .stdin(Stdio::null())
                .stdout(File::create(destination_path.join("stdout.log")).unwrap())
                .stderr(File::create(destination_path.join("stderr.log")).unwrap())
                .status()
                .expect("Failed to execute `docker logs`");
            assert!(
                docker_logs_status.success(),
                "`docker logs` failed with status {docker_logs_status:?}"
            );
        }
    }
}
