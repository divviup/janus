//! Functionality for tests interacting with Janus (<https://github.com/divviup/janus>).

use crate::logs::CopyLogs;
use interop_binaries::{
    test_util::await_http_server, testcontainer::Aggregator, AggregatorAddTaskRequest,
};
use janus_core::{
    message::Role,
    test_util::kubernetes::{Cluster, PortForward},
    time::RealClock,
};
use janus_server::{
    binary_utils::{database_pool, datastore},
    config::DbConfig,
    task::Task,
};
use k8s_openapi::api::core::v1::Secret;
use portpicker::pick_unused_port;
use std::{
    collections::HashMap,
    path::Path,
    process::{Command, Stdio},
};
use testcontainers::{clients::Cli, Container, RunnableImage};
use tracing::debug;
use url::Url;

/// Represents a running Janus test instance
#[allow(clippy::large_enum_variant)]
pub enum Janus<'a> {
    /// Janus components are spawned in a container, and completely destroyed once the test ends.
    Container {
        role: Role,
        container: Container<'a, Aggregator>,
    },

    /// Janus components are assumed to already be running in the Kubernetes cluster. Running tests
    /// against the cluster will persistently mutate the Janus deployment, for instance by writing
    /// new tasks and reports into its datastore.
    KubernetesCluster {
        aggregator_port_forward: PortForward,
    },
}

impl<'a> Janus<'a> {
    /// Create & start a new hermetic Janus test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new_in_container(
        container_client: &'a Cli,
        network: &str,
        task: &Task,
    ) -> Janus<'a> {
        // Start the Janus interop aggregator container running.
        let endpoint = task.aggregator_url(task.role).unwrap();
        let container = container_client.run(
            RunnableImage::from(Aggregator::default())
                .with_network(network)
                .with_container_name(endpoint.host_str().unwrap()),
        );
        let port = container.get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT);

        // Wait for the container to start listening on its port.
        await_http_server(port).await;

        // Write the given task to the Janus instance we started.
        let http_client = reqwest::Client::default();
        let resp = http_client
            .post(Url::parse(&format!("http://127.0.0.1:{}/internal/test/add_task", port)).unwrap())
            .json(&AggregatorAddTaskRequest::from(task.clone()))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let resp: HashMap<String, Option<String>> = resp.json().await.unwrap();
        assert_eq!(resp.get("status"), Some(&Some("success".to_string())));

        Self::Container {
            role: task.role,
            container,
        }
    }

    /// Set up a test case running in a Kubernetes cluster where Janus components and a datastore
    /// are assumed to already be deployed.
    pub async fn new_with_kubernetes_cluster<P>(
        kubeconfig_path: P,
        kubernetes_context_name: &str,
        namespace: &str,
        task: &Task,
    ) -> Janus<'static>
    where
        P: AsRef<Path>,
    {
        let cluster = Cluster::new(kubeconfig_path, kubernetes_context_name);

        // Read the Postgres password and the datastore encryption key from Kubernetes secrets
        let secrets_api: kube::Api<Secret> =
            kube::Api::namespaced(cluster.client().await, namespace);

        let database_password_secret = secrets_api.get("postgresql").await.unwrap();
        let database_password = String::from_utf8(
            database_password_secret
                .data
                .unwrap()
                .get("postgres-password")
                .unwrap()
                .0
                .clone(),
        )
        .unwrap();

        let datastore_key_secret = secrets_api.get("datastore-key").await.unwrap();
        let datastore_key = String::from_utf8(
            datastore_key_secret
                .data
                .unwrap()
                .get("datastore_key")
                .unwrap()
                .0
                .clone(),
        )
        .unwrap();

        // Forward database port so we can provision the task. We assume here that there is a
        // service named "postgresql" listening on port 5432. We could instead look up the service
        // by some label and dynamically discover its port, but being coupled to a label value isn't
        // much different than being coupled to a service name.
        let local_db_port = pick_unused_port().unwrap();
        let _datastore_port_forward = cluster
            .forward_port(namespace, "postgresql", local_db_port, 5432)
            .await;
        debug!("forwarded DB port");

        let pool = database_pool(
            &DbConfig {
                url: Url::parse(&format!(
                    "postgres://postgres:{database_password}@127.0.0.1:{local_db_port}/postgres"
                ))
                .unwrap(),
                connection_pool_timeouts_secs: 60,
            },
            None,
        )
        .await
        .unwrap();

        // Since the Janus components are already running when the task is provisioned, they all
        // must be configured to frequently poll the datastore for new tasks, or the test that
        // depends on this task being defined will likely time out or otherwise fail.
        // This should become more robust in the future when we implement dynamic task provisioning
        // (#44).
        datastore(pool, RealClock::default(), &[datastore_key])
            .unwrap()
            .put_task(task)
            .await
            .unwrap();

        let aggregator_port_forward = cluster
            .forward_port(namespace, "aggregator", pick_unused_port().unwrap(), 80)
            .await;

        Self::KubernetesCluster {
            aggregator_port_forward,
        }
    }

    /// Returns the port of the aggregator on the host.
    pub fn port(&self) -> u16 {
        match self {
            Janus::Container { role: _, container } => {
                container.get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT)
            }
            Janus::KubernetesCluster {
                aggregator_port_forward,
            } => aggregator_port_forward.local_port(),
        }
    }
}

impl<'a> CopyLogs for Janus<'a> {
    fn logs<P: AsRef<Path>>(&self, destination: &P) {
        match self {
            Janus::Container { role, container } => {
                let container_source_path = format!("{}:logs/", container.id());

                let host_destination_path = destination
                    .as_ref()
                    .join(format!("{}-{}", role, container.id()))
                    .into_os_string()
                    .into_string()
                    .unwrap();

                let args = ["cp", &container_source_path, &host_destination_path];
                debug!(?args, "invoking docker");
                let child_status = Command::new("docker")
                    .args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap()
                    .wait()
                    .unwrap();
                assert!(
                    child_status.success(),
                    "docker cp failed with status {:?}",
                    child_status.code()
                );
            }
            // No-op: when running tests against the cluster, we gather up logfiles with `kind
            // export logs`
            Janus::KubernetesCluster {
                aggregator_port_forward: _,
            } => {}
        }
    }
}
