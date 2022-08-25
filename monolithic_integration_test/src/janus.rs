//! Functionality for tests interacting with Janus (<https://github.com/divviup/janus>).

use crate::CONTAINER_CLIENT;
use interop_binaries::{test_util::await_http_server, testcontainer::Aggregator, AddTaskRequest};
use janus_core::{
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
use std::collections::HashMap;
use std::path::Path;
use testcontainers::{Container, RunnableImage};
use tracing::debug;
use url::Url;

/// Represents a running Janus test instance
#[allow(clippy::large_enum_variant)]
pub enum Janus {
    /// Janus components are spawned in a container, and completely destroyed once the test ends.
    Container {
        container: Container<'static, Aggregator>,
    },

    /// Janus components are assumed to already be running in the Kubernetes cluster. Running tests
    /// against the cluster will persistently mutate the Janus deployment, for instance by writing
    /// new tasks and reports into its datastore.
    KubernetesCluster {
        aggregator_port_forward: PortForward,
    },
}

impl Janus {
    /// Create & start a new hermetic Janus test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new_in_container(network: &str, task: &Task) -> Self {
        // Start the Janus interop aggregator container running.
        let endpoint = task.aggregator_url(task.role).unwrap();
        let container = CONTAINER_CLIENT.run(
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
            .post(Url::parse(&format!("http://localhost:{}/internal/test/add_task", port)).unwrap())
            .json(&AddTaskRequest::from(task.clone()))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let resp: HashMap<String, Option<String>> = resp.json().await.unwrap();
        assert_eq!(resp.get("status"), Some(&Some("success".to_string())));

        Janus::Container { container }
    }

    /// Set up a test case running in a Kubernetes cluster where Janus components and a datastore
    /// are assumed to already be deployed.
    pub async fn new_with_kubernetes_cluster<P>(
        kubeconfig_path: P,
        kubernetes_context_name: &str,
        namespace: &str,
        task: &Task,
    ) -> Self
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
            Janus::Container { container } => {
                container.get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT)
            }
            Janus::KubernetesCluster {
                aggregator_port_forward,
            } => aggregator_port_forward.local_port(),
        }
    }
}
