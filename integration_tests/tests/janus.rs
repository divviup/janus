use common::{submit_measurements_and_verify_aggregate, test_task_builders};
use janus_aggregator::task::Task;
use janus_core::{
    hpke::HpkePrivateKey,
    task::VdafInstance,
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
};
use janus_integration_tests::janus::Janus;
use janus_interop_binaries::test_util::generate_network_name;
use std::env::{self, VarError};
use testcontainers::clients::Cli;
use url::Url;

mod common;

/// A pair of Janus instances, running somewhere, against which integration tests may be run.
struct JanusPair<'a> {
    /// The leader's view of the task configured in both Janus aggregators.
    leader_task: Task,
    /// The private key corresponding to the collector HPKE configuration in the task configured in
    /// both Janus aggregators.
    collector_private_key: HpkePrivateKey,

    /// Handle to the leader's resources, which are released on drop.
    leader: Janus<'a>,
    /// Handle to the helper's resources, which are released on drop.
    helper: Janus<'a>,
}

impl<'a> JanusPair<'a> {
    /// Set up a new Janus test instance with a new task, using the provided VDAF. If the
    /// environment variables listed below are set, then the test instance is backed by an
    /// already-running Kubernetes cluster. Otherwise, an ephemeral, in-process instance of Janus
    /// is spawned. In either case, the Janus aggregators' API endpoints will be available on the
    /// local loopback interface, at the URLs in `Self.leader_task.aggregator_endpoints`.
    ///
    /// If connecting to the Kubernetes cluster API (k8s API, not DAP API) at an IP address over
    /// HTTPS (e.g., "https://127.0.0.1:42356"), then the `integration_tests` package must be built
    /// with the `kube-openssl` feature, as the default rustls can't validate IP addresses in
    /// certificates. e.g., `cargo test --features kube-openssl --package integration_tests`
    ///
    /// Environment variables:
    ///  - `JANUS_E2E_KUBE_CONFIG_PATH`: The path to a `kubectl` configuration file containing
    ///    the information needed to connect to the Kubernetes cluster where the test is to be run.
    ///  - `JANUS_E2E_KUBECTL_CONTEXT_NAME`: The name of a `kubectl` context defined in the config
    ///    at `JANUS_E2E_KUBE_CONFIG_PATH`. The context will be used to connect to the Kubernetes
    ///    cluster where the test is to be run. The context should grant sufficient cluster
    ///    permissions to view secrets and forward ports to services.
    ///  - `JANUS_E2E_LEADER_NAMESPACE`: The Kubernetes namespace where the DAP leader is deployed.
    ///  - `JANUS_E2E_HELPER_NAMESPACE`: The Kubernetes namespace where the DAP helper is deployed.
    pub async fn new(container_client: &'a Cli, vdaf: VdafInstance) -> JanusPair<'a> {
        let (collector_private_key, leader_task, helper_task) = test_task_builders(vdaf);

        // The environment variables should either all be present, or all be absent
        let (leader_task, leader, helper) = match (
            env::var("JANUS_E2E_KUBE_CONFIG_PATH"),
            env::var("JANUS_E2E_KUBECTL_CONTEXT_NAME"),
            env::var("JANUS_E2E_LEADER_NAMESPACE"),
            env::var("JANUS_E2E_HELPER_NAMESPACE"),
        ) {
            (
                Ok(kubeconfig_path),
                Ok(kubectl_context_name),
                Ok(leader_namespace),
                Ok(helper_namespace),
            ) => {
                // From outside the cluster, the aggregators are reached at "localhost:<port>",
                // where "port" is whatever unused port we use with `kubectl port-forward`. But when
                // the aggregators talk to each other, they do it on the cluster's private network,
                // and so they need the in-cluster DNS name of the other aggregator. However, since
                // aggregators use the endpoint URLs in the task to construct collect job URIs, we
                // must only fix the _peer_ aggregator's endpoint.
                let leader_endpoints = {
                    let mut endpoints = leader_task.aggregator_endpoints().to_vec();
                    endpoints[1] = Self::in_cluster_aggregator_url(&helper_namespace);
                    endpoints
                };
                let leader_task = leader_task
                    .with_aggregator_endpoints(leader_endpoints)
                    .build();
                let leader = Janus::new_with_kubernetes_cluster(
                    &kubeconfig_path,
                    &kubectl_context_name,
                    &leader_namespace,
                    &leader_task,
                )
                .await;

                let helper_endpoints = {
                    let mut endpoints = helper_task.aggregator_endpoints().to_vec();
                    endpoints[0] = Self::in_cluster_aggregator_url(&leader_namespace);
                    endpoints
                };
                let helper_task = helper_task
                    .with_aggregator_endpoints(helper_endpoints)
                    .build();
                let helper = Janus::new_with_kubernetes_cluster(
                    &kubeconfig_path,
                    &kubectl_context_name,
                    &helper_namespace,
                    &helper_task,
                )
                .await;

                (leader_task, leader, helper)
            }
            (
                Err(VarError::NotPresent),
                Err(VarError::NotPresent),
                Err(VarError::NotPresent),
                Err(VarError::NotPresent),
            ) => {
                let leader_task = leader_task.build();
                let network = generate_network_name();
                let leader =
                    Janus::new_in_container(container_client, &network, &leader_task).await;
                let helper =
                    Janus::new_in_container(container_client, &network, &helper_task.build()).await;
                (leader_task, leader, helper)
            }
            _ => panic!("unexpected environment variables"),
        };

        Self {
            leader_task,
            collector_private_key,
            leader,
            helper,
        }
    }

    fn in_cluster_aggregator_url(namespace: &str) -> Url {
        Url::parse(&format!(
            "http://aggregator.{namespace}.svc.cluster.local:80"
        ))
        .unwrap()
    }
}

/// This test exercises Prio3Aes128Count with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_janus_count() {
    install_test_trace_subscriber();

    // Start servers.
    let container_client = container_client();
    let janus_pair = JanusPair::new(&container_client, VdafInstance::Prio3Aes128Count).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
    )
    .await;
}

/// This test exercises Prio3Aes128Sum with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_janus_sum_16() {
    install_test_trace_subscriber();

    // Start servers.
    let container_client = container_client();
    let janus_pair =
        JanusPair::new(&container_client, VdafInstance::Prio3Aes128Sum { bits: 16 }).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
    )
    .await;
}

/// This test exercises Prio3Aes128Histogram with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_janus_histogram_4_buckets() {
    install_test_trace_subscriber();

    let buckets = Vec::from([3, 6, 8]);

    // Start servers.
    let container_client = container_client();
    let janus_pair = JanusPair::new(
        &container_client,
        VdafInstance::Prio3Aes128Histogram { buckets },
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
    )
    .await;
}
