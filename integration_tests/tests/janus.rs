use common::submit_measurements_and_verify_aggregate;
use integration_tests::janus::Janus;
use interop_binaries::test_util::generate_network_name;
use janus_core::{
    hpke::{test_util::generate_test_hpke_config_and_private_key, HpkePrivateKey},
    task::VdafInstance,
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
};
use janus_messages::Role;
use janus_server::task::{
    test_util::{generate_auth_token, TaskBuilder},
    Task,
};
use rand::random;
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
    /// Set up a new Janus test instance with the provided task. If the environment variables listed
    /// below are set, then the test instance is backed by an already-running Kubernetes cluster.
    /// Otherwise, an ephemeral, in-process instance of Janus is spawned. In either case, the Janus
    /// aggregators' API endpoints will be available on the local loopback interface, at the URLs in
    /// `Self.leader_task.aggregator_endpoints`.
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
    pub async fn new(container_client: &'a Cli) -> JanusPair<'a> {
        let task_id = random();
        let endpoint_random_value = hex::encode(random::<[u8; 4]>());
        let endpoints = Vec::from([
            Url::parse(&format!("http://leader-{endpoint_random_value}:8080/")).unwrap(),
            Url::parse(&format!("http://helper-{endpoint_random_value}:8080/")).unwrap(),
        ]);
        let (collector_hpke_config, collector_private_key) =
            generate_test_hpke_config_and_private_key();
        let aggregator_auth_tokens = Vec::from([generate_auth_token()]);
        let leader_task = TaskBuilder::new(VdafInstance::Prio3Aes128Count.into(), Role::Leader)
            .with_task_id(task_id)
            .with_min_batch_size(46)
            .with_collector_hpke_config(collector_hpke_config.clone())
            .with_aggregator_auth_tokens(aggregator_auth_tokens.clone());
        let helper_task = TaskBuilder::new(VdafInstance::Prio3Aes128Count.into(), Role::Helper)
            .with_task_id(task_id)
            .with_min_batch_size(46)
            .with_collector_hpke_config(collector_hpke_config)
            .with_aggregator_auth_tokens(aggregator_auth_tokens);

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
                let leader_task = leader_task
                    .with_aggregator_endpoints({
                        let mut endpoints = endpoints.clone();
                        endpoints[1] = Self::in_cluster_aggregator_url(&helper_namespace);
                        endpoints
                    })
                    .build();
                let leader = Janus::new_with_kubernetes_cluster(
                    &kubeconfig_path,
                    &kubectl_context_name,
                    &leader_namespace,
                    &leader_task,
                )
                .await;

                let helper_task = helper_task
                    .with_aggregator_endpoints({
                        let mut endpoints = endpoints;
                        endpoints[0] = Self::in_cluster_aggregator_url(&leader_namespace);
                        endpoints
                    })
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
                let leader_task = leader_task
                    .with_aggregator_endpoints(endpoints.clone())
                    .build();
                let helper_task = helper_task.with_aggregator_endpoints(endpoints).build();
                let network = generate_network_name();
                let leader =
                    Janus::new_in_container(container_client, &network, &leader_task).await;
                let helper =
                    Janus::new_in_container(container_client, &network, &helper_task).await;
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

// This test places Janus in both the leader & helper roles.
#[tokio::test(flavor = "multi_thread")]
async fn janus_janus() {
    install_test_trace_subscriber();

    // Start servers.
    let container_client = container_client();
    let janus_pair = JanusPair::new(&container_client).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
    )
    .await;
}
