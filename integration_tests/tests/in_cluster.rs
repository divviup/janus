#![cfg(feature = "in-cluster")]

use anyhow::anyhow;
use base64::engine::{
    general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use common::{submit_measurements_and_verify_aggregate, test_task_builders};
use http::header::{ACCEPT, CONTENT_TYPE};
use janus_aggregator_core::task::{QueryType, Task};
use janus_core::{
    hpke::HpkePrivateKey,
    task::VdafInstance,
    test_util::{
        install_test_trace_subscriber,
        kubernetes::{Cluster, PortForward},
    },
};
use janus_integration_tests::client::ClientBackend;
use janus_messages::{Role, TaskId};
use prio::codec::Encode;
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

mod common;

struct InClusterJanusPair {
    /// The leader's view of the task configured in both Janus aggregators.
    leader_task: Task,
    /// The private key corresponding to the collector HPKE configuration in the task configured in
    /// both Janus aggregators.
    collector_private_key: HpkePrivateKey,

    /// Handle to the leader's resources, which are released on drop.
    leader: InClusterJanus,
    /// Handle to the helper's resources, which are released on drop.
    helper: InClusterJanus,
}

impl InClusterJanusPair {
    /// Set up a new DAP task, using the given VDAF and query type, in a pair of existing Janus
    /// instances in a Kubernetes cluster. `divviup-api` is used to configure the task in each Janus
    /// instance. The following environment variables must be set.
    ///
    ///  - `JANUS_E2E_KUBE_CONFIG_PATH`: The path to a kubeconfig file, containing the information
    ///    needed to connect to the cluster.
    ///  - `JANUS_E2E_KUBECTL_CONTEXT_NAME`: The name of a context in the kubeconfig file.
    ///  - `JANUS_E2E_LEADER_NAMESPACE`: The Kubernetes namespace where the DAP leader is deployed.
    ///  - `JANUS_E2E_LEADER_API_NAMESPACE`: The Kubernetes namespace where the leader's instance of
    ///    divviup-api is deployed.
    ///  - `JANUS_E2E_HELPER_NAMESPACE`: The Kubernetes namespace where the DAP helper is deployed.
    ///  - `JANUS_E2E_HELPER_API_NAMESPACE`: The Kubernetes namespace where the helper's instance of
    ///    divviup-api is deployed.
    async fn new(vdaf: VdafInstance, query_type: QueryType) -> Self {
        let (collector_private_key, mut leader_task, mut helper_task) =
            test_task_builders(vdaf, query_type);
        leader_task = leader_task.with_min_batch_size(100);
        helper_task = helper_task.with_min_batch_size(100);

        let (
            kubeconfig_path,
            kubectl_context_name,
            leader_namespace,
            leader_api_namespace,
            helper_namespace,
            helper_api_namespace,
        ) = match (
            env::var("JANUS_E2E_KUBE_CONFIG_PATH"),
            env::var("JANUS_E2E_KUBECTL_CONTEXT_NAME"),
            env::var("JANUS_E2E_LEADER_NAMESPACE"),
            env::var("JANUS_E2E_LEADER_API_NAMESPACE"),
            env::var("JANUS_E2E_HELPER_NAMESPACE"),
            env::var("JANUS_E2E_HELPER_API_NAMESPACE"),
        ) {
            (
                Ok(kubeconfig_path),
                Ok(kubectl_context_name),
                Ok(leader_namespace),
                Ok(leader_api_namespace),
                Ok(helper_namespace),
                Ok(helper_api_namespace),
            ) => (
                kubeconfig_path,
                kubectl_context_name,
                leader_namespace,
                leader_api_namespace,
                helper_namespace,
                helper_api_namespace,
            ),
            _ => panic!("missing or invalid environment variables"),
        };

        let cluster = Cluster::new(&kubeconfig_path, &kubectl_context_name);

        // From outside the cluster, the aggregators are reached at a dynamically allocated port on
        // localhost. When the aggregators talk to each other, they do so in the cluster's network,
        // so they need the in-cluster DNS name of the other aggregator, and they can use well-known
        // service port numbers. The leader uses its view of its own endpoint URL to construct
        // collection job URIs, so we will only patch each aggregator's view of its peer's endpoint.
        let leader_endpoints = {
            let mut endpoints = leader_task.aggregator_endpoints().to_vec();
            endpoints[1] = Self::in_cluster_aggregator_url(&helper_namespace);
            endpoints
        };
        let leader_task = leader_task
            .with_aggregator_endpoints(leader_endpoints)
            .build();
        let leader = InClusterJanus::new(
            &cluster,
            &leader_namespace,
            &leader_api_namespace,
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
        let helper = InClusterJanus::new(
            &cluster,
            &helper_namespace,
            &helper_api_namespace,
            &helper_task,
        )
        .await;

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

struct InClusterJanus {
    aggregator_port_forward: PortForward,
}

impl InClusterJanus {
    /// Set up a port forward to an existing Janus instance in a Kubernetes cluster, and provision a
    /// DAP task in it via divviup-api.
    async fn new(
        cluster: &Cluster,
        aggregator_namespace: &str,
        control_plane_namespace: &str,
        task: &Task,
    ) -> Self {
        let divviup_api_port_forward = cluster
            .forward_port(control_plane_namespace, "divviup-api", 80)
            .await;
        divviup_api_create_task(&divviup_api_port_forward, task).await;
        let aggregator_port_forward = cluster
            .forward_port(aggregator_namespace, "aggregator", 80)
            .await;
        Self {
            aggregator_port_forward,
        }
    }

    fn port(&self) -> u16 {
        self.aggregator_port_forward.local_port()
    }
}

// Serialization/deserialization helper structures for interaction with divviup-api.

#[derive(Deserialize)]
struct Account {
    id: String,
}

#[derive(Serialize)]
struct Histogram {
    buckets: Vec<u64>,
}

#[derive(Serialize)]
struct Sum {
    bits: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum ApiVdaf {
    Count,
    Histogram(Histogram),
    Sum(Sum),
}

impl TryFrom<&VdafInstance> for ApiVdaf {
    type Error = anyhow::Error;

    fn try_from(vdaf: &VdafInstance) -> Result<Self, Self::Error> {
        match vdaf {
            VdafInstance::Prio3Count => Ok(ApiVdaf::Count),
            VdafInstance::Prio3Sum { bits } => Ok(ApiVdaf::Sum(Sum { bits: *bits })),
            VdafInstance::Prio3Histogram { buckets } => Ok(ApiVdaf::Histogram(Histogram {
                buckets: buckets.clone(),
            })),
            _ => Err(anyhow!("unsupported VDAF: {vdaf:?}")),
        }
    }
}

#[derive(Serialize)]
struct NewTaskRequest {
    name: String,
    id: TaskId,
    partner_url: String,
    vdaf: ApiVdaf,
    min_batch_size: u64,
    max_batch_size: Option<u64>,
    is_leader: bool,
    vdaf_verify_key: String,
    expiration: String,
    time_precision_seconds: u64,
    hpke_config: String,
    aggregator_auth_token: String,
    collector_auth_token: Option<String>,
}

impl TryFrom<&Task> for NewTaskRequest {
    type Error = anyhow::Error;

    fn try_from(task: &Task) -> Result<Self, Self::Error> {
        let partner_url = match task.role() {
            Role::Leader => task.aggregator_endpoints()[Role::Helper.index().unwrap()].to_string(),
            Role::Helper => task.aggregator_endpoints()[Role::Leader.index().unwrap()].to_string(),
            _ => unreachable!(),
        };
        let max_batch_size = match task.query_type() {
            QueryType::TimeInterval => None,
            QueryType::FixedSize { max_batch_size } => Some(*max_batch_size),
        };
        let collector_auth_token = if *task.role() == Role::Leader {
            Some(URL_SAFE_NO_PAD.encode(task.primary_collector_auth_token().as_ref()))
        } else {
            None
        };
        Ok(Self {
            name: format!("Integration test task: {task:?}"),
            id: *task.id(),
            partner_url,
            max_batch_size,
            vdaf: task.vdaf().try_into()?,
            min_batch_size: task.min_batch_size(),
            is_leader: *task.role() == Role::Leader,
            vdaf_verify_key: URL_SAFE_NO_PAD.encode(&task.vdaf_verify_keys()[0]),
            expiration: "3000-01-01T00:00:00Z".to_owned(),
            time_precision_seconds: task.time_precision().as_seconds(),
            hpke_config: STANDARD.encode(task.collector_hpke_config().get_encoded()),
            aggregator_auth_token: URL_SAFE_NO_PAD
                .encode(task.primary_aggregator_auth_token().as_ref()),
            collector_auth_token,
        })
    }
}

const DIVVIUP_CONTENT_TYPE: &str = "application/vnd.divviup+json;version=0.1";

async fn divviup_api_create_task(port_forward: &PortForward, task: &Task) {
    // TODO(#1528): divviup-api is responsible for provisioning the task into both aggregators. This
    // will need to adopt its new task creation message.

    let client = reqwest::Client::new();
    // Create an account first. (We should be implicitly logged in as a testing user already,
    // assuming divviup-api was built with the integration-testing feature)
    let create_account_resp = client
        .post(&format!(
            "http://127.0.0.1:{}/api/accounts",
            port_forward.local_port()
        ))
        .header(CONTENT_TYPE, DIVVIUP_CONTENT_TYPE)
        .header(ACCEPT, DIVVIUP_CONTENT_TYPE)
        .body("{\"name\":\"Integration test account\"}")
        .send()
        .await
        .unwrap();
    let create_account_status = create_account_resp.status();
    if !create_account_status.is_success() {
        let response_text_res = create_account_resp.text().await;
        panic!(
            "Account creation request returned status code {}, {:?}",
            create_account_status, response_text_res
        );
    }
    let account = create_account_resp.json::<Account>().await.unwrap();

    // Create the task within the new account.
    let request = NewTaskRequest::try_from(task).unwrap();
    let create_task_resp = client
        .post(format!(
            "http://127.0.0.1:{}/api/accounts/{}/tasks",
            port_forward.local_port(),
            account.id
        ))
        .json(&request)
        .header(CONTENT_TYPE, DIVVIUP_CONTENT_TYPE)
        .header(ACCEPT, DIVVIUP_CONTENT_TYPE)
        .send()
        .await
        .unwrap();
    let create_task_status = create_task_resp.status();
    if !create_task_status.is_success() {
        let response_text_res = create_task_resp.text().await;
        panic!(
            "Task creation request returned status code {}, {:?}",
            create_task_status, response_text_res
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_count() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let janus_pair =
        InClusterJanusPair::new(VdafInstance::Prio3Count, QueryType::TimeInterval).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
        &ClientBackend::InProcess,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_sum() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let janus_pair =
        InClusterJanusPair::new(VdafInstance::Prio3Sum { bits: 16 }, QueryType::TimeInterval).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
        &ClientBackend::InProcess,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_histogram() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let buckets = Vec::from([3, 6, 8]);
    let janus_pair = InClusterJanusPair::new(
        VdafInstance::Prio3Histogram { buckets },
        QueryType::TimeInterval,
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
        &ClientBackend::InProcess,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_fixed_size() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let janus_pair = InClusterJanusPair::new(
        VdafInstance::Prio3Count,
        QueryType::FixedSize {
            max_batch_size: 110,
        },
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &janus_pair.leader_task,
        &janus_pair.collector_private_key,
        &ClientBackend::InProcess,
    )
    .await;
}
