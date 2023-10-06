//! Functionality for tests interacting with Daphne (<https://github.com/cloudflare/daphne>).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use derivative::Derivative;
use janus_aggregator_core::task::QueryType;
use janus_aggregator_core::task::{test_util::TaskBuilder, Task};
use janus_interop_binaries::test_util::await_http_server;
use janus_interop_binaries::{log_export_path, AggregatorRole, VdafObject};
use janus_messages::query_type::{FixedSize, QueryType as _, TimeInterval};
use janus_messages::{Role, TaskId, Time};
use prio::codec::Encode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{
    fs::{create_dir_all, File},
    process::{Command, Stdio},
    thread::panicking,
};
use testcontainers::{clients::Cli, Container, GenericImage, RunnableImage};
use url::Url;

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
            .with_container_name(endpoint.host_str().unwrap())
            .with_env_var(("DAP_DEFAULT_VERSION", "v02")); // https://github.com/cloudflare/daphne/blob/bf992e9af3d7dece19b5a6cc3b271470a27d3695/daphne_worker/src/config.rs#L151-L152
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
        aggregator_add_task(port, task).await;

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

// Note: the latest version of Daphne implements the latest version of the interop test API, even
// when operating against a prior version of the DAP spec (e.g. DAP-02). We work around this by
// encoding our add task request as expected by the latest version of the interop test API spec.

/// Send an interop test API request to add a DAP task. This assumes the server is available on
/// some localhost port.
async fn aggregator_add_task(port: u16, task: Task) {
    let http_client = reqwest::Client::default();
    let resp = http_client
        .post(Url::parse(&format!("http://127.0.0.1:{port}/internal/test/add_task")).unwrap())
        .json(&AggregatorAddTaskRequest::from(task))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp: HashMap<String, Option<String>> = resp.json().await.unwrap();
    assert_eq!(
        resp.get("status"),
        Some(&Some("success".to_string())),
        "error: {:?}",
        resp.get("error")
    );
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct AggregatorAddTaskRequest {
    pub task_id: TaskId, // uses unpadded base64url
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    pub leader: Url,
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    pub helper: Url,
    pub vdaf: VdafObject,
    pub leader_authentication_token: String,
    #[serde(default)]
    pub collector_authentication_token: Option<String>,
    pub role: AggregatorRole,
    pub vdaf_verify_key: String, // in unpadded base64url
    pub max_batch_query_count: u64,
    pub query_type: u8,
    pub min_batch_size: u64,
    pub max_batch_size: Option<u64>,
    pub time_precision: u64,           // in seconds
    pub collector_hpke_config: String, // in unpadded base64url
    pub task_expiration: Option<u64>,  // in seconds since the epoch
}

impl From<Task> for AggregatorAddTaskRequest {
    fn from(task: Task) -> Self {
        let (query_type, max_batch_size) = match task.query_type() {
            QueryType::TimeInterval => (TimeInterval::CODE as u8, None),
            QueryType::FixedSize { max_batch_size, .. } => {
                (FixedSize::CODE as u8, Some(*max_batch_size))
            }
        };
        Self {
            task_id: *task.id(),
            leader: task.aggregator_url(&Role::Leader).unwrap().clone(),
            helper: task.aggregator_url(&Role::Helper).unwrap().clone(),
            vdaf: task.vdaf().clone().into(),
            leader_authentication_token: String::from_utf8(
                task.primary_aggregator_auth_token().as_ref().to_vec(),
            )
            .unwrap(),
            collector_authentication_token: if task.role() == &Role::Leader {
                Some(
                    String::from_utf8(task.primary_collector_auth_token().as_ref().to_vec())
                        .unwrap(),
                )
            } else {
                None
            },
            role: (*task.role()).try_into().unwrap(),
            vdaf_verify_key: URL_SAFE_NO_PAD
                .encode(task.vdaf_verify_keys().first().unwrap().as_ref()),
            max_batch_query_count: task.max_batch_query_count(),
            query_type,
            min_batch_size: task.min_batch_size(),
            max_batch_size,
            time_precision: task.time_precision().as_seconds(),
            collector_hpke_config: URL_SAFE_NO_PAD
                .encode(task.collector_hpke_config().unwrap().get_encoded()),
            task_expiration: task.task_expiration().map(Time::as_seconds_since_epoch),
        }
    }
}
