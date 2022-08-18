//! Functionality for tests interacting with Daphne (<https://github.com/cloudflare/daphne>).

use crate::{await_http_server, CONTAINER_CLIENT};
use janus_core::message::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId, Role};
use janus_server::task::{Task, VdafInstance};
use lazy_static::lazy_static;
use portpicker::pick_unused_port;
use rand::{thread_rng, Rng};
use regex::Regex;
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    process::{Command, Stdio},
    sync::{mpsc, Mutex},
    thread,
    time::Duration,
};
use testcontainers::{core::Port, images::generic::GenericImage, Container, RunnableImage};
use tokio::{select, sync::oneshot, task, time::interval};

const TEST_DAPHNE_IMAGE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/test_daphne.tar"));
static TEST_DAPHNE_IMAGE_HASH: Mutex<Option<String>> = Mutex::new(None);

lazy_static! {
    static ref DOCKER_HASH_RE: Regex = Regex::new(r"sha256:([0-9a-f]{64})").unwrap();
}

/// Represents a running Daphne test instance.
pub struct Daphne {
    daphne_container: Container<'static, GenericImage>,

    // Task lifetime management.
    start_shutdown_sender: Option<oneshot::Sender<()>>,
    shutdown_complete_receiver: Option<mpsc::Receiver<()>>,
}

impl Daphne {
    /// Create & start a new hermetic Daphne test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new(network: &str, task: &Task) -> Self {
        // Generate values needed for the Daphne environment configuration based on the provided
        // Janus task definition.

        // Daphne currently only supports an HPKE config of (X25519HkdfSha256, HkdfSha256,
        // Aes128Gcm); this is checked in `DaphneHpkeConfig::from`.
        let dap_hpke_receiver_config_list = serde_json::to_string(
            &task
                .hpke_keys
                .values()
                .map(|(hpke_config, private_key)| DaphneHpkeReceiverConfig {
                    config: DaphneHpkeConfig::from(hpke_config.clone()),
                    secret_key: hex::encode(private_key.as_ref()),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        // The DAP bucket key is an internal, private key used to map client reports to internal
        // storage buckets.
        let mut dap_bucket_key = [0; 16];
        thread_rng().fill(&mut dap_bucket_key);

        // The DAP collect ID key is an internal, private key used to map collect requests to a
        // collect job ID. (It's only used when Daphne is in the Leader role, but we populate it
        // either way.)
        let mut dap_collect_id_key = [0; 16];
        thread_rng().fill(&mut dap_collect_id_key);

        let dap_task_list = serde_json::to_string(&HashMap::from([(
            hex::encode(task.id.as_bytes()),
            DaphneDapTaskConfig {
                leader_url: task.aggregator_url(Role::Leader).unwrap().clone(),
                helper_url: task.aggregator_url(Role::Helper).unwrap().clone(),
                min_batch_duration: task.min_batch_duration.as_seconds(),
                min_batch_size: task.min_batch_size,
                vdaf: daphne_vdaf_config_from_janus_vdaf(&task.vdaf),
                vdaf_verify_key: hex::encode(task.vdaf_verify_keys.first().unwrap()),
                collector_hpke_config: DaphneHpkeConfig::from(task.collector_hpke_config.clone()),
            },
        )]))
        .unwrap();

        // Daphne currently only supports one auth token per task. Janus supports multiple tokens
        // per task to allow rotation; we supply Daphne with the "primary" token.
        let aggregator_bearer_token_list = json!({
            hex::encode(task.id.as_bytes()): String::from_utf8(task.primary_aggregator_auth_token().as_bytes().to_vec()).unwrap()
        }).to_string();
        let collector_bearer_token_list = if task.role == Role::Leader {
            json!({
                hex::encode(task.id.as_bytes()): String::from_utf8(task.primary_collector_auth_token().as_bytes().to_vec()).unwrap()
            }).to_string()
        } else {
            String::new()
        };

        // Get the test Daphne docker image hash; if necessary, do one-time setup to write the image
        // to Docker.
        let image_hash = {
            let mut image_hash = TEST_DAPHNE_IMAGE_HASH.lock().unwrap();
            if image_hash.is_none() {
                let mut docker_load_child = Command::new("docker")
                    .args(["load", "--quiet"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("Failed to execute `docker load` for test Daphne");
                let mut child_stdin = docker_load_child.stdin.take().unwrap();
                let writer_handle = thread::spawn(move || {
                    // We write in a separate thread as "writing more than a pipe buffer's
                    // worth of input to stdin without also reading stdout and stderr at the
                    // same time may cause a deadlock."
                    child_stdin.write_all(TEST_DAPHNE_IMAGE_BYTES)
                });
                let mut child_stdout = docker_load_child.stdout.take().unwrap();
                let mut stdout = String::new();
                child_stdout
                    .read_to_string(&mut stdout)
                    .expect("Couldn't read stdout from docker");
                let caps = DOCKER_HASH_RE
                    .captures(&stdout)
                    .expect("Couldn't find image ID from `docker load` output");
                let hash = caps.get(1).unwrap().as_str().to_string();
                // The first `expect` catches panics, the second `expect` catches write errors.
                writer_handle
                    .join()
                    .expect("Couldn't write test Daphne image to docker")
                    .expect("Couldn't write test Daphne image to docker");
                *image_hash = Some(hash);
            }
            image_hash.as_ref().unwrap().clone()
        };

        // Start the Daphne test container running.
        let port = pick_unused_port().expect("Couldn't pick unused port");
        let endpoint = task.aggregator_url(task.role).unwrap();

        let args = [
            (
                "DAP_AGGREGATOR_ROLE".to_string(),
                task.role.as_str().to_string(),
            ),
            (
                "DAP_HPKE_RECEIVER_CONFIG_LIST".to_string(),
                dap_hpke_receiver_config_list,
            ),
            ("DAP_BUCKET_KEY".to_string(), hex::encode(&dap_bucket_key)),
            ("DAP_BUCKET_COUNT".to_string(), "2".to_string()),
            (
                "DAP_COLLECT_ID_KEY".to_string(),
                hex::encode(&dap_collect_id_key),
            ),
            ("DAP_TASK_LIST".to_string(), dap_task_list),
            (
                "DAP_LEADER_BEARER_TOKEN_LIST".to_string(),
                aggregator_bearer_token_list,
            ),
            (
                "DAP_COLLECTOR_BEARER_TOKEN_LIST".to_string(),
                collector_bearer_token_list,
            ),
        ]
        .into_iter()
        .map(|(env_var, env_val)| format!("--binding={env_var}={env_val}"))
        .collect();
        let runnable_image = RunnableImage::from((GenericImage::new("sha256", &image_hash), args))
            .with_network(network)
            .with_container_name(endpoint.host_str().unwrap())
            .with_mapped_port(Port {
                local: port,
                internal: 8080,
            });
        let daphne_container = CONTAINER_CLIENT.run(runnable_image);

        // Wait for Daphne container to begin listening on the port.
        await_http_server(port).await;

        // Set up a task that occasionally hits the /internal/process endpoint, which is required
        // for Daphne to progress aggregations. (this is only required if Daphne is in the Leader
        // role, but for simplicity we hit the endpoint either way -- the resulting 404's do not
        // cause problems if Daphne is acting as the helper)
        let (start_shutdown_sender, mut start_shutdown_receiver) = oneshot::channel();
        let (shutdown_complete_sender, shutdown_complete_receiver) = mpsc::channel();
        task::spawn({
            let http_client = reqwest::Client::default();
            let mut request_url = task
                .aggregator_url(task.role)
                .unwrap()
                .join("/internal/process")
                .unwrap();
            request_url.set_host(Some("localhost")).unwrap();
            request_url.set_port(Some(port)).unwrap();

            let mut interval = interval(Duration::from_millis(250));
            async move {
                loop {
                    select! {
                        _ = interval.tick() => (),
                        _ = &mut start_shutdown_receiver => {
                            shutdown_complete_sender.send(()).unwrap();
                            return;
                        },
                    }

                    // The body is a JSON-encoding of Daphne's `InternalAggregateInfo`.
                    let _ = http_client
                        .post(request_url.clone())
                        .json(&json!({
                            "max_buckets": 1000,
                            "max_reports": 1000,
                        }))
                        .send()
                        .await;
                }
            }
        });

        Self {
            daphne_container,
            start_shutdown_sender: Some(start_shutdown_sender),
            shutdown_complete_receiver: Some(shutdown_complete_receiver),
        }
    }

    /// Returns the port of the aggregator on the host.
    pub fn port(&self) -> u16 {
        self.daphne_container.get_host_port_ipv4(8080)
    }
}

impl Drop for Daphne {
    fn drop(&mut self) {
        let start_shutdown_sender = self.start_shutdown_sender.take().unwrap();
        let shutdown_complete_receiver = self.shutdown_complete_receiver.take().unwrap();
        start_shutdown_sender.send(()).unwrap();
        shutdown_complete_receiver.recv().unwrap();
    }
}

fn daphne_vdaf_config_from_janus_vdaf(vdaf: &VdafInstance) -> daphne::VdafConfig {
    match vdaf {
        VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
            daphne::VdafConfig::Prio3(daphne::Prio3Config::Count)
        }

        VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram { buckets }) => {
            daphne::VdafConfig::Prio3(daphne::Prio3Config::Histogram {
                buckets: buckets.clone(),
            })
        }

        VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { bits }) => {
            daphne::VdafConfig::Prio3(daphne::Prio3Config::Sum { bits: *bits })
        }

        _ => panic!("Unsupported VdafInstance: {:?}", vdaf),
    }
}

// Corresponds to Daphne's `HpkeReceiverConfig`. We can't use that type directly as some of the
// fields we need to populate (e.g. `secret_key`) are not public.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DaphneHpkeReceiverConfig {
    config: DaphneHpkeConfig,
    secret_key: String,
}

// Corresponds to Daphne's `HpkeConfig`. We can't use that type directly as some of the fields we
// need to populate (e.g. `public_key`) are not public.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DaphneHpkeConfig {
    id: u8,
    kem_id: HpkeKemId,
    kdf_id: HpkeKdfId,
    aead_id: HpkeAeadId,
    public_key: String,
}

impl From<HpkeConfig> for DaphneHpkeConfig {
    fn from(hpke_config: HpkeConfig) -> Self {
        // Daphne currently only supports this specific HPKE configuration, so make sure that we
        // are converting something Daphne can use.
        assert_eq!(hpke_config.kem_id(), HpkeKemId::X25519HkdfSha256);
        assert_eq!(hpke_config.kdf_id(), HpkeKdfId::HkdfSha256);
        assert_eq!(hpke_config.aead_id(), HpkeAeadId::Aes128Gcm);

        DaphneHpkeConfig {
            id: u8::from(hpke_config.id()),
            kem_id: hpke_config.kem_id(),
            kdf_id: hpke_config.kdf_id(),
            aead_id: hpke_config.aead_id(),
            public_key: hex::encode(hpke_config.public_key().as_bytes()),
        }
    }
}

// Corresponds to Daphne's `DapTaskConfig`. We can't use that type directly as some of the fields we
// need to populate (e.g. `vdaf_verify_key`) are not public.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DaphneDapTaskConfig {
    pub leader_url: Url,
    pub helper_url: Url,
    pub min_batch_duration: u64,
    pub min_batch_size: u64,
    pub vdaf: daphne::VdafConfig,
    pub vdaf_verify_key: String,
    pub collector_hpke_config: DaphneHpkeConfig,
}
