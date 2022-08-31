use base64::URL_SAFE_NO_PAD;
use janus_core::{
    hpke::{generate_hpke_config_and_private_key, HpkePrivateKey},
    message::{HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, Role},
};
use janus_server::task::{Task, VdafInstance};
use prio::codec::Encode;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};
use url::Url;

#[cfg(feature = "testcontainer")]
pub mod testcontainer;

pub mod status {
    pub static SUCCESS: &str = "success";
    pub static ERROR: &str = "error";
    pub static COMPLETE: &str = "complete";
    pub static IN_PROGRESS: &str = "in progress";
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VdafObject {
    Prio3Aes128Count,
    Prio3Aes128Sum { bits: u32 },
    Prio3Aes128Histogram { buckets: Vec<u64> },
}

impl From<VdafInstance> for VdafObject {
    fn from(vdaf: VdafInstance) -> Self {
        match vdaf {
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
                VdafObject::Prio3Aes128Count
            }
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { bits }) => {
                VdafObject::Prio3Aes128Sum { bits }
            }
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram {
                buckets,
            }) => VdafObject::Prio3Aes128Histogram { buckets },
            _ => panic!("Unsupported VDAF: {:?}", vdaf),
        }
    }
}

impl From<VdafObject> for VdafInstance {
    fn from(vdaf: VdafObject) -> Self {
        match vdaf {
            VdafObject::Prio3Aes128Count => {
                VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count)
            }
            VdafObject::Prio3Aes128Sum { bits } => {
                VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { bits })
            }
            VdafObject::Prio3Aes128Histogram { buckets } => {
                VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram { buckets })
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddTaskRequest {
    pub task_id: String, // in unpadded base64url
    pub leader: Url,
    pub helper: Url,
    pub vdaf: VdafObject,
    pub leader_authentication_token: String,
    #[serde(default)]
    pub collector_authentication_token: Option<String>,
    pub aggregator_id: u8,
    pub verify_key: String, // in unpadded base64url
    pub max_batch_lifetime: u64,
    pub min_batch_size: u64,
    pub min_batch_duration: u64,       // in seconds
    pub collector_hpke_config: String, // in unpadded base64url
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTaskResponse {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

impl From<Task> for AddTaskRequest {
    fn from(task: Task) -> Self {
        Self {
            task_id: base64::encode_config(task.id.as_bytes(), URL_SAFE_NO_PAD),
            leader: task.aggregator_url(Role::Leader).unwrap().clone(),
            helper: task.aggregator_url(Role::Helper).unwrap().clone(),
            vdaf: task.vdaf.clone().into(),
            leader_authentication_token: String::from_utf8(
                task.aggregator_auth_tokens
                    .first()
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap(),
            collector_authentication_token: task
                .collector_auth_tokens
                .first()
                .map(|t| String::from_utf8(t.as_bytes().to_vec()).unwrap()),
            aggregator_id: task.role.index().unwrap().try_into().unwrap(),
            verify_key: base64::encode_config(
                task.vdaf_verify_keys().first().unwrap().as_bytes(),
                URL_SAFE_NO_PAD,
            ),
            max_batch_lifetime: task.max_batch_lifetime,
            min_batch_size: task.min_batch_size,
            min_batch_duration: task.min_batch_duration.as_seconds(),
            collector_hpke_config: base64::encode_config(
                &task.collector_hpke_config.get_encoded(),
                URL_SAFE_NO_PAD,
            ),
        }
    }
}

pub fn install_tracing_subscriber() -> anyhow::Result<()> {
    let stdout_filter = EnvFilter::from_default_env();
    let layer = tracing_subscriber::fmt::layer()
        .with_thread_ids(true)
        .with_level(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .pretty();
    let subscriber = Registry::default().with(stdout_filter.and_then(layer));
    tracing::subscriber::set_global_default(subscriber)?;

    LogTracer::init()?;

    Ok(())
}

/// This registry lazily generates up to 256 HPKE key pairs, one with each possible
/// [`HpkeConfigId`].
#[derive(Default)]
pub struct HpkeConfigRegistry {
    keypairs: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
}

impl HpkeConfigRegistry {
    pub fn new() -> HpkeConfigRegistry {
        Default::default()
    }

    /// Get the keypair associated with a given ID.
    pub fn fetch_keypair(&mut self, id: HpkeConfigId) -> (HpkeConfig, HpkePrivateKey) {
        self.keypairs
            .entry(id)
            .or_insert_with(|| {
                generate_hpke_config_and_private_key(
                    id,
                    // These algorithms should be broadly compatible with other DAP implementations, since they
                    // are required by section 6 of draft-ietf-ppm-dap-01.
                    HpkeKemId::X25519HkdfSha256,
                    HpkeKdfId::HkdfSha256,
                    HpkeAeadId::Aes128Gcm,
                )
            })
            .clone()
    }

    /// Choose a random [`HpkeConfigId`], and then get the keypair associated with that ID.
    pub fn get_random_keypair(&mut self) -> (HpkeConfig, HpkePrivateKey) {
        let id = HpkeConfigId::from(thread_rng().gen::<u8>());
        self.fetch_keypair(id)
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use backoff::{future::retry, ExponentialBackoff};
    use futures::TryFutureExt;
    use rand::{thread_rng, Rng};
    use std::time::Duration;
    use url::Url;

    lazy_static::lazy_static! {
        static ref DOCKER_HASH_RE: regex::Regex = regex::Regex::new(r"sha256:([0-9a-f]{64})").unwrap();
    }

    /// Waits a while for the given IPv4 port to start responding to HTTP requests, panicking if
    /// this doesn't happen soon enough.
    pub async fn await_http_server(port: u16) {
        let http_client = reqwest::Client::default();
        // Explicitly connect to IPv4 localhost so that we don't accidentally try to talk to a
        // different container's IPv6 port.
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        retry(
            // (We use ExponentialBackoff as a constant-time backoff as the built-in Constant
            // backoff will never time out.)
            ExponentialBackoff {
                initial_interval: Duration::from_millis(250),
                max_interval: Duration::from_millis(250),
                multiplier: 1.0,
                max_elapsed_time: Some(Duration::from_secs(10)),
                ..Default::default()
            },
            || {
                http_client
                    .get(url.clone())
                    .send()
                    .map_err(backoff::Error::transient)
            },
        )
        .await
        .unwrap();
    }

    /// Loads a given zstd-compressed docker image into Docker. Returns the hash of the loaded
    /// image, e.g. as referenced by `sha256:$HASH`. Panics on failure.
    pub fn load_zstd_compressed_docker_image(compressed_image: &[u8]) -> String {
        use std::{
            io::{Cursor, Read},
            process::{Command, Stdio},
            thread,
        };

        let mut docker_load_child = Command::new("docker")
            .args(["load", "--quiet"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to execute `docker load`");
        let child_stdin = docker_load_child.stdin.take().unwrap();
        thread::scope(|s| {
            let writer_handle = s.spawn(|| {
                // We write in a separate thread as "writing more than a pipe buffer's
                // worth of input to stdin without also reading stdout and stderr at the
                // same time may cause a deadlock."
                zstd::stream::copy_decode(Cursor::new(compressed_image), child_stdin)
            });
            let reader_handle = s.spawn(|| {
                let mut child_stdout = docker_load_child.stdout.take().unwrap();
                let mut stdout = String::new();
                child_stdout
                    .read_to_string(&mut stdout)
                    .expect("Couldn't read image ID from docker");
                let caps = DOCKER_HASH_RE
                    .captures(&stdout)
                    .expect("Couldn't find image ID from `docker load` output");
                caps.get(1).unwrap().as_str().to_string()
            });

            // The first `expect` catches panics, the second `expect` catches write errors.
            writer_handle
                .join()
                .expect("Couldn't write image to docker")
                .expect("Couldn't write image to docker");
            reader_handle.join().unwrap()
        })
    }

    pub fn generate_network_name() -> String {
        generate_unique_name("janus_ephemeral_network")
    }

    pub fn generate_unique_name(prefix: &str) -> String {
        let mut buf = [0; 4];
        thread_rng().fill(&mut buf);
        format!("{}_{}", prefix, hex::encode(buf))
    }
}
