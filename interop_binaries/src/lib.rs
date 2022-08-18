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
            vdaf: task.vdaf.into(),
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
                task.vdaf_verify_keys.first().unwrap(),
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
