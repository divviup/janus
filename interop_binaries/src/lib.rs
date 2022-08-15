use janus_core::{
    hpke::{generate_hpke_config_and_private_key, HpkePrivateKey},
    message::{HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId},
    task::VdafInstance,
};
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::collections::HashMap;
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

pub mod status {
    pub static SUCCESS: &str = "success";
    pub static ERROR: &str = "error";
    pub static COMPLETE: &str = "complete";
    pub static IN_PROGRESS: &str = "in progress";
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum VdafObject {
    Prio3Aes128Count {},
    Prio3Aes128Sum { bits: u32 },
    Prio3Aes128Histogram { buckets: Vec<u64> },
}

impl From<VdafObject> for VdafInstance {
    fn from(object: VdafObject) -> VdafInstance {
        match object {
            VdafObject::Prio3Aes128Count {} => VdafInstance::Prio3Aes128Count,
            VdafObject::Prio3Aes128Sum { bits } => VdafInstance::Prio3Aes128Sum { bits },
            VdafObject::Prio3Aes128Histogram { buckets } => {
                VdafInstance::Prio3Aes128Histogram { buckets }
            }
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
