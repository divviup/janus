use janus_core::task::VdafInstance;
use serde::Deserialize;
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
