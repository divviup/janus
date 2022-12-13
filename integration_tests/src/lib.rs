//! This crate contains functionality useful for Janus integration tests.

use base64::{
    alphabet::URL_SAFE,
    engine::fast_portable::{FastPortable, NO_PAD},
};
use janus_messages::{BatchId, TaskId};

pub mod client;
#[cfg(feature = "daphne")]
pub mod daphne;
pub mod janus;

/// Provides access to find which batch identifiers have been assigned in a fixed-size task.
///
/// Note that this will be made obsolete by "current_batch" requests in DAP-03.
#[async_trait::async_trait]
pub trait BatchDiscovery {
    async fn get_batch_ids(&self, task_id: &TaskId) -> anyhow::Result<Vec<BatchId>>;
}

const URL_SAFE_NO_PAD: FastPortable = FastPortable::from(&URL_SAFE, NO_PAD);
