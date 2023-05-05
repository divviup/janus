//! This crate contains functionality useful for Janus integration tests.

use janus_messages::{BatchId, TaskId};

pub mod client;
pub mod janus;

/// Provides access to find which batch identifiers have been assigned in a fixed-size task.
///
/// Note that this will be made obsolete by "current_batch" requests in DAP-03.
#[async_trait::async_trait]
pub trait BatchDiscovery {
    async fn get_batch_ids(&self, task_id: &TaskId) -> anyhow::Result<Vec<BatchId>>;
}
