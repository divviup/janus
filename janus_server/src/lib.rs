#![allow(clippy::too_many_arguments)]

pub mod aggregator;
pub mod binary_utils;
pub mod config;
pub mod datastore;
pub mod messages;
pub mod metrics;
pub mod task;
pub mod trace;

/// A secret byte array. This does not implement `Debug` or `Display`, to avoid accidental
/// inclusion in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(buf: Vec<u8>) -> Self {
        Self(buf)
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
