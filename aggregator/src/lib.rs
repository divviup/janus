#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::too_many_arguments)]

use base64::{
    alphabet::{STANDARD, URL_SAFE},
    engine::fast_portable::{FastPortable, NO_PAD},
};

pub mod aggregator;
pub mod binary_utils;
pub mod config;
#[macro_use]
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

const STANDARD_NO_PAD: FastPortable = FastPortable::from(&STANDARD, NO_PAD);
const URL_SAFE_NO_PAD: FastPortable = FastPortable::from(&URL_SAFE, NO_PAD);
