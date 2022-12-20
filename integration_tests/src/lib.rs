//! This crate contains functionality useful for Janus integration tests.

use base64::{
    alphabet::URL_SAFE,
    engine::fast_portable::{FastPortable, NO_PAD},
};

pub mod client;
#[cfg(feature = "daphne")]
pub mod daphne;
pub mod janus;

const URL_SAFE_NO_PAD: FastPortable = FastPortable::from(&URL_SAFE, NO_PAD);
