//! Extensions on nonce representations from `janus_messages`.

use crate::time::{Clock, TimeExt};
use janus_messages::{Duration, Error, Nonce, NonceChecksum};
use prio::codec::Encode;
use rand::random;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};

/// Additional methods for working with a [`NonceChecksum`].
pub trait NonceChecksumExt {
    /// Initialize a checksum from a single nonce.
    fn from_nonce(nonce: Nonce) -> Self;

    /// Compute SHA256 over a nonce.
    fn nonce_digest(nonce: Nonce) -> [u8; SHA256_OUTPUT_LEN];

    /// Incorporate the provided nonce into this checksum.
    fn update(&mut self, nonce: Nonce);

    /// Combine another checksum with this one.
    fn combine(&mut self, other: NonceChecksum);
}

impl NonceChecksumExt for NonceChecksum {
    fn from_nonce(nonce: Nonce) -> Self {
        Self::from(Self::nonce_digest(nonce))
    }

    fn nonce_digest(nonce: Nonce) -> [u8; SHA256_OUTPUT_LEN] {
        digest(&SHA256, &nonce.get_encoded())
            .as_ref()
            .try_into()
            // panic if somehow the digest ring computes isn't 32 bytes long.
            .unwrap()
    }

    /// Incorporate the provided nonce into this checksum.
    fn update(&mut self, nonce: Nonce) {
        self.combine(Self::from_nonce(nonce))
    }

    /// Combine another checksum with this one.
    fn combine(&mut self, other: NonceChecksum) {
        self.as_mut()
            .iter_mut()
            .zip(other.as_ref())
            .for_each(|(x, y)| *x ^= y)
    }
}

/// Additional methods for working with a [`Nonce`].
pub trait NonceExt {
    /// Generate a fresh nonce based on the current time.
    fn generate<C: Clock>(clock: &C, min_batch_duration: Duration) -> Result<Nonce, Error>;
}

impl NonceExt for Nonce {
    fn generate<C: Clock>(clock: &C, min_batch_duration: Duration) -> Result<Nonce, Error> {
        Ok(Nonce::new(
            clock
                .now()
                .to_batch_unit_interval_start(min_batch_duration)?,
            random(),
        ))
    }
}
