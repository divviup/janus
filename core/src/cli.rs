//! Types useful for creating CLI tools.
use std::fmt::Display;

use clap::ValueEnum;
use janus_messages::{HpkeAeadId, HpkeKdfId, HpkeKemId};

#[derive(Debug, Copy, Clone, ValueEnum)]
#[value()]
pub enum KemAlgorithm {
    /// DHKEM(P-256, HKDF-SHA256)
    #[value(name = "p-256")]
    P256HkdfSha256,

    /// DHKEM(X25519, HKDF-SHA256)
    #[value(name = "x25519")]
    X25519HkdfSha256,
}

impl From<KemAlgorithm> for HpkeKemId {
    fn from(value: KemAlgorithm) -> Self {
        match value {
            KemAlgorithm::P256HkdfSha256 => HpkeKemId::P256HkdfSha256,
            KemAlgorithm::X25519HkdfSha256 => HpkeKemId::X25519HkdfSha256,
        }
    }
}

impl Display for KemAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This is safe to unwrap because we don't skip any enum variants.
        let possible_value = self.to_possible_value().unwrap();
        f.write_str(possible_value.get_name())
    }
}

#[derive(Debug, Copy, Clone, ValueEnum)]
#[value()]
pub enum KdfAlgorithm {
    /// HKDF-SHA256
    #[value(name = "hkdf-sha256")]
    HkdfSha256,

    /// HKDF-SHA384
    #[value(name = "hkdf-sha384")]
    HkdfSha384,

    /// HKDF-SHA512
    #[value(name = "hkdf-sha512")]
    HkdfSha512,
}

impl From<KdfAlgorithm> for HpkeKdfId {
    fn from(value: KdfAlgorithm) -> Self {
        match value {
            KdfAlgorithm::HkdfSha256 => HpkeKdfId::HkdfSha256,
            KdfAlgorithm::HkdfSha384 => HpkeKdfId::HkdfSha384,
            KdfAlgorithm::HkdfSha512 => HpkeKdfId::HkdfSha512,
        }
    }
}

impl Display for KdfAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This is safe to unwrap because we don't skip any enum variants.
        let possible_value = self.to_possible_value().unwrap();
        f.write_str(possible_value.get_name())
    }
}

#[derive(Debug, Copy, Clone, ValueEnum)]
#[value()]
pub enum AeadAlgorithm {
    /// AES-128-GCM
    #[value(name = "aes-128-gcm")]
    Aes128Gcm,

    /// AES-256-GCM
    #[value(name = "aes-256-gcm")]
    Aes256Gcm,

    /// ChaCha20Poly1305
    #[value(name = "chacha20poly1305")]
    ChaCha20Poly1305,
}

impl From<AeadAlgorithm> for HpkeAeadId {
    fn from(value: AeadAlgorithm) -> Self {
        match value {
            AeadAlgorithm::Aes128Gcm => HpkeAeadId::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm => HpkeAeadId::Aes256Gcm,
            AeadAlgorithm::ChaCha20Poly1305 => HpkeAeadId::ChaCha20Poly1305,
        }
    }
}

impl Display for AeadAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This is safe to unwrap because we don't skip any enum variants.
        let possible_value = self.to_possible_value().unwrap();
        f.write_str(possible_value.get_name())
    }
}
