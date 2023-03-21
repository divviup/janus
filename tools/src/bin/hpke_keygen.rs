use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, ValueEnum};
use janus_core::hpke::generate_hpke_config_and_private_key;
use janus_messages::{HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId};
use prio::codec::Encode;
use serde_yaml::to_writer;
use std::{
    fmt::Display,
    io::{stdout, Write},
};

fn main() -> Result<()> {
    let options = Options::parse();

    let id = HpkeConfigId::from(options.id);
    let keypair = generate_hpke_config_and_private_key(
        id,
        options.kem.into(),
        options.kdf.into(),
        options.aead.into(),
    );

    let mut writer = stdout().lock();

    writeln!(writer, "# HPKE configuration, Janus format")?;
    to_writer(&mut writer, keypair.config())?;

    writeln!(writer, "---")?;

    writeln!(writer, "# HPKE private key, in base64url")?;
    writeln!(
        writer,
        "{}",
        URL_SAFE_NO_PAD.encode(keypair.private_key().as_ref())
    )?;

    writeln!(writer, "---")?;

    writeln!(writer, "# HPKE keypair, Janus format")?;
    to_writer(&mut writer, &keypair)?;

    writeln!(writer, "---")?;

    writeln!(writer, "# HPKE configuration, DAP encoded, in base64url")?;
    writeln!(
        writer,
        "{}",
        URL_SAFE_NO_PAD.encode(keypair.config().get_encoded())
    )?;

    Ok(())
}

#[derive(Debug, Clone, ValueEnum)]
#[value()]
enum KemAlgorithm {
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

#[derive(Debug, Clone, ValueEnum)]
#[value()]
enum KdfAlgorithm {
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

#[derive(Debug, Clone, ValueEnum)]
#[value()]
enum AeadAlgorithm {
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

#[derive(Debug, Parser)]
#[command(name = "hpke_keygen", about = "DAP-compatible HPKE keypair generator")]
struct Options {
    /// Numeric identifier of the HPKE configuration.
    id: u8,

    /// HPKE Key Encapsulation Mechanism algorithm.
    #[arg(long, default_value_t = KemAlgorithm::X25519HkdfSha256)]
    kem: KemAlgorithm,

    /// HPKE Key Derivation Function algorithm.
    #[arg(long, default_value_t = KdfAlgorithm::HkdfSha256)]
    kdf: KdfAlgorithm,

    /// HPKE Authenticated Encryption with Associated Data algorithm.
    #[arg(long, default_value_t = AeadAlgorithm::Aes128Gcm)]
    aead: AeadAlgorithm,
}

#[cfg(test)]
mod tests {
    use crate::Options;
    use clap::CommandFactory;

    #[test]
    fn verify_clap_app() {
        Options::command().debug_assert();
    }
}
