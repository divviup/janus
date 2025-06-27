use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use janus_core::{
    cli::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    hpke::HpkeKeypair,
};
use janus_messages::HpkeConfigId;
use prio::codec::Encode;
use serde_yaml::to_writer;
use std::io::{Write, stdout};

fn main() -> Result<()> {
    let options = Options::parse();

    let id = HpkeConfigId::from(options.id);
    let keypair = HpkeKeypair::generate(
        id,
        options.kem.into(),
        options.kdf.into(),
        options.aead.into(),
    )?;

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
        URL_SAFE_NO_PAD.encode(keypair.config().get_encoded()?)
    )?;

    Ok(())
}

#[derive(Debug, Parser)]
#[command(name = "hpke_keygen", about = "DAP-compatible HPKE keypair generator")]
struct Options {
    /// Numeric identifier of the HPKE configuration
    id: u8,

    /// HPKE Key Encapsulation Mechanism algorithm
    #[arg(long, default_value_t = KemAlgorithm::X25519HkdfSha256)]
    kem: KemAlgorithm,

    /// HPKE Key Derivation Function algorithm
    #[arg(long, default_value_t = KdfAlgorithm::HkdfSha256)]
    kdf: KdfAlgorithm,

    /// HPKE Authenticated Encryption with Associated Data algorithm
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
