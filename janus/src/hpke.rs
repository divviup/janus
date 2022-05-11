use crate::message::{Extension, HpkeConfig, Nonce};
use prio::codec::{encode_u16_items, Encode};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid HPKE configuration: {0}")]
    InvalidConfiguration(&'static str),
}

impl TryFrom<&HpkeConfig> for hpke_dispatch::Config {
    type Error = Error;

    fn try_from(config: &HpkeConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            aead: (config.aead_id() as u16)
                .try_into()
                .map_err(|_| Self::Error::InvalidConfiguration("did not recognize aead"))?,
            kdf: (config.kdf_id() as u16)
                .try_into()
                .map_err(|_| Self::Error::InvalidConfiguration("did not recognize kdf"))?,
            kem: (config.kem_id() as u16)
                .try_into()
                .map_err(|_| Self::Error::InvalidConfiguration("did not recognize kem"))?,
        })
    }
}

/// Construct the HPKE associated data for sealing or opening data enciphered for a report or report
/// share, per §4.3.2 and 4.4.2.2 of draft-gpew-priv-ppm
pub fn associated_data_for_report_share(nonce: Nonce, extensions: &[Extension]) -> Vec<u8> {
    let mut associated_data = vec![];
    nonce.encode(&mut associated_data);
    encode_u16_items(&mut associated_data, &(), extensions);
    associated_data
}
