use crate::message::HpkeConfig;

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
