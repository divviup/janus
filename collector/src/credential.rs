use hpke_dispatch::{Aead, Kdf, Kem};
use janus_core::{
    auth_tokens::{AuthenticationToken, BearerToken},
    hpke::{HpkeKeypair, HpkePrivateKey},
};
use janus_messages::{HpkeConfig, HpkeConfigId, HpkePublicKey};
use serde::{Deserialize, Serialize};

/// Serializable representation of a private collector credential, which contains all secrets a
/// collector uses to interact with an aggregator.
///
/// It contains the [`BearerToken`] for authorization to an aggregator, and the private HPKE
/// configuration for decrypting aggregate shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCollectorCredential {
    id: HpkeConfigId,
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
    public_key: HpkePublicKey,
    private_key: HpkePrivateKey,
    token: BearerToken,
}

impl PrivateCollectorCredential {
    /// Returns the [`AuthenticationToken`] necessary for connecting to an aggregator for collection.
    pub fn authentication_token(&self) -> AuthenticationToken {
        AuthenticationToken::Bearer(self.token.clone())
    }

    /// Returns the [`HpkeKeypair`] necessary for decrypting aggregate shares.
    pub fn hpke_keypair(&self) -> HpkeKeypair {
        HpkeKeypair::new(
            HpkeConfig::new(
                self.id,
                (self.kem as u16).into(),
                (self.kdf as u16).into(),
                (self.aead as u16).into(),
                self.public_key.clone(),
            ),
            self.private_key.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::PrivateCollectorCredential;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use janus_core::{
        auth_tokens::AuthenticationToken,
        hpke::{HpkeKeypair, HpkePrivateKey},
    };
    use janus_messages::{
        HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey,
    };

    const SAMPLE_COLLECTOR_CREDENTIAL: &str = r#"{
  "aead": "AesGcm128",
  "id": 66,
  "kdf": "Sha256",
  "kem": "X25519HkdfSha256",
  "private_key": "uKkTvzKLfYNUPZcoKI7hV64zS06OWgBkbivBL4Sw4mo",
  "public_key": "CcDghts2boltt9GQtBUxdUsVR83SCVYHikcGh33aVlU",
  "token": "Krx-CLfdWo1ULAfsxhr0rA"
}
"#;

    #[test]
    fn serde_collector_credential() {
        let credential: PrivateCollectorCredential =
            serde_json::from_str(SAMPLE_COLLECTOR_CREDENTIAL).unwrap();

        let expected_keypair = HpkeKeypair::new(
            HpkeConfig::new(
                HpkeConfigId::from(66),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
                HpkePublicKey::from(
                    URL_SAFE_NO_PAD
                        .decode("CcDghts2boltt9GQtBUxdUsVR83SCVYHikcGh33aVlU")
                        .unwrap(),
                ),
            ),
            HpkePrivateKey::from(
                URL_SAFE_NO_PAD
                    .decode("uKkTvzKLfYNUPZcoKI7hV64zS06OWgBkbivBL4Sw4mo")
                    .unwrap(),
            ),
        );
        let expected_token = AuthenticationToken::Bearer("Krx-CLfdWo1ULAfsxhr0rA".parse().unwrap());

        assert_eq!(credential.hpke_keypair(), expected_keypair);
        assert_eq!(credential.authentication_token(), expected_token);
    }
}
