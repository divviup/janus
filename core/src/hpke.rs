//! Encryption and decryption of messages using HPKE (RFC 9180).
use crate::DAP_VERSION_IDENTIFIER;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use constcat::concat;
use educe::Educe;
use hpke_dispatch::{HpkeError, Kem, Keypair};
use janus_messages::{
    HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, Role,
};
use serde::{
    Deserialize, Serialize, Serializer,
    de::{self, Visitor},
};
use std::{
    fmt::{self, Debug},
    str::FromStr,
};

#[cfg(feature = "test-util")]
use {quickcheck::Arbitrary, rand::random};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error occurred in the underlying HPKE library.
    #[error("HPKE error: {0}")]
    Hpke(#[from] HpkeError),
    #[error("invalid HPKE configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("unsupported KEM")]
    UnsupportedKem,
    #[error("base64 decode failure: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

/// Checks whether the algorithms used by the provided [`HpkeConfig`] are supported.
pub fn is_hpke_config_supported(config: &HpkeConfig) -> Result<(), Error> {
    hpke_dispatch_config_from_hpke_config(config)?;
    Ok(())
}

fn hpke_dispatch_config_from_hpke_config(
    config: &HpkeConfig,
) -> Result<hpke_dispatch::Config, Error> {
    Ok(hpke_dispatch::Config {
        aead: u16::from(*config.aead_id())
            .try_into()
            .map_err(|_| Error::InvalidConfiguration("did not recognize aead"))?,
        kdf: u16::from(*config.kdf_id())
            .try_into()
            .map_err(|_| Error::InvalidConfiguration("did not recognize kdf"))?,
        kem: u16::from(*config.kem_id())
            .try_into()
            .map_err(|_| Error::InvalidConfiguration("did not recognize kem"))?,
    })
}

/// Labels incorporated into HPKE application info string
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Label {
    InputShare,
    AggregateShare,
}

impl Label {
    /// Get the message-specific portion of the application info string for this label.
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::InputShare => concat!(DAP_VERSION_IDENTIFIER, " input share").as_bytes(),
            Self::AggregateShare => concat!(DAP_VERSION_IDENTIFIER, " aggregate share").as_bytes(),
        }
    }
}

/// Application info used in HPKE context construction
#[derive(Clone, Debug)]
pub struct HpkeApplicationInfo(Vec<u8>);

impl HpkeApplicationInfo {
    /// Construct HPKE application info from the provided label and participant roles.
    pub fn new(label: &Label, sender_role: &Role, recipient_role: &Role) -> Self {
        Self(
            [
                label.as_bytes(),
                &[*sender_role as u8],
                &[*recipient_role as u8],
            ]
            .concat(),
        )
    }
}

/// An HPKE private key, serialized using the `SerializePrivateKey` function as
/// described in RFC 9180, §4 and §7.1.2.
// TODO(#230): refactor HpkePrivateKey to simplify usage
#[derive(Clone, Educe, PartialEq, Eq)]
#[educe(Debug)]
pub struct HpkePrivateKey(#[educe(Debug(ignore))] Vec<u8>);

impl HpkePrivateKey {
    /// Construct a private key from its serialized form.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HpkePrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl FromStr for HpkePrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(URL_SAFE_NO_PAD.decode(s)?))
    }
}

/// This customized implementation serializes a [`HpkePrivateKey`] as a base64url-encoded string,
/// instead of as a byte array. This is more compact and ergonomic when serialized to YAML.
impl Serialize for HpkePrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(self.as_ref());
        serializer.serialize_str(&encoded)
    }
}

struct HpkePrivateKeyVisitor;

impl Visitor<'_> for HpkePrivateKeyVisitor {
    type Value = HpkePrivateKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a base64url-encoded string")
    }

    fn visit_str<E>(self, value: &str) -> Result<HpkePrivateKey, E>
    where
        E: de::Error,
    {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| E::custom("invalid base64url value"))?;
        Ok(HpkePrivateKey::new(decoded))
    }
}

/// This customized implementation deserializes a [`HpkePrivateKey`] as a base64url-encoded string,
/// instead of as a byte array. This is more compact and ergonomic when serialized to YAML.
impl<'de> Deserialize<'de> for HpkePrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(HpkePrivateKeyVisitor)
    }
}

/// Encrypt `plaintext` using the provided `recipient_config` and return the HPKE ciphertext.
///
/// The provided `application_info` and `associated_data` are cryptographically bound to the
/// ciphertext and are required to successfully decrypt it.
pub fn seal(
    recipient_config: &HpkeConfig,
    application_info: &HpkeApplicationInfo,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<HpkeCiphertext, Error> {
    // In DAP, an HPKE context can only be used once (we have no means of ensuring that sender and
    // recipient "increment" nonces in lockstep), so this method creates a new HPKE context on each
    // call.
    let output = hpke_dispatch_config_from_hpke_config(recipient_config)?.base_mode_seal(
        recipient_config.public_key().as_ref(),
        &application_info.0,
        plaintext,
        associated_data,
    )?;

    Ok(HpkeCiphertext::new(
        *recipient_config.id(),
        output.encapped_key,
        output.ciphertext,
    ))
}

/// Decrypt `ciphertext` using the provided `recipient_keypair`, and return the plaintext. The
/// `application_info` and `associated_data` must match what was provided to [`seal()`] exactly.
pub fn open(
    recipient_keypair: &HpkeKeypair,
    application_info: &HpkeApplicationInfo,
    ciphertext: &HpkeCiphertext,
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    hpke_dispatch_config_from_hpke_config(recipient_keypair.config())?
        .base_mode_open(
            &recipient_keypair.private_key().0,
            ciphertext.encapsulated_key(),
            &application_info.0,
            ciphertext.payload(),
            associated_data,
        )
        .map_err(Into::into)
}

/// An HPKE configuration and its corresponding private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeKeypair {
    config: HpkeConfig,
    private_key: HpkePrivateKey, // uses unpadded base64url
}

impl HpkeKeypair {
    /// Construct a keypair from its two halves.
    pub fn new(config: HpkeConfig, private_key: HpkePrivateKey) -> HpkeKeypair {
        HpkeKeypair {
            config,
            private_key,
        }
    }

    /// Generate a new HPKE keypair. This function errors if the supplied key encapsulation
    /// mechanism is not supported by the underlying HPKE library.
    pub fn generate(
        hpke_config_id: HpkeConfigId,
        kem_id: HpkeKemId,
        kdf_id: HpkeKdfId,
        aead_id: HpkeAeadId,
    ) -> Result<Self, Error> {
        let Keypair {
            private_key,
            public_key,
        } = match kem_id {
            HpkeKemId::X25519HkdfSha256 => Kem::X25519HkdfSha256.gen_keypair(),
            HpkeKemId::P256HkdfSha256 => Kem::DhP256HkdfSha256.gen_keypair(),
            _ => return Err(Error::UnsupportedKem),
        };
        Ok(Self::new(
            HpkeConfig::new(
                hpke_config_id,
                kem_id,
                kdf_id,
                aead_id,
                HpkePublicKey::from(public_key),
            ),
            HpkePrivateKey::new(private_key),
        ))
    }

    /// Retrieve the HPKE configuration from this keypair.
    pub fn config(&self) -> &HpkeConfig {
        &self.config
    }

    /// Retrieve the HPKE private key from this keypair.
    pub fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }
}

/// The algorithms used for each HPKE primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(deny_unknown_fields)]
pub struct HpkeCiphersuite {
    kem_id: HpkeKemId,
    kdf_id: HpkeKdfId,
    aead_id: HpkeAeadId,
}

impl HpkeCiphersuite {
    pub fn new(kem_id: HpkeKemId, kdf_id: HpkeKdfId, aead_id: HpkeAeadId) -> Self {
        Self {
            kem_id,
            kdf_id,
            aead_id,
        }
    }

    pub fn kem_id(&self) -> HpkeKemId {
        self.kem_id
    }

    pub fn kdf_id(&self) -> HpkeKdfId {
        self.kdf_id
    }

    pub fn aead_id(&self) -> HpkeAeadId {
        self.aead_id
    }
}

impl From<&HpkeConfig> for HpkeCiphersuite {
    fn from(value: &HpkeConfig) -> Self {
        Self {
            kem_id: *value.kem_id(),
            kdf_id: *value.kdf_id(),
            aead_id: *value.aead_id(),
        }
    }
}

#[cfg(feature = "test-util")]
impl Arbitrary for HpkeCiphersuite {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        // Note that this does not span all possible combinations of algorithms. This is done to
        // keep the cardinality low, and since Janus doesn't support all KEMs.
        Self {
            kem_id: *g
                .choose(&[HpkeKemId::P256HkdfSha256, HpkeKemId::X25519HkdfSha256])
                .unwrap(),
            kdf_id: *g
                .choose(&[HpkeKdfId::HkdfSha256, HpkeKdfId::HkdfSha512])
                .unwrap(),
            aead_id: *g
                .choose(&[HpkeAeadId::Aes128Gcm, HpkeAeadId::ChaCha20Poly1305])
                .unwrap(),
        }
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
impl HpkeKeypair {
    pub fn test() -> Self {
        Self::test_with_id(random())
    }

    pub fn test_with_id(id: HpkeConfigId) -> Self {
        Self::test_with_ciphersuite(
            id,
            HpkeCiphersuite::new(
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
            ),
        )
    }

    pub fn test_with_ciphersuite(id: HpkeConfigId, ciphersuite: HpkeCiphersuite) -> Self {
        Self::generate(
            id,
            ciphersuite.kem_id(),
            ciphersuite.kdf_id(),
            ciphersuite.aead_id(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{HpkeApplicationInfo, Label};
    #[allow(deprecated)]
    use crate::hpke::{HpkeKeypair, HpkePrivateKey, open, seal};
    use hpke_dispatch::{Kem, Keypair};
    use janus_messages::{
        HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey,
        Role,
    };
    use serde::Deserialize;
    use std::collections::HashSet;

    #[test]
    fn exchange_message() {
        let hpke_keypair = HpkeKeypair::test();
        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(
            hpke_keypair.config(),
            &application_info,
            message,
            associated_data,
        )
        .unwrap();

        let plaintext = open(
            &hpke_keypair,
            &application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn wrong_private_key() {
        let hpke_keypair = HpkeKeypair::test();
        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(
            hpke_keypair.config(),
            &application_info,
            message,
            associated_data,
        )
        .unwrap();

        // Attempt to decrypt with different private key, and verify this fails.
        let wrong_hpke_keypair = HpkeKeypair::test();
        open(
            &wrong_hpke_keypair,
            &application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap_err();
    }

    #[test]
    fn wrong_application_info() {
        let hpke_keypair = HpkeKeypair::test();
        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(
            hpke_keypair.config(),
            &application_info,
            message,
            associated_data,
        )
        .unwrap();

        let wrong_application_info =
            HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Client, &Role::Leader);
        open(
            &hpke_keypair,
            &wrong_application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap_err();
    }

    #[test]
    fn wrong_associated_data() {
        let hpke_keypair = HpkeKeypair::test();
        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(
            hpke_keypair.config(),
            &application_info,
            message,
            associated_data,
        )
        .unwrap();

        // Sender and receiver must agree on AAD for each message.
        let wrong_associated_data = b"wrong associated data";
        open(
            &hpke_keypair,
            &application_info,
            &ciphertext,
            wrong_associated_data,
        )
        .unwrap_err();
    }

    fn round_trip_check(kem_id: HpkeKemId, kdf_id: HpkeKdfId, aead_id: HpkeAeadId) {
        const ASSOCIATED_DATA: &[u8] = b"round trip test associated data";
        const MESSAGE: &[u8] = b"round trip test message";

        let kem = Kem::try_from(u16::from(kem_id)).unwrap();

        let Keypair {
            private_key,
            public_key,
        } = kem.gen_keypair();
        let hpke_config = HpkeConfig::new(
            HpkeConfigId::from(0),
            kem_id,
            kdf_id,
            aead_id,
            HpkePublicKey::from(public_key),
        );
        let hpke_private_key = HpkePrivateKey::new(private_key);
        let hpke_keypair = HpkeKeypair::new(hpke_config, hpke_private_key);
        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);

        let ciphertext = seal(
            hpke_keypair.config(),
            &application_info,
            MESSAGE,
            ASSOCIATED_DATA,
        )
        .unwrap();
        let plaintext = open(
            &hpke_keypair,
            &application_info,
            &ciphertext,
            ASSOCIATED_DATA,
        )
        .unwrap();

        assert_eq!(plaintext, MESSAGE);
    }

    #[test]
    fn round_trip_all_algorithms() {
        for kem_id in [HpkeKemId::P256HkdfSha256, HpkeKemId::X25519HkdfSha256] {
            for kdf_id in [
                HpkeKdfId::HkdfSha256,
                HpkeKdfId::HkdfSha384,
                HpkeKdfId::HkdfSha512,
            ] {
                for aead_id in [HpkeAeadId::Aes128Gcm, HpkeAeadId::Aes256Gcm] {
                    round_trip_check(kem_id, kdf_id, aead_id)
                }
            }
        }
    }

    #[derive(Deserialize)]
    struct EncryptionRecord {
        #[serde(with = "hex")]
        aad: Vec<u8>,
        #[serde(with = "hex")]
        ct: Vec<u8>,
        #[serde(with = "hex")]
        nonce: Vec<u8>,
        #[serde(with = "hex")]
        pt: Vec<u8>,
    }

    /// This structure corresponds to the format of the JSON test vectors included with the HPKE
    /// RFC. Only a subset of fields are used; all intermediate calculations are ignored.
    #[derive(Deserialize)]
    struct TestVector {
        mode: u16,
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        #[serde(with = "hex")]
        info: Vec<u8>,
        #[serde(with = "hex")]
        enc: Vec<u8>,
        #[serde(with = "hex", rename = "pkRm")]
        serialized_public_key: Vec<u8>,
        #[serde(with = "hex", rename = "skRm")]
        serialized_private_key: Vec<u8>,
        #[serde(with = "hex")]
        base_nonce: Vec<u8>,
        encryptions: Vec<EncryptionRecord>,
    }

    #[test]
    fn decrypt_test_vectors() {
        // This test can be run with the original test vector file that accompanied the HPKE
        // specification, but the file checked in to the repository has been trimmed down to
        // exclude unused information, in the interest of smaller file sizes.
        //
        // See https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json
        //
        // The file was processed with the following command:
        // jq 'map({mode, kem_id, kdf_id, aead_id, info, enc, pkRm, skRm, base_nonce, encryptions: [.encryptions[0]]} | select(.mode == 0) | select(.aead_id != 65535))'
        let test_vectors: Vec<TestVector> =
            serde_json::from_str(include_str!("test-vectors.json")).unwrap();
        let mut algorithms_tested = HashSet::new();
        for test_vector in test_vectors {
            if test_vector.mode != 0 {
                // We are only interested in the "base" mode.
                continue;
            }
            let kem_id = match HpkeKemId::from(test_vector.kem_id) {
                kem_id @ HpkeKemId::P256HkdfSha256 | kem_id @ HpkeKemId::X25519HkdfSha256 => kem_id,
                _ => {
                    // Skip unsupported KEMs.
                    continue;
                }
            };
            let kdf_id = test_vector.kdf_id.into();
            if test_vector.aead_id == 0xffff {
                // Skip export-only test vectors.
                continue;
            }
            let aead_id = test_vector.aead_id.into();

            for encryption in test_vector.encryptions {
                if encryption.nonce != test_vector.base_nonce {
                    // DAP only performs single-shot encryption with each context, ignore any
                    // other encryptions in the test vectors.
                    continue;
                }

                let hpke_config = HpkeConfig::new(
                    HpkeConfigId::from(0),
                    kem_id,
                    kdf_id,
                    aead_id,
                    HpkePublicKey::from(test_vector.serialized_public_key.clone()),
                );
                let hpke_private_key = HpkePrivateKey(test_vector.serialized_private_key.clone());
                let hpke_keypair = HpkeKeypair::new(hpke_config, hpke_private_key);
                let application_info = HpkeApplicationInfo(test_vector.info.clone());
                let ciphertext = HpkeCiphertext::new(
                    HpkeConfigId::from(0),
                    test_vector.enc.clone(),
                    encryption.ct,
                );

                let plaintext = open(
                    &hpke_keypair,
                    &application_info,
                    &ciphertext,
                    &encryption.aad,
                )
                .unwrap();
                assert_eq!(plaintext, encryption.pt);

                algorithms_tested.insert((
                    u16::from(kem_id),
                    u16::from(kdf_id),
                    u16::from(aead_id),
                ));
            }
        }

        // We expect that this tests 12 out of the 18 implemented algorithm combinations. The test
        // vector file that accompanies the HPKE does include any vectors for the SHA-384 KDF, only
        // HKDF-SHA256 and HKDF-SHA512. (This can be confirmed with the command
        // `jq '.[] | .kdf_id' test-vectors.json | sort | uniq`) The `hpke` crate only supports two
        // KEMs, DHKEM(P-256, HKDF-SHA256) and DHKEM(X25519, HKDF-SHA256). There are three AEADs,
        // all of which are supported by the `hpke` crate, and all of which have test vectors
        // provided. (AES-128-GCM, AES-256-GCM, and ChaCha20Poly1305) This makes for an expected
        // total of 2 * 2 * 3 = 12 unique combinations of algorithms.
        assert_eq!(algorithms_tested.len(), 12);
    }
}
