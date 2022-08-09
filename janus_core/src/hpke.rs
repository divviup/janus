//! Encryption and decryption of messages using HPKE (RFC 9180).

use crate::message::{
    Extension, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId,
    HpkePublicKey, Interval, Nonce, Role, TaskId,
};
use hpke_dispatch::{HpkeError, Kem, Keypair};
use prio::codec::{encode_u16_items, Encode};
use rand::{thread_rng, Rng};
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error occurred in the underlying HPKE library.
    #[error("HPKE error: {0}")]
    Hpke(#[from] HpkeError),
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
pub fn associated_data_for_report_share(
    task_id: TaskId,
    nonce: Nonce,
    extensions: &[Extension],
) -> Vec<u8> {
    let mut associated_data = vec![];
    task_id.encode(&mut associated_data);
    nonce.encode(&mut associated_data);
    encode_u16_items(&mut associated_data, &(), extensions);
    associated_data
}

/// Construct the HPKE associated data for sealing or opening an aggregate share.
pub fn associated_data_for_aggregate_share(task_id: TaskId, batch_interval: Interval) -> Vec<u8> {
    let mut associated_data = Vec::new();
    task_id.encode(&mut associated_data);
    batch_interval.encode(&mut associated_data);
    associated_data
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
            Self::InputShare => b"dap-01 input share",
            Self::AggregateShare => b"dap-01 aggregate share",
        }
    }
}

/// Application info used in HPKE context construction
#[derive(Clone, Debug)]
pub struct HpkeApplicationInfo(Vec<u8>);

impl HpkeApplicationInfo {
    /// Construct HPKE application info from the provided PPM task ID, label and
    /// participant roles.
    pub fn new(label: Label, sender_role: Role, recipient_role: Role) -> Self {
        Self(
            [
                label.as_bytes(),
                &[sender_role as u8],
                &[recipient_role as u8],
            ]
            .concat(),
        )
    }
}

/// An HPKE private key, serialized using the `SerializePrivateKey` function as
/// described in RFC 9180, §4 and §7.1.2.
// TODO(#230): refactor HpkePrivateKey to simplify usage
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkePrivateKey(Vec<u8>);

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
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HpkePrivateKey(hex::decode(s)?))
    }
}

/// Encrypt `plaintext` using the provided `recipient_config` and return the HPKE ciphertext. The
/// provided `application_info` and `associated_data` are cryptographically bound to the ciphertext
/// and are required to successfully decrypt it.
// In PPM, an HPKE context can only be used once (we have no means of
// ensuring that sender and recipient "increment" nonces in lockstep), so
// this method creates a new HPKE context on each call.
pub fn seal(
    recipient_config: &HpkeConfig,
    application_info: &HpkeApplicationInfo,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<HpkeCiphertext, Error> {
    let output = hpke_dispatch::Config::try_from(recipient_config)?.base_mode_seal(
        recipient_config.public_key().as_bytes(),
        &application_info.0,
        plaintext,
        associated_data,
    )?;

    Ok(HpkeCiphertext::new(
        recipient_config.id(),
        output.encapped_key,
        output.ciphertext,
    ))
}

/// Decrypt `ciphertext` using the provided `recipient_config` & `recipient_private_key`, and return
/// the plaintext. The `application_info` and `associated_data` must match what was provided to
/// [`seal()`] exactly.
pub fn open(
    recipient_config: &HpkeConfig,
    recipient_private_key: &HpkePrivateKey,
    application_info: &HpkeApplicationInfo,
    ciphertext: &HpkeCiphertext,
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    hpke_dispatch::Config::try_from(recipient_config)?
        .base_mode_open(
            &recipient_private_key.0,
            ciphertext.encapsulated_context(),
            &application_info.0,
            ciphertext.payload(),
            associated_data,
        )
        .map_err(Into::into)
}

/// Generate a new HPKE keypair and return it as an HpkeConfig (public portion) and
/// HpkePrivateKey (private portion).
pub fn generate_hpke_config_and_private_key() -> (HpkeConfig, HpkePrivateKey) {
    let Keypair {
        private_key,
        public_key,
    } = Kem::X25519HkdfSha256.gen_keypair();
    (
        HpkeConfig::new(
            HpkeConfigId::from(thread_rng().gen::<u8>()),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
            HpkePublicKey::new(public_key),
        ),
        HpkePrivateKey::new(private_key),
    )
}

#[cfg(test)]
mod tests {
    use super::{generate_hpke_config_and_private_key, HpkeApplicationInfo, Label};
    use crate::{
        hpke::{open, seal, HpkePrivateKey},
        message::{
            HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId,
            HpkePublicKey, Role,
        },
    };
    use hpke_dispatch::{Kem, Keypair};
    use serde::Deserialize;
    use std::collections::HashSet;

    #[test]
    fn exchange_message() {
        let (hpke_config, hpke_private_key) = generate_hpke_config_and_private_key();
        let application_info =
            HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(&hpke_config, &application_info, message, associated_data).unwrap();

        let plaintext = open(
            &hpke_config,
            &hpke_private_key,
            &application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn wrong_private_key() {
        let (hpke_config, _) = generate_hpke_config_and_private_key();
        let application_info =
            HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(&hpke_config, &application_info, message, associated_data).unwrap();

        // Attempt to decrypt with different private key, and verify this fails.
        let (wrong_hpke_config, wrong_hpke_private_key) = generate_hpke_config_and_private_key();
        open(
            &wrong_hpke_config,
            &wrong_hpke_private_key,
            &application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap_err();
    }

    #[test]
    fn wrong_application_info() {
        let (hpke_config, hpke_private_key) = generate_hpke_config_and_private_key();
        let application_info =
            HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(&hpke_config, &application_info, message, associated_data).unwrap();

        let wrong_application_info =
            HpkeApplicationInfo::new(Label::AggregateShare, Role::Client, Role::Leader);
        open(
            &hpke_config,
            &hpke_private_key,
            &wrong_application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap_err();
    }

    #[test]
    fn wrong_associated_data() {
        let (hpke_config, hpke_private_key) = generate_hpke_config_and_private_key();
        let application_info =
            HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader);
        let message = b"a message that is secret";
        let associated_data = b"message associated data";

        let ciphertext = seal(&hpke_config, &application_info, message, associated_data).unwrap();

        // Sender and receiver must agree on AAD for each message.
        let wrong_associated_data = b"wrong associated data";
        open(
            &hpke_config,
            &hpke_private_key,
            &application_info,
            &ciphertext,
            wrong_associated_data,
        )
        .unwrap_err();
    }

    fn round_trip_check(kem_id: HpkeKemId, kdf_id: HpkeKdfId, aead_id: HpkeAeadId) {
        const ASSOCIATED_DATA: &[u8] = b"round trip test associated data";
        const MESSAGE: &[u8] = b"round trip test message";

        let kem = Kem::try_from(kem_id as u16).unwrap();

        let Keypair {
            private_key,
            public_key,
        } = kem.gen_keypair();
        let hpke_config = HpkeConfig::new(
            HpkeConfigId::from(0),
            kem_id,
            kdf_id,
            aead_id,
            HpkePublicKey::new(public_key),
        );
        let hpke_private_key = HpkePrivateKey::new(private_key);
        let application_info =
            HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader);

        let ciphertext = seal(&hpke_config, &application_info, MESSAGE, ASSOCIATED_DATA).unwrap();
        let plaintext = open(
            &hpke_config,
            &hpke_private_key,
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
            let kem_id = if let Ok(kem_id) = test_vector.kem_id.try_into() {
                kem_id
            } else {
                // Skip unsupported KEMs.
                continue;
            };
            let kdf_id = test_vector.kdf_id.try_into().unwrap();
            if test_vector.aead_id == 0xffff {
                // Skip export-only test vectors.
                continue;
            }
            let aead_id = test_vector.aead_id.try_into().unwrap();

            for encryption in test_vector.encryptions {
                if encryption.nonce != test_vector.base_nonce {
                    // PPM only performs single-shot encryption with each context, ignore any
                    // other encryptions in the test vectors.
                    continue;
                }

                let hpke_config = HpkeConfig::new(
                    HpkeConfigId::from(0),
                    kem_id,
                    kdf_id,
                    aead_id,
                    HpkePublicKey::new(test_vector.serialized_public_key.clone()),
                );
                let hpke_private_key = HpkePrivateKey(test_vector.serialized_private_key.clone());
                let application_info = HpkeApplicationInfo(test_vector.info.clone());
                let ciphertext = HpkeCiphertext::new(
                    HpkeConfigId::from(0),
                    test_vector.enc.clone(),
                    encryption.ct,
                );

                let plaintext = open(
                    &hpke_config,
                    &hpke_private_key,
                    &application_info,
                    &ciphertext,
                    &encryption.aad,
                )
                .unwrap();
                assert_eq!(plaintext, encryption.pt);

                algorithms_tested.insert((kem_id as u16, kdf_id as u16, aead_id as u16));
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
