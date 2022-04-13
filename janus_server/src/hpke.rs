//! Encryption and decryption of messages using HPKE (RFC 9180).

use crate::message::{HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, Role, TaskId};
use hpke::{
    aead::{Aead, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf},
    kem::{DhP256HkdfSha256, X25519HkdfSha256},
    Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable,
};
use rand::thread_rng;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wrapper around errors from crate hpke. See [`hpke::HpkeError`] for more
    /// details on possible variants.
    #[error("HPKE error")]
    Hpke(#[from] HpkeError),
    #[error("invalid HPKE configuration: {0}")]
    InvalidConfiguration(&'static str),
}

/// Labels incorporated into HPKE application info string
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Label {
    InputShare,
    AggregateShare,
}

impl Label {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::InputShare => b"ppm input share",
            Self::AggregateShare => b"ppm aggregate share",
        }
    }
}

/// An HPKE private key, serialized using the `SerializePrivateKey` function as
/// described in RFC 9180, §4 and §7.1.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkePrivateKey(Vec<u8>);

impl HpkePrivateKey {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
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

/// Application info used in HPKE context construction
#[derive(Clone, Debug)]
struct HpkeApplicationInfo(Vec<u8>);

impl HpkeApplicationInfo {
    /// Construct HPKE application info from the provided PPM task ID, label and
    /// participant roles.
    fn new(task_id: TaskId, label: Label, sender_role: Role, recipient_role: Role) -> Self {
        Self(
            [
                task_id.as_bytes(),
                label.as_bytes(),
                &[sender_role as u8],
                &[recipient_role as u8],
            ]
            .concat(),
        )
    }
}

/// A one-shot HPKE sender that encrypts messages to the public key in
/// `recipient_config` using the AEAD, key derivation and key encapsulation
/// mechanisms specified in `recipient_config`, and using `label`, `sender_role`
/// and `recipient_role` to derive application info.
//
// This type only exists separately from Sender so that we can have a type that
// doesn't "leak" the generic type parameters into the caller.
#[derive(Clone, Debug)]
pub struct HpkeSender {
    task_id: TaskId,
    recipient_config: HpkeConfig,
    label: Label,
    sender_role: Role,
    recipient_role: Role,
}

impl HpkeSender {
    /// Create an [`HpkeSender`] with the provided parameters.
    pub fn new(
        task_id: TaskId,
        recipient_config: HpkeConfig,
        label: Label,
        sender_role: Role,
        recipient_role: Role,
    ) -> Self {
        Self {
            task_id,
            recipient_config,
            label,
            sender_role,
            recipient_role,
        }
    }

    /// Create an [`HpkeSender`] configured to encrypt messages to the provided
    /// [`HpkeRecipient`].
    #[cfg(test)]
    pub(crate) fn from_recipient(recipient: &HpkeRecipient) -> Self {
        Self {
            task_id: recipient.task_id,
            recipient_config: recipient.config.clone(),
            label: recipient.label,
            sender_role: recipient.sender_role,
            recipient_role: recipient.recipient_role,
        }
    }

    /// Encrypt `plaintext` and return the HPKE ciphertext.
    ///
    /// In PPM, an HPKE context can only be used once (we have no means of
    /// ensuring that sender and recipient "increment" nonces in lockstep), so
    /// this method creates a new HPKE context on each call.
    pub(crate) fn seal(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<HpkeCiphertext, Error> {
        // We must manually dispatch to each possible specialization of seal
        let seal = match (
            self.recipient_config.aead_id,
            self.recipient_config.kdf_id,
            self.recipient_config.kem_id,
        ) {
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::P256HkdfSha256) => {
                seal::<AesGcm128, HkdfSha256, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::P256HkdfSha256) => {
                seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha256, HpkeKemId::P256HkdfSha256) => {
                seal::<ChaCha20Poly1305, HkdfSha256, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::P256HkdfSha256) => {
                seal::<AesGcm128, HkdfSha384, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::P256HkdfSha256) => {
                seal::<AesGcm256, HkdfSha384, DhP256HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha384, HpkeKemId::P256HkdfSha256) => {
                seal::<ChaCha20Poly1305, HkdfSha384, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::P256HkdfSha256) => {
                seal::<AesGcm128, HkdfSha512, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::P256HkdfSha256) => {
                seal::<AesGcm256, HkdfSha512, DhP256HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha512, HpkeKemId::P256HkdfSha256) => {
                seal::<ChaCha20Poly1305, HkdfSha512, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::X25519HkdfSha256) => {
                seal::<AesGcm128, HkdfSha256, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::X25519HkdfSha256) => {
                seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha256, HpkeKemId::X25519HkdfSha256) => {
                seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::X25519HkdfSha256) => {
                seal::<AesGcm128, HkdfSha384, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::X25519HkdfSha256) => {
                seal::<AesGcm256, HkdfSha384, X25519HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha384, HpkeKemId::X25519HkdfSha256) => {
                seal::<ChaCha20Poly1305, HkdfSha384, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::X25519HkdfSha256) => {
                seal::<AesGcm128, HkdfSha512, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::X25519HkdfSha256) => {
                seal::<AesGcm256, HkdfSha512, X25519HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha512, HpkeKemId::X25519HkdfSha256) => {
                seal::<ChaCha20Poly1305, HkdfSha512, X25519HkdfSha256>
            }
        };
        let application_info = HpkeApplicationInfo::new(
            self.task_id,
            self.label,
            self.sender_role,
            self.recipient_role,
        );
        seal(
            &self.recipient_config,
            application_info,
            plaintext,
            associated_data,
        )
    }
}

// This function exists separately from struct HpkeSender to abstract away its
// generic parameters
fn seal<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem>(
    recipient_config: &HpkeConfig,
    application_info: HpkeApplicationInfo,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<HpkeCiphertext, Error> {
    // Deserialize recipient pub into the appropriate PublicKey type for the KEM.
    let recipient_public_key = Encapsulate::PublicKey::from_bytes(&recipient_config.public_key.0)?;

    let (encapsulated_context, ciphertext) =
        hpke::single_shot_seal::<Encrypt, Derive, Encapsulate, _>(
            &OpModeS::Base,
            &recipient_public_key,
            &application_info.0,
            plaintext,
            associated_data,
            &mut thread_rng(),
        )?;

    Ok(HpkeCiphertext {
        config_id: recipient_config.id,
        encapsulated_context: encapsulated_context.to_bytes().to_vec(),
        payload: ciphertext,
    })
}

/// An HPKE recipient that decrypts messages encrypted to the public key in
/// `recipient_config`, using the AEAD, key derivation and key encapsulation
/// mechanisms specified in `recipient_config`, and using `label`, `sender_role`
/// and `recipient_role` to derive application info.
//
// This type only exists separately from Recipient so that we can have a type
// that doesn't "leak" the generic type parameters into the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeRecipient {
    task_id: TaskId,
    config: HpkeConfig,
    label: Label,
    sender_role: Role,
    recipient_role: Role,
    recipient_private_key: HpkePrivateKey,
}

impl HpkeRecipient {
    /// Create an HPKE recipient from the provided parameters.
    pub fn new(
        task_id: TaskId,
        hpke_config: &HpkeConfig,
        label: Label,
        sender_role: Role,
        recipient_role: Role,
        serialized_private_key: &HpkePrivateKey,
    ) -> Self {
        Self {
            task_id,
            config: hpke_config.clone(),
            label,
            sender_role,
            recipient_role,
            recipient_private_key: serialized_private_key.clone(),
        }
    }

    /// The HPKE configuration for this recipient.
    pub fn config(&self) -> &HpkeConfig {
        &self.config
    }

    /// The private key used by this recipient.
    pub fn private_key(&self) -> &HpkePrivateKey {
        &self.recipient_private_key
    }

    /// Generate a new X25519HkdfSha256 keypair and construct an HPKE recipient
    /// using the private key, with KEM = X25519HkdfSha256, KDF = HkdfSha512 and
    /// AEAD = ChaCha20Poly1305, and the specified label, and roles.
    pub fn generate(
        task_id: TaskId,
        label: Label,
        sender_role: Role,
        recipient_role: Role,
    ) -> Self {
        use crate::message::{HpkeConfigId, HpkePublicKey};

        let mut rng = thread_rng();

        let (private_key, public_key) = X25519HkdfSha256::gen_keypair(&mut rng);

        let config = HpkeConfig {
            id: HpkeConfigId(0),
            kem_id: HpkeKemId::X25519HkdfSha256,
            kdf_id: HpkeKdfId::HkdfSha512,
            aead_id: HpkeAeadId::ChaCha20Poly1305,
            public_key: HpkePublicKey(public_key.to_bytes().as_slice().to_vec()),
        };

        Self {
            task_id,
            config,
            label,
            sender_role,
            recipient_role,
            recipient_private_key: HpkePrivateKey(private_key.to_bytes().as_slice().to_vec()),
        }
    }

    /// Decrypt `ciphertext` and return the plaintext.
    ///
    /// In PPM, an HPKE context can only be used once (we have no means of
    /// ensuring that sender and recipient "increment" nonces in lockstep), so
    /// this method creates a new HPKE context on each call.
    pub(crate) fn open(
        &self,
        ciphertext: &HpkeCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let application_info = HpkeApplicationInfo::new(
            self.task_id,
            self.label,
            self.sender_role,
            self.recipient_role,
        );
        self.open_internal(ciphertext, application_info, associated_data)
    }

    /// Decrypt `ciphertext` and return the plaintext, but with a directly-specified application
    /// information byte string. In normal operation, this is called by [open] with the
    /// PPM-specified domain separation information. Test may use this directly to provide non-PPM
    /// application information byte strings, for example to check against the HPKE RFC's test
    /// vectors.
    fn open_internal(
        &self,
        ciphertext: &HpkeCiphertext,
        application_info: HpkeApplicationInfo,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // We must manually dispatch to each possible specialization of open
        let open = match (self.config.aead_id, self.config.kdf_id, self.config.kem_id) {
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::P256HkdfSha256) => {
                open::<AesGcm128, HkdfSha256, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::P256HkdfSha256) => {
                open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha256, HpkeKemId::P256HkdfSha256) => {
                open::<ChaCha20Poly1305, HkdfSha256, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::P256HkdfSha256) => {
                open::<AesGcm128, HkdfSha384, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::P256HkdfSha256) => {
                open::<AesGcm256, HkdfSha384, DhP256HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha384, HpkeKemId::P256HkdfSha256) => {
                open::<ChaCha20Poly1305, HkdfSha384, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::P256HkdfSha256) => {
                open::<AesGcm128, HkdfSha512, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::P256HkdfSha256) => {
                open::<AesGcm256, HkdfSha512, DhP256HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha512, HpkeKemId::P256HkdfSha256) => {
                open::<ChaCha20Poly1305, HkdfSha512, DhP256HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::X25519HkdfSha256) => {
                open::<AesGcm128, HkdfSha256, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha256, HpkeKemId::X25519HkdfSha256) => {
                open::<AesGcm256, HkdfSha256, X25519HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha256, HpkeKemId::X25519HkdfSha256) => {
                open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::X25519HkdfSha256) => {
                open::<AesGcm128, HkdfSha384, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha384, HpkeKemId::X25519HkdfSha256) => {
                open::<AesGcm256, HkdfSha384, X25519HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha384, HpkeKemId::X25519HkdfSha256) => {
                open::<ChaCha20Poly1305, HkdfSha384, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes128Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::X25519HkdfSha256) => {
                open::<AesGcm128, HkdfSha512, X25519HkdfSha256>
            }
            (HpkeAeadId::Aes256Gcm, HpkeKdfId::HkdfSha512, HpkeKemId::X25519HkdfSha256) => {
                open::<AesGcm256, HkdfSha512, X25519HkdfSha256>
            }
            (HpkeAeadId::ChaCha20Poly1305, HpkeKdfId::HkdfSha512, HpkeKemId::X25519HkdfSha256) => {
                open::<ChaCha20Poly1305, HkdfSha512, X25519HkdfSha256>
            }
        };
        open(
            application_info,
            ciphertext,
            associated_data,
            &self.recipient_private_key,
        )
    }
}

// This function exists separately from struct HpkeRecipient to abstract away its
// generic parameters
fn open<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem>(
    application_info: HpkeApplicationInfo,
    ciphertext: &HpkeCiphertext,
    associated_data: &[u8],
    serialized_recipient_private_key: &HpkePrivateKey,
) -> Result<Vec<u8>, Error> {
    // Deserialize recipient priv into the appropriate PrivateKey type for the KEM.
    let recipient_private_key =
        Encapsulate::PrivateKey::from_bytes(&serialized_recipient_private_key.0)?;

    // Deserialize sender encapsulated key into the appropriate EncappedKey for the KEM.
    let sender_encapped_key =
        Encapsulate::EncappedKey::from_bytes(&ciphertext.encapsulated_context)?;

    Ok(hpke::single_shot_open::<Encrypt, Derive, Encapsulate>(
        &OpModeR::Base,
        &recipient_private_key,
        &sender_encapped_key,
        &application_info.0,
        &ciphertext.payload,
        associated_data,
    )?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde::Deserialize;

    use super::*;
    use crate::{
        message::{HpkeConfigId, HpkePublicKey},
        trace::test_util::install_test_trace_subscriber,
    };

    #[test]
    fn exchange_message() {
        install_test_trace_subscriber();
        let task_id = TaskId::random();
        // Sender and receiver must agree on AAD for each message
        let associated_data = b"message associated data";
        let message = b"a message that is secret";

        let recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let sender = HpkeSender {
            task_id: recipient.task_id,
            recipient_config: recipient.config.clone(),
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        };

        let ciphertext = sender.seal(message, associated_data).unwrap();
        let plaintext = recipient.open(&ciphertext, associated_data).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn wrong_private_key() {
        install_test_trace_subscriber();
        let task_id = TaskId::random();
        // Sender and receiver must agree on AAD for each message
        let associated_data = b"message associated data";
        let message = b"a message that is secret";

        let recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let sender = HpkeSender {
            task_id: recipient.task_id,
            recipient_config: recipient.config,
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        };

        let ciphertext = sender.seal(message, associated_data).unwrap();

        // Attempt to decrypt with different private key
        let wrong_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        wrong_recipient
            .open(&ciphertext, associated_data)
            .unwrap_err();
    }

    #[test]
    fn wrong_application_info() {
        install_test_trace_subscriber();
        let task_id = TaskId::random();
        // Sender and receiver must agree on AAD for each message
        let associated_data = b"message associated data";
        let message = b"a message that is secret";

        let recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let sender = HpkeSender {
            task_id: recipient.task_id,
            recipient_config: recipient.config.clone(),
            label: Label::AggregateShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        };

        let ciphertext = sender.seal(message, associated_data).unwrap();
        recipient.open(&ciphertext, associated_data).unwrap_err();
    }

    #[test]
    fn wrong_associated_data() {
        install_test_trace_subscriber();
        let task_id = TaskId::random();
        let message = b"a message that is secret";

        let recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let sender = HpkeSender {
            task_id: recipient.task_id,
            recipient_config: recipient.config.clone(),
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        };

        let ciphertext = sender.seal(message, b"correct associated data").unwrap();
        recipient
            .open(&ciphertext, b"wrong associated data")
            .unwrap_err();
    }

    fn round_trip_check<KEM: hpke::Kem, KDF: hpke::kdf::Kdf, AEAD: hpke::aead::Aead>() {
        static ASSOCIATED_DATA: &[u8] = b"round trip test associated data";
        static MESSAGE: &[u8] = b"round trip test message";

        let task_id = TaskId::random();
        let mut rng = thread_rng();

        let (private_key, public_key) = KEM::gen_keypair(&mut rng);
        let config = HpkeConfig {
            id: HpkeConfigId(0),
            kem_id: KEM::KEM_ID.try_into().unwrap(),
            kdf_id: KDF::KDF_ID.try_into().unwrap(),
            aead_id: AEAD::AEAD_ID.try_into().unwrap(),
            public_key: HpkePublicKey(public_key.to_bytes().to_vec()),
        };
        let recipient = HpkeRecipient {
            task_id,
            config,
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
            recipient_private_key: HpkePrivateKey(private_key.to_bytes().to_vec()),
        };
        let sender = HpkeSender::from_recipient(&recipient);

        let ciphertext = sender.seal(MESSAGE, ASSOCIATED_DATA).unwrap();
        let plaintext = recipient.open(&ciphertext, ASSOCIATED_DATA).unwrap();

        assert_eq!(plaintext, MESSAGE);
    }

    #[test]
    fn round_trip_all_algorithms() {
        round_trip_check::<DhP256HkdfSha256, HkdfSha256, AesGcm128>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha256, AesGcm256>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha256, ChaCha20Poly1305>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha384, AesGcm128>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha384, AesGcm256>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha384, ChaCha20Poly1305>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha512, AesGcm128>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha512, AesGcm256>();
        round_trip_check::<DhP256HkdfSha256, HkdfSha512, ChaCha20Poly1305>();
        round_trip_check::<X25519HkdfSha256, HkdfSha256, AesGcm128>();
        round_trip_check::<X25519HkdfSha256, HkdfSha256, AesGcm256>();
        round_trip_check::<X25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>();
        round_trip_check::<X25519HkdfSha256, HkdfSha384, AesGcm128>();
        round_trip_check::<X25519HkdfSha256, HkdfSha384, AesGcm256>();
        round_trip_check::<X25519HkdfSha256, HkdfSha384, ChaCha20Poly1305>();
        round_trip_check::<X25519HkdfSha256, HkdfSha512, AesGcm128>();
        round_trip_check::<X25519HkdfSha256, HkdfSha512, AesGcm256>();
        round_trip_check::<X25519HkdfSha256, HkdfSha512, ChaCha20Poly1305>();
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

                let config_id = HpkeConfigId(0);
                let config = HpkeConfig {
                    id: config_id,
                    kem_id,
                    kdf_id,
                    aead_id,
                    public_key: HpkePublicKey(test_vector.serialized_public_key.clone()),
                };
                let recipient = HpkeRecipient {
                    task_id: TaskId([0; 32]),
                    config,
                    label: Label::InputShare,
                    sender_role: Role::Client,
                    recipient_role: Role::Leader,
                    recipient_private_key: HpkePrivateKey(
                        test_vector.serialized_private_key.clone(),
                    ),
                };

                let application_info = HpkeApplicationInfo(test_vector.info.clone());
                let ciphertext = HpkeCiphertext {
                    config_id,
                    encapsulated_context: test_vector.enc.clone(),
                    payload: encryption.ct.clone(),
                };
                let plaintext = recipient
                    .open_internal(&ciphertext, application_info, &encryption.aad)
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
