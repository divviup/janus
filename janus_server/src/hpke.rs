//! Encryption and decryption of messages using HPKE (RFC 9180).

use crate::message::{HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, Role, TaskId};
use hpke::{
    aead::{Aead, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha512, Kdf},
    kem::{DhP256HkdfSha256, X25519HkdfSha256},
    setup_receiver, setup_sender, Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable,
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
        match (
            self.recipient_config.kem_id,
            self.recipient_config.kdf_id,
            self.recipient_config.aead_id,
        ) {
            (HpkeKemId::P256HkdfSha256, HpkeKdfId::HkdfSha256, HpkeAeadId::Aes256Gcm) => {
                seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
                    &self.recipient_config,
                    HpkeApplicationInfo::new(
                        self.task_id,
                        self.label,
                        self.sender_role,
                        self.recipient_role,
                    ),
                    plaintext,
                    associated_data,
                )
            }
            (HpkeKemId::X25519HkdfSha256, HpkeKdfId::HkdfSha512, HpkeAeadId::ChaCha20Poly1305) => {
                seal::<ChaCha20Poly1305, HkdfSha512, X25519HkdfSha256>(
                    &self.recipient_config,
                    HpkeApplicationInfo::new(
                        self.task_id,
                        self.label,
                        self.sender_role,
                        self.recipient_role,
                    ),
                    plaintext,
                    associated_data,
                )
            }
            (_, _, _) => Err(Error::InvalidConfiguration(
                "unsupported set of HPKE algorithms",
            )),
        }
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
    let mut rng = thread_rng();

    // Deserialize recipient pub into the appropriate PublicKey type for the
    // KEM
    let recipient_public_key = Encapsulate::PublicKey::from_bytes(&recipient_config.public_key.0)?;

    let (encapsulated_context, mut context) = setup_sender::<Encrypt, Derive, Encapsulate, _>(
        &OpModeS::Base,
        &recipient_public_key,
        &application_info.0,
        &mut rng,
    )?;

    Ok(HpkeCiphertext {
        config_id: recipient_config.id,
        encapsulated_context: encapsulated_context.to_bytes().to_vec(),
        payload: context.seal(plaintext, associated_data)?,
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
        // We must manually dispatch to each possible specialization of open
        match (self.config.kem_id, self.config.kdf_id, self.config.aead_id) {
            (HpkeKemId::P256HkdfSha256, HpkeKdfId::HkdfSha256, HpkeAeadId::Aes256Gcm) => {
                open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
                    HpkeApplicationInfo::new(
                        self.task_id,
                        self.label,
                        self.sender_role,
                        self.recipient_role,
                    ),
                    ciphertext,
                    associated_data,
                    &self.recipient_private_key,
                )
            }
            (HpkeKemId::X25519HkdfSha256, HpkeKdfId::HkdfSha512, HpkeAeadId::ChaCha20Poly1305) => {
                open::<ChaCha20Poly1305, HkdfSha512, X25519HkdfSha256>(
                    HpkeApplicationInfo::new(
                        self.task_id,
                        self.label,
                        self.sender_role,
                        self.recipient_role,
                    ),
                    ciphertext,
                    associated_data,
                    &self.recipient_private_key,
                )
            }
            (_, _, _) => Err(Error::InvalidConfiguration(
                "unsupported set of HPKE algorithms",
            )),
        }
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
    // Deserialize recipient priv into the appropriate PrivateKey type for
    // the KEM
    let recipient_private_key =
        Encapsulate::PrivateKey::from_bytes(&serialized_recipient_private_key.0)?;

    // Deserialize sender encapsulated key into the appropriate EncappedKey for
    // the KEM
    let sender_encapped_key =
        Encapsulate::EncappedKey::from_bytes(&ciphertext.encapsulated_context)?;

    let mut context = setup_receiver::<Encrypt, Derive, Encapsulate>(
        &OpModeR::Base,
        &recipient_private_key,
        &sender_encapped_key,
        &application_info.0,
    )?;

    Ok(context.open(&ciphertext.payload, associated_data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::test_util::install_test_trace_subscriber;

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
}
