//! PPM protocol message definitions with serialization/deserialization support.

use anyhow::anyhow;
use chrono::NaiveDateTime;
use hpke::{
    aead::{self, Aead},
    kdf::{self, Kdf},
    kem, Kem,
};
use num_enum::TryFromPrimitive;
use postgres_types::{FromSql, ToSql};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use rand::{thread_rng, Rng};
use ring::{
    digest::SHA256_OUTPUT_LEN,
    error::Unspecified,
    hmac::{self, HMAC_SHA256},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    io::{self, Cursor, ErrorKind, Read},
    marker::PhantomData,
    str::FromStr,
};

/// AuthenticatedEncoder can encode messages into the format used by authenticated PPM messages. The
/// encoding format is the encoding format of the underlying message, followed by a 32-byte
/// authentication tag.
pub struct AuthenticatedEncoder<M: Encode> {
    msg: M,
}

impl<M: Encode> AuthenticatedEncoder<M> {
    /// new creates a new AuthenticatedEncoder which will encode the given message.
    pub fn new(msg: M) -> AuthenticatedEncoder<M> {
        Self { msg }
    }

    /// encode encodes the message using the given key.
    pub fn encode(&self, key: &hmac::Key) -> Vec<u8> {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let mut buf = Vec::new();
        self.msg.encode(&mut buf);
        let tag = hmac::sign(key, &buf);
        buf.extend_from_slice(tag.as_ref());
        buf
    }
}

/// AuthenticatedRequestDecoder can decode messages in the "authenticated request" format used by
/// authenticated PPM request messages. This format places the task ID as the first 32 bytes, the
/// authentication tag as the last 32 bytes, and all interior bytes as opaque message data. The
/// included message is decoded from a concatenation of the task ID & the opaque interior message
/// bytes. (This means that the task ID is aliased as both a field interpreted by the envelope, as
/// well as part of the opaque message bytes to be decoded; this allows us to save having to
/// specify the task ID twice.)
pub struct AuthenticatedRequestDecoder<M: Decode> {
    buf: Vec<u8>,
    _msg_type: PhantomData<M>,
}

impl<M: Decode> AuthenticatedRequestDecoder<M> {
    /// MIN_BUFFER_SIZE defines the minimum size of a decodable buffer for a request.
    pub const MIN_BUFFER_SIZE: usize = TaskId::ENCODED_LEN + SHA256_OUTPUT_LEN;

    /// new creates a new AuthenticatedRequestDecoder which will attempt to decode the given bytes.
    /// If the given buffer is not at least MIN_BUFFER_SIZE bytes large, an error will be returned.
    pub fn new(buf: Vec<u8>) -> Result<AuthenticatedRequestDecoder<M>, CodecError> {
        if buf.len() < Self::MIN_BUFFER_SIZE {
            return Err(CodecError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "buffer too small",
            )));
        }

        Ok(Self {
            buf,
            _msg_type: PhantomData,
        })
    }

    /// task_id retrieves the unauthenticated task ID associated with this message. This task ID
    /// should be used only to determine the appropriate key to use to authenticate & decode the
    /// message.
    pub fn task_id(&self) -> TaskId {
        // Retrieve task_id from the buffer bytes.
        let mut buf = [0u8; TaskId::ENCODED_LEN];
        buf.copy_from_slice(&self.buf[..TaskId::ENCODED_LEN]);
        TaskId(buf)
    }

    /// decode authenticates & decodes the message using the given key.
    pub fn decode(&self, key: &hmac::Key) -> Result<M, AuthenticatedDecodeError> {
        authenticated_decode(key, &self.buf)
    }
}

/// Errors that may occur when decoding an authenticated PPM structure. This may indicate that
/// either the authentication tag was invalid or that there was a parsing error reading the
/// envelope or the message contained within.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedDecodeError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("invalid HMAC tag")]
    InvalidHmac,
}

/// AuthenticatedResponseDecoder can decode messages in the "authenticated response" format used by
/// authenticated PPM response messages. This format places the authentication tag as the last 32
/// bytes, and all prior bytes as opaque message data.
pub struct AuthenticatedResponseDecoder<M: Decode> {
    buf: Vec<u8>,
    _msg_type: PhantomData<M>,
}

impl<M: Decode> AuthenticatedResponseDecoder<M> {
    // MIN_BUFFER_SIZE defines the minimum size of a decodable buffer for a response.
    pub const MIN_BUFFER_SIZE: usize = SHA256_OUTPUT_LEN;

    /// new creates a new AuthenticatedResponseDecoder which will attempt to decode the given bytes.
    /// If the given buffer is not at least MIN_BUFFER_SIZE bytes large, an error will be returned.
    pub fn new(buf: Vec<u8>) -> Result<AuthenticatedResponseDecoder<M>, CodecError> {
        if buf.len() < Self::MIN_BUFFER_SIZE {
            return Err(CodecError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "buffer too small",
            )));
        }

        Ok(Self {
            buf,
            _msg_type: PhantomData,
        })
    }

    /// decode authenticates & decodes the message using the given key.
    pub fn decode(&self, key: &hmac::Key) -> Result<M, AuthenticatedDecodeError> {
        authenticated_decode(key, &self.buf)
    }
}

fn authenticated_decode<M: Decode>(
    key: &hmac::Key,
    buf: &[u8],
) -> Result<M, AuthenticatedDecodeError> {
    let (msg_bytes, tag) = buf.split_at(buf.len() - SHA256_OUTPUT_LEN);
    hmac::verify(key, msg_bytes, tag)
        .map_err(|_: Unspecified| AuthenticatedDecodeError::InvalidHmac)?;
    M::get_decoded(msg_bytes).map_err(AuthenticatedDecodeError::from)
}

/// PPM protocol message representing a duration with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Duration(pub(crate) u64);

impl Duration {
    pub fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }
}

impl Encode for Duration {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for Duration {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

/// PPM protocol message representing an instant in time with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(pub(crate) u64);

impl Time {
    pub(crate) fn as_naive_date_time(&self) -> NaiveDateTime {
        NaiveDateTime::from_timestamp(self.0 as i64, 0)
    }

    pub(crate) fn from_naive_date_time(time: NaiveDateTime) -> Self {
        Self(time.timestamp() as u64)
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encode for Time {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for Time {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

/// PPM protocol message representing a half-open interval of time with a resolution of seconds;
/// the start of the interval is included while the end of the interval is excluded.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Interval {
    /// The start of the interval.
    pub(crate) start: Time,
    /// The length of the interval.
    pub(crate) duration: Duration,
}

impl Encode for Interval {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.start.encode(bytes);
        self.duration.encode(bytes);
    }
}

impl Decode for Interval {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let start = Time::decode(bytes)?;
        let duration = Duration::decode(bytes)?;

        Ok(Self { start, duration })
    }
}

/// PPM protocol message representing a nonce uniquely identifying a client report.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce {
    /// The time at which the report was generated.
    pub(crate) time: Time,
    /// A randomly generated value.
    pub(crate) rand: u64,
}

impl Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.time, self.rand)
    }
}

impl Encode for Nonce {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.time.encode(bytes);
        self.rand.encode(bytes);
    }
}

impl Decode for Nonce {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let time = Time::decode(bytes)?;
        let rand = u64::decode(bytes)?;

        Ok(Self { time, rand })
    }
}

/// PPM protocol message representing the different roles that participants can adopt.
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u8)]
pub enum Role {
    Collector = 0,
    Client = 1,
    Leader = 2,
    Helper = 3,
}

impl Role {
    /// True if this [`Role`] is one of the aggregators.
    pub(crate) fn is_aggregator(&self) -> bool {
        matches!(self, Role::Leader | Role::Helper)
    }

    /// If this [`Role`] is one of the aggregators, returns the index at which
    /// that aggregator's message or data can be found in various lists, or
    /// `None` if the role is not an aggregator.
    pub(crate) fn index(&self) -> Option<usize> {
        match self {
            // draft-gpew-priv-ppm §4.2: the leader's endpoint MUST be the first
            Role::Leader => Some(0),
            Role::Helper => Some(1),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collector => "collector",
            Self::Client => "client",
            Self::Leader => "leader",
            Self::Helper => "helper",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown role {0}")]
pub struct RoleParseError(String);

impl FromStr for Role {
    type Err = RoleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "collector" => Ok(Self::Collector),
            "client" => Ok(Self::Client),
            "leader" => Ok(Self::Leader),
            "helper" => Ok(Self::Helper),
            _ => Err(RoleParseError(s.to_owned())),
        }
    }
}

impl Encode for Role {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u8).encode(bytes);
    }
}

impl Decode for Role {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected Role value {}", val).into()))
    }
}

/// PPM protocol message representing an identifier for an HPKE config.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeConfigId(pub(crate) u8);

impl Display for HpkeConfigId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encode for HpkeConfigId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for HpkeConfigId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u8::decode(bytes)?))
    }
}

/// PPM protocol message representing an HPKE ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HpkeCiphertext {
    /// An identifier of the HPKE configuration used to seal the message.
    pub(crate) config_id: HpkeConfigId,
    /// An encasulated HPKE context.
    pub(crate) encapsulated_context: Vec<u8>,
    /// An HPKE ciphertext.
    pub(crate) payload: Vec<u8>,
}

impl Encode for HpkeCiphertext {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.config_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.encapsulated_context);
        encode_u16_items(bytes, &(), &self.payload);
    }
}

impl Decode for HpkeCiphertext {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let config_id = HpkeConfigId::decode(bytes)?;
        let encapsulated_context = decode_u16_items(&(), bytes)?;
        let payload = decode_u16_items(&(), bytes)?;

        Ok(Self {
            config_id,
            encapsulated_context,
            payload,
        })
    }
}

/// PPM protocol message representing an identifier for a PPM task.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub(crate) [u8; Self::ENCODED_LEN]);

impl Debug for TaskId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Encode for TaskId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for TaskId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut decoded = [0u8; Self::ENCODED_LEN];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl TaskId {
    /// ENCODED_LEN is the length of a task ID in bytes when encoded.
    pub(crate) const ENCODED_LEN: usize = 32;

    /// Get a reference to the task ID as a byte slice
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Generate a random [`TaskId`]
    pub fn random() -> Self {
        let mut buf = [0u8; Self::ENCODED_LEN];
        thread_rng().fill(&mut buf);
        Self(buf)
    }
}

/// PPM protocol message representing an HPKE key encapsulation mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKemId {
    /// NIST P-256 keys and HKDF-SHA256.
    P256HkdfSha256 = kem::DhP256HkdfSha256::KEM_ID,
    /// X25519 keys and HKDF-SHA256.
    X25519HkdfSha256 = kem::X25519HkdfSha256::KEM_ID,
}

impl Encode for HpkeKemId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for HpkeKemId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKemId value {}", val).into()))
    }
}

/// PPM protocol message representing an HPKE key derivation function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKdfId {
    /// HMAC Key Derivation Function SHA256.
    HkdfSha256 = kdf::HkdfSha256::KDF_ID,
    /// HMAC Key Derivation Function SHA384.
    HkdfSha384 = kdf::HkdfSha384::KDF_ID,
    /// HMAC Key Derivation Function SHA512.
    HkdfSha512 = kdf::HkdfSha512::KDF_ID,
}

impl Encode for HpkeKdfId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for HpkeKdfId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKdfId value {}", val).into()))
    }
}

/// PPM protocol message representing an HPKE AEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeAeadId {
    /// AES-128-GCM.
    Aes128Gcm = aead::AesGcm128::AEAD_ID,
    /// AES-256-GCM.
    Aes256Gcm = aead::AesGcm256::AEAD_ID,
    /// ChaCha20Poly1305.
    ChaCha20Poly1305 = aead::ChaCha20Poly1305::AEAD_ID,
}

impl Encode for HpkeAeadId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for HpkeAeadId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKemId value {}", val).into()))
    }
}

/// PPM protocol message representing an HPKE public key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkePublicKey(pub(crate) Vec<u8>);

impl Encode for HpkePublicKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.0);
    }
}

impl Decode for HpkePublicKey {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let key = decode_u16_items(&(), bytes)?;
        Ok(Self(key))
    }
}

impl Debug for HpkePublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// PPM protocol message representing an HPKE config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeConfig {
    pub(crate) id: HpkeConfigId,
    pub(crate) kem_id: HpkeKemId,
    pub(crate) kdf_id: HpkeKdfId,
    pub(crate) aead_id: HpkeAeadId,
    pub(crate) public_key: HpkePublicKey,
}

impl Encode for HpkeConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.id.encode(bytes);
        self.kem_id.encode(bytes);
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
        self.public_key.encode(bytes);
    }
}

impl Decode for HpkeConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let id = HpkeConfigId::decode(bytes)?;
        let kem_id = HpkeKemId::decode(bytes)?;
        let kdf_id = HpkeKdfId::decode(bytes)?;
        let aead_id = HpkeAeadId::decode(bytes)?;
        let public_key = HpkePublicKey::decode(bytes)?;

        Ok(Self {
            id,
            kem_id,
            kdf_id,
            aead_id,
            public_key,
        })
    }
}

/// PPM protocol message representing a client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub(crate) task_id: TaskId,
    pub(crate) nonce: Nonce,
    pub(crate) extensions: Vec<Extension>,
    pub(crate) encrypted_input_shares: Vec<HpkeCiphertext>,
}

impl Report {
    /// Construct the HPKE associated data for sealing or opening this report,
    /// per §4.3.2 and 4.4.2.2 of draft-gpew-priv-ppm
    pub(crate) fn associated_data(nonce: Nonce, extensions: &[Extension]) -> Vec<u8> {
        let mut associated_data = vec![];
        nonce.encode(&mut associated_data);
        encode_u16_items(&mut associated_data, &(), extensions);

        associated_data
    }
}

impl Encode for Report {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.nonce.encode(bytes);
        encode_u16_items(bytes, &(), &self.extensions);
        encode_u16_items(bytes, &(), &self.encrypted_input_shares);
    }
}

impl Decode for Report {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let timestamp = Nonce::decode(bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;
        let encrypted_input_shares = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            nonce: timestamp,
            extensions,
            encrypted_input_shares,
        })
    }
}

/// PPM protocol message representing an arbitrary extension included in a client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub(crate) extension_type: ExtensionType,
    pub(crate) extension_data: Vec<u8>,
}

impl Encode for Extension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.extension_type.encode(bytes);
        encode_u16_items(bytes, &(), &self.extension_data);
    }
}

impl Decode for Extension {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let extension_type = ExtensionType::decode(bytes)?;
        let extension_data = decode_u16_items(&(), bytes)?;

        Ok(Self {
            extension_type,
            extension_data,
        })
    }
}

/// PPM protocol message representing the type of an extension included in a client report.
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum ExtensionType {
    Tbd = 0,
}

impl Encode for ExtensionType {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for ExtensionType {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(anyhow!("unexpected ExtensionType value {}", val).into())
        })
    }
}

/// PPM protocol message representing one aggregator's share of a single client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportShare {
    pub(crate) nonce: Nonce,
    pub(crate) extensions: Vec<Extension>,
    pub(crate) encrypted_input_share: HpkeCiphertext,
}

impl Encode for ReportShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.nonce.encode(bytes);
        encode_u16_items(bytes, &(), &self.extensions);
        self.encrypted_input_share.encode(bytes);
    }
}

impl Decode for ReportShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let nonce = Nonce::decode(bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;
        let encrypted_input_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            nonce,
            extensions,
            encrypted_input_share,
        })
    }
}

/// PPM protocol message representing a transition in the state machine of a VDAF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub(crate) nonce: Nonce,
    pub(crate) trans_data: TransitionTypeSpecificData,
}

impl Encode for Transition {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.nonce.encode(bytes);
        self.trans_data.encode(bytes);
    }
}

impl Decode for Transition {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let nonce = Nonce::decode(bytes)?;
        let trans_data = TransitionTypeSpecificData::decode(bytes)?;

        Ok(Self { nonce, trans_data })
    }
}

/// PPM protocol message representing transition-type-specific data, included in a Transition
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionTypeSpecificData {
    Continued { payload: Vec<u8> },
    Finished,
    Failed { error: TransitionError },
}

impl Encode for TransitionTypeSpecificData {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Continued { payload } => {
                0u8.encode(bytes);
                encode_u16_items(bytes, &(), payload);
            }
            Self::Finished => 1u8.encode(bytes),
            Self::Failed { error } => {
                2u8.encode(bytes);
                error.encode(bytes);
            }
        }
    }
}

impl Decode for TransitionTypeSpecificData {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        let trans_data = match val {
            0 => Self::Continued {
                payload: decode_u16_items(&(), bytes)?,
            },
            1 => Self::Finished,
            2 => Self::Failed {
                error: TransitionError::decode(bytes)?,
            },
            _ => {
                return Err(CodecError::Other(
                    anyhow!("unexpected TransitionType value {}", val).into(),
                ))
            }
        };

        Ok(trans_data)
    }
}

/// PPM protocol message representing an error while transitioning a VDAF's state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, ToSql, FromSql)]
#[repr(u8)]
pub enum TransitionError {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
    UnrecognizedNonce = 6,
}

impl Encode for TransitionError {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u8).encode(bytes);
    }
}

impl Decode for TransitionError {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(anyhow!("unexpected TransitionError value {}", val).into())
        })
    }
}

/// PPM protocol message representing an identifier for an aggregation job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregationJobId(pub(crate) [u8; Self::ENCODED_LEN]);

impl Encode for AggregationJobId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for AggregationJobId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut decoded = [0u8; 32];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl AggregationJobId {
    /// ENCODED_LEN is the length of an aggregation job ID in bytes when encoded.
    const ENCODED_LEN: usize = 32;

    /// Generate a random [`AggregationJobId`]
    pub fn random() -> Self {
        let mut buf = [0u8; Self::ENCODED_LEN];
        thread_rng().fill(&mut buf);
        Self(buf)
    }
}

/// PPM protocol message representing an aggregation request from the leader to a helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateReq {
    pub(crate) task_id: TaskId,
    pub(crate) job_id: AggregationJobId,
    pub(crate) body: AggregateReqBody,
}

impl Encode for AggregateReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);

        match &self.body {
            AggregateReqBody::AggregateInitReq { agg_param, seq } => {
                0u8.encode(bytes);
                encode_u16_items(bytes, &(), agg_param);
                encode_u16_items(bytes, &(), seq);
            }
            AggregateReqBody::AggregateContinueReq { seq } => {
                1u8.encode(bytes);
                encode_u16_items(bytes, &(), seq);
            }
        }
    }
}

impl Decode for AggregateReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;

        let msg_type = u8::decode(bytes)?;
        let body = match msg_type {
            0 => {
                let agg_param = decode_u16_items(&(), bytes)?;
                let seq = decode_u16_items(&(), bytes)?;
                AggregateReqBody::AggregateInitReq { agg_param, seq }
            }
            1 => {
                let seq = decode_u16_items(&(), bytes)?;
                AggregateReqBody::AggregateContinueReq { seq }
            }
            _ => {
                return Err(CodecError::Other(
                    anyhow!("unexpected AggregateReqType message type {}", msg_type).into(),
                ))
            }
        };

        Ok(AggregateReq {
            task_id,
            job_id,
            body,
        })
    }
}

/// PPM protocol (sub-)message indicating the "body" of an AggregateReq message, i.e. an
/// AggregateInitReq or AggregateContinueReq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AggregateReqBody {
    AggregateInitReq {
        agg_param: Vec<u8>,
        seq: Vec<ReportShare>,
    },
    AggregateContinueReq {
        seq: Vec<Transition>,
    },
}

/// PPM protocol message representing a helper's response to a request from the leader to initiate
/// or continue aggregation of a sequence of client reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateResp {
    pub(crate) seq: Vec<Transition>,
}

impl Encode for AggregateResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.seq);
    }
}

impl Decode for AggregateResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let seq = decode_u16_items(&(), bytes)?;
        Ok(Self { seq })
    }
}

/// PPM protocol message representing a request from the leader to a helper to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareReq {
    pub(crate) task_id: TaskId,
    pub(crate) batch_interval: Interval,
    pub(crate) report_count: u64,
    pub(crate) checksum: [u8; 32],
}

impl Encode for AggregateShareReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
        self.report_count.encode(bytes);
        bytes.extend_from_slice(&self.checksum);
    }
}

impl Decode for AggregateShareReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_interval = Interval::decode(bytes)?;
        let report_count = u64::decode(bytes)?;
        let mut checksum = [0u8; 32];
        bytes.read_exact(&mut checksum)?;

        Ok(Self {
            task_id,
            batch_interval,
            report_count,
            checksum,
        })
    }
}

/// PPM protocol message representing a helper's response to the leader's request to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareResp {
    pub(crate) encrypted_aggregate_share: HpkeCiphertext,
}

impl Encode for AggregateShareResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.encrypted_aggregate_share.encode(bytes);
    }
}

impl Decode for AggregateShareResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let encrypted_aggregate_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            encrypted_aggregate_share,
        })
    }
}

/// PPM protocol message representing a request from the collector to the leader to provide
/// aggregate shares for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectReq {
    pub(crate) task_id: TaskId,
    pub(crate) batch_interval: Interval,
    pub(crate) agg_param: Vec<u8>,
}

impl Encode for CollectReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
        encode_u16_items(bytes, &(), &self.agg_param);
    }
}

impl Decode for CollectReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_interval = Interval::decode(bytes)?;
        let agg_param = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            batch_interval,
            agg_param,
        })
    }
}

/// PPM protocol message representing a leader's response to the collector's request to provide
/// aggregate shares for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectResp {
    pub(crate) encrypted_agg_shares: Vec<HpkeCiphertext>,
}

impl Encode for CollectResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.encrypted_agg_shares);
    }
}

impl Decode for CollectResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let encrypted_agg_shares = decode_u16_items(&(), bytes)?;

        Ok(Self {
            encrypted_agg_shares,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref HMAC_KEY: hmac::Key = hmac::Key::new(
            HMAC_SHA256,
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        );
    }

    fn roundtrip_encoding<T>(vals_and_encodings: &[(T, &str)])
    where
        T: Encode + Decode + core::fmt::Debug + Eq,
    {
        for (val, hex_encoding) in vals_and_encodings {
            let mut encoded_val = Vec::new();
            val.encode(&mut encoded_val);
            let encoding = hex::decode(hex_encoding).unwrap();
            assert_eq!(encoding, encoded_val);
            let decoded_val = T::decode(&mut Cursor::new(&encoded_val)).unwrap();
            assert_eq!(val, &decoded_val);
        }
    }

    #[test]
    fn roundtrip_authenticated_request_encoding() {
        let msg = AggregateReq {
            task_id: TaskId([
                31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ]),
            job_id: AggregationJobId([u8::MIN; 32]),
            body: AggregateReqBody::AggregateInitReq {
                agg_param: Vec::from("012345"),
                seq: vec![
                    ReportShare {
                        nonce: Nonce {
                            time: Time(54321),
                            rand: 314,
                        },
                        extensions: vec![Extension {
                            extension_type: ExtensionType::Tbd,
                            extension_data: Vec::from("0123"),
                        }],
                        encrypted_input_share: HpkeCiphertext {
                            config_id: HpkeConfigId(42),
                            encapsulated_context: Vec::from("012345"),
                            payload: Vec::from("543210"),
                        },
                    },
                    ReportShare {
                        nonce: Nonce {
                            time: Time(73542),
                            rand: 515,
                        },
                        extensions: vec![Extension {
                            extension_type: ExtensionType::Tbd,
                            extension_data: Vec::from("3210"),
                        }],
                        encrypted_input_share: HpkeCiphertext {
                            config_id: HpkeConfigId(13),
                            encapsulated_context: Vec::from("abce"),
                            payload: Vec::from("abfd"),
                        },
                    },
                ],
            },
        };

        let want_encoded_msg = msg.get_encoded();
        let want_tag = hmac::sign(&*HMAC_KEY, &want_encoded_msg);

        let encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);
        let (got_encoded_msg, got_tag) =
            encoded_bytes.split_at(encoded_bytes.len() - SHA256_OUTPUT_LEN);
        assert_eq!(want_encoded_msg, got_encoded_msg);
        assert_eq!(want_tag.as_ref(), got_tag);

        let decoder = AuthenticatedRequestDecoder::new(encoded_bytes).unwrap();
        assert_eq!(msg.task_id, decoder.task_id());
        let got_msg = decoder.decode(&*HMAC_KEY).unwrap();
        assert_eq!(msg, got_msg);
    }

    #[test]
    fn authenticated_request_bad_tag() {
        let msg = AggregateReq {
            task_id: TaskId([u8::MIN; 32]),
            job_id: AggregationJobId([u8::MAX; 32]),
            body: AggregateReqBody::AggregateContinueReq { seq: Vec::new() },
        };

        let mut encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);

        // Verify we can decode the unmodified bytes back to the original message.
        let got_msg = AuthenticatedRequestDecoder::new(encoded_bytes.clone())
            .unwrap()
            .decode(&*HMAC_KEY)
            .unwrap();
        assert_eq!(msg, got_msg);

        // Verify that modifying the bytes causes decoding to fail.
        let ln = encoded_bytes.len();
        encoded_bytes[ln - 1] ^= 0xFF;
        let rslt: Result<AggregateReq, AuthenticatedDecodeError> =
            AuthenticatedRequestDecoder::new(encoded_bytes.clone())
                .unwrap()
                .decode(&*HMAC_KEY);
        assert_matches!(rslt, Err(AuthenticatedDecodeError::InvalidHmac));
    }

    #[test]
    fn roundtrip_authenticated_response_encoding() {
        let msg = AggregateResp {
            seq: vec![
                Transition {
                    nonce: Nonce {
                        time: Time(54372),
                        rand: 53,
                    },
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::from("012345"),
                    },
                },
                Transition {
                    nonce: Nonce {
                        time: Time(12345),
                        rand: 413,
                    },
                    trans_data: TransitionTypeSpecificData::Finished,
                },
            ],
        };

        let want_encoded_msg = msg.get_encoded();
        let want_tag = hmac::sign(&*HMAC_KEY, &want_encoded_msg);

        let encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);
        let (got_encoded_msg, got_tag) =
            encoded_bytes.split_at(encoded_bytes.len() - SHA256_OUTPUT_LEN);
        assert_eq!(want_encoded_msg, got_encoded_msg);
        assert_eq!(want_tag.as_ref(), got_tag);

        let decoder = AuthenticatedResponseDecoder::new(encoded_bytes).unwrap();
        let got_msg = decoder.decode(&*HMAC_KEY).unwrap();
        assert_eq!(msg, got_msg);
    }

    #[test]
    fn authenticated_response_bad_tag() {
        let msg = AggregateResp { seq: Vec::new() };

        let mut encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);

        // Verify we can decode the unmodified bytes back to the original message.
        let got_msg = AuthenticatedResponseDecoder::new(encoded_bytes.clone())
            .unwrap()
            .decode(&*HMAC_KEY)
            .unwrap();
        assert_eq!(msg, got_msg);

        // Verify that modifying the bytes causes decoding to fail.
        let ln = encoded_bytes.len();
        encoded_bytes[ln - 1] ^= 0xFF;
        let rslt: Result<AggregateReq, AuthenticatedDecodeError> =
            AuthenticatedResponseDecoder::new(encoded_bytes.clone())
                .unwrap()
                .decode(&*HMAC_KEY);
        assert_matches!(rslt, Err(AuthenticatedDecodeError::InvalidHmac));
    }

    #[test]
    fn roundtrip_duration() {
        roundtrip_encoding(&[
            (Duration(u64::MIN), "0000000000000000"),
            (Duration(12345), "0000000000003039"),
            (Duration(u64::MAX), "FFFFFFFFFFFFFFFF"),
        ])
    }

    #[test]
    fn roundtrip_time() {
        roundtrip_encoding(&[
            (Time(u64::MIN), "0000000000000000"),
            (Time(12345), "0000000000003039"),
            (Time(u64::MAX), "FFFFFFFFFFFFFFFF"),
        ])
    }

    #[test]
    fn roundtrip_interval() {
        roundtrip_encoding(&[
            (
                Interval {
                    start: Time(u64::MIN),
                    duration: Duration(u64::MAX),
                },
                concat!(
                    "0000000000000000", // start
                    "FFFFFFFFFFFFFFFF", // duration
                ),
            ),
            (
                Interval {
                    start: Time(54321),
                    duration: Duration(12345),
                },
                concat!(
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
            (
                Interval {
                    start: Time(u64::MAX),
                    duration: Duration(u64::MIN),
                },
                concat!(
                    "FFFFFFFFFFFFFFFF", // start
                    "0000000000000000", // duration
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_role() {
        roundtrip_encoding(&[
            (Role::Collector, "00"),
            (Role::Client, "01"),
            (Role::Leader, "02"),
            (Role::Helper, "03"),
        ]);
    }

    #[test]
    fn roundtrip_hpke_config_id() {
        roundtrip_encoding(&[
            (HpkeConfigId(u8::MIN), "00"),
            (HpkeConfigId(10), "0A"),
            (HpkeConfigId(u8::MAX), "FF"),
        ])
    }

    #[test]
    fn roundtrip_hpke_ciphertext() {
        roundtrip_encoding(&[
            (
                HpkeCiphertext {
                    config_id: HpkeConfigId(10),
                    encapsulated_context: Vec::from("0123"),
                    payload: Vec::from("4567"),
                },
                concat!(
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "0004",     // length
                        "34353637", // opaque data
                    ),
                ),
            ),
            (
                HpkeCiphertext {
                    config_id: HpkeConfigId(12),
                    encapsulated_context: Vec::from("01234"),
                    payload: Vec::from("567"),
                },
                concat!(
                    "0C", // config_id
                    concat!(
                        // encapsulated_context
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // payload
                        "0003",   // length
                        "353637", // opaque data
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_task_id() {
        roundtrip_encoding(&[
            (
                TaskId([u8::MIN; 32]),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                TaskId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                TaskId([u8::MAX; 32]),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
        ])
    }

    #[test]
    fn roundtrip_hpke_kem_id() {
        roundtrip_encoding(&[
            (HpkeKemId::P256HkdfSha256, "0010"),
            (HpkeKemId::X25519HkdfSha256, "0020"),
        ])
    }

    #[test]
    fn roundtrip_hpke_kdf_id() {
        roundtrip_encoding(&[
            (HpkeKdfId::HkdfSha256, "0001"),
            (HpkeKdfId::HkdfSha384, "0002"),
            (HpkeKdfId::HkdfSha512, "0003"),
        ])
    }

    #[test]
    fn roundtrip_hpke_aead_id() {
        roundtrip_encoding(&[
            (HpkeAeadId::Aes128Gcm, "0001"),
            (HpkeAeadId::Aes256Gcm, "0002"),
            (HpkeAeadId::ChaCha20Poly1305, "0003"),
        ])
    }

    #[test]
    fn roundtrip_hpke_public_key() {
        roundtrip_encoding(&[
            (
                HpkePublicKey(Vec::new()),
                concat!(
                    "0000", // length
                    "",     // opaque data
                ),
            ),
            (
                HpkePublicKey(Vec::from("0123456789abcdef")),
                concat!(
                    "0010",                             // length
                    "30313233343536373839616263646566"  // opaque data
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_hpke_config() {
        roundtrip_encoding(&[
            (
                HpkeConfig {
                    id: HpkeConfigId(12),
                    kem_id: HpkeKemId::P256HkdfSha256,
                    kdf_id: HpkeKdfId::HkdfSha512,
                    aead_id: HpkeAeadId::Aes256Gcm,
                    public_key: HpkePublicKey(Vec::new()),
                },
                concat!(
                    "0C",   // id
                    "0010", // kem_id
                    "0003", // kdf_id
                    "0002", // aead_id
                    concat!(
                        // public_key
                        "0000", // length
                        "",     // opaque data
                    )
                ),
            ),
            (
                HpkeConfig {
                    id: HpkeConfigId(23),
                    kem_id: HpkeKemId::X25519HkdfSha256,
                    kdf_id: HpkeKdfId::HkdfSha256,
                    aead_id: HpkeAeadId::ChaCha20Poly1305,
                    public_key: HpkePublicKey(Vec::from("0123456789abcdef")),
                },
                concat!(
                    "17",   // id
                    "0020", // kem_id
                    "0001", // kdf_id
                    "0003", // aead_id
                    concat!(
                        // public_key
                        "0010",                             // length
                        "30313233343536373839616263646566", // opaque data
                    )
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report() {
        roundtrip_encoding(&[
            (
                Report {
                    task_id: TaskId([u8::MIN; 32]),
                    nonce: Nonce {
                        time: Time(12345),
                        rand: 413,
                    },
                    extensions: vec![],
                    encrypted_input_shares: vec![],
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // nonce
                        "0000000000003039", // time
                        "000000000000019D", // rand
                    ),
                    concat!(
                        // extensions
                        "0000", // length
                    ),
                    concat!(
                        // encrypted_input_shares
                        "0000", // length
                    )
                ),
            ),
            (
                Report {
                    task_id: TaskId([u8::MAX; 32]),
                    nonce: Nonce {
                        time: Time(54321),
                        rand: 314,
                    },
                    extensions: vec![Extension {
                        extension_type: ExtensionType::Tbd,
                        extension_data: Vec::from("0123"),
                    }],
                    encrypted_input_shares: vec![
                        HpkeCiphertext {
                            config_id: HpkeConfigId(42),
                            encapsulated_context: Vec::from("012345"),
                            payload: Vec::from("543210"),
                        },
                        HpkeCiphertext {
                            config_id: HpkeConfigId(13),
                            encapsulated_context: Vec::from("abce"),
                            payload: Vec::from("abfd"),
                        },
                    ],
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                    concat!(
                        "000000000000D431", // time
                        "000000000000013A", // rand
                    ),
                    concat!(
                        // extensions
                        "0008", // length
                        concat!(
                            "0000", // extension_type
                            concat!(
                                // extension_data
                                "0004",     // length
                                "30313233", // opaque data
                            ),
                        )
                    ),
                    concat!(
                        // encrypted_input_shares
                        "001E", // length
                        concat!(
                            "2A", // config_id
                            concat!(
                                // encapsulated_context
                                "0006",         // length
                                "303132333435"  // opaque data
                            ),
                            concat!(
                                // payload
                                "0006",         // length
                                "353433323130", // opaque data
                            ),
                        ),
                        concat!(
                            "0D", // config_id
                            concat!(
                                // encapsulated_context
                                "0004",     // length
                                "61626365", // opaque data
                            ),
                            concat!(
                                // payload
                                "0004",     // length
                                "61626664", // opaque data
                            ),
                        ),
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_extension() {
        roundtrip_encoding(&[
            (
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::new(),
                },
                concat!(
                    "0000", // extension_type
                    concat!(
                        // extension_data
                        "0000", // length
                        "",     // opaque data
                    ),
                ),
            ),
            (
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::from("0123"),
                },
                concat!(
                    "0000", // extension_type
                    concat!(
                        // extension_data
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_extension_type() {
        roundtrip_encoding(&[(ExtensionType::Tbd, "0000")])
    }

    #[test]
    fn roundtrip_transition() {
        roundtrip_encoding(&[
            (
                Transition {
                    nonce: Nonce {
                        time: Time(54372),
                        rand: 53,
                    },
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::from("012345"),
                    },
                },
                concat!(
                    concat!(
                        // nonce
                        "000000000000D464", // time
                        "0000000000000035", // rand
                    ),
                    "00", // trans_type
                    concat!(
                        // payload
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
            (
                Transition {
                    nonce: Nonce {
                        time: Time(12345),
                        rand: 413,
                    },
                    trans_data: TransitionTypeSpecificData::Finished,
                },
                concat!(
                    concat!(
                        // nonce
                        "0000000000003039", // time
                        "000000000000019D", // rand
                    ),
                    "01", // trans_type
                ),
            ),
            (
                Transition {
                    nonce: Nonce {
                        time: Time(345078),
                        rand: 98345,
                    },
                    trans_data: TransitionTypeSpecificData::Failed {
                        error: TransitionError::UnrecognizedNonce,
                    },
                },
                concat!(
                    concat!(
                        // nonce
                        "00000000000543F6", // time
                        "0000000000018029", // rand
                    ),
                    "02", // trans_type
                    "06", // trans_error
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_transition_error() {
        roundtrip_encoding(&[
            (TransitionError::BatchCollected, "00"),
            (TransitionError::HpkeDecryptError, "04"),
            (TransitionError::HpkeUnknownConfigId, "03"),
            (TransitionError::ReportDropped, "02"),
            (TransitionError::ReportReplayed, "01"),
            (TransitionError::UnrecognizedNonce, "06"),
            (TransitionError::VdafPrepError, "05"),
        ])
    }

    #[test]
    fn roundtrip_aggregation_job_id() {
        roundtrip_encoding(&[
            (
                AggregationJobId([u8::MIN; 32]),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                AggregationJobId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                AggregationJobId([u8::MAX; 32]),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_req() {
        roundtrip_encoding(&[
            (
                AggregateReq {
                    task_id: TaskId([u8::MAX; 32]),
                    job_id: AggregationJobId([u8::MIN; 32]),
                    body: AggregateReqBody::AggregateInitReq {
                        agg_param: Vec::from("012345"),
                        seq: vec![
                            ReportShare {
                                nonce: Nonce {
                                    time: Time(54321),
                                    rand: 314,
                                },
                                extensions: vec![Extension {
                                    extension_type: ExtensionType::Tbd,
                                    extension_data: Vec::from("0123"),
                                }],
                                encrypted_input_share: HpkeCiphertext {
                                    config_id: HpkeConfigId(42),
                                    encapsulated_context: Vec::from("012345"),
                                    payload: Vec::from("543210"),
                                },
                            },
                            ReportShare {
                                nonce: Nonce {
                                    time: Time(73542),
                                    rand: 515,
                                },
                                extensions: vec![Extension {
                                    extension_type: ExtensionType::Tbd,
                                    extension_data: Vec::from("3210"),
                                }],
                                encrypted_input_share: HpkeCiphertext {
                                    config_id: HpkeConfigId(13),
                                    encapsulated_context: Vec::from("abce"),
                                    payload: Vec::from("abfd"),
                                },
                            },
                        ],
                    },
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                    "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                    "00",                                                               // msg_type
                    concat!(
                        // agg_init_req
                        concat!(
                            // agg_param
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                        concat!(
                            // seq
                            "0052", // length
                            concat!(
                                concat!(
                                    // nonce
                                    "000000000000D431", // time
                                    "000000000000013A", // rand
                                ),
                                concat!(
                                    // extensions
                                    "0008", // length
                                    concat!(
                                        "0000", // extension_type
                                        concat!(
                                            // extension_data
                                            "0004",     // length
                                            "30313233", // opaque data
                                        ),
                                    ),
                                ),
                                concat!(
                                    // encrypted_input_share
                                    "2A", // config_id
                                    concat!(
                                        // encapsulated_context
                                        "0006",         // length
                                        "303132333435", // opaque data
                                    ),
                                    concat!(
                                        // payload
                                        "0006",         // length
                                        "353433323130", // opaque data
                                    ),
                                ),
                            ),
                            concat!(
                                concat!(
                                    // nonce
                                    "0000000000011F46", // time
                                    "0000000000000203", // rand
                                ),
                                concat!(
                                    // extensions
                                    "0008", // length
                                    concat!(
                                        "0000", // extension_type
                                        concat!(
                                            // extension_data
                                            "0004",     // length
                                            "33323130", // opaque data
                                        ),
                                    ),
                                ),
                                concat!(
                                    "0D", // config_id
                                    concat!(
                                        // encapsulated_context
                                        "0004",     // length
                                        "61626365", // opaque data
                                    ),
                                    concat!(
                                        // payload
                                        "0004",     // length
                                        "61626664", // opaque data
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            (
                AggregateReq {
                    task_id: TaskId([u8::MIN; 32]),
                    job_id: AggregationJobId([u8::MAX; 32]),
                    body: AggregateReqBody::AggregateContinueReq {
                        seq: vec![
                            Transition {
                                nonce: Nonce {
                                    time: Time(54372),
                                    rand: 53,
                                },
                                trans_data: TransitionTypeSpecificData::Continued {
                                    payload: Vec::from("012345"),
                                },
                            },
                            Transition {
                                nonce: Nonce {
                                    time: Time(12345),
                                    rand: 413,
                                },
                                trans_data: TransitionTypeSpecificData::Finished,
                            },
                        ],
                    },
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                    "01",                                                               // msg_type
                    concat!(
                        // agg_continue_req
                        concat!(
                            // seq
                            "002A", // length
                            concat!(
                                concat!(
                                    // nonce
                                    "000000000000D464", // time
                                    "0000000000000035", // rand
                                ),
                                "00", // trans_type
                                concat!(
                                    // payload
                                    "0006",         // length
                                    "303132333435", // opaque data
                                ),
                            ),
                            concat!(
                                concat!(
                                    // nonce
                                    "0000000000003039", // time
                                    "000000000000019D", // rand
                                ),
                                "01", // trans_type
                            )
                        ),
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_resp() {
        roundtrip_encoding(&[
            (
                AggregateResp { seq: vec![] },
                concat!(concat!(
                    // seq
                    "0000", // length
                ),),
            ),
            (
                AggregateResp {
                    seq: vec![
                        Transition {
                            nonce: Nonce {
                                time: Time(54372),
                                rand: 53,
                            },
                            trans_data: TransitionTypeSpecificData::Continued {
                                payload: Vec::from("012345"),
                            },
                        },
                        Transition {
                            nonce: Nonce {
                                time: Time(12345),
                                rand: 413,
                            },
                            trans_data: TransitionTypeSpecificData::Finished,
                        },
                    ],
                },
                concat!(concat!(
                    //seq
                    "002A", // length
                    concat!(
                        concat!(
                            // nonce
                            "000000000000D464", // time
                            "0000000000000035", // rand
                        ),
                        "00", // trans_type
                        concat!(
                            // payload
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        concat!(
                            // nonce
                            "0000000000003039", // time
                            "000000000000019D", // rand
                        ),
                        "01", // trans_type
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_share_req() {
        roundtrip_encoding(&[
            (
                AggregateShareReq {
                    task_id: TaskId([u8::MIN; 32]),
                    batch_interval: Interval {
                        start: Time(54321),
                        duration: Duration(12345),
                    },
                    report_count: 439,
                    checksum: [u8::MIN; 32],
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    "00000000000001B7", // report_count
                    "0000000000000000000000000000000000000000000000000000000000000000", // checksum
                ),
            ),
            (
                AggregateShareReq {
                    task_id: TaskId([12u8; 32]),
                    batch_interval: Interval {
                        start: Time(50821),
                        duration: Duration(84354),
                    },
                    report_count: 8725,
                    checksum: [u8::MAX; 32],
                },
                concat!(
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
                    concat!(
                        // batch_interval
                        "000000000000C685", // start
                        "0000000000014982", // duration
                    ),
                    "0000000000002215", // report_count
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_share_resp() {
        roundtrip_encoding(&[
            (
                AggregateShareResp {
                    encrypted_aggregate_share: HpkeCiphertext {
                        config_id: HpkeConfigId(10),
                        encapsulated_context: Vec::from("0123"),
                        payload: Vec::from("4567"),
                    },
                },
                concat!(concat!(
                    // encrypted_aggregate_share
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "0004",     // length
                        "34353637", // opaque data
                    ),
                )),
            ),
            (
                AggregateShareResp {
                    encrypted_aggregate_share: HpkeCiphertext {
                        config_id: HpkeConfigId(12),
                        encapsulated_context: Vec::from("01234"),
                        payload: Vec::from("567"),
                    },
                },
                concat!(concat!(
                    // encrypted_aggregate_share
                    "0C", // config_id
                    concat!(
                        // encapsulated_context
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        "0003",   // length
                        "353637", // opaque data
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_collect_req() {
        roundtrip_encoding(&[
            (
                CollectReq {
                    task_id: TaskId([u8::MIN; 32]),
                    batch_interval: Interval {
                        start: Time(54321),
                        duration: Duration(12345),
                    },
                    agg_param: Vec::new(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id,
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    concat!(
                        // agg_param
                        "0000", // length
                        "",     // opaque data
                    ),
                ),
            ),
            (
                CollectReq {
                    task_id: TaskId([13u8; 32]),
                    batch_interval: Interval {
                        start: Time(48913),
                        duration: Duration(44721),
                    },
                    agg_param: Vec::from("012345"),
                },
                concat!(
                    "0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D", // task_id
                    concat!(
                        // batch_interval
                        "000000000000BF11", // start
                        "000000000000AEB1", // duration
                    ),
                    concat!(
                        // agg_param
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_collect_resp() {
        roundtrip_encoding(&[
            (
                CollectResp {
                    encrypted_agg_shares: Vec::new(),
                },
                concat!(concat!(
                    // encrypted_agg_shares
                    "0000", // length
                )),
            ),
            (
                CollectResp {
                    encrypted_agg_shares: vec![
                        HpkeCiphertext {
                            config_id: HpkeConfigId(10),
                            encapsulated_context: Vec::from("0123"),
                            payload: Vec::from("4567"),
                        },
                        HpkeCiphertext {
                            config_id: HpkeConfigId(12),
                            encapsulated_context: Vec::from("01234"),
                            payload: Vec::from("567"),
                        },
                    ],
                },
                concat!(concat!(
                    // encrypted_agg_shares
                    "001A", // length
                    concat!(
                        "0A", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // payload
                            "0004",     // length
                            "34353637", // opaque data
                        ),
                    ),
                    concat!(
                        "0C", // config_id
                        concat!(
                            // encapsulated_context
                            "0005",       // length
                            "3031323334", // opaque data
                        ),
                        concat!(
                            // payload
                            "0003",   // length
                            "353637", // opaque data
                        ),
                    )
                )),
            ),
        ])
    }
}
