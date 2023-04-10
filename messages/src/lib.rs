//! Messages defined by the [Distributed Aggregation Protocol][dap] with serialization and
//! deserialization support.
//!
//! [dap]: https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/

use self::query_type::{FixedSize, QueryType, TimeInterval};
use anyhow::anyhow;
use base64::{display::Base64Display, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use derivative::Derivative;
use num_enum::TryFromPrimitive;
use prio::codec::{
    decode_u16_items, decode_u32_items, encode_u16_items, encode_u32_items, CodecError, Decode,
    Encode,
};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{
    de::{self, Visitor},
    Deserialize, Serialize, Serializer,
};
use std::{
    fmt::{self, Debug, Display, Formatter},
    io::{Cursor, Read},
    num::TryFromIntError,
    str::FromStr,
};

pub mod problem_type;

/// Errors returned by functions and methods in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An invalid parameter was passed.
    #[error("{0}")]
    InvalidParameter(&'static str),
    /// An illegal arithmetic operation on a [`Time`] or [`Duration`].
    #[error("{0}")]
    IllegalTimeArithmetic(&'static str),
    /// An unsupported algorithm identifier was encountered.
    #[error("Unsupported {0} algorithm identifier {1}")]
    UnsupportedAlgorithmIdentifier(&'static str, u16),
}

/// DAP protocol message representing a duration with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Duration(u64);

impl Duration {
    pub const ZERO: Duration = Duration::from_seconds(0);

    /// Create a duration representing the provided number of seconds.
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Get the number of seconds this duration represents.
    pub fn as_seconds(&self) -> u64 {
        self.0
    }
}

impl Encode for Duration {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for Duration {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

impl Display for Duration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} seconds", self.0)
    }
}

/// DAP protocol message representing an instant in time with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Time(u64);

impl Time {
    /// Construct a [`Time`] representing the instant that is a given number of seconds after
    /// January 1st, 1970, at 0:00:00 UTC (i.e., the instant with the Unix timestamp of
    /// `timestamp`).
    pub const fn from_seconds_since_epoch(timestamp: u64) -> Self {
        Self(timestamp)
    }

    /// Get the number of seconds from January 1st, 1970, at 0:00:00 UTC to the instant represented
    /// by this [`Time`] (i.e., the Unix timestamp for the instant it represents).
    pub fn as_seconds_since_epoch(&self) -> u64 {
        self.0
    }

    /// Construct a [`Time`] representing an instant in the distant future.
    pub fn distant_future() -> Self {
        // Wednesday, March 14, 2255 4 PM GMT. This is well past the time used by MockClock, and
        // past any date at which Janus is likely to be run.
        Self::from_seconds_since_epoch(9000000000)
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

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for Time {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

/// DAP protocol message representing a half-open interval of time with a resolution of seconds;
/// the start of the interval is included while the end of the interval is excluded.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Interval {
    /// The start of the interval.
    start: Time,
    /// The length of the interval.
    duration: Duration,
}

impl Interval {
    /// Create a new [`Interval`] from the provided start and duration. Returns an error if the end
    /// of the interval cannot be represented as a [`Time`].
    pub fn new(start: Time, duration: Duration) -> Result<Self, Error> {
        start
            .0
            .checked_add(duration.0)
            .ok_or(Error::IllegalTimeArithmetic("duration overflows time"))?;

        Ok(Self { start, duration })
    }

    /// Returns a [`Time`] representing the included start of this interval.
    pub fn start(&self) -> &Time {
        &self.start
    }

    /// Get the duration of this interval.
    pub fn duration(&self) -> &Duration {
        &self.duration
    }
}

impl Encode for Interval {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.start.encode(bytes);
        self.duration.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.start.encoded_len()? + self.duration.encoded_len()?)
    }
}

impl Decode for Interval {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let start = Time::decode(bytes)?;
        let duration = Duration::decode(bytes)?;

        Self::new(start, duration).map_err(|e| CodecError::Other(Box::new(e)))
    }
}

impl Display for Interval {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "start: {} duration: {}", self.start, self.duration)
    }
}

/// DAP protocol message representing an ID uniquely identifying a batch, for fixed-size tasks.
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchId([u8; Self::LEN]);

impl BatchId {
    /// LEN is the length of a batch ID in bytes.
    pub const LEN: usize = 32;
}

impl From<[u8; Self::LEN]> for BatchId {
    fn from(batch_id: [u8; Self::LEN]) -> Self {
        Self(batch_id)
    }
}

impl<'a> TryFrom<&'a [u8]> for BatchId {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            "byte slice has incorrect length for BatchId"
        })?))
    }
}

impl AsRef<[u8; Self::LEN]> for BatchId {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Debug for BatchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BatchId({})",
            Base64Display::new(&self.0, &URL_SAFE_NO_PAD)
        )
    }
}

impl Display for BatchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

impl Encode for BatchId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(Self::LEN)
    }
}

impl Decode for BatchId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut batch_id = [0; Self::LEN];
        bytes.read_exact(&mut batch_id)?;
        Ok(Self(batch_id))
    }
}

impl Distribution<BatchId> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BatchId {
        BatchId(rng.gen())
    }
}

/// DAP protocol message representing an ID uniquely identifying a client report.
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReportId([u8; Self::LEN]);

impl ReportId {
    /// LEN is the length of a report ID in bytes.
    pub const LEN: usize = 16;
}

impl From<[u8; Self::LEN]> for ReportId {
    fn from(report_id: [u8; Self::LEN]) -> Self {
        Self(report_id)
    }
}

impl<'a> TryFrom<&'a [u8]> for ReportId {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            "byte slice has incorrect length for ReportId"
        })?))
    }
}

impl AsRef<[u8; Self::LEN]> for ReportId {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Debug for ReportId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReportId({})",
            Base64Display::new(&self.0, &URL_SAFE_NO_PAD)
        )
    }
}

impl Display for ReportId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

impl Encode for ReportId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(Self::LEN)
    }
}

impl Decode for ReportId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut report_id = [0; Self::LEN];
        bytes.read_exact(&mut report_id)?;
        Ok(Self(report_id))
    }
}

impl FromStr for ReportId {
    type Err = Box<dyn Debug>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|err| Box::new(err) as Box<dyn Debug>)?;
        Self::try_from(bytes.as_ref()).map_err(|err| Box::new(err) as Box<dyn Debug>)
    }
}

impl Distribution<ReportId> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> ReportId {
        ReportId(rng.gen())
    }
}

/// Checksum over DAP report IDs, defined in §4.4.4.3.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct ReportIdChecksum([u8; Self::LEN]);

impl ReportIdChecksum {
    /// LEN is the length of a report ID checksum in bytes.
    pub const LEN: usize = 32;
}

impl From<[u8; Self::LEN]> for ReportIdChecksum {
    fn from(checksum: [u8; Self::LEN]) -> Self {
        Self(checksum)
    }
}

impl<'a> TryFrom<&'a [u8]> for ReportIdChecksum {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            "byte slice has incorrect length for ReportIdChecksum"
        })?))
    }
}

impl AsRef<[u8]> for ReportIdChecksum {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for ReportIdChecksum {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Display for ReportIdChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Encode for ReportIdChecksum {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(Self::LEN)
    }
}

impl Decode for ReportIdChecksum {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut checksum = Self::default();
        bytes.read_exact(&mut checksum.0)?;

        Ok(checksum)
    }
}

#[cfg(feature = "test-util")]
impl Distribution<ReportIdChecksum> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> ReportIdChecksum {
        ReportIdChecksum(rng.gen())
    }
}

/// DAP protocol message representing the different roles that participants can adopt.
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
    pub fn is_aggregator(&self) -> bool {
        matches!(self, Role::Leader | Role::Helper)
    }

    /// If this [`Role`] is one of the aggregators, returns the index at which
    /// that aggregator's message or data can be found in various lists, or
    /// `None` if the role is not an aggregator.
    pub fn index(&self) -> Option<usize> {
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

    fn encoded_len(&self) -> Option<usize> {
        Some(1)
    }
}

impl Decode for Role {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected Role value {}", val).into()))
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// DAP protocol message representing an identifier for an HPKE config.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HpkeConfigId(u8);

impl Display for HpkeConfigId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encode for HpkeConfigId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for HpkeConfigId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u8::decode(bytes)?))
    }
}

impl From<u8> for HpkeConfigId {
    fn from(value: u8) -> HpkeConfigId {
        HpkeConfigId(value)
    }
}

impl From<HpkeConfigId> for u8 {
    fn from(id: HpkeConfigId) -> u8 {
        id.0
    }
}

impl Distribution<HpkeConfigId> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> HpkeConfigId {
        HpkeConfigId(rng.gen())
    }
}

/// DAP protocol message representing an identifier for a DAP task.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId([u8; Self::LEN]);

impl TaskId {
    /// LEN is the length of a task ID in bytes.
    pub const LEN: usize = 32;
}

impl Debug for TaskId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TaskId({})",
            Base64Display::new(&self.0, &URL_SAFE_NO_PAD)
        )
    }
}

impl Display for TaskId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

impl Encode for TaskId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(Self::LEN)
    }
}

impl Decode for TaskId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut decoded = [0u8; Self::LEN];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl From<[u8; Self::LEN]> for TaskId {
    fn from(task_id: [u8; Self::LEN]) -> Self {
        Self(task_id)
    }
}

impl<'a> TryFrom<&'a [u8]> for TaskId {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            "byte slice has incorrect length for TaskId"
        })?))
    }
}

impl AsRef<[u8; Self::LEN]> for TaskId {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl FromStr for TaskId {
    type Err = Box<dyn Debug>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|err| Box::new(err) as Box<dyn Debug>)?;
        Self::try_from(bytes.as_ref()).map_err(|err| Box::new(err) as Box<dyn Debug>)
    }
}

impl Distribution<TaskId> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> TaskId {
        TaskId(rng.gen())
    }
}

/// This customized implementation serializes a [`TaskId`] as a base64url-encoded string, instead
/// of as a byte array. This is more compact and ergonomic when serialized to YAML, and aligns with
/// other uses of base64url encoding in DAP.
impl Serialize for TaskId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(self.as_ref());
        serializer.serialize_str(&encoded)
    }
}

struct TaskIdVisitor;

impl<'de> Visitor<'de> for TaskIdVisitor {
    type Value = TaskId;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a base64url-encoded string that decodes to 32 bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<TaskId, E>
    where
        E: de::Error,
    {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| E::custom("invalid base64url value"))?;

        TaskId::try_from(decoded.as_slice()).map_err(|e| E::custom(e))
    }
}

/// This customized implementation deserializes a [`TaskId`] as a base64url-encoded string, instead
/// of as a byte array. This is more compact and ergonomic when serialized to YAML, and aligns with
/// other uses of base64url encoding in DAP.
impl<'de> Deserialize<'de> for TaskId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(TaskIdVisitor)
    }
}

/// DAP protocol message representing an HPKE key encapsulation mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKemId {
    /// NIST P-256 keys and HKDF-SHA256.
    P256HkdfSha256 = 0x0010,
    /// X25519 keys and HKDF-SHA256.
    X25519HkdfSha256 = 0x0020,
}

impl Encode for HpkeKemId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(2)
    }
}

impl Decode for HpkeKemId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(Error::UnsupportedAlgorithmIdentifier("HpkeKemId", val).into())
        })
    }
}

/// DAP protocol message representing an HPKE key derivation function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKdfId {
    /// HMAC Key Derivation Function SHA256.
    HkdfSha256 = 0x0001,
    /// HMAC Key Derivation Function SHA384.
    HkdfSha384 = 0x0002,
    /// HMAC Key Derivation Function SHA512.
    HkdfSha512 = 0x0003,
}

impl Encode for HpkeKdfId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(2)
    }
}

impl Decode for HpkeKdfId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(Error::UnsupportedAlgorithmIdentifier("HpkeKdfId", val).into())
        })
    }
}

/// DAP protocol message representing an HPKE AEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeAeadId {
    /// AES-128-GCM.
    Aes128Gcm = 0x0001,
    /// AES-256-GCM.
    Aes256Gcm = 0x0002,
    /// ChaCha20Poly1305.
    ChaCha20Poly1305 = 0x0003,
}

impl Encode for HpkeAeadId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(2)
    }
}

impl Decode for HpkeAeadId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(Error::UnsupportedAlgorithmIdentifier("HpkeAeadId", val).into())
        })
    }
}

/// DAP protocol message representing an arbitrary extension included in a client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: Vec<u8>,
}

impl Extension {
    /// Construct an extension from its type and payload.
    pub fn new(extension_type: ExtensionType, extension_data: Vec<u8>) -> Extension {
        Extension {
            extension_type,
            extension_data,
        }
    }

    /// Returns the type of this extension.
    pub fn extension_type(&self) -> &ExtensionType {
        &self.extension_type
    }

    /// Returns the unparsed data representing this extension.
    pub fn extension_data(&self) -> &[u8] {
        &self.extension_data
    }
}

impl Encode for Extension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.extension_type.encode(bytes);
        encode_u16_items(bytes, &(), &self.extension_data);
    }

    fn encoded_len(&self) -> Option<usize> {
        // Type, length prefix, and extension data.
        Some(self.extension_type.encoded_len()? + 2 + self.extension_data.len())
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

/// DAP protocol message representing the type of an extension included in a client report.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum ExtensionType {
    Tbd = 0,
}

impl Encode for ExtensionType {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(2)
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

/// DAP protocol message representing an HPKE ciphertext.
#[derive(Clone, Derivative, Eq, PartialEq)]
#[derivative(Debug)]
pub struct HpkeCiphertext {
    /// An identifier of the HPKE configuration used to seal the message.
    config_id: HpkeConfigId,
    /// An encasulated HPKE key.
    #[derivative(Debug = "ignore")]
    encapsulated_key: Vec<u8>,
    /// An HPKE ciphertext.
    #[derivative(Debug = "ignore")]
    payload: Vec<u8>,
}

impl HpkeCiphertext {
    /// Construct a HPKE ciphertext message from its components.
    pub fn new(
        config_id: HpkeConfigId,
        encapsulated_key: Vec<u8>,
        payload: Vec<u8>,
    ) -> HpkeCiphertext {
        HpkeCiphertext {
            config_id,
            encapsulated_key,
            payload,
        }
    }

    /// Get the configuration identifier associated with this ciphertext.
    pub fn config_id(&self) -> &HpkeConfigId {
        &self.config_id
    }

    /// Get the encapsulated key from this ciphertext message.
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }

    /// Get the encrypted payload from this ciphertext message.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Encode for HpkeCiphertext {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.config_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.encapsulated_key);
        encode_u32_items(bytes, &(), &self.payload);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            self.config_id.encoded_len()?
                + 2
                + self.encapsulated_key.len()
                + 4
                + self.payload.len(),
        )
    }
}

impl Decode for HpkeCiphertext {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let config_id = HpkeConfigId::decode(bytes)?;
        let encapsulated_key = decode_u16_items(&(), bytes)?;
        let payload = decode_u32_items(&(), bytes)?;

        Ok(Self {
            config_id,
            encapsulated_key,
            payload,
        })
    }
}

/// DAP protocol message representing an HPKE public key.
// TODO(#230): refactor HpkePublicKey & HpkeConfig to simplify usage
#[derive(Clone, PartialEq, Eq)]
pub struct HpkePublicKey(Vec<u8>);

impl From<Vec<u8>> for HpkePublicKey {
    fn from(key: Vec<u8>) -> Self {
        Self(key)
    }
}

impl AsRef<[u8]> for HpkePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for HpkePublicKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.0);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(2 + self.0.len())
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

/// This customized implementation serializes a [`HpkePublicKey`] as a base64url-encoded string,
/// instead of as a byte array. This is more compact and ergonomic when serialized to YAML.
impl Serialize for HpkePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(self.as_ref());
        serializer.serialize_str(&encoded)
    }
}

struct HpkePublicKeyVisitor;

impl<'de> Visitor<'de> for HpkePublicKeyVisitor {
    type Value = HpkePublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a base64url-encoded string")
    }

    fn visit_str<E>(self, value: &str) -> Result<HpkePublicKey, E>
    where
        E: de::Error,
    {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| E::custom("invalid base64url value"))?;
        Ok(HpkePublicKey::from(decoded))
    }
}

/// This customized implementation deserializes a [`HpkePublicKey`] as a base64url-encoded string,
/// instead of as a byte array. This is more compact and ergonomic when serialized to YAML.
impl<'de> Deserialize<'de> for HpkePublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(HpkePublicKeyVisitor)
    }
}

/// DAP protocol message representing an HPKE config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeConfig {
    id: HpkeConfigId,
    kem_id: HpkeKemId,
    kdf_id: HpkeKdfId,
    aead_id: HpkeAeadId,
    public_key: HpkePublicKey,
}

impl HpkeConfig {
    /// Construct a HPKE configuration message from its components.
    pub fn new(
        id: HpkeConfigId,
        kem_id: HpkeKemId,
        kdf_id: HpkeKdfId,
        aead_id: HpkeAeadId,
        public_key: HpkePublicKey,
    ) -> HpkeConfig {
        HpkeConfig {
            id,
            kem_id,
            kdf_id,
            aead_id,
            public_key,
        }
    }

    /// Returns the HPKE config ID associated with this HPKE configuration.
    pub fn id(&self) -> &HpkeConfigId {
        &self.id
    }

    /// Retrieve the key encapsulation mechanism algorithm identifier associated with this HPKE configuration.
    pub fn kem_id(&self) -> &HpkeKemId {
        &self.kem_id
    }

    /// Retrieve the key derivation function algorithm identifier associated with this HPKE configuration.
    pub fn kdf_id(&self) -> &HpkeKdfId {
        &self.kdf_id
    }

    /// Retrieve the AEAD algorithm identifier associated with this HPKE configuration.
    pub fn aead_id(&self) -> &HpkeAeadId {
        &self.aead_id
    }

    /// Retrieve the public key from this HPKE configuration.
    pub fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }
}

impl Encode for HpkeConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.id.encode(bytes);
        self.kem_id.encode(bytes);
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
        self.public_key.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            self.id.encoded_len()?
                + self.kem_id.encoded_len()?
                + self.kdf_id.encoded_len()?
                + self.aead_id.encoded_len()?
                + self.public_key.encoded_len()?,
        )
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

/// DAP protocol message representing a list of HPKE configurations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeConfigList(Vec<HpkeConfig>);

impl HpkeConfigList {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-hpke-config-list";

    /// Construct an HPKE configuration list.
    pub fn new(hpke_configs: Vec<HpkeConfig>) -> Self {
        Self(hpke_configs)
    }

    pub fn hpke_configs(&self) -> &[HpkeConfig] {
        &self.0
    }
}

impl Encode for HpkeConfigList {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.0);
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut length = 2;
        for hpke_config in self.0.iter() {
            length += hpke_config.encoded_len()?;
        }
        Some(length)
    }
}

impl Decode for HpkeConfigList {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(decode_u16_items(&(), bytes)?))
    }
}

/// DAP protocol message representing client report metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportMetadata {
    report_id: ReportId,
    time: Time,
}

impl ReportMetadata {
    /// Construct a report's metadata from its components.
    pub fn new(report_id: ReportId, time: Time) -> Self {
        Self { report_id, time }
    }

    /// Retrieve the report ID from this report metadata.
    pub fn id(&self) -> &ReportId {
        &self.report_id
    }

    /// Retrieve the client timestamp from this report metadata.
    pub fn time(&self) -> &Time {
        &self.time
    }
}

impl Encode for ReportMetadata {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.report_id.encode(bytes);
        self.time.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.report_id.encoded_len()? + self.time.encoded_len()?)
    }
}

impl Decode for ReportMetadata {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let report_id = ReportId::decode(bytes)?;
        let time = Time::decode(bytes)?;

        Ok(Self { report_id, time })
    }
}

/// DAP protocol message representing the plaintext of an input share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaintextInputShare {
    extensions: Vec<Extension>,
    payload: Vec<u8>,
}

impl PlaintextInputShare {
    /// Construct a plaintext input share from its components.
    pub fn new(extensions: Vec<Extension>, payload: Vec<u8>) -> Self {
        Self {
            extensions,
            payload,
        }
    }

    /// Retrieve the extensions from this plaintext input share.
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// Retrieve the payload from this plaintext input share.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Encode for PlaintextInputShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.extensions);
        encode_u32_items(bytes, &(), &self.payload);
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut length = 2;
        for extension in self.extensions.iter() {
            length += extension.encoded_len()?;
        }
        length += 4;
        length += self.payload.len();
        Some(length)
    }
}

impl Decode for PlaintextInputShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let extensions = decode_u16_items(&(), bytes)?;
        let payload = decode_u32_items(&(), bytes)?;

        Ok(Self {
            extensions,
            payload,
        })
    }
}

/// DAP protocol message representing a client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    metadata: ReportMetadata,
    public_share: Vec<u8>,
    leader_encrypted_input_share: HpkeCiphertext,
    helper_encrypted_input_share: HpkeCiphertext,
}

impl Report {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-report";

    /// Construct a report from its components.
    pub fn new(
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        leader_encrypted_input_share: HpkeCiphertext,
        helper_encrypted_input_share: HpkeCiphertext,
    ) -> Self {
        Self {
            metadata,
            public_share,
            leader_encrypted_input_share,
            helper_encrypted_input_share,
        }
    }

    /// Retrieve the metadata from this report.
    pub fn metadata(&self) -> &ReportMetadata {
        &self.metadata
    }

    /// Retrieve the public share from this report.
    pub fn public_share(&self) -> &[u8] {
        &self.public_share
    }

    /// Retrieve the encrypted leader input share from this report.
    pub fn leader_encrypted_input_share(&self) -> &HpkeCiphertext {
        &self.leader_encrypted_input_share
    }

    /// Retrieve the encrypted helper input share from this report.
    pub fn helper_encrypted_input_share(&self) -> &HpkeCiphertext {
        &self.helper_encrypted_input_share
    }
}

impl Encode for Report {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.metadata.encode(bytes);
        encode_u32_items(bytes, &(), &self.public_share);
        self.leader_encrypted_input_share.encode(bytes);
        self.helper_encrypted_input_share.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut length = self.metadata.encoded_len()?;
        length += 4;
        length += self.public_share.len();
        length += self.leader_encrypted_input_share.encoded_len()?;
        length += self.helper_encrypted_input_share.encoded_len()?;
        Some(length)
    }
}

impl Decode for Report {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let metadata = ReportMetadata::decode(bytes)?;
        let public_share = decode_u32_items(&(), bytes)?;
        let leader_encrypted_input_share = HpkeCiphertext::decode(bytes)?;
        let helper_encrypted_input_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            metadata,
            public_share,
            leader_encrypted_input_share,
            helper_encrypted_input_share,
        })
    }
}

/// DAP protocol message representing a fixed-size query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixedSizeQuery {
    ByBatchId { batch_id: BatchId },
    CurrentBatch,
}

impl Encode for FixedSizeQuery {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            FixedSizeQuery::ByBatchId { batch_id } => {
                0u8.encode(bytes);
                batch_id.encode(bytes);
            }
            FixedSizeQuery::CurrentBatch => 1u8.encode(bytes),
        }
    }

    fn encoded_len(&self) -> Option<usize> {
        match self {
            FixedSizeQuery::ByBatchId { batch_id } => Some(1 + batch_id.encoded_len()?),
            FixedSizeQuery::CurrentBatch => Some(1),
        }
    }
}

impl Decode for FixedSizeQuery {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let query_type = u8::decode(bytes)?;
        match query_type {
            0 => {
                let batch_id = BatchId::decode(bytes)?;
                Ok(FixedSizeQuery::ByBatchId { batch_id })
            }
            1 => Ok(FixedSizeQuery::CurrentBatch),
            _ => Err(CodecError::Other(
                anyhow!("unexpected FixedSizeQueryType value {}", query_type).into(),
            )),
        }
    }
}

/// Represents a query for a specific batch identifier, received from a Collector as part of the
/// collection flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query<Q: QueryType> {
    query_body: Q::QueryBody,
}

impl<Q: QueryType> Query<Q> {
    /// Constructs a new query from its components.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::new_time_interval`] or
    /// [`Self::new_fixed_size`].
    pub fn new(query_body: Q::QueryBody) -> Self {
        Self { query_body }
    }

    /// Gets the query body included in this query.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::batch_interval`] or
    /// [`Self::fixed_size_query`].
    pub fn query_body(&self) -> &Q::QueryBody {
        &self.query_body
    }
}

impl Query<TimeInterval> {
    /// Constructs a new query for a time-interval task.
    pub fn new_time_interval(batch_interval: Interval) -> Self {
        Self::new(batch_interval)
    }

    /// Gets the batch interval associated with this query.
    pub fn batch_interval(&self) -> &Interval {
        self.query_body()
    }
}

impl Query<FixedSize> {
    /// Constructs a new query for a fixed-size task.
    pub fn new_fixed_size(fixed_size_query: FixedSizeQuery) -> Self {
        Self::new(fixed_size_query)
    }

    /// Gets the fixed size query associated with this query.
    pub fn fixed_size_query(&self) -> &FixedSizeQuery {
        self.query_body()
    }
}

impl<Q: QueryType> Encode for Query<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Q::CODE.encode(bytes);
        self.query_body.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(1 + self.query_body.encoded_len()?)
    }
}

impl<Q: QueryType> Decode for Query<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let query_body = Q::QueryBody::decode(bytes)?;

        Ok(Self { query_body })
    }
}

/// DAP protocol message representing a request from the collector to the leader to provide
/// aggregate shares for a given batch.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct CollectionReq<Q: QueryType> {
    query: Query<Q>,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: Vec<u8>,
}

impl<Q: QueryType> CollectionReq<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-collect-req";

    /// Constructs a new collect request from its components.
    pub fn new(query: Query<Q>, aggregation_parameter: Vec<u8>) -> Self {
        Self {
            query,
            aggregation_parameter,
        }
    }

    /// Gets the query associated with this collect request.
    pub fn query(&self) -> &Query<Q> {
        &self.query
    }

    /// Gets the aggregation parameter associated with this collect request.
    pub fn aggregation_parameter(&self) -> &[u8] {
        &self.aggregation_parameter
    }
}

impl<Q: QueryType> Encode for CollectionReq<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.query.encode(bytes);
        encode_u32_items(bytes, &(), &self.aggregation_parameter);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.query.encoded_len()? + 4 + self.aggregation_parameter.len())
    }
}

impl<Q: QueryType> Decode for CollectionReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let query = Query::decode(bytes)?;
        let aggregation_parameter = decode_u32_items(&(), bytes)?;

        Ok(Self {
            query,
            aggregation_parameter,
        })
    }
}

/// DAP protocol message representing a partial batch selector, identifying a batch of interest in
/// cases where some query types can infer the selector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialBatchSelector<Q: QueryType> {
    batch_identifier: Q::PartialBatchIdentifier,
}

impl<Q: QueryType> PartialBatchSelector<Q> {
    /// Constructs a new partial batch selector.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::new_time_interval`] or
    /// [`Self::new_fixed_size`].
    pub fn new(batch_identifier: Q::PartialBatchIdentifier) -> Self {
        Self { batch_identifier }
    }

    /// Gets the batch identifier associated with this collect response.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::PartialBatchIdentifier {
        &self.batch_identifier
    }
}

impl PartialBatchSelector<TimeInterval> {
    /// Constructs a new partial batch selector for a time-interval task.
    pub fn new_time_interval() -> Self {
        Self::new(())
    }
}

impl PartialBatchSelector<FixedSize> {
    /// Constructs a new partial batch selector for a fixed-size task.
    pub fn new_fixed_size(batch_id: BatchId) -> Self {
        Self::new(batch_id)
    }

    /// Gets the batch ID associated with this partial batch selector.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<Q: QueryType> Encode for PartialBatchSelector<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Q::CODE.encode(bytes);
        self.batch_identifier.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(1 + self.batch_identifier.encoded_len()?)
    }
}

impl<Q: QueryType> Decode for PartialBatchSelector<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let batch_identifier = Q::PartialBatchIdentifier::decode(bytes)?;

        Ok(Self { batch_identifier })
    }
}

/// DAP protocol message representing an identifier for a collection.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CollectionJobId([u8; Self::LEN]);

impl CollectionJobId {
    /// LEN is the length of a collection ID in bytes.
    pub const LEN: usize = 16;
}

impl AsRef<[u8; Self::LEN]> for CollectionJobId {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for CollectionJobId {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            "byte slice has incorrect length for CollectionId"
        })?))
    }
}

impl FromStr for CollectionJobId {
    type Err = Box<dyn Debug>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|err| Box::new(err) as Box<dyn Debug>)?;
        Self::try_from(bytes.as_ref()).map_err(|err| Box::new(err) as Box<dyn Debug>)
    }
}

impl Debug for CollectionJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CollectionId({})",
            Base64Display::new(&self.0, &URL_SAFE_NO_PAD)
        )
    }
}

impl Display for CollectionJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

impl Distribution<CollectionJobId> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CollectionJobId {
        CollectionJobId(rng.gen())
    }
}

/// DAP protocol message representing a leader's response to the collector's request to provide
/// aggregate shares for a given query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection<Q: QueryType> {
    partial_batch_selector: PartialBatchSelector<Q>,
    report_count: u64,
    interval: Interval,
    leader_encrypted_agg_share: HpkeCiphertext,
    helper_encrypted_agg_share: HpkeCiphertext,
}

impl<Q: QueryType> Collection<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-collection";

    /// Constructs a new collection.
    pub fn new(
        partial_batch_selector: PartialBatchSelector<Q>,
        report_count: u64,
        interval: Interval,
        leader_encrypted_agg_share: HpkeCiphertext,
        helper_encrypted_agg_share: HpkeCiphertext,
    ) -> Self {
        Self {
            partial_batch_selector,
            report_count,
            interval,
            leader_encrypted_agg_share,
            helper_encrypted_agg_share,
        }
    }

    /// Retrieves the batch selector associated with this collection.
    pub fn partial_batch_selector(&self) -> &PartialBatchSelector<Q> {
        &self.partial_batch_selector
    }

    /// Retrieves the number of reports that were aggregated into this collection.
    pub fn report_count(&self) -> u64 {
        self.report_count
    }

    /// Retrieves the interval spanned by the reports aggregated into this collection.
    pub fn interval(&self) -> &Interval {
        &self.interval
    }

    /// Retrieves the leader encrypted aggregate share associated with this collection.
    pub fn leader_encrypted_aggregate_share(&self) -> &HpkeCiphertext {
        &self.leader_encrypted_agg_share
    }

    /// Retrieves the helper encrypted aggregate share associated with this collection.
    pub fn helper_encrypted_aggregate_share(&self) -> &HpkeCiphertext {
        &self.helper_encrypted_agg_share
    }
}

impl<Q: QueryType> Encode for Collection<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.partial_batch_selector.encode(bytes);
        self.report_count.encode(bytes);
        self.interval.encode(bytes);
        self.leader_encrypted_agg_share.encode(bytes);
        self.helper_encrypted_agg_share.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            self.partial_batch_selector.encoded_len()?
                + self.report_count.encoded_len()?
                + self.interval.encoded_len()?
                + self.leader_encrypted_agg_share.encoded_len()?
                + self.helper_encrypted_agg_share.encoded_len()?,
        )
    }
}

impl<Q: QueryType> Decode for Collection<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let partial_batch_selector = PartialBatchSelector::decode(bytes)?;
        let report_count = u64::decode(bytes)?;
        let interval = Interval::decode(bytes)?;
        let leader_encrypted_agg_share = HpkeCiphertext::decode(bytes)?;
        let helper_encrypted_agg_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            partial_batch_selector,
            report_count,
            interval,
            leader_encrypted_agg_share,
            helper_encrypted_agg_share,
        })
    }
}

/// DAP message representing the additional associated data for an input share encryption operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputShareAad {
    task_id: TaskId,
    metadata: ReportMetadata,
    public_share: Vec<u8>,
}

impl InputShareAad {
    /// Constructs a new input share AAD.
    pub fn new(task_id: TaskId, metadata: ReportMetadata, public_share: Vec<u8>) -> Self {
        Self {
            task_id,
            metadata,
            public_share,
        }
    }

    /// Retrieves the task ID associated with this input share AAD.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Retrieves the report metadata associated with this input share AAD.
    pub fn metadata(&self) -> &ReportMetadata {
        &self.metadata
    }

    /// Retrieves the public share associated with this input share AAD.
    pub fn public_share(&self) -> &[u8] {
        &self.public_share
    }
}

impl Encode for InputShareAad {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.metadata.encode(bytes);
        encode_u32_items(bytes, &(), &self.public_share);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            self.task_id.encoded_len()?
                + self.metadata.encoded_len()?
                + 4
                + self.public_share.len(),
        )
    }
}

impl Decode for InputShareAad {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let metadata = ReportMetadata::decode(bytes)?;
        let public_share = decode_u32_items(&(), bytes)?;

        Ok(Self {
            task_id,
            metadata,
            public_share,
        })
    }
}

/// DAP message representing the additional associated data for an aggregate share encryption
/// operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareAad<Q: QueryType> {
    task_id: TaskId,
    batch_selector: BatchSelector<Q>,
}

impl<Q: QueryType> AggregateShareAad<Q> {
    /// Constructs a new aggregate share AAD.
    pub fn new(task_id: TaskId, batch_selector: BatchSelector<Q>) -> Self {
        Self {
            task_id,
            batch_selector,
        }
    }

    /// Retrieves the task ID associated with this aggregate share AAD.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Retrieves the batch selector associated with this aggregate share AAD.
    pub fn batch_selector(&self) -> &BatchSelector<Q> {
        &self.batch_selector
    }
}

impl<Q: QueryType> Encode for AggregateShareAad<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_selector.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.task_id.encoded_len()? + self.batch_selector.encoded_len()?)
    }
}

impl<Q: QueryType> Decode for AggregateShareAad<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_selector = BatchSelector::decode(bytes)?;

        Ok(Self {
            task_id,
            batch_selector,
        })
    }
}

pub mod query_type {
    use crate::{Collection, FixedSizeQuery, Query};

    use super::{BatchId, Interval};
    use anyhow::anyhow;
    use num_enum::TryFromPrimitive;
    use prio::codec::{CodecError, Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::{
        fmt::{Debug, Display},
        hash::Hash,
        io::Cursor,
    };

    /// QueryType represents a DAP query type. This is a task-level configuration setting which
    /// determines how individual client reports are grouped together into batches for collection.
    pub trait QueryType: Clone + Debug + PartialEq + Eq + Send + Sync + 'static {
        /// The [`Code`] associated with this query type.
        const CODE: Code;

        /// The type of a batch identifier.
        type BatchIdentifier: Display
            + Debug
            + Clone
            + Hash
            + PartialEq
            + Eq
            + Encode
            + Decode
            + Send
            + Sync;

        /// The type of a batch identifier as it appears in a `PartialBatchSelector`. Will be either
        /// the same type as `BatchIdentifier`, or `()`.
        type PartialBatchIdentifier: Debug
            + Clone
            + Hash
            + PartialEq
            + Eq
            + Encode
            + Decode
            + Send
            + Sync;

        /// The type of the body of a [`Query`] for this query type.
        type QueryBody: Debug + Clone + PartialEq + Eq + Encode + Decode + Send + Sync;

        /// Computes the `PartialBatchIdentifier` corresponding to the given
        /// `BatchIdentifier`.
        fn partial_batch_identifier(
            batch_identifier: &Self::BatchIdentifier,
        ) -> &Self::PartialBatchIdentifier;

        /// Retrieves the batch identifier associated with an ongoing collection.
        fn batch_identifier_for_collection(
            query: &Query<Self>,
            collect_resp: &Collection<Self>,
        ) -> Self::BatchIdentifier;
    }

    /// Represents a `time-interval` DAP query type.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct TimeInterval;

    impl QueryType for TimeInterval {
        const CODE: Code = Code::TimeInterval;

        type BatchIdentifier = Interval;
        type PartialBatchIdentifier = ();
        type QueryBody = Interval;

        fn partial_batch_identifier(_: &Self::BatchIdentifier) -> &Self::PartialBatchIdentifier {
            &()
        }

        fn batch_identifier_for_collection(
            query: &Query<Self>,
            _: &Collection<Self>,
        ) -> Self::BatchIdentifier {
            *query.batch_interval()
        }
    }

    /// Represents a `fixed-size` DAP query type.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct FixedSize;

    impl QueryType for FixedSize {
        const CODE: Code = Code::FixedSize;

        type BatchIdentifier = BatchId;
        type PartialBatchIdentifier = BatchId;
        type QueryBody = FixedSizeQuery;

        fn partial_batch_identifier(
            batch_identifier: &Self::BatchIdentifier,
        ) -> &Self::PartialBatchIdentifier {
            batch_identifier
        }

        fn batch_identifier_for_collection(
            _: &Query<Self>,
            collect_resp: &Collection<Self>,
        ) -> Self::BatchIdentifier {
            *collect_resp.partial_batch_selector().batch_identifier()
        }
    }

    /// DAP protocol message representing the type of a query.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
    #[repr(u8)]
    pub enum Code {
        Reserved = 0,
        TimeInterval = 1,
        FixedSize = 2,
    }

    impl Code {
        pub fn decode_expecting_value(
            bytes: &mut Cursor<&[u8]>,
            expected_code: Code,
        ) -> Result<(), CodecError> {
            let code = Self::decode(bytes)?;
            if code != expected_code {
                return Err(CodecError::Other(
                    format!("unexpected query_type: {code:?} (expected {expected_code:?})").into(),
                ));
            }
            Ok(())
        }
    }

    impl Encode for Code {
        fn encode(&self, bytes: &mut Vec<u8>) {
            (*self as u8).encode(bytes);
        }

        fn encoded_len(&self) -> Option<usize> {
            Some(1)
        }
    }

    impl Decode for Code {
        fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
            let val = u8::decode(bytes)?;
            Self::try_from(val).map_err(|_| {
                CodecError::Other(anyhow!("unexpected QueryType value {}", val).into())
            })
        }
    }
}

/// DAP protocol message representing one aggregator's share of a single client report.
#[derive(Derivative, Clone, PartialEq, Eq)]
#[derivative(Debug)]
pub struct ReportShare {
    metadata: ReportMetadata,
    #[derivative(Debug = "ignore")]
    public_share: Vec<u8>,
    encrypted_input_share: HpkeCiphertext,
}

impl ReportShare {
    /// Constructs a new report share from its components.
    pub fn new(
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        encrypted_input_share: HpkeCiphertext,
    ) -> Self {
        Self {
            metadata,
            public_share,
            encrypted_input_share,
        }
    }

    /// Gets the metadata associated with this report share.
    pub fn metadata(&self) -> &ReportMetadata {
        &self.metadata
    }

    /// Gets the public share associated with this report share.
    pub fn public_share(&self) -> &[u8] {
        &self.public_share
    }

    /// Gets the encrypted input share associated with this report share.
    pub fn encrypted_input_share(&self) -> &HpkeCiphertext {
        &self.encrypted_input_share
    }
}

impl Encode for ReportShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.metadata.encode(bytes);
        encode_u32_items(bytes, &(), &self.public_share);
        self.encrypted_input_share.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            self.metadata.encoded_len()?
                + 4
                + self.public_share.len()
                + self.encrypted_input_share.encoded_len()?,
        )
    }
}

impl Decode for ReportShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let metadata = ReportMetadata::decode(bytes)?;
        let public_share = decode_u32_items(&(), bytes)?;
        let encrypted_input_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            metadata,
            public_share,
            encrypted_input_share,
        })
    }
}

/// DAP protocol message representing information required to initialize preparation of a report for
/// aggregation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportPrepInit {
    report_share: ReportShare,
    leader_prep_share: Vec<u8>,
}

impl ReportPrepInit {
    /// Constructs a new report preparation initialization message from its components.
    pub fn new(report_share: ReportShare, leader_prep_share: Vec<u8>) -> Self {
        Self {
            report_share,
            leader_prep_share,
        }
    }

    /// Gets the report share associated with this report prep init.
    pub fn report_share(&self) -> &ReportShare {
        &self.report_share
    }

    /// Gets the leader preparation share associated with this report prep init.
    pub fn leader_prep_share(&self) -> &[u8] {
        &self.leader_prep_share
    }
}

impl Encode for ReportPrepInit {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.report_share.encode(bytes);
        encode_u32_items(bytes, &(), &self.leader_prep_share);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.report_share.encoded_len()? + 4 + self.leader_prep_share.len())
    }
}

impl Decode for ReportPrepInit {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let report_share = ReportShare::decode(bytes)?;
        let leader_prep_share = decode_u32_items(&(), bytes)?;

        Ok(Self {
            report_share,
            leader_prep_share,
        })
    }
}

/// DAP protocol message representing the result of a preparation step in a VDAF evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareStep {
    report_id: ReportId,
    result: PrepareStepResult,
}

impl PrepareStep {
    /// Constructs a new prepare step from its components.
    pub fn new(report_id: ReportId, result: PrepareStepResult) -> Self {
        Self { report_id, result }
    }

    /// Gets the report ID associated with this prepare step.
    pub fn report_id(&self) -> &ReportId {
        &self.report_id
    }

    /// Gets the result associated with this prepare step.
    pub fn result(&self) -> &PrepareStepResult {
        &self.result
    }
}

impl Encode for PrepareStep {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.report_id.encode(bytes);
        self.result.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.report_id.encoded_len()? + self.result.encoded_len()?)
    }
}

impl Decode for PrepareStep {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let report_id = ReportId::decode(bytes)?;
        let result = PrepareStepResult::decode(bytes)?;

        Ok(Self { report_id, result })
    }
}

/// DAP protocol message representing result-type-specific data associated with a preparation step
/// in a VDAF evaluation. Included in a PrepareStep message.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub enum PrepareStepResult {
    Continued {
        #[derivative(Debug = "ignore")]
        prep_msg: Vec<u8>,
        #[derivative(Debug = "ignore")]
        prep_share: Vec<u8>,
    },
    Finished {
        #[derivative(Debug = "ignore")]
        prep_msg: Vec<u8>,
    },
    Failed(ReportShareError),
}

impl Encode for PrepareStepResult {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // The encoding includes an implicit discriminator byte, called PrepareStepResult in the
        // DAP spec.
        match self {
            Self::Continued {
                prep_msg,
                prep_share,
            } => {
                0u8.encode(bytes);
                encode_u32_items(bytes, &(), prep_msg);
                encode_u32_items(bytes, &(), prep_share);
            }
            Self::Finished { prep_msg } => {
                1u8.encode(bytes);
                encode_u32_items(bytes, &(), prep_msg);
            }
            Self::Failed(error) => {
                2u8.encode(bytes);
                error.encode(bytes);
            }
        }
    }

    fn encoded_len(&self) -> Option<usize> {
        match self {
            PrepareStepResult::Continued {
                prep_msg,
                prep_share,
            } => Some(1 + 4 + prep_msg.len() + 4 + prep_share.len()),
            PrepareStepResult::Finished { prep_msg } => Some(1 + 4 + prep_msg.len()),
            PrepareStepResult::Failed(error) => Some(1 + error.encoded_len()?),
        }
    }
}

impl Decode for PrepareStepResult {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Ok(match val {
            0 => {
                let prep_msg = decode_u32_items(&(), bytes)?;
                let prep_share = decode_u32_items(&(), bytes)?;
                Self::Continued {
                    prep_msg,
                    prep_share,
                }
            }
            1 => {
                let prep_msg = decode_u32_items(&(), bytes)?;
                Self::Finished { prep_msg }
            }
            2 => Self::Failed(ReportShareError::decode(bytes)?),
            _ => return Err(CodecError::UnexpectedValue),
        })
    }
}

/// DAP protocol message representing an error while preparing a report share for aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ReportShareError {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
    BatchSaturated = 6,
    TaskExpired = 7,
    UnrecognizedMessage = 8,
}

impl Encode for ReportShareError {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u8).encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(1)
    }
}

impl Decode for ReportShareError {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(anyhow!("unexpected ReportShareError value {}", val).into())
        })
    }
}

/// DAP protocol message representing an identifier for an aggregation job.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregationJobId([u8; Self::LEN]);

impl AggregationJobId {
    /// LEN is the length of an aggregation job ID in bytes.
    pub const LEN: usize = 16;
}

impl From<[u8; Self::LEN]> for AggregationJobId {
    fn from(aggregation_job_id: [u8; Self::LEN]) -> Self {
        Self(aggregation_job_id)
    }
}

impl<'a> TryFrom<&'a [u8]> for AggregationJobId {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            Error::InvalidParameter("byte slice has incorrect length for AggregationJobId")
        })?))
    }
}

impl AsRef<[u8; Self::LEN]> for AggregationJobId {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl FromStr for AggregationJobId {
    type Err = Box<dyn Debug>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|err| Box::new(err) as Box<dyn Debug>)?;
        Self::try_from(bytes.as_ref()).map_err(|err| Box::new(err) as Box<dyn Debug>)
    }
}

impl Debug for AggregationJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AggregationJobId({})",
            Base64Display::new(&self.0, &URL_SAFE_NO_PAD)
        )
    }
}

impl Display for AggregationJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

impl Distribution<AggregationJobId> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AggregationJobId {
        AggregationJobId(rng.gen())
    }
}

/// DAP protocol message representing an aggregation job initialization request from leader to
/// helper.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct AggregationJobInitializeReq<Q: QueryType> {
    #[derivative(Debug = "ignore")]
    aggregation_parameter: Vec<u8>,
    partial_batch_selector: PartialBatchSelector<Q>,
    report_inits: Vec<ReportPrepInit>,
}

impl<Q: QueryType> AggregationJobInitializeReq<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregation-job-init-req";

    /// Constructs an aggregate initialization request from its components.
    pub fn new(
        aggregation_parameter: Vec<u8>,
        partial_batch_selector: PartialBatchSelector<Q>,
        report_inits: Vec<ReportPrepInit>,
    ) -> Self {
        Self {
            aggregation_parameter,
            partial_batch_selector,
            report_inits,
        }
    }

    /// Gets the aggregation parameter associated with this aggregate initialization request.
    pub fn aggregation_parameter(&self) -> &[u8] {
        &self.aggregation_parameter
    }

    /// Gets the partial batch selector associated with this aggregate initialization request.
    pub fn batch_selector(&self) -> &PartialBatchSelector<Q> {
        &self.partial_batch_selector
    }

    /// Gets the report preparation initialization messages associated with this aggregate
    /// initialization request.
    pub fn report_inits(&self) -> &[ReportPrepInit] {
        &self.report_inits
    }
}

impl<Q: QueryType> Encode for AggregationJobInitializeReq<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u32_items(bytes, &(), &self.aggregation_parameter);
        self.partial_batch_selector.encode(bytes);
        encode_u32_items(bytes, &(), &self.report_inits);
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut length = 4 + self.aggregation_parameter.len();
        length += self.partial_batch_selector.encoded_len()?;
        length += 4;
        for report_init in &self.report_inits {
            length += report_init.encoded_len()?;
        }
        Some(length)
    }
}

impl<Q: QueryType> Decode for AggregationJobInitializeReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let aggregation_parameter = decode_u32_items(&(), bytes)?;
        let partial_batch_selector = PartialBatchSelector::decode(bytes)?;
        let report_inits = decode_u32_items(&(), bytes)?;

        Ok(Self {
            aggregation_parameter,
            partial_batch_selector,
            report_inits,
        })
    }
}

/// Type representing the round of an aggregation job.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AggregationJobRound(u16);

impl AggregationJobRound {
    /// Construct a new [`AggregationJobRound`] representing the round after this one.
    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl Display for AggregationJobRound {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encode for AggregationJobRound {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for AggregationJobRound {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u16::decode(bytes)?))
    }
}

impl From<u16> for AggregationJobRound {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<AggregationJobRound> for u16 {
    fn from(value: AggregationJobRound) -> Self {
        value.0
    }
}

impl TryFrom<i32> for AggregationJobRound {
    // This implementation is convenient for converting from the representation of a round in
    // PostgreSQL, where the smallest type that can store a u16 is `integer`, which is represented
    // as i32 in Rust.

    type Error = TryFromIntError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(AggregationJobRound(u16::try_from(value)?))
    }
}

/// DAP protocol message representing a request to continue an aggregation job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregationJobContinueReq {
    round: AggregationJobRound,
    prepare_steps: Vec<PrepareStep>,
}

impl AggregationJobContinueReq {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregation-job-continue-req";

    /// Constructs a new aggregate continuation response from its components.
    pub fn new(round: AggregationJobRound, prepare_steps: Vec<PrepareStep>) -> Self {
        Self {
            round,
            prepare_steps,
        }
    }

    /// Gets the round of VDAF preparation this aggregation job is on.
    pub fn round(&self) -> AggregationJobRound {
        self.round
    }

    /// Gets the prepare steps associated with this aggregate continuation response.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregationJobContinueReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.round.encode(bytes);
        encode_u32_items(bytes, &(), &self.prepare_steps);
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut length = self.round.encoded_len()?;
        length += 4;
        for prepare_step in self.prepare_steps.iter() {
            length += prepare_step.encoded_len()?;
        }
        Some(length)
    }
}

impl Decode for AggregationJobContinueReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let round = AggregationJobRound::decode(bytes)?;
        let prepare_steps = decode_u32_items(&(), bytes)?;
        Ok(Self::new(round, prepare_steps))
    }
}

/// DAP protocol message representing the response to an aggregation job initialization or
/// continuation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregationJobResp {
    prepare_steps: Vec<PrepareStep>,
}

impl AggregationJobResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregation-job-resp";

    /// Constructs a new aggregate continuation response from its components.
    pub fn new(prepare_steps: Vec<PrepareStep>) -> Self {
        Self { prepare_steps }
    }

    /// Gets the prepare steps associated with this aggregate continuation response.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregationJobResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u32_items(bytes, &(), &self.prepare_steps);
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut length = 4;
        for prepare_step in self.prepare_steps.iter() {
            length += prepare_step.encoded_len()?;
        }
        Some(length)
    }
}

impl Decode for AggregationJobResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let prepare_steps = decode_u32_items(&(), bytes)?;
        Ok(Self { prepare_steps })
    }
}

/// DAP protocol message identifying a batch of interest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSelector<Q: QueryType> {
    batch_identifier: Q::BatchIdentifier,
}

impl<Q: QueryType> BatchSelector<Q> {
    /// Constructs a new batch selector from its components.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::new_time_interval`] or
    /// [`Self::new_fixed_size`].
    pub fn new(batch_identifier: Q::BatchIdentifier) -> Self {
        Self { batch_identifier }
    }

    /// Gets the batch identifier associated with this batch selector.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::batch_interval`] or
    /// [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
        &self.batch_identifier
    }
}

impl BatchSelector<TimeInterval> {
    /// Constructs a new batch selector for time-interval tasks.
    pub fn new_time_interval(batch_interval: Interval) -> Self {
        Self::new(batch_interval)
    }

    /// Gets the batch interval associated with this batch selector.
    pub fn batch_interval(&self) -> &Interval {
        self.batch_identifier()
    }
}

impl BatchSelector<FixedSize> {
    /// Constructs a new batch selector for fixed-size tasks.
    pub fn new_fixed_size(batch_id: BatchId) -> Self {
        Self::new(batch_id)
    }

    /// Gets the batch ID associated with this batch selector.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<Q: QueryType> Encode for BatchSelector<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Q::CODE.encode(bytes);
        self.batch_identifier.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(1 + self.batch_identifier.encoded_len()?)
    }
}

impl<Q: QueryType> Decode for BatchSelector<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let batch_identifier = Q::BatchIdentifier::decode(bytes)?;

        Ok(Self { batch_identifier })
    }
}

/// DAP protocol message representing a request from the leader to a helper to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct AggregateShareReq<Q: QueryType> {
    batch_selector: BatchSelector<Q>,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: Vec<u8>,
    report_count: u64,
    checksum: ReportIdChecksum,
}

impl<Q: QueryType> AggregateShareReq<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-share-req";

    /// Constructs a new aggregate share request from its components.
    pub fn new(
        batch_selector: BatchSelector<Q>,
        aggregation_parameter: Vec<u8>,
        report_count: u64,
        checksum: ReportIdChecksum,
    ) -> Self {
        Self {
            batch_selector,
            aggregation_parameter,
            report_count,
            checksum,
        }
    }

    /// Gets the batch selector associated with this aggregate share request.
    pub fn batch_selector(&self) -> &BatchSelector<Q> {
        &self.batch_selector
    }

    /// Gets the aggregation parameter associated with this aggregate share request.
    pub fn aggregation_parameter(&self) -> &[u8] {
        &self.aggregation_parameter
    }

    /// Gets the report count associated with this aggregate share request.
    pub fn report_count(&self) -> u64 {
        self.report_count
    }

    /// Gets the checksum associated with this aggregate share request.
    pub fn checksum(&self) -> &ReportIdChecksum {
        &self.checksum
    }
}

impl<Q: QueryType> Encode for AggregateShareReq<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.batch_selector.encode(bytes);
        encode_u32_items(bytes, &(), &self.aggregation_parameter);
        self.report_count.encode(bytes);
        self.checksum.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            self.batch_selector.encoded_len()?
                + 4
                + self.aggregation_parameter.len()
                + self.report_count.encoded_len()?
                + self.checksum.encoded_len()?,
        )
    }
}

impl<Q: QueryType> Decode for AggregateShareReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let batch_selector = BatchSelector::decode(bytes)?;
        let aggregation_parameter = decode_u32_items(&(), bytes)?;
        let report_count = u64::decode(bytes)?;
        let checksum = ReportIdChecksum::decode(bytes)?;

        Ok(Self {
            batch_selector,
            aggregation_parameter,
            report_count,
            checksum,
        })
    }
}

/// DAP protocol message representing a helper's response to the leader's request to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShare {
    encrypted_aggregate_share: HpkeCiphertext,
}

impl AggregateShare {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-share";

    /// Constructs a new aggregate share response from its components.
    pub fn new(encrypted_aggregate_share: HpkeCiphertext) -> Self {
        Self {
            encrypted_aggregate_share,
        }
    }

    /// Gets the encrypted aggregate share associated with this aggregate share response.
    pub fn encrypted_aggregate_share(&self) -> &HpkeCiphertext {
        &self.encrypted_aggregate_share
    }
}

impl Encode for AggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.encrypted_aggregate_share.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        self.encrypted_aggregate_share.encoded_len()
    }
}

impl Decode for AggregateShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let encrypted_aggregate_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            encrypted_aggregate_share,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        query_type, AggregateShare, AggregateShareAad, AggregateShareReq,
        AggregationJobContinueReq, AggregationJobInitializeReq, AggregationJobResp,
        AggregationJobRound, BatchId, BatchSelector, Collection, CollectionReq, Duration,
        Extension, ExtensionType, FixedSize, FixedSizeQuery, HpkeAeadId, HpkeCiphertext,
        HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, InputShareAad, Interval,
        PartialBatchSelector, PlaintextInputShare, PrepareStep, PrepareStepResult, Query, Report,
        ReportId, ReportIdChecksum, ReportMetadata, ReportPrepInit, ReportShare, ReportShareError,
        Role, TaskId, Time, TimeInterval,
    };
    use assert_matches::assert_matches;
    use prio::codec::{CodecError, Decode, Encode};
    use serde_test::{assert_de_tokens_error, assert_tokens, Token};
    use std::{fmt::Debug, io::Cursor};

    fn roundtrip_encoding<T>(vals_and_encodings: &[(T, &str)])
    where
        T: Encode + Decode + Debug + Eq,
    {
        for (val, hex_encoding) in vals_and_encodings {
            let mut encoded_val = Vec::new();
            val.encode(&mut encoded_val);
            let encoding = hex::decode(hex_encoding).unwrap();
            assert_eq!(
                encoding, encoded_val,
                "Couldn't roundtrip (encoded value differs): {val:?}"
            );
            let decoded_val = T::decode(&mut Cursor::new(&encoded_val)).unwrap();
            assert_eq!(
                val, &decoded_val,
                "Couldn't roundtrip (decoded value differs): {val:?}"
            );
            assert_eq!(
                encoded_val.len(),
                val.encoded_len().expect("No encoded length hint"),
                "Encoded length hint is incorrect: {val:?}"
            )
        }
    }

    #[test]
    fn roundtrip_duration() {
        roundtrip_encoding(&[
            (Duration::from_seconds(u64::MIN), "0000000000000000"),
            (Duration::from_seconds(12345), "0000000000003039"),
            (Duration::from_seconds(u64::MAX), "FFFFFFFFFFFFFFFF"),
        ])
    }

    #[test]
    fn roundtrip_time() {
        roundtrip_encoding(&[
            (Time::from_seconds_since_epoch(u64::MIN), "0000000000000000"),
            (Time::from_seconds_since_epoch(12345), "0000000000003039"),
            (Time::from_seconds_since_epoch(u64::MAX), "FFFFFFFFFFFFFFFF"),
        ])
    }

    #[test]
    fn roundtrip_interval() {
        Interval::new(
            Time::from_seconds_since_epoch(1),
            Duration::from_seconds(u64::MAX),
        )
        .unwrap_err();

        let encoded = Interval {
            start: Time::from_seconds_since_epoch(1),
            duration: Duration::from_seconds(u64::MAX),
        }
        .get_encoded();
        assert_eq!(
            encoded,
            hex::decode(concat!(
                "0000000000000001", // start
                "FFFFFFFFFFFFFFFF", // duration))
            ))
            .unwrap()
        );

        assert_matches!(Interval::get_decoded(&encoded), Err(CodecError::Other(_)));

        roundtrip_encoding(&[
            (
                Interval {
                    start: Time::from_seconds_since_epoch(u64::MIN),
                    duration: Duration::from_seconds(u64::MAX),
                },
                concat!(
                    "0000000000000000", // start
                    "FFFFFFFFFFFFFFFF", // duration
                ),
            ),
            (
                Interval {
                    start: Time::from_seconds_since_epoch(54321),
                    duration: Duration::from_seconds(12345),
                },
                concat!(
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
            (
                Interval {
                    start: Time::from_seconds_since_epoch(u64::MAX),
                    duration: Duration::from_seconds(u64::MIN),
                },
                concat!(
                    "FFFFFFFFFFFFFFFF", // start
                    "0000000000000000", // duration
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_batch_id() {
        roundtrip_encoding(&[
            (
                BatchId::from([u8::MIN; BatchId::LEN]),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                BatchId::from([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                BatchId::from([u8::MAX; TaskId::LEN]),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
        ])
    }

    #[test]
    fn roundtrip_report_id() {
        roundtrip_encoding(&[
            (
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                "0102030405060708090a0b0c0d0e0f10",
            ),
            (
                ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                "100f0e0d0c0b0a090807060504030201",
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
    fn roundtrip_task_id() {
        roundtrip_encoding(&[
            (
                TaskId::from([u8::MIN; TaskId::LEN]),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                TaskId::from([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                TaskId::from([u8::MAX; TaskId::LEN]),
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
    fn roundtrip_extension() {
        roundtrip_encoding(&[
            (
                Extension::new(ExtensionType::Tbd, Vec::new()),
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
                Extension::new(ExtensionType::Tbd, Vec::from("0123")),
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
    fn roundtrip_hpke_ciphertext() {
        roundtrip_encoding(&[
            (
                HpkeCiphertext::new(HpkeConfigId::from(10), Vec::from("0123"), Vec::from("4567")),
                concat!(
                    "0A", // config_id
                    concat!(
                        // encapsulated_key
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "34353637", // opaque data
                    ),
                ),
            ),
            (
                HpkeCiphertext::new(HpkeConfigId::from(12), Vec::from("01234"), Vec::from("567")),
                concat!(
                    "0C", // config_id
                    concat!(
                        // encapsulated_key
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "353637",   // opaque data
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_hpke_public_key() {
        roundtrip_encoding(&[
            (
                HpkePublicKey::from(Vec::new()),
                concat!(
                    "0000", // length
                    "",     // opaque data
                ),
            ),
            (
                HpkePublicKey::from(Vec::from("0123456789abcdef")),
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
                HpkeConfig::new(
                    HpkeConfigId::from(12),
                    HpkeKemId::P256HkdfSha256,
                    HpkeKdfId::HkdfSha512,
                    HpkeAeadId::Aes256Gcm,
                    HpkePublicKey::from(Vec::new()),
                ),
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
                HpkeConfig::new(
                    HpkeConfigId::from(23),
                    HpkeKemId::X25519HkdfSha256,
                    HpkeKdfId::HkdfSha256,
                    HpkeAeadId::ChaCha20Poly1305,
                    HpkePublicKey::from(Vec::from("0123456789abcdef")),
                ),
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
    fn decode_unknown_hpke_algorithms() {
        let unknown_kem_id = hex::decode(concat!(
            "0C",   // id
            "9999", // kem_id
            "0003", // kdf_id
            "0002", // aead_id
            concat!(
                // public_key
                "0000", // length
                "",     // opaque data
            )
        ))
        .unwrap();

        let err = HpkeConfig::get_decoded(&unknown_kem_id).unwrap_err();
        assert_matches!(
            err,
            CodecError::Other(e) => assert_matches!(
                e.downcast::<super::Error>().unwrap().as_ref(),
                &super::Error::UnsupportedAlgorithmIdentifier("HpkeKemId", 0x9999)
            )
        );

        let unknown_kdf_id = hex::decode(concat!(
            "0C",   // id
            "0010", // kem_id
            "9999", // kdf_id
            "0002", // aead_id
            concat!(
                // public_key
                "0000", // length
                "",     // opaque data
            )
        ))
        .unwrap();

        let err = HpkeConfig::get_decoded(&unknown_kdf_id).unwrap_err();
        assert_matches!(
            err,
            CodecError::Other(e) => assert_matches!(
                e.downcast::<super::Error>().unwrap().as_ref(),
                &super::Error::UnsupportedAlgorithmIdentifier("HpkeKdfId", 0x9999)
            )
        );

        let unknown_aead_id = hex::decode(concat!(
            "0C",   // id
            "0010", // kem_id
            "0003", // kdf_id
            "9999", // aead_id
            concat!(
                // public_key
                "0000", // length
                "",     // opaque data
            )
        ))
        .unwrap();

        let err = HpkeConfig::get_decoded(&unknown_aead_id).unwrap_err();
        assert_matches!(
            err,
            CodecError::Other(e) => assert_matches!(
                e.downcast::<super::Error>().unwrap().as_ref(),
                &super::Error::UnsupportedAlgorithmIdentifier("HpkeAeadId", 0x9999)
            )
        );
    }

    #[test]
    fn roundtrip_report_metadata() {
        roundtrip_encoding(&[
            (
                ReportMetadata::new(
                    ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    Time::from_seconds_since_epoch(12345),
                ),
                concat!(
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "0000000000003039",                 // time
                ),
            ),
            (
                ReportMetadata::new(
                    ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                    Time::from_seconds_since_epoch(54321),
                ),
                concat!(
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "000000000000D431",                 // time
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_plaintext_input_share() {
        roundtrip_encoding(&[
            (
                PlaintextInputShare::new(Vec::new(), Vec::from("0123")),
                concat!(
                    concat!(
                        // extensions
                        "0000", // length
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "30313233", // opaque data
                    )
                ),
            ),
            (
                PlaintextInputShare::new(
                    Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
                    Vec::from("4567"),
                ),
                concat!(
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
                        // payload
                        "00000004", // length
                        "34353637", // opaque data
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report() {
        roundtrip_encoding(&[
            (
                Report::new(
                    ReportMetadata::new(
                        ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Time::from_seconds_since_epoch(12345),
                    ),
                    Vec::new(),
                    HpkeCiphertext::new(
                        HpkeConfigId::from(42),
                        Vec::from("012345"),
                        Vec::from("543210"),
                    ),
                    HpkeCiphertext::new(
                        HpkeConfigId::from(13),
                        Vec::from("abce"),
                        Vec::from("abfd"),
                    ),
                ),
                concat!(
                    concat!(
                        // metadata
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "0000000000003039",                 // time
                    ),
                    concat!(
                        // public_share
                        "00000000", // length
                    ),
                    concat!(
                        // leader_encrypted_input_share
                        "2A", // config_id
                        concat!(
                            // encapsulated_context
                            "0006",         // length
                            "303132333435"  // opaque data
                        ),
                        concat!(
                            // payload
                            "00000006",     // length
                            "353433323130", // opaque data
                        ),
                    ),
                    concat!(
                        // helper_encrypted_input_share
                        "0D", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "61626365", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "61626664", // opaque data
                        ),
                    ),
                ),
            ),
            (
                Report::new(
                    ReportMetadata::new(
                        ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                        Time::from_seconds_since_epoch(54321),
                    ),
                    Vec::from("3210"),
                    HpkeCiphertext::new(
                        HpkeConfigId::from(42),
                        Vec::from("012345"),
                        Vec::from("543210"),
                    ),
                    HpkeCiphertext::new(
                        HpkeConfigId::from(13),
                        Vec::from("abce"),
                        Vec::from("abfd"),
                    ),
                ),
                concat!(
                    concat!(
                        // metadata
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "000000000000D431",                 // time
                    ),
                    concat!(
                        // public_share
                        "00000004", // length
                        "33323130", // opaque data
                    ),
                    concat!(
                        // leader_encrypted_input_share
                        "2A", // config_id
                        concat!(
                            // encapsulated_context
                            "0006",         // length
                            "303132333435"  // opaque data
                        ),
                        concat!(
                            // payload
                            "00000006",     // length
                            "353433323130", // opaque data
                        ),
                    ),
                    concat!(
                        // helper_encrypted_input_share
                        "0D", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "61626365", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "61626664", // opaque data
                        ),
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_fixed_size_query() {
        roundtrip_encoding(&[
            (
                FixedSizeQuery::ByBatchId {
                    batch_id: BatchId::from([10u8; 32]),
                },
                concat!(
                    "00",                                                               // query_type
                    "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                ),
            ),
            (
                FixedSizeQuery::CurrentBatch,
                concat!(
                    "01", // query_type
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_query() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                Query::<TimeInterval> {
                    query_body: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                },
                concat!(
                    "01", // query_type
                    concat!(
                        // query_body
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                ),
            ),
            (
                Query::<TimeInterval> {
                    query_body: Interval::new(
                        Time::from_seconds_since_epoch(48913),
                        Duration::from_seconds(44721),
                    )
                    .unwrap(),
                },
                concat!(
                    "01", // query_type
                    concat!(
                        // query_body
                        "000000000000BF11", // start
                        "000000000000AEB1", // duration
                    ),
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                Query::<FixedSize> {
                    query_body: FixedSizeQuery::ByBatchId {
                        batch_id: BatchId::from([10u8; 32]),
                    },
                },
                concat!(
                    "02", // query_type
                    concat!(
                        // query_body
                        "00", // query_type
                        "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                    ),
                ),
            ),
            (
                Query::<FixedSize> {
                    query_body: FixedSizeQuery::CurrentBatch,
                },
                concat!(
                    "02", // query_type
                    concat!(
                        // query_body
                        "01", // query_type
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_collection_req() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                CollectionReq::<TimeInterval> {
                    query: Query {
                        query_body: Interval::new(
                            Time::from_seconds_since_epoch(54321),
                            Duration::from_seconds(12345),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::new(),
                },
                concat!(
                    concat!(
                        // query
                        "01", // query_type
                        concat!(
                            // query_body
                            "000000000000D431", // start
                            "0000000000003039", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000000", // length
                        "",         // opaque data
                    ),
                ),
            ),
            (
                CollectionReq::<TimeInterval> {
                    query: Query {
                        query_body: Interval::new(
                            Time::from_seconds_since_epoch(48913),
                            Duration::from_seconds(44721),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::from("012345"),
                },
                concat!(
                    concat!(
                        // query
                        "01", // query_type
                        concat!(
                            // batch_interval
                            "000000000000BF11", // start
                            "000000000000AEB1", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                CollectionReq::<FixedSize> {
                    query: Query {
                        query_body: FixedSizeQuery::ByBatchId {
                            batch_id: BatchId::from([10u8; 32]),
                        },
                    },
                    aggregation_parameter: Vec::new(),
                },
                concat!(
                    concat!(
                        "02", // query_type
                        concat!(
                            // query_body
                            "00", // query_type
                            "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000000", // length
                        "",         // opaque data
                    ),
                ),
            ),
            (
                CollectionReq::<FixedSize> {
                    query: Query::<FixedSize> {
                        query_body: FixedSizeQuery::CurrentBatch,
                    },
                    aggregation_parameter: Vec::from("012345"),
                },
                concat!(
                    concat!(
                        "02", // query_type
                        concat!(
                            // query_body
                            "01", // query_type
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
        ]);
    }

    #[test]
    fn roundtrip_partial_batch_selector() {
        // TimeInterval.
        roundtrip_encoding(&[(
            PartialBatchSelector::new_time_interval(),
            concat!(
                "01", // query_type
            ),
        )]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                PartialBatchSelector::new_fixed_size(BatchId::from([3u8; 32])),
                concat!(
                    "02",                                                               // query_type
                    "0303030303030303030303030303030303030303030303030303030303030303", // batch_id
                ),
            ),
            (
                PartialBatchSelector::new_fixed_size(BatchId::from([4u8; 32])),
                concat!(
                    "02",                                                               // query_type
                    "0404040404040404040404040404040404040404040404040404040404040404", // batch_id
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_collection() {
        let interval = Interval {
            start: Time::from_seconds_since_epoch(54321),
            duration: Duration::from_seconds(12345),
        };
        // TimeInterval.
        roundtrip_encoding(&[
            (
                Collection {
                    partial_batch_selector: PartialBatchSelector::new_time_interval(),
                    report_count: 0,
                    interval,
                    leader_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(10),
                        Vec::from("0123"),
                        Vec::from("4567"),
                    ),
                    helper_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(12),
                        Vec::from("01234"),
                        Vec::from("567"),
                    ),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "01", // query_type
                    ),
                    "0000000000000000", // report_count
                    concat!(
                        // interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    concat!(
                        // leader_encrypted_agg_share
                        "0A", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "34353637", // opaque data
                        ),
                    ),
                    concat!(
                        // helper_encrypted_agg_share
                        "0C", // config_id
                        concat!(
                            // encapsulated_context
                            "0005",       // length
                            "3031323334", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000003", // length
                            "353637",   // opaque data
                        ),
                    )
                ),
            ),
            (
                Collection {
                    partial_batch_selector: PartialBatchSelector::new_time_interval(),
                    report_count: 23,
                    interval,
                    leader_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(10),
                        Vec::from("0123"),
                        Vec::from("4567"),
                    ),
                    helper_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(12),
                        Vec::from("01234"),
                        Vec::from("567"),
                    ),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "01", // query_type
                    ),
                    "0000000000000017", // report_count
                    concat!(
                        // interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    concat!(
                        // leader_encrypted_agg_share
                        "0A", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "34353637", // opaque data
                        ),
                    ),
                    concat!(
                        // helper_encrypted_agg_share
                        "0C", // config_id
                        concat!(
                            // encapsulated_context
                            "0005",       // length
                            "3031323334", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000003", // length
                            "353637",   // opaque data
                        ),
                    )
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                Collection {
                    partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                        [3u8; 32],
                    )),
                    report_count: 0,
                    interval,
                    leader_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(10),
                        Vec::from("0123"),
                        Vec::from("4567"),
                    ),
                    helper_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(12),
                        Vec::from("01234"),
                        Vec::from("567"),
                    ),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "02", // query_type
                        "0303030303030303030303030303030303030303030303030303030303030303", // batch_id
                    ),
                    "0000000000000000", // report_count
                    concat!(
                        // interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    concat!(
                        // leader_encrypted_agg_share
                        "0A", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "34353637", // opaque data
                        ),
                    ),
                    concat!(
                        // helper_encrypted_agg_share
                        "0C", // config_id
                        concat!(
                            // encapsulated_context
                            "0005",       // length
                            "3031323334", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000003", // length
                            "353637",   // opaque data
                        ),
                    )
                ),
            ),
            (
                Collection {
                    partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                        [4u8; 32],
                    )),
                    report_count: 23,
                    interval,
                    leader_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(10),
                        Vec::from("0123"),
                        Vec::from("4567"),
                    ),
                    helper_encrypted_agg_share: HpkeCiphertext::new(
                        HpkeConfigId::from(12),
                        Vec::from("01234"),
                        Vec::from("567"),
                    ),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "02", // query_type
                        "0404040404040404040404040404040404040404040404040404040404040404", // batch_id
                    ),
                    "0000000000000017", // report_count
                    concat!(
                        // interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    concat!(
                        // leader_encrypted_agg_share
                        "0A", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "34353637", // opaque data
                        ),
                    ),
                    concat!(
                        // helper_encrypted_agg_share
                        "0C", // config_id
                        concat!(
                            // encapsulated_context
                            "0005",       // length
                            "3031323334", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000003", // length
                            "353637",   // opaque data
                        ),
                    )
                ),
            ),
        ]);
    }

    #[test]
    fn roundtrip_code() {
        roundtrip_encoding(&[
            (query_type::Code::Reserved, "00"),
            (query_type::Code::TimeInterval, "01"),
            (query_type::Code::FixedSize, "02"),
        ])
    }

    #[test]
    fn roundtrip_report_share() {
        roundtrip_encoding(&[
            (
                ReportShare {
                    metadata: ReportMetadata::new(
                        ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Time::from_seconds_since_epoch(54321),
                    ),
                    public_share: Vec::new(),
                    encrypted_input_share: HpkeCiphertext::new(
                        HpkeConfigId::from(42),
                        Vec::from("012345"),
                        Vec::from("543210"),
                    ),
                },
                concat!(
                    concat!(
                        // metadata
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "000000000000D431",                 // time
                    ),
                    concat!(
                        // public_share
                        "00000000", // length
                        "",         // opaque data
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
                            "00000006",     // length
                            "353433323130", // opaque data
                        ),
                    ),
                ),
            ),
            (
                ReportShare {
                    metadata: ReportMetadata::new(
                        ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                        Time::from_seconds_since_epoch(73542),
                    ),
                    public_share: Vec::from("0123"),
                    encrypted_input_share: HpkeCiphertext::new(
                        HpkeConfigId::from(13),
                        Vec::from("abce"),
                        Vec::from("abfd"),
                    ),
                },
                concat!(
                    concat!(
                        // metadata
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "0000000000011F46",                 // time
                    ),
                    concat!(
                        // public_share
                        "00000004", // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // encrypted_input_share
                        "0D", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "61626365", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "61626664", // opaque data
                        ),
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report_prep_init() {
        roundtrip_encoding(&[
            (
                ReportPrepInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                            Time::from_seconds_since_epoch(54321),
                        ),
                        public_share: Vec::new(),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    leader_prep_share: Vec::from("012345"),
                },
                concat!(
                    concat!(
                        // report_share
                        concat!(
                            // metadata
                            "0102030405060708090A0B0C0D0E0F10", // report_id
                            "000000000000D431",                 // time
                        ),
                        concat!(
                            // public_share
                            "00000000", // length
                            "",         // opaque data
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
                                "00000006",     // length
                                "353433323130", // opaque data
                            ),
                        ),
                    ),
                    concat!(
                        // leader_prep_share
                        "00000006",     // length
                        "303132333435", // opaque data
                    )
                ),
            ),
            (
                ReportPrepInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                            Time::from_seconds_since_epoch(73542),
                        ),
                        public_share: Vec::from("0123"),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                    leader_prep_share: Vec::new(),
                },
                concat!(
                    concat!(
                        // report_share
                        concat!(
                            // metadata
                            "100F0E0D0C0B0A090807060504030201", // report_id
                            "0000000000011F46",                 // time
                        ),
                        concat!(
                            // public_share
                            "00000004", // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // encrypted_input_share
                            "0D", // config_id
                            concat!(
                                // encapsulated_context
                                "0004",     // length
                                "61626365", // opaque data
                            ),
                            concat!(
                                // payload
                                "00000004", // length
                                "61626664", // opaque data
                            ),
                        ),
                    ),
                    concat!(
                        // leader_prep_share
                        "00000000", // length
                        ""          // opaque data
                    )
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_prepare_step() {
        roundtrip_encoding(&[
            (
                PrepareStep {
                    report_id: ReportId::from([
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    ]),
                    result: PrepareStepResult::Continued {
                        prep_msg: Vec::from("012345"),
                        prep_share: Vec::from("543210"),
                    },
                },
                concat!(
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "00",                               // prepare_step_result
                    concat!(
                        // prep_msg
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                    concat!(
                        // prep_share
                        "00000006",     // length
                        "353433323130", // opaque data
                    ),
                ),
            ),
            (
                PrepareStep {
                    report_id: ReportId::from([
                        16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                    ]),
                    result: PrepareStepResult::Finished {
                        prep_msg: Vec::from("012345"),
                    },
                },
                concat!(
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "01",                               // prepare_step_result
                    concat!(
                        // prep_msg
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
            (
                PrepareStep {
                    report_id: ReportId::from([255; 16]),
                    result: PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // report_id
                    "02",                               // prepare_step_result
                    "05",                               // report_share_error
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report_share_error() {
        roundtrip_encoding(&[
            (ReportShareError::BatchCollected, "00"),
            (ReportShareError::ReportReplayed, "01"),
            (ReportShareError::ReportDropped, "02"),
            (ReportShareError::HpkeUnknownConfigId, "03"),
            (ReportShareError::HpkeDecryptError, "04"),
            (ReportShareError::VdafPrepError, "05"),
        ])
    }

    #[test]
    fn roundtrip_aggregation_job_initialize_req() {
        // TimeInterval.
        roundtrip_encoding(&[(
            AggregationJobInitializeReq {
                aggregation_parameter: Vec::from("012345"),
                partial_batch_selector: PartialBatchSelector::new_time_interval(),
                report_inits: Vec::from([
                    ReportPrepInit {
                        report_share: ReportShare {
                            metadata: ReportMetadata::new(
                                ReportId::from([
                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                ]),
                                Time::from_seconds_since_epoch(54321),
                            ),
                            public_share: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                        leader_prep_share: Vec::from("012345"),
                    },
                    ReportPrepInit {
                        report_share: ReportShare {
                            metadata: ReportMetadata::new(
                                ReportId::from([
                                    16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                                ]),
                                Time::from_seconds_since_epoch(73542),
                            ),
                            public_share: Vec::from("0123"),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(13),
                                Vec::from("abce"),
                                Vec::from("abfd"),
                            ),
                        },
                        leader_prep_share: Vec::new(),
                    },
                ]),
            },
            concat!(
                concat!(
                    // aggregation_parameter
                    "00000006",     // length
                    "303132333435", // opaque data
                ),
                concat!(
                    // partial_batch_selector
                    "01", // query_type
                ),
                concat!(
                    // report_inits
                    "0000006C", // length
                    concat!(
                        concat!(
                            // report_share
                            concat!(
                                // metadata
                                "0102030405060708090A0B0C0D0E0F10", // report_id
                                "000000000000D431",                 // time
                            ),
                            concat!(
                                // public_share
                                "00000000", // length
                                "",         // opaque data
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
                                    "00000006",     // length
                                    "353433323130", // opaque data
                                ),
                            ),
                        ),
                        concat!(
                            // leader_prep_share
                            "00000006",     // length
                            "303132333435", // opaque data
                        )
                    ),
                    concat!(
                        concat!(
                            concat!(
                                // metadata
                                "100F0E0D0C0B0A090807060504030201", // report_id
                                "0000000000011F46",                 // time
                            ),
                            concat!(
                                // public_share
                                "00000004", // length
                                "30313233", // opaque data
                            ),
                            concat!(
                                // encrypted_input_share
                                "0D", // config_id
                                concat!(
                                    // encapsulated_context
                                    "0004",     // length
                                    "61626365", // opaque data
                                ),
                                concat!(
                                    // payload
                                    "00000004", // length
                                    "61626664", // opaque data
                                ),
                            ),
                        ),
                        concat!(
                            // leader_prep_share
                            "00000000", // length
                            ""          // opaque data
                        )
                    ),
                ),
            ),
        )]);

        // FixedSize.
        roundtrip_encoding(&[(
            AggregationJobInitializeReq::<FixedSize> {
                aggregation_parameter: Vec::from("012345"),
                partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                    [2u8; 32],
                )),
                report_inits: Vec::from([
                    ReportPrepInit {
                        report_share: ReportShare {
                            metadata: ReportMetadata::new(
                                ReportId::from([
                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                ]),
                                Time::from_seconds_since_epoch(54321),
                            ),
                            public_share: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                        leader_prep_share: Vec::from("012345"),
                    },
                    ReportPrepInit {
                        report_share: ReportShare {
                            metadata: ReportMetadata::new(
                                ReportId::from([
                                    16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                                ]),
                                Time::from_seconds_since_epoch(73542),
                            ),
                            public_share: Vec::from("0123"),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(13),
                                Vec::from("abce"),
                                Vec::from("abfd"),
                            ),
                        },
                        leader_prep_share: Vec::new(),
                    },
                ]),
            },
            concat!(
                concat!(
                    // aggregation_parameter
                    "00000006",     // length
                    "303132333435", // opaque data
                ),
                concat!(
                    // partial_batch_selector
                    "02", // query_type
                    "0202020202020202020202020202020202020202020202020202020202020202", // batch_id
                ),
                concat!(
                    // report_inits
                    "0000006C", // length
                    concat!(
                        concat!(
                            // report_share
                            concat!(
                                // metadata
                                "0102030405060708090A0B0C0D0E0F10", // report_id
                                "000000000000D431",                 // time
                            ),
                            concat!(
                                // public_share
                                "00000000", // length
                                "",         // opaque data
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
                                    "00000006",     // length
                                    "353433323130", // opaque data
                                ),
                            ),
                        ),
                        concat!(
                            // leader_prep_share
                            "00000006",     // length
                            "303132333435", // opaque data
                        )
                    ),
                    concat!(
                        concat!(
                            concat!(
                                // metadata
                                "100F0E0D0C0B0A090807060504030201", // report_id
                                "0000000000011F46",                 // time
                            ),
                            concat!(
                                // public_share
                                "00000004", // length
                                "30313233", // opaque data
                            ),
                            concat!(
                                // encrypted_input_share
                                "0D", // config_id
                                concat!(
                                    // encapsulated_context
                                    "0004",     // length
                                    "61626365", // opaque data
                                ),
                                concat!(
                                    // payload
                                    "00000004", // length
                                    "61626664", // opaque data
                                ),
                            ),
                        ),
                        concat!(
                            // leader_prep_share
                            "00000000", // length
                            ""          // opaque data
                        )
                    ),
                ),
            ),
        )])
    }

    #[test]
    fn roundtrip_aggregation_job_continue_req() {
        roundtrip_encoding(&[(
            AggregationJobContinueReq {
                round: AggregationJobRound(42405),
                prepare_steps: Vec::from([
                    PrepareStep {
                        report_id: ReportId::from([
                            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                        ]),
                        result: PrepareStepResult::Continued {
                            prep_msg: Vec::from("012345"),
                            prep_share: Vec::from("543210"),
                        },
                    },
                    PrepareStep {
                        report_id: ReportId::from([
                            16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                        ]),
                        result: PrepareStepResult::Finished {
                            prep_msg: Vec::from("012345"),
                        },
                    },
                ]),
            },
            concat!(
                "A5A5", // round
                concat!(
                    // prepare_steps
                    "00000040", // length
                    concat!(
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "00",                               // prepare_step_result
                        concat!(
                            // prep_msg
                            "00000006",     // length
                            "303132333435", // opaque data
                        ),
                        concat!(
                            // prep_share
                            "00000006",     // length
                            "353433323130", // opaque data
                        ),
                    ),
                    concat!(
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "01",                               // prepare_step_result
                        concat!(
                            // prep_msg
                            "00000006",     // length
                            "303132333435", // opaque data
                        ),
                    )
                ),
            ),
        )])
    }

    #[test]
    fn roundtrip_aggregation_job_resp() {
        roundtrip_encoding(&[(
            AggregationJobResp {
                prepare_steps: Vec::from([
                    PrepareStep {
                        report_id: ReportId::from([
                            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                        ]),
                        result: PrepareStepResult::Continued {
                            prep_msg: Vec::from("012345"),
                            prep_share: Vec::from("543210"),
                        },
                    },
                    PrepareStep {
                        report_id: ReportId::from([
                            16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                        ]),
                        result: PrepareStepResult::Finished {
                            prep_msg: Vec::from("012345"),
                        },
                    },
                ]),
            },
            concat!(concat!(
                // prepare_steps
                "00000040", // length
                concat!(
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "00",                               // prepare_step_result
                    concat!(
                        // prep_msg
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                    concat!(
                        // prep_share
                        "00000006",     // length
                        "353433323130", // opaque data
                    ),
                ),
                concat!(
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "01",                               // prepare_step_result
                    concat!(
                        // prep_msg
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                )
            ),),
        )])
    }

    #[test]
    fn roundtrip_batch_selector() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                BatchSelector::<TimeInterval> {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                },
                concat!(
                    "01", // query_type
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                ),
            ),
            (
                BatchSelector::<TimeInterval> {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(50821),
                        Duration::from_seconds(84354),
                    )
                    .unwrap(),
                },
                concat!(
                    "01", // query_type
                    concat!(
                        // batch_interval
                        "000000000000C685", // start
                        "0000000000014982", // duration
                    ),
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                BatchSelector::<FixedSize> {
                    batch_identifier: BatchId::from([12u8; 32]),
                },
                concat!(
                    // batch_selector
                    "02", // query_type
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // batch_id
                ),
            ),
            (
                BatchSelector::<FixedSize> {
                    batch_identifier: BatchId::from([7u8; 32]),
                },
                concat!(
                    "02",                                                               // query_type
                    "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_share_req() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                AggregateShareReq::<TimeInterval> {
                    batch_selector: BatchSelector {
                        batch_identifier: Interval::new(
                            Time::from_seconds_since_epoch(54321),
                            Duration::from_seconds(12345),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::new(),
                    report_count: 439,
                    checksum: ReportIdChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
                },
                concat!(
                    concat!(
                        // batch_selector
                        "01", // query_type
                        concat!(
                            // batch_interval
                            "000000000000D431", // start
                            "0000000000003039", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000000", // length
                        "",         // opaque data
                    ),
                    "00000000000001B7", // report_count
                    "0000000000000000000000000000000000000000000000000000000000000000", // checksum
                ),
            ),
            (
                AggregateShareReq::<TimeInterval> {
                    batch_selector: BatchSelector {
                        batch_identifier: Interval::new(
                            Time::from_seconds_since_epoch(50821),
                            Duration::from_seconds(84354),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::from("012345"),
                    report_count: 8725,
                    checksum: ReportIdChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
                },
                concat!(
                    concat!(
                        // batch_selector
                        "01", // query_type
                        concat!(
                            // batch_interval
                            "000000000000C685", // start
                            "0000000000014982", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                    "0000000000002215", // report_count
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                AggregateShareReq::<FixedSize> {
                    batch_selector: BatchSelector {
                        batch_identifier: BatchId::from([12u8; 32]),
                    },
                    aggregation_parameter: Vec::new(),
                    report_count: 439,
                    checksum: ReportIdChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
                },
                concat!(
                    concat!(
                        // batch_selector
                        "02", // query_type
                        "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // batch_id
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000000", // length
                        "",         // opaque data
                    ),
                    "00000000000001B7", // report_count
                    "0000000000000000000000000000000000000000000000000000000000000000", // checksum
                ),
            ),
            (
                AggregateShareReq::<FixedSize> {
                    batch_selector: BatchSelector {
                        batch_identifier: BatchId::from([7u8; 32]),
                    },
                    aggregation_parameter: Vec::from("012345"),
                    report_count: 8725,
                    checksum: ReportIdChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
                },
                concat!(
                    concat!(
                        // batch_selector
                        "02", // query_type
                        "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                    "0000000000002215", // report_count
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
                ),
            ),
        ]);
    }

    #[test]
    fn roundtrip_aggregate_share() {
        roundtrip_encoding(&[
            (
                AggregateShare {
                    encrypted_aggregate_share: HpkeCiphertext::new(
                        HpkeConfigId::from(10),
                        Vec::from("0123"),
                        Vec::from("4567"),
                    ),
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
                        "00000004", // length
                        "34353637", // opaque data
                    ),
                )),
            ),
            (
                AggregateShare {
                    encrypted_aggregate_share: HpkeCiphertext::new(
                        HpkeConfigId::from(12),
                        Vec::from("01234"),
                        Vec::from("567"),
                    ),
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
                        "00000003", // length
                        "353637",   // opaque data
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_input_share_aad() {
        roundtrip_encoding(&[(
            InputShareAad {
                task_id: TaskId::from([12u8; 32]),
                metadata: ReportMetadata::new(
                    ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    Time::from_seconds_since_epoch(54321),
                ),
                public_share: Vec::from("0123"),
            },
            concat!(
                "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
                concat!(
                    // metadata
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "000000000000D431",                 // time
                ),
                concat!(
                    // public_share
                    "00000004", // length
                    "30313233", // opaque data
                ),
            ),
        )])
    }

    #[test]
    fn roundtrip_aggregate_share_aad() {
        // TimeInterval.
        roundtrip_encoding(&[(
            AggregateShareAad::<TimeInterval> {
                task_id: TaskId::from([12u8; 32]),
                batch_selector: BatchSelector {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                },
            },
            concat!(
                "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
                concat!(
                    // batch_selector
                    "01", // query_type
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                ),
            ),
        )]);

        // FixedSize.
        roundtrip_encoding(&[(
            AggregateShareAad::<FixedSize> {
                task_id: TaskId::from([u8::MIN; 32]),
                batch_selector: BatchSelector {
                    batch_identifier: BatchId::from([7u8; 32]),
                },
            },
            concat!(
                "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                concat!(
                    // batch_selector
                    "02", // query_type
                    "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
                ),
            ),
        )])
    }

    #[test]
    fn taskid_serde() {
        assert_tokens(
            &TaskId::from([0; 32]),
            &[Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
        );
        assert_de_tokens_error::<TaskId>(
            &[Token::Str("/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
            "invalid base64url value",
        );
        assert_de_tokens_error::<TaskId>(
            &[Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
            "byte slice has incorrect length for TaskId",
        );
        assert_de_tokens_error::<TaskId>(
            &[Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
            "byte slice has incorrect length for TaskId",
        );
    }

    #[test]
    fn hpke_public_key_serde() {
        assert_tokens(
            &HpkePublicKey::from(Vec::from([1, 2, 3, 4])),
            &[Token::Str("AQIDBA")],
        );
        assert_de_tokens_error::<HpkePublicKey>(&[Token::Str("/AAAA")], "invalid base64url value");
    }
}
