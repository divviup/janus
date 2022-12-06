//! Messages defined by the [Distributed Aggregation Protocol][dap] with serialization and
//! deserialization support.
//!
//! [dap]: https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/

use self::query_type::{FixedSize, QueryType, TimeInterval};
use anyhow::anyhow;
use base64::{display::Base64Display, URL_SAFE_NO_PAD};
use derivative::Derivative;
use num_enum::TryFromPrimitive;
use prio::codec::{
    decode_u16_items, decode_u32_items, encode_u16_items, encode_u32_items, CodecError, Decode,
    Encode,
};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    io::{Cursor, Read},
    str::FromStr,
};

pub mod problem_type;

/// Errors returned by functions and methods in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An illegal arithmetic operation on a [`Time`] or [`Duration`].
    #[error("{0}")]
    IllegalTimeArithmetic(&'static str),
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
    pub fn as_seconds(self) -> u64 {
        self.0
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
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Display for BatchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Encode for BatchId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
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
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Display for ReportId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Encode for ReportId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for ReportId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut report_id = [0; Self::LEN];
        bytes.read_exact(&mut report_id)?;
        Ok(Self(report_id))
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
}

impl Decode for ReportIdChecksum {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut checksum = Self::default();
        bytes.read_exact(&mut checksum.0)?;

        Ok(checksum)
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

/// DAP protocol message representing an identifier for a DAP task.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Display for TaskId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Encode for TaskId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
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
    fn from(task_id: [u8; TaskId::LEN]) -> Self {
        Self(task_id)
    }
}

impl AsRef<[u8; Self::LEN]> for TaskId {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Distribution<TaskId> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> TaskId {
        TaskId(rng.gen())
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
}

impl Decode for HpkeKemId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKemId value {}", val).into()))
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
}

impl Decode for HpkeKdfId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKdfId value {}", val).into()))
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
}

impl Decode for HpkeAeadId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeAeadId value {}", val).into()))
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-hpke-config";

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
    task_id: TaskId,
    metadata: ReportMetadata,
    public_share: Vec<u8>,
    encrypted_input_shares: Vec<HpkeCiphertext>,
}

impl Report {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-report";

    /// Construct a report from its components.
    pub fn new(
        task_id: TaskId,
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        encrypted_input_shares: Vec<HpkeCiphertext>,
    ) -> Self {
        Self {
            task_id,
            metadata,
            public_share,
            encrypted_input_shares,
        }
    }

    /// Retrieve the task identifier from this report.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Retrieve the metadata from this report.
    pub fn metadata(&self) -> &ReportMetadata {
        &self.metadata
    }

    pub fn public_share(&self) -> &[u8] {
        &self.public_share
    }

    /// Get this report's encrypted input shares.
    pub fn encrypted_input_shares(&self) -> &[HpkeCiphertext] {
        &self.encrypted_input_shares
    }
}

impl Encode for Report {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.metadata.encode(bytes);
        encode_u32_items(bytes, &(), &self.public_share);
        encode_u32_items(bytes, &(), &self.encrypted_input_shares);
    }
}

impl Decode for Report {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let metadata = ReportMetadata::decode(bytes)?;
        let public_share = decode_u32_items(&(), bytes)?;
        let encrypted_input_shares = decode_u32_items(&(), bytes)?;

        Ok(Self {
            task_id,
            metadata,
            public_share,
            encrypted_input_shares,
        })
    }
}

/// Represents a query for a specific batch identifier, received from a Collector as part of the
/// collection flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query<Q: QueryType> {
    batch_identifier: Q::BatchIdentifier,
}

impl<Q: QueryType> Query<Q> {
    /// Constructs a new query from its components.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::new_time_interval`] or
    /// [`Self::new_fixed_size`].
    pub fn new(batch_identifier: Q::BatchIdentifier) -> Self {
        Self { batch_identifier }
    }

    /// Gets the batch identifier included in this query.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::batch_interval`] or
    /// [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
        &self.batch_identifier
    }
}

impl Query<TimeInterval> {
    /// Constructs a new query for a time-interval task.
    pub fn new_time_interval(batch_interval: Interval) -> Self {
        Self::new(batch_interval)
    }

    /// Gets the batch interval associated with this query.
    pub fn batch_interval(&self) -> &Interval {
        self.batch_identifier()
    }
}

impl Query<FixedSize> {
    /// Constructs a new query for a fixed-size task.
    pub fn new_fixed_size(batch_id: BatchId) -> Self {
        Self::new(batch_id)
    }

    /// Gets the batch ID associated with this query.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<Q: QueryType> Encode for Query<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Q::CODE.encode(bytes);
        self.batch_identifier.encode(bytes);
    }
}

impl<Q: QueryType> Decode for Query<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let batch_identifier = Q::BatchIdentifier::decode(bytes)?;

        Ok(Self { batch_identifier })
    }
}

/// DAP protocol message representing a request from the collector to the leader to provide
/// aggregate shares for a given batch.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct CollectReq<Q: QueryType> {
    task_id: TaskId,
    query: Query<Q>,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: Vec<u8>,
}

impl<Q: QueryType> CollectReq<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-collect-req";

    /// Constructs a new collect request from its components.
    pub fn new(task_id: TaskId, query: Query<Q>, aggregation_parameter: Vec<u8>) -> Self {
        Self {
            task_id,
            query,
            aggregation_parameter,
        }
    }

    /// Gets the task ID associated with this collect request.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
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

impl<Q: QueryType> Encode for CollectReq<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.query.encode(bytes);
        encode_u32_items(bytes, &(), &self.aggregation_parameter);
    }
}

impl<Q: QueryType> Decode for CollectReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let query = Query::decode(bytes)?;
        let aggregation_parameter = decode_u32_items(&(), bytes)?;

        Ok(Self {
            task_id,
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
}

impl<Q: QueryType> Decode for PartialBatchSelector<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let batch_identifier = Q::PartialBatchIdentifier::decode(bytes)?;

        Ok(Self { batch_identifier })
    }
}

/// DAP protocol message representing a leader's response to the collector's request to provide
/// aggregate shares for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectResp<Q: QueryType> {
    partial_batch_selector: PartialBatchSelector<Q>,
    report_count: u64,
    encrypted_aggregate_shares: Vec<HpkeCiphertext>,
}

impl<Q: QueryType> CollectResp<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-collect-resp";

    /// Constructs a new collect response.
    pub fn new(
        partial_batch_selector: PartialBatchSelector<Q>,
        report_count: u64,
        encrypted_aggregate_shares: Vec<HpkeCiphertext>,
    ) -> Self {
        Self {
            partial_batch_selector,
            report_count,
            encrypted_aggregate_shares,
        }
    }

    /// Gets the batch selector associated with this collect response.
    pub fn partial_batch_selector(&self) -> &PartialBatchSelector<Q> {
        &self.partial_batch_selector
    }

    /// Gets the report count associated with this collect response.
    pub fn report_count(&self) -> u64 {
        self.report_count
    }

    /// Gets the encrypted aggregate shares associated with this collect response.
    pub fn encrypted_aggregate_shares(&self) -> &[HpkeCiphertext] {
        &self.encrypted_aggregate_shares
    }
}

impl<Q: QueryType> Encode for CollectResp<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.partial_batch_selector.encode(bytes);
        self.report_count.encode(bytes);
        encode_u32_items(bytes, &(), &self.encrypted_aggregate_shares);
    }
}

impl<Q: QueryType> Decode for CollectResp<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let partial_batch_selector = PartialBatchSelector::decode(bytes)?;
        let report_count = u64::decode(bytes)?;
        let encrypted_aggregate_shares = decode_u32_items(&(), bytes)?;

        Ok(Self {
            partial_batch_selector,
            report_count,
            encrypted_aggregate_shares,
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

        /// Computes the `PartialBatchIdentifier` corresponding to the given
        /// `BatchIdentifier`.
        fn partial_batch_identifier(
            batch_identifier: &Self::BatchIdentifier,
        ) -> &Self::PartialBatchIdentifier;
    }

    /// Represents a `time-interval` DAP query type.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct TimeInterval;

    impl QueryType for TimeInterval {
        const CODE: Code = Code::TimeInterval;

        type BatchIdentifier = Interval;
        type PartialBatchIdentifier = ();

        fn partial_batch_identifier(_: &Self::BatchIdentifier) -> &Self::PartialBatchIdentifier {
            &()
        }
    }

    /// Represents a `fixed-size` DAP query type.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct FixedSize;

    impl QueryType for FixedSize {
        const CODE: Code = Code::FixedSize;

        type BatchIdentifier = BatchId;
        type PartialBatchIdentifier = BatchId;

        fn partial_batch_identifier(
            batch_identifier: &Self::BatchIdentifier,
        ) -> &Self::PartialBatchIdentifier {
            batch_identifier
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
    Continued(#[derivative(Debug = "ignore")] Vec<u8>), // content is a serialized preparation message
    Finished,
    Failed(ReportShareError),
}

impl Encode for PrepareStepResult {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // The encoding includes an implicit discriminator byte, called PrepareStepResult in the
        // DAP spec.
        match self {
            Self::Continued(vdaf_msg) => {
                0u8.encode(bytes);
                encode_u32_items(bytes, &(), vdaf_msg);
            }
            Self::Finished => 1u8.encode(bytes),
            Self::Failed(error) => {
                2u8.encode(bytes);
                error.encode(bytes);
            }
        }
    }
}

impl Decode for PrepareStepResult {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Ok(match val {
            0 => Self::Continued(decode_u32_items(&(), bytes)?),
            1 => Self::Finished,
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
    pub const LEN: usize = 32;
}

impl AsRef<[u8; Self::LEN]> for AggregationJobId {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Debug for AggregationJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AggregationJobId({})",
            Base64Display::with_config(&self.0, base64::URL_SAFE_NO_PAD)
        )
    }
}

impl Display for AggregationJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Base64Display::with_config(&self.0, base64::URL_SAFE_NO_PAD)
        )
    }
}

impl Encode for AggregationJobId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for AggregationJobId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut decoded = [0u8; Self::LEN];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl Distribution<AggregationJobId> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AggregationJobId {
        AggregationJobId(rng.gen())
    }
}

/// DAP protocol message representing an aggregation initialization request from leader to helper.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct AggregateInitializeReq<Q: QueryType> {
    task_id: TaskId,
    job_id: AggregationJobId,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: Vec<u8>,
    partial_batch_selector: PartialBatchSelector<Q>,
    report_shares: Vec<ReportShare>,
}

impl<Q: QueryType> AggregateInitializeReq<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-initialize-req";

    /// Constructs an aggregate initialization request from its components.
    pub fn new(
        task_id: TaskId,
        job_id: AggregationJobId,
        aggregation_parameter: Vec<u8>,
        partial_batch_selector: PartialBatchSelector<Q>,
        report_shares: Vec<ReportShare>,
    ) -> Self {
        Self {
            task_id,
            job_id,
            aggregation_parameter,
            partial_batch_selector,
            report_shares,
        }
    }

    /// Gets the task ID associated with this aggregate initialization request.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the aggregation job ID associated with this aggregate initialization request.
    pub fn job_id(&self) -> &AggregationJobId {
        &self.job_id
    }

    /// Gets the aggregation parameter associated with this aggregate initialization request.
    pub fn aggregation_parameter(&self) -> &[u8] {
        &self.aggregation_parameter
    }

    /// Gets the partial batch selector associated with this aggregate initialization request.
    pub fn batch_selector(&self) -> &PartialBatchSelector<Q> {
        &self.partial_batch_selector
    }

    /// Gets the report shares associated with this aggregate initialization request.
    pub fn report_shares(&self) -> &[ReportShare] {
        &self.report_shares
    }
}

impl<Q: QueryType> Encode for AggregateInitializeReq<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);
        encode_u32_items(bytes, &(), &self.aggregation_parameter);
        self.partial_batch_selector.encode(bytes);
        encode_u32_items(bytes, &(), &self.report_shares);
    }
}

impl<Q: QueryType> Decode for AggregateInitializeReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;
        let aggregation_parameter = decode_u32_items(&(), bytes)?;
        let partial_batch_selector = PartialBatchSelector::decode(bytes)?;
        let report_shares = decode_u32_items(&(), bytes)?;

        Ok(Self {
            task_id,
            job_id,
            aggregation_parameter,
            partial_batch_selector,
            report_shares,
        })
    }
}

/// DAP protocol message representing an aggregation initialization response from helper to leader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateInitializeResp {
    prepare_steps: Vec<PrepareStep>,
}

impl AggregateInitializeResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-initialize-resp";

    /// Constructs a new aggregate initialization response from its components.
    pub fn new(prepare_steps: Vec<PrepareStep>) -> Self {
        Self { prepare_steps }
    }

    /// Gets the prepare steps associated with this aggregate initialization response.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregateInitializeResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u32_items(bytes, &(), &self.prepare_steps);
    }
}

impl Decode for AggregateInitializeResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let prepare_steps = decode_u32_items(&(), bytes)?;
        Ok(Self { prepare_steps })
    }
}

/// DAP protocol message representing an aggregation continuation request from leader to helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueReq {
    task_id: TaskId,
    job_id: AggregationJobId,
    prepare_steps: Vec<PrepareStep>,
}

impl AggregateContinueReq {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-continue-req";

    /// Constructs a new aggregate continuation request from its components.
    pub fn new(task_id: TaskId, job_id: AggregationJobId, prepare_steps: Vec<PrepareStep>) -> Self {
        Self {
            task_id,
            job_id,
            prepare_steps,
        }
    }

    /// Gets the task ID associated with this aggregate continuation request.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the aggregation job ID associated with this aggregate continuation request.
    pub fn job_id(&self) -> &AggregationJobId {
        &self.job_id
    }

    /// Gets the prepare steps associated with this aggregate continuation request.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregateContinueReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);
        encode_u32_items(bytes, &(), &self.prepare_steps);
    }
}

impl Decode for AggregateContinueReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;
        let prepare_steps = decode_u32_items(&(), bytes)?;
        Ok(Self {
            task_id,
            job_id,
            prepare_steps,
        })
    }
}

/// DAP protocol message representing an aggregation continue response from helper to leader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueResp {
    prepare_steps: Vec<PrepareStep>,
}

impl AggregateContinueResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-continue-resp";

    /// Constructs a new aggregate continuation response from its components.
    pub fn new(prepare_steps: Vec<PrepareStep>) -> Self {
        Self { prepare_steps }
    }

    /// Gets the prepare steps associated with this aggregate continuation response.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregateContinueResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u32_items(bytes, &(), &self.prepare_steps);
    }
}

impl Decode for AggregateContinueResp {
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
    task_id: TaskId,
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
        task_id: TaskId,
        batch_selector: BatchSelector<Q>,
        aggregation_parameter: Vec<u8>,
        report_count: u64,
        checksum: ReportIdChecksum,
    ) -> Self {
        Self {
            task_id,
            batch_selector,
            aggregation_parameter,
            report_count,
            checksum,
        }
    }

    /// Gets the task ID associated with this aggregate share request.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
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
        self.task_id.encode(bytes);
        self.batch_selector.encode(bytes);
        encode_u32_items(bytes, &(), &self.aggregation_parameter);
        self.report_count.encode(bytes);
        self.checksum.encode(bytes);
    }
}

impl<Q: QueryType> Decode for AggregateShareReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_selector = BatchSelector::decode(bytes)?;
        let aggregation_parameter = decode_u32_items(&(), bytes)?;
        let report_count = u64::decode(bytes)?;
        let checksum = ReportIdChecksum::decode(bytes)?;

        Ok(Self {
            task_id,
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
pub struct AggregateShareResp {
    encrypted_aggregate_share: HpkeCiphertext,
}

impl AggregateShareResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-share-resp";

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

#[cfg(test)]
mod tests {
    use crate::{
        query_type::{self, FixedSize, TimeInterval},
        AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq,
        AggregateInitializeResp, AggregateShareAad, AggregateShareReq, AggregateShareResp,
        AggregationJobId, BatchId, BatchSelector, CollectReq, CollectResp, Duration, Extension,
        ExtensionType, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId,
        HpkePublicKey, InputShareAad, Interval, PartialBatchSelector, PlaintextInputShare,
        PrepareStep, PrepareStepResult, Query, Report, ReportId, ReportIdChecksum, ReportMetadata,
        ReportShare, ReportShareError, Role, TaskId, Time,
    };
    use assert_matches::assert_matches;
    use prio::codec::{CodecError, Decode, Encode};
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
                    TaskId::from([u8::MIN; TaskId::LEN]),
                    ReportMetadata::new(
                        ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Time::from_seconds_since_epoch(12345),
                    ),
                    Vec::new(),
                    Vec::new(),
                ),
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
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
                        // encrypted_input_shares
                        "00000000", // length
                    )
                ),
            ),
            (
                Report::new(
                    TaskId::from([u8::MAX; TaskId::LEN]),
                    ReportMetadata::new(
                        ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                        Time::from_seconds_since_epoch(54321),
                    ),
                    Vec::from("3210"),
                    Vec::from([
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
                    ]),
                ),
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
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
                        // encrypted_input_shares
                        "00000022", // length
                        concat!(
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
            ),
        ])
    }

    #[test]
    fn roundtrip_query() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                Query::<TimeInterval> {
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
                Query::<TimeInterval> {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(48913),
                        Duration::from_seconds(44721),
                    )
                    .unwrap(),
                },
                concat!(
                    "01", // query_type
                    concat!(
                        // batch_interval
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
                    batch_identifier: BatchId::from([10u8; 32]),
                },
                concat!(
                    "02",                                                               // query_type
                    "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                ),
            ),
            (
                Query::<FixedSize> {
                    batch_identifier: BatchId::from([8u8; 32]),
                },
                concat!(
                    "02",                                                               // query_type
                    "0808080808080808080808080808080808080808080808080808080808080808", // batch_id
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_collect_req() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                CollectReq::<TimeInterval> {
                    task_id: TaskId::from([u8::MIN; 32]),
                    query: Query {
                        batch_identifier: Interval::new(
                            Time::from_seconds_since_epoch(54321),
                            Duration::from_seconds(12345),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::new(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id,
                    concat!(
                        // query
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
                ),
            ),
            (
                CollectReq::<TimeInterval> {
                    task_id: TaskId::from([13u8; 32]),
                    query: Query {
                        batch_identifier: Interval::new(
                            Time::from_seconds_since_epoch(48913),
                            Duration::from_seconds(44721),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::from("012345"),
                },
                concat!(
                    "0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D", // task_id
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
                CollectReq::<FixedSize> {
                    task_id: TaskId::from([u8::MIN; 32]),
                    query: Query {
                        batch_identifier: BatchId::from([10u8; 32]),
                    },
                    aggregation_parameter: Vec::new(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id,
                    concat!(
                        // query
                        "02", // query_type
                        "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                    ),
                    concat!(
                        // aggregation_parameter
                        "00000000", // length
                        "",         // opaque data
                    ),
                ),
            ),
            (
                CollectReq::<FixedSize> {
                    task_id: TaskId::from([13u8; 32]),
                    query: Query {
                        batch_identifier: BatchId::from([8u8; 32]),
                    },
                    aggregation_parameter: Vec::from("012345"),
                },
                concat!(
                    "0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D", // task_id
                    concat!(
                        // query
                        "02", // query_type
                        "0808080808080808080808080808080808080808080808080808080808080808", // batch_id
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
    fn roundtrip_collect_resp() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                CollectResp {
                    partial_batch_selector: PartialBatchSelector::new_time_interval(),
                    report_count: 0,
                    encrypted_aggregate_shares: Vec::new(),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "01", // query_type
                    ),
                    "0000000000000000", // report_count
                    concat!(
                        // encrypted_aggregate_shares
                        "00000000", // length
                    )
                ),
            ),
            (
                CollectResp {
                    partial_batch_selector: PartialBatchSelector::new_time_interval(),
                    report_count: 23,
                    encrypted_aggregate_shares: Vec::from([
                        HpkeCiphertext::new(
                            HpkeConfigId::from(10),
                            Vec::from("0123"),
                            Vec::from("4567"),
                        ),
                        HpkeCiphertext::new(
                            HpkeConfigId::from(12),
                            Vec::from("01234"),
                            Vec::from("567"),
                        ),
                    ]),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "01", // query_type
                    ),
                    "0000000000000017", // report_count
                    concat!(
                        // encrypted_aggregate_shares
                        "0000001E", // length
                        concat!(
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
                    )
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                CollectResp {
                    partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                        [3u8; 32],
                    )),
                    report_count: 0,
                    encrypted_aggregate_shares: Vec::new(),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "02", // query_type
                        "0303030303030303030303030303030303030303030303030303030303030303", // batch_id
                    ),
                    "0000000000000000", // report_count
                    concat!(
                        // encrypted_aggregate_shares
                        "00000000", // length
                    )
                ),
            ),
            (
                CollectResp {
                    partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                        [4u8; 32],
                    )),
                    report_count: 23,
                    encrypted_aggregate_shares: Vec::from([
                        HpkeCiphertext::new(
                            HpkeConfigId::from(10),
                            Vec::from("0123"),
                            Vec::from("4567"),
                        ),
                        HpkeCiphertext::new(
                            HpkeConfigId::from(12),
                            Vec::from("01234"),
                            Vec::from("567"),
                        ),
                    ]),
                },
                concat!(
                    concat!(
                        // partial_batch_selector
                        "02", // query_type
                        "0404040404040404040404040404040404040404040404040404040404040404", // batch_id
                    ),
                    "0000000000000017", // report_count
                    concat!(
                        // encrypted_aggregate_shares
                        "0000001E", // length
                        concat!(
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
    fn roundtrip_prepare_step() {
        roundtrip_encoding(&[
            (
                PrepareStep {
                    report_id: ReportId::from([
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    ]),
                    result: PrepareStepResult::Continued(Vec::from("012345")),
                },
                concat!(
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "00",                               // prepare_step_result
                    concat!(
                        // vdaf_msg
                        "00000006",     // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
            (
                PrepareStep {
                    report_id: ReportId::from([
                        16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                    ]),
                    result: PrepareStepResult::Finished,
                },
                concat!(
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "01",                               // prepare_step_result
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
    fn roundtrip_aggregate_initialize_req() {
        // TimeInterval.
        roundtrip_encoding(&[(
            AggregateInitializeReq {
                task_id: TaskId::from([u8::MAX; 32]),
                job_id: AggregationJobId([u8::MIN; 32]),
                aggregation_parameter: Vec::from("012345"),
                partial_batch_selector: PartialBatchSelector::new_time_interval(),
                report_shares: Vec::from([
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
                ]),
            },
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                "0000000000000000000000000000000000000000000000000000000000000000", // job_id
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
                    // report_shares
                    "0000005E", // length
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
                    concat!(
                        concat!(
                            // metadata
                            "100F0E0D0C0B0A090807060504030201", // report_id
                            "0000000000011F46",                 // time
                        ),
                        concat!(
                            "00000004", // payload
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
            ),
        )]);

        // FixedSize.
        roundtrip_encoding(&[(
            AggregateInitializeReq::<FixedSize> {
                task_id: TaskId::from([u8::MAX; 32]),
                job_id: AggregationJobId([u8::MIN; 32]),
                aggregation_parameter: Vec::from("012345"),
                partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                    [2u8; 32],
                )),
                report_shares: Vec::from([
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
                ]),
            },
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                "0000000000000000000000000000000000000000000000000000000000000000", // job_id
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
                    // report_shares
                    "0000005E", // length
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
            ),
        )])
    }

    #[test]
    fn roundtrip_aggregate_initialize_resp() {
        roundtrip_encoding(&[
            (
                AggregateInitializeResp {
                    prepare_steps: Vec::new(),
                },
                concat!(concat!(
                    // prepare_steps
                    "00000000", // length
                ),),
            ),
            (
                AggregateInitializeResp {
                    prepare_steps: Vec::from([
                        PrepareStep {
                            report_id: ReportId::from([
                                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            ]),
                            result: PrepareStepResult::Continued(Vec::from("012345")),
                        },
                        PrepareStep {
                            report_id: ReportId::from([
                                16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                            ]),
                            result: PrepareStepResult::Finished,
                        },
                    ]),
                },
                concat!(concat!(
                    // prepare_steps
                    "0000002C", // length
                    concat!(
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "00",                               // prepare_step_result
                        concat!(
                            // payload
                            "00000006",     // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "01",                               // prepare_step_result
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_continue_req() {
        roundtrip_encoding(&[(
            AggregateContinueReq {
                task_id: TaskId::from([u8::MIN; 32]),
                job_id: AggregationJobId([u8::MAX; 32]),
                prepare_steps: Vec::from([
                    PrepareStep {
                        report_id: ReportId::from([
                            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                        ]),
                        result: PrepareStepResult::Continued(Vec::from("012345")),
                    },
                    PrepareStep {
                        report_id: ReportId::from([
                            16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                        ]),
                        result: PrepareStepResult::Finished,
                    },
                ]),
            },
            concat!(
                "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                concat!(
                    // prepare_steps
                    "0000002C", // length
                    concat!(
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "00",                               // prepare_step_result
                        concat!(
                            // payload
                            "00000006",     // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "01",                               // prepare_step_result
                    )
                ),
            ),
        )])
    }

    #[test]
    fn roundtrip_aggregate_continue_resp() {
        roundtrip_encoding(&[
            (
                AggregateContinueResp {
                    prepare_steps: Vec::new(),
                },
                concat!(concat!(
                    // prepare_steps
                    "00000000", // length
                ),),
            ),
            (
                AggregateContinueResp {
                    prepare_steps: Vec::from([
                        PrepareStep {
                            report_id: ReportId::from([
                                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            ]),
                            result: PrepareStepResult::Continued(Vec::from("012345")),
                        },
                        PrepareStep {
                            report_id: ReportId::from([
                                16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                            ]),
                            result: PrepareStepResult::Finished,
                        },
                    ]),
                },
                concat!(concat!(
                    // prepare_steps
                    "0000002C", // length
                    concat!(
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "00",                               // prepare_step_result
                        concat!(
                            // payload
                            "00000006",     // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "01",                               // prepare_step_result
                    ),
                )),
            ),
        ])
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
                    task_id: TaskId::from([u8::MIN; 32]),
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
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
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
                    task_id: TaskId::from([12u8; 32]),
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
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
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
                    task_id: TaskId::from([u8::MIN; 32]),
                    batch_selector: BatchSelector {
                        batch_identifier: BatchId::from([12u8; 32]),
                    },
                    aggregation_parameter: Vec::new(),
                    report_count: 439,
                    checksum: ReportIdChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
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
                    task_id: TaskId::from([12u8; 32]),
                    batch_selector: BatchSelector {
                        batch_identifier: BatchId::from([7u8; 32]),
                    },
                    aggregation_parameter: Vec::from("012345"),
                    report_count: 8725,
                    checksum: ReportIdChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
                },
                concat!(
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
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
    fn roundtrip_aggregate_share_resp() {
        roundtrip_encoding(&[
            (
                AggregateShareResp {
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
                AggregateShareResp {
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
}
