//! PPM protocol message definitions with serialization/deserialization support.

use crate::{hpke::associated_data_for_report_share, time::Clock};
use anyhow::anyhow;
use chrono::NaiveDateTime;
use hpke_dispatch::{Aead, Kdf, Kem};
use num_enum::TryFromPrimitive;
#[cfg(feature = "database")]
use postgres_protocol::types::{
    range_from_sql, range_to_sql, timestamp_from_sql, timestamp_to_sql,
};
#[cfg(feature = "database")]
use postgres_types::{accepts, to_sql_checked, FromSql, ToSql};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use rand::{thread_rng, Rng};
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    io::{Cursor, Read},
    str::FromStr,
};

/// Errors returned by functions and methods in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An illegal arithmetic operation on a [`Time`] or [`Duration`].
    #[error("{0}")]
    IllegalTimeArithmetic(&'static str),
}

/// PPM protocol message representing a duration with a resolution of seconds.
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

    /// Create a duration representing the provided number of minutes.
    pub fn from_minutes(minutes: u64) -> Result<Self, Error> {
        60u64
            .checked_mul(minutes)
            .map(Self::from_seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    /// Create a duration representing the provided number of hours.
    pub fn from_hours(hours: u64) -> Result<Self, Error> {
        3600u64
            .checked_mul(hours)
            .map(Self::from_seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
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

/// PPM protocol message representing an instant in time with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(u64);

impl Time {
    /// Convert this [`Time`] into a [`NaiveDateTime`], representing an instant in the UTC timezone.
    pub fn as_naive_date_time(&self) -> NaiveDateTime {
        NaiveDateTime::from_timestamp(self.0 as i64, 0)
    }

    /// Convert a [`NaiveDateTime`] representing an instant in the UTC timezone into a [`Time`].
    pub fn from_naive_date_time(time: NaiveDateTime) -> Self {
        Self(time.timestamp() as u64)
    }

    /// Get the number of seconds from January 1st, 1970, at 0:00:00 UTC to the instant represented
    /// by this [`Time`] (i.e., the Unix timestamp for the instant it represents).
    pub fn as_seconds_since_epoch(&self) -> u64 {
        self.0
    }

    /// Construct a [`Time`] representing the instant that is a given number of seconds after
    /// January 1st, 1970, at 0:00:00 UTC (i.e., the instant with the Unix timestamp of
    /// `timestamp`).
    pub fn from_seconds_since_epoch(timestamp: u64) -> Self {
        Self(timestamp)
    }

    /// Add the provided duration to this time.
    pub fn add(&self, duration: Duration) -> Result<Self, Error> {
        self.0
            .checked_add(duration.0)
            .map(Self)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    /// Subtract the provided duration from this time.
    pub fn sub(&self, duration: Duration) -> Result<Self, Error> {
        self.0
            .checked_sub(duration.0)
            .map(Self)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    /// Get the difference between the provided `other` and `self`. `self` must be after `other`.
    pub fn difference(&self, other: Self) -> Result<Duration, Error> {
        self.0
            .checked_sub(other.0)
            .map(Duration)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    /// Compute the start of the batch interval containing this Time, given the batch unit duration.
    pub fn to_batch_unit_interval_start(
        &self,
        min_batch_duration: Duration,
    ) -> Result<Self, Error> {
        let rem = self
            .0
            .checked_rem(min_batch_duration.0)
            .ok_or(Error::IllegalTimeArithmetic(
                "remainder would overflow/underflow",
            ))?;
        self.0
            .checked_sub(rem)
            .map(Self)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    /// Returns true if this [`Time`] occurs after `time`.
    pub fn is_after(&self, time: Time) -> bool {
        self.0 > time.0
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
        start.add(duration)?;

        Ok(Self { start, duration })
    }

    /// Returns a [`Time`] representing the included start of this interval.
    pub fn start(&self) -> Time {
        self.start
    }

    /// Get the duration of this interval.
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns a [`Time`] representing the excluded end of this interval.
    pub fn end(&self) -> Time {
        // [`Self::new`] verified that this addition doesn't overflow.
        self.start.add(self.duration).unwrap()
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

/// Number of seconds from 1970-01-01 to 2000-01-01.
#[cfg(feature = "database")]
const TIME_SEC_CONVERSION: u64 = 946_684_800;
/// Number of milliseconds per second.
#[cfg(feature = "database")]
const USEC_PER_SEC: u64 = 1_000_000;

#[cfg(feature = "database")]
impl<'a> FromSql<'a> for Interval {
    fn from_sql(
        _: &postgres_types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        use postgres_protocol::types::{Range::*, RangeBound::*};

        match range_from_sql(raw)? {
            Empty => Err("Interval cannot represent an empty timestamp range".into()),
            Nonempty(Inclusive(None), _)
            | Nonempty(Exclusive(None), _)
            | Nonempty(_, Inclusive(None))
            | Nonempty(_, Exclusive(None)) => {
                Err("Interval cannot represent a timestamp range with a null bound".into())
            }
            Nonempty(Unbounded, _) | Nonempty(_, Unbounded) => {
                Err("Interval cannot represent an unbounded timestamp range".into())
            }
            Nonempty(Exclusive(_), _) | Nonempty(_, Inclusive(_)) => {
                Err("Interval can only represent timestamp ranges that are closed at the start and open at the end".into())
            }
            Nonempty(Inclusive(Some(start_raw)), Exclusive(Some(end_raw))) => {
                // These timestamps represent the number of microseconds before (if negative) or
                // after (if positive) midnight, 1/1/2000.
                let start_timestamp = timestamp_from_sql(start_raw)?;
                let end_timestamp = timestamp_from_sql(end_raw)?;

                // Convert to Unix timestamp, in seconds since midnight 1/1/1970.
                let negative = start_timestamp < 0;
                let abs_start_us = start_timestamp.unsigned_abs();
                let abs_start_secs = abs_start_us / USEC_PER_SEC;
                let time = if negative {
                    if abs_start_secs > TIME_SEC_CONVERSION {
                        return Err("Interval cannot represent timestamp ranges starting before the Unix epoch".into());
                    }
                    Time::from_seconds_since_epoch(TIME_SEC_CONVERSION - abs_start_secs)
                } else {
                    Time::from_seconds_since_epoch(TIME_SEC_CONVERSION + abs_start_secs)
                };

                if end_timestamp < start_timestamp {
                    return Err("timestamp range ends before it starts".into());
                }
                let duration_us = end_timestamp.abs_diff(start_timestamp);
                let duration = Duration::from_seconds(duration_us / USEC_PER_SEC);

                Ok(Interval::new(time, duration)?)
            }
        }
    }

    accepts!(TS_RANGE);
}

#[cfg(feature = "database")]
impl ToSql for Interval {
    fn to_sql(
        &self,
        _: &postgres_types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        let start_unix_timestamp_secs = i64::try_from(self.start().as_seconds_since_epoch())
            .map_err(|_| "Interval start is out of range")?;
        let duration_secs = i64::try_from(self.duration().as_seconds())
            .map_err(|_| "Interval duration is out of range")?;

        // Convert from the 2000 epoch to the 1970 epoch, and from seconds to microseconds.
        let start_sql_usec = start_unix_timestamp_secs
            .checked_sub(TIME_SEC_CONVERSION as i64)
            .ok_or("timestamp range start calculation overflowed")?
            .checked_mul(USEC_PER_SEC as i64)
            .ok_or("timestamp range start calculation overflowed")?;
        let end_sql_usec = start_unix_timestamp_secs
            .checked_add(duration_secs)
            .ok_or("timestamp range end calculation overflowed")?
            .checked_sub(TIME_SEC_CONVERSION as i64)
            .ok_or("timestamp range end calculation overflowed")?
            .checked_mul(USEC_PER_SEC as i64)
            .ok_or("timestamp range end calculation overflowed")?;

        range_to_sql(
            |out| {
                timestamp_to_sql(start_sql_usec, out);
                Ok(postgres_protocol::types::RangeBound::Inclusive(
                    postgres_protocol::IsNull::No,
                ))
            },
            |out| {
                timestamp_to_sql(end_sql_usec, out);
                Ok(postgres_protocol::types::RangeBound::Exclusive(
                    postgres_protocol::IsNull::No,
                ))
            },
            out,
        )?;

        Ok(postgres_types::IsNull::No)
    }

    accepts!(TS_RANGE);

    to_sql_checked!();
}

/// PPM protocol message representing a nonce uniquely identifying a client report.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce {
    /// The time at which the report was generated.
    time: Time,
    /// A randomly generated value.
    rand: [u8; 8],
}

impl Nonce {
    /// Construct a nonce with the given time and random parts.
    pub fn new(time: Time, rand: [u8; 8]) -> Nonce {
        Nonce { time, rand }
    }

    /// Generate a fresh nonce with the current time.
    pub fn generate<C: Clock>(clock: &C) -> Nonce {
        Nonce {
            time: clock.now(),
            rand: rand::random(),
        }
    }

    /// Get the time component of a nonce.
    pub fn time(&self) -> Time {
        self.time
    }

    /// Get the random component of a nonce.
    pub fn rand(&self) -> [u8; 8] {
        self.rand
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.time, hex::encode(self.rand))
    }
}

impl Encode for Nonce {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.time.encode(bytes);
        bytes.extend_from_slice(&self.rand);
    }
}

impl Decode for Nonce {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let time = Time::decode(bytes)?;
        let mut rand = [0; 8];
        bytes.read_exact(&mut rand)?;

        Ok(Self { time, rand })
    }
}

/// Checksum over DAP report nonces, defined in §4.4.4.3.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct NonceChecksum([u8; SHA256_OUTPUT_LEN]);

impl NonceChecksum {
    /// Initialize a checksum from a single nonce.
    pub fn from_nonce(nonce: Nonce) -> Self {
        Self(Self::nonce_digest(nonce))
    }

    /// Compute SHA256 over a nonce.
    fn nonce_digest(nonce: Nonce) -> [u8; SHA256_OUTPUT_LEN] {
        digest(&SHA256, &nonce.get_encoded())
            .as_ref()
            .try_into()
            // panic if somehow the digest ring computes isn't 32 bytes long.
            .unwrap()
    }

    /// Incorporate the provided nonce into this checksum.
    pub fn update(&mut self, nonce: Nonce) {
        self.combine(Self::from_nonce(nonce))
    }

    /// Combine another checksum with this one.
    pub fn combine(&mut self, other: NonceChecksum) {
        self.0.iter_mut().zip(other.0).for_each(|(x, y)| *x ^= y)
    }
}

impl Display for NonceChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Encode for NonceChecksum {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for NonceChecksum {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut checksum = Self::default();
        bytes.read_exact(&mut checksum.0)?;

        Ok(checksum)
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

/// PPM protocol message representing an identifier for an HPKE config.
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

/// PPM protocol message representing an identifier for a PPM task.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TaskId([u8; Self::ENCODED_LEN]);

impl Debug for TaskId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TaskId({})",
            base64::display::Base64Display::with_config(&self.0, base64::URL_SAFE_NO_PAD)
        )
    }
}

impl Display for TaskId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            base64::display::Base64Display::with_config(&self.0, base64::URL_SAFE_NO_PAD)
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
        let mut decoded = [0u8; Self::ENCODED_LEN];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl TaskId {
    /// ENCODED_LEN is the length of a task ID in bytes when encoded.
    pub const ENCODED_LEN: usize = 32;

    /// Get a reference to the task ID as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Generate a random [`TaskId`]
    pub fn random() -> Self {
        let mut buf = [0u8; Self::ENCODED_LEN];
        thread_rng().fill(&mut buf);
        Self(buf)
    }

    /// Construct a [`TaskId`] from a byte array.
    pub fn new(buf: [u8; Self::ENCODED_LEN]) -> Self {
        Self(buf)
    }
}

/// PPM protocol message representing an HPKE key encapsulation mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKemId {
    /// NIST P-256 keys and HKDF-SHA256.
    P256HkdfSha256 = Kem::DhP256HkdfSha256 as u16,
    /// X25519 keys and HKDF-SHA256.
    X25519HkdfSha256 = Kem::X25519HkdfSha256 as u16,
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
    HkdfSha256 = Kdf::Sha256 as u16,
    /// HMAC Key Derivation Function SHA384.
    HkdfSha384 = Kdf::Sha384 as u16,
    /// HMAC Key Derivation Function SHA512.
    HkdfSha512 = Kdf::Sha512 as u16,
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
    Aes128Gcm = Aead::AesGcm128 as u16,
    /// AES-256-GCM.
    Aes256Gcm = Aead::AesGcm256 as u16,
    /// ChaCha20Poly1305.
    ChaCha20Poly1305 = Aead::ChaCha20Poly1305 as u16,
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

/// PPM protocol message representing an arbitrary extension included in a client report.
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

/// PPM protocol message representing an HPKE ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HpkeCiphertext {
    /// An identifier of the HPKE configuration used to seal the message.
    config_id: HpkeConfigId,
    /// An encasulated HPKE context.
    encapsulated_context: Vec<u8>,
    /// An HPKE ciphertext.
    payload: Vec<u8>,
}

impl HpkeCiphertext {
    /// Construct a HPKE ciphertext message from its components.
    pub fn new(
        config_id: HpkeConfigId,
        encapsulated_context: Vec<u8>,
        payload: Vec<u8>,
    ) -> HpkeCiphertext {
        HpkeCiphertext {
            config_id,
            encapsulated_context,
            payload,
        }
    }

    /// Get the configuration identifier associated with this ciphertext.
    pub fn config_id(&self) -> HpkeConfigId {
        self.config_id
    }

    /// Get the encapsulated key from this ciphertext message.
    pub fn encapsulated_context(&self) -> &[u8] {
        &self.encapsulated_context
    }

    /// Get the encrypted payload from this ciphertext message.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
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

/// PPM protocol message representing an HPKE public key.
// TODO(#230): refactor HpkePublicKey & HpkeConfig to simplify usage
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkePublicKey(pub(crate) Vec<u8>);

impl HpkePublicKey {
    /// Construct a `HpkePublicKey` from its byte array form.
    pub fn new(buf: Vec<u8>) -> HpkePublicKey {
        HpkePublicKey(buf)
    }

    /// Return the contents of this public key.
    pub fn as_bytes(&self) -> &[u8] {
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

/// PPM protocol message representing an HPKE config.
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
    pub fn id(&self) -> HpkeConfigId {
        self.id
    }

    /// Retrieve the key encapsulation mechanism algorithm identifier associated with this HPKE configuration.
    pub fn kem_id(&self) -> HpkeKemId {
        self.kem_id
    }

    /// Retrieve the key derivation function algorithm identifier associated with this HPKE configuration.
    pub fn kdf_id(&self) -> HpkeKdfId {
        self.kdf_id
    }

    /// Retrieve the AEAD algorithm identifier associated with this HPKE configuration.
    pub fn aead_id(&self) -> HpkeAeadId {
        self.aead_id
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

/// PPM protocol message representing a client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    task_id: TaskId,
    nonce: Nonce,
    extensions: Vec<Extension>,
    encrypted_input_shares: Vec<HpkeCiphertext>,
}

impl Report {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-report";

    /// Construct a report from its components.
    pub fn new(
        task_id: TaskId,
        nonce: Nonce,
        extensions: Vec<Extension>,
        encrypted_input_shares: Vec<HpkeCiphertext>,
    ) -> Report {
        Report {
            task_id,
            nonce,
            extensions,
            encrypted_input_shares,
        }
    }

    /// Retrieve the task identifier from this report.
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Get this report's nonce.
    pub fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Get this report's extensions.
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// Get this report's encrypted input shares.
    pub fn encrypted_input_shares(&self) -> &[HpkeCiphertext] {
        &self.encrypted_input_shares
    }

    /// Get the authenticated additional data associated with this report.
    pub fn associated_data(&self) -> Vec<u8> {
        associated_data_for_report_share(self.task_id, self.nonce, &self.extensions)
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

#[cfg(test)]
mod tests {
    use super::{
        Duration, Extension, ExtensionType, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId,
        HpkeKdfId, HpkeKemId, HpkePublicKey, Interval, Nonce, Report, Role, TaskId, Time,
    };
    use assert_matches::assert_matches;
    use prio::codec::{CodecError, Decode, Encode};
    use std::io::Cursor;

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
    fn roundtrip_nonce() {
        roundtrip_encoding(&[
            (
                Nonce::new(
                    Time::from_seconds_since_epoch(12345),
                    [1, 2, 3, 4, 5, 6, 7, 8],
                ),
                concat!(
                    "0000000000003039", // time
                    "0102030405060708", // rand
                ),
            ),
            (
                Nonce::new(
                    Time::from_seconds_since_epoch(54321),
                    [8, 7, 6, 5, 4, 3, 2, 1],
                ),
                concat!(
                    "000000000000D431", // time
                    "0807060504030201", // rand
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
    fn roundtrip_task_id() {
        roundtrip_encoding(&[
            (
                TaskId::new([u8::MIN; 32]),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                TaskId::new([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                TaskId::new([u8::MAX; 32]),
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
                HpkeCiphertext::new(HpkeConfigId::from(12), Vec::from("01234"), Vec::from("567")),
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
    fn roundtrip_hpke_public_key() {
        roundtrip_encoding(&[
            (
                HpkePublicKey::new(Vec::new()),
                concat!(
                    "0000", // length
                    "",     // opaque data
                ),
            ),
            (
                HpkePublicKey::new(Vec::from("0123456789abcdef")),
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
                    HpkePublicKey::new(Vec::new()),
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
                    HpkePublicKey::new(Vec::from("0123456789abcdef")),
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
    fn roundtrip_report() {
        roundtrip_encoding(&[
            (
                Report::new(
                    TaskId::new([u8::MIN; 32]),
                    Nonce::new(
                        Time::from_seconds_since_epoch(12345),
                        [1, 2, 3, 4, 5, 6, 7, 8],
                    ),
                    vec![],
                    vec![],
                ),
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // nonce
                        "0000000000003039", // time
                        "0102030405060708", // rand
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
                Report::new(
                    TaskId::new([u8::MAX; 32]),
                    Nonce::new(
                        Time::from_seconds_since_epoch(54321),
                        [8, 7, 6, 5, 4, 3, 2, 1],
                    ),
                    vec![Extension::new(ExtensionType::Tbd, Vec::from("0123"))],
                    vec![
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
                    ],
                ),
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                    concat!(
                        "000000000000D431", // time
                        "0807060504030201", // rand
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
}
