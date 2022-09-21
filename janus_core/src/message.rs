//! DAP protocol message definitions with serialization/deserialization support.

use self::query_type::{FixedSize, QueryType, TimeInterval};
use crate::hpke::associated_data_for_report_share;
use anyhow::anyhow;
use base64::{display::Base64Display, URL_SAFE_NO_PAD};
use chrono::NaiveDateTime;
use derivative::Derivative;
use hpke_dispatch::{Aead, Kdf, Kem};
use num_enum::TryFromPrimitive;
#[cfg(feature = "database")]
use postgres_protocol::types::{
    range_from_sql, range_to_sql, timestamp_from_sql, timestamp_to_sql,
};
#[cfg(feature = "database")]
use postgres_types::{accepts, to_sql_checked, FromSql, ToSql};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use rand::{distributions::Standard, prelude::Distribution};
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

/// Number of milliseconds per second.
const USEC_PER_SEC: u64 = 1_000_000;

/// DAP protocol message representing a duration with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Duration(u64);

impl Duration {
    pub const ZERO: Duration = Duration::from_seconds(0);

    /// Create a duration representing the provided number of seconds.
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Create a duration from a number of microseconds. The time will be
    /// rounded down to the next second.
    pub const fn from_microseconds(microseconds: u64) -> Self {
        Self(microseconds / USEC_PER_SEC)
    }

    /// Get the number of seconds this duration represents.
    pub fn as_seconds(self) -> u64 {
        self.0
    }

    /// Get the number of microseconds this duration represents. Note that the
    /// precision of this type is one second, so this method will always
    /// return a multiple of 1,000,000 microseconds.
    pub fn as_microseconds(self) -> Result<u64, Error> {
        self.0
            .checked_mul(USEC_PER_SEC)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
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

/// DAP protocol message representing an instant in time with a resolution of seconds.
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
        start.add(duration)?;

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

/// The SQL timestamp epoch, midnight UTC on 2000-01-01.
#[cfg(feature = "database")]
const SQL_EPOCH_TIME: Time = Time(946_684_800);

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

                // Convert from SQL timestamp representation to the internal representation.
                let negative = start_timestamp < 0;
                let abs_start_us = start_timestamp.unsigned_abs();
                let abs_start_duration = Duration::from_microseconds(abs_start_us);
                let time = if negative {
                    SQL_EPOCH_TIME.sub(abs_start_duration).map_err(|_| "Interval cannot represent timestamp ranges starting before the Unix epoch")?
                } else {
                    SQL_EPOCH_TIME.add(abs_start_duration).map_err(|_| "overflow when converting to Interval")?
                };

                if end_timestamp < start_timestamp {
                    return Err("timestamp range ends before it starts".into());
                }
                let duration_us = end_timestamp.abs_diff(start_timestamp);
                let duration = Duration::from_microseconds(duration_us);

                Ok(Interval::new(time, duration)?)
            }
        }
    }

    accepts!(TS_RANGE);
}

#[cfg(feature = "database")]
fn time_to_sql_timestamp(time: Time) -> Result<i64, Error> {
    if time.is_after(SQL_EPOCH_TIME) {
        let absolute_difference_us = time.difference(SQL_EPOCH_TIME)?.as_microseconds()?;
        absolute_difference_us
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("timestamp conversion overflowed"))
    } else {
        let absolute_difference_us = SQL_EPOCH_TIME.difference(time)?.as_microseconds()?;
        Ok(-i64::try_from(absolute_difference_us)
            .map_err(|_| Error::IllegalTimeArithmetic("timestamp conversion overflowed"))?)
    }
}

#[cfg(feature = "database")]
impl ToSql for Interval {
    fn to_sql(
        &self,
        _: &postgres_types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        // Convert the interval start and end to SQL timestamps.
        let start_sql_usec = time_to_sql_timestamp(*self.start())
            .map_err(|_| "millisecond timestamp of Interval start overflowed")?;
        let end_sql_usec = time_to_sql_timestamp(self.end())
            .map_err(|_| "millisecond timestamp of Interval end overflowed")?;

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

/// DAP protocol message representing an ID uniquely identifying a batch, for fixed-size tasks.
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchId([u8; Self::ENCODED_LEN]);

impl BatchId {
    /// ENCODED_LEN is the length of a batch ID in bytes when encoded.
    pub const ENCODED_LEN: usize = 32;
}

impl From<[u8; Self::ENCODED_LEN]> for BatchId {
    fn from(batch_id: [u8; Self::ENCODED_LEN]) -> Self {
        Self(batch_id)
    }
}

impl AsRef<[u8; Self::ENCODED_LEN]> for BatchId {
    fn as_ref(&self) -> &[u8; Self::ENCODED_LEN] {
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
        let mut batch_id = [0; Self::ENCODED_LEN];
        bytes.read_exact(&mut batch_id)?;
        Ok(Self(batch_id))
    }
}

impl Distribution<BatchId> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BatchId {
        BatchId(rng.gen())
    }
}

/// DAP protocol message representing a nonce uniquely identifying a client report.
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce([u8; Self::ENCODED_LEN]);

impl Nonce {
    /// ENCODED_LEN is the length of a nonce in bytes when encoded.
    pub const ENCODED_LEN: usize = 16;
}

impl From<[u8; Self::ENCODED_LEN]> for Nonce {
    fn from(nonce: [u8; Self::ENCODED_LEN]) -> Self {
        Self(nonce)
    }
}

impl AsRef<[u8; Self::ENCODED_LEN]> for Nonce {
    fn as_ref(&self) -> &[u8; Self::ENCODED_LEN] {
        &self.0
    }
}

impl Debug for Nonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Nonce({})",
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Base64Display::with_config(&self.0, URL_SAFE_NO_PAD)
        )
    }
}

impl Encode for Nonce {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for Nonce {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut nonce = [0; Self::ENCODED_LEN];
        bytes.read_exact(&mut nonce)?;
        Ok(Self(nonce))
    }
}

impl Distribution<Nonce> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Nonce {
        Nonce(rng.gen())
    }
}

/// Checksum over DAP report nonces, defined in §4.4.4.3.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct NonceChecksum([u8; SHA256_OUTPUT_LEN]);

impl NonceChecksum {
    /// Initialize a checksum from a single nonce.
    pub fn for_nonce(nonce: &Nonce) -> Self {
        Self(Self::nonce_digest(nonce))
    }

    /// Compute SHA256 over a nonce.
    fn nonce_digest(nonce: &Nonce) -> [u8; SHA256_OUTPUT_LEN] {
        digest(&SHA256, nonce.as_ref())
            .as_ref()
            .try_into()
            // panic if somehow the digest ring computes isn't 32 bytes long.
            .unwrap()
    }

    /// Incorporate the provided nonce into this checksum.
    pub fn update(&mut self, nonce: &Nonce) {
        self.combine(&Self::for_nonce(nonce))
    }

    /// Combine another checksum with this one.
    pub fn combine(&mut self, other: &NonceChecksum) {
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
pub struct TaskId([u8; Self::ENCODED_LEN]);

impl TaskId {
    /// ENCODED_LEN is the length of a task ID in bytes when encoded.
    pub const ENCODED_LEN: usize = 32;
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
        let mut decoded = [0u8; Self::ENCODED_LEN];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl From<[u8; Self::ENCODED_LEN]> for TaskId {
    fn from(task_id: [u8; TaskId::ENCODED_LEN]) -> Self {
        Self(task_id)
    }
}

impl AsRef<[u8; Self::ENCODED_LEN]> for TaskId {
    fn as_ref(&self) -> &[u8; Self::ENCODED_LEN] {
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

/// DAP protocol message representing an HPKE key derivation function.
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

/// DAP protocol message representing an HPKE AEAD.
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
        encode_u16_items(bytes, &(), &self.payload); // TODO(#471): should be encode_u32_items
    }
}

impl Decode for HpkeCiphertext {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let config_id = HpkeConfigId::decode(bytes)?;
        let encapsulated_key = decode_u16_items(&(), bytes)?;
        let payload = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items

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
    time: Time,
    nonce: Nonce,
    extensions: Vec<Extension>,
}

impl ReportMetadata {
    /// Construct a report's metadata from its components.
    pub fn new(time: Time, nonce: Nonce, extensions: Vec<Extension>) -> Self {
        Self {
            time,
            nonce,
            extensions,
        }
    }

    /// Retrieve the client timestamp from this report metadata.
    pub fn time(&self) -> &Time {
        &self.time
    }

    /// Retrieve the nonce from this report metadata.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Retrieve the extensions from this report metadata.
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }
}

impl Encode for ReportMetadata {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.time.encode(bytes);
        self.nonce.encode(bytes);
        encode_u16_items(bytes, &(), &self.extensions);
    }
}

impl Decode for ReportMetadata {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let time = Time::decode(bytes)?;
        let nonce = Nonce::decode(bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;

        Ok(Self {
            time,
            nonce,
            extensions,
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

    /// Get the authenticated additional data associated with this report.
    pub fn associated_data(&self) -> Vec<u8> {
        associated_data_for_report_share(self.task_id, &self.metadata, &self.public_share)
    }
}

impl Encode for Report {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.metadata.encode(bytes);
        encode_u16_items(bytes, &(), &self.public_share); // TODO(#471): should be encode_u32_items
        encode_u16_items(bytes, &(), &self.encrypted_input_shares); // TODO(#471): should be encode_u32_items
    }
}

impl Decode for Report {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let metadata = ReportMetadata::decode(bytes)?;
        let public_share = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items
        let encrypted_input_shares = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items

        Ok(Self {
            task_id,
            metadata,
            public_share,
            encrypted_input_shares,
        })
    }
}

#[cfg(feature = "test-util")]
impl Report {
    pub fn new_dummy(task_id: TaskId, when: Time) -> Report {
        use rand::random;
        Report::new(
            task_id,
            ReportMetadata::new(when, random(), Vec::new()),
            Vec::new(),
            Vec::new(),
        )
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
/// aggregate shares for a given batch interval.
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
        encode_u16_items(bytes, &(), &self.aggregation_parameter);
    }
}

impl<Q: QueryType> Decode for CollectReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let query = Query::decode(bytes)?;
        let aggregation_parameter = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            query,
            aggregation_parameter,
        })
    }
}

/// DAP protocol message representing a leader's response to the collector's request to provide
/// aggregate shares for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectResp<Q: QueryType> {
    batch_identifier: Q::CollectRespBatchIdentifier,
    report_count: u64,
    encrypted_aggregate_shares: Vec<HpkeCiphertext>,
}

impl<Q: QueryType> CollectResp<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-collect-resp";

    /// Constructs a new collect response.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::new_time_interval`] or
    /// [`Self::new_fixed_size`].
    pub fn new(
        batch_identifier: Q::CollectRespBatchIdentifier,
        report_count: u64,
        encrypted_aggregate_shares: Vec<HpkeCiphertext>,
    ) -> Self {
        Self {
            batch_identifier,
            report_count,
            encrypted_aggregate_shares,
        }
    }

    /// Gets the batch identifier associated with this collect response.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::CollectRespBatchIdentifier {
        &self.batch_identifier
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

impl CollectResp<TimeInterval> {
    /// Constructs a new collect response for a time-interval task.
    pub fn new_time_interval(
        report_count: u64,
        encrypted_aggregate_shares: Vec<HpkeCiphertext>,
    ) -> Self {
        Self::new((), report_count, encrypted_aggregate_shares)
    }
}

impl CollectResp<FixedSize> {
    /// Constructs a new collect response for a fixed-size task.
    pub fn new_fixed_size(
        batch_id: BatchId,
        report_count: u64,
        encrypted_aggregate_shares: Vec<HpkeCiphertext>,
    ) -> Self {
        Self::new(batch_id, report_count, encrypted_aggregate_shares)
    }

    // Gets the batch ID associated with this collect response.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<Q: QueryType> Encode for CollectResp<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Q::CODE.encode(bytes);
        self.batch_identifier.encode(bytes);
        self.report_count.encode(bytes);
        encode_u16_items(bytes, &(), &self.encrypted_aggregate_shares); // TODO(#471): should be encode_u32_items
    }
}

impl<Q: QueryType> Decode for CollectResp<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let batch_identifier = Q::CollectRespBatchIdentifier::decode(bytes)?;
        let report_count = u64::decode(bytes)?;
        let encrypted_aggregate_shares = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items

        Ok(Self {
            batch_identifier,
            report_count,
            encrypted_aggregate_shares,
        })
    }
}

pub mod query_type {
    use super::{BatchId, Interval};
    use anyhow::anyhow;
    use num_enum::TryFromPrimitive;
    use prio::codec::{CodecError, Decode, Encode};
    use serde::{Deserialize, Serialize};
    use std::{fmt::Debug, io::Cursor};

    /// QueryType represents a DAP query type. This is a task-level configuration setting which
    /// determines how individual client reports are grouped together into batches for collection.
    pub trait QueryType: Clone + Debug + PartialEq + Eq {
        /// The [`Code`] associated with this query type.
        const CODE: Code;

        /// The type of a batch identifier.
        type BatchIdentifier: Debug + Clone + PartialEq + Eq + Encode + Decode + Send + Sync;

        /// The type of a batch identifier as it appears in an `AggregateInitializeReq`. Will
        /// either be the same type as `BatchIdentifier`, or `()`.
        type AggregateInitializeReqBatchIdentifier: Debug + Clone + PartialEq + Eq + Encode + Decode;

        /// The type of a batch identifier as it appears in a `CollectResp`. Will either be the
        /// same type as `BatchIdentifier`, or `()`.
        type CollectRespBatchIdentifier: Debug + Clone + PartialEq + Eq + Encode + Decode;

        /// Computes the `CollectRespBatchIdentifier` corresponding to the given
        /// `BatchIdentifier`.
        fn collect_resp_batch_identifier_from(
            batch_identifier: Self::BatchIdentifier,
        ) -> Self::CollectRespBatchIdentifier;
    }

    /// Represents a `time-interval` DAP query type.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct TimeInterval;

    impl QueryType for TimeInterval {
        const CODE: Code = Code::TimeInterval;

        type BatchIdentifier = Interval;
        type AggregateInitializeReqBatchIdentifier = ();
        type CollectRespBatchIdentifier = ();

        fn collect_resp_batch_identifier_from(
            _: Self::BatchIdentifier,
        ) -> Self::CollectRespBatchIdentifier {
        }
    }

    /// Represents a `fixed-size` DAP query type.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct FixedSize;

    impl QueryType for FixedSize {
        const CODE: Code = Code::FixedSize;

        type BatchIdentifier = BatchId;
        type AggregateInitializeReqBatchIdentifier = BatchId;
        type CollectRespBatchIdentifier = BatchId;

        fn collect_resp_batch_identifier_from(
            batch_identifier: Self::BatchIdentifier,
        ) -> Self::CollectRespBatchIdentifier {
            batch_identifier
        }
    }

    /// DAP protocol message representing the type of a query.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
    #[repr(u16)]
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
            (*self as u16).encode(bytes);
        }
    }

    impl Decode for Code {
        fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
            let val = u16::decode(bytes)?;
            Self::try_from(val).map_err(|_| {
                CodecError::Other(anyhow!("unexpected QueryType value {}", val).into())
            })
        }
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use prio::codec::{Decode, Encode};
    use std::{fmt::Debug, io::Cursor};

    pub fn roundtrip_encoding<T>(vals_and_encodings: &[(T, &str)])
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
}

#[cfg(test)]
mod tests {
    use super::{
        query_type::{self, FixedSize, TimeInterval},
        test_util::roundtrip_encoding,
        BatchId, CollectReq, CollectResp, Duration, Extension, ExtensionType, HpkeAeadId,
        HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, Interval,
        Nonce, Query, Report, ReportMetadata, Role, TaskId, Time,
    };
    use assert_matches::assert_matches;
    use prio::codec::{CodecError, Decode, Encode};

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
                BatchId::from([u8::MIN; BatchId::ENCODED_LEN]),
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
                BatchId::from([u8::MAX; TaskId::ENCODED_LEN]),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
        ])
    }

    #[test]
    fn roundtrip_nonce() {
        roundtrip_encoding(&[
            (
                Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                "0102030405060708090a0b0c0d0e0f10",
            ),
            (
                Nonce::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
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
                TaskId::from([u8::MIN; TaskId::ENCODED_LEN]),
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
                TaskId::from([u8::MAX; TaskId::ENCODED_LEN]),
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
                    Time::from_seconds_since_epoch(12345),
                    Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    Vec::new(),
                ),
                concat!(
                    // nonce
                    "0000000000003039",                 // time
                    "0102030405060708090a0b0c0d0e0f10", // nonce
                    concat!(
                        // extensions
                        "0000", // length
                    ),
                ),
            ),
            (
                ReportMetadata::new(
                    Time::from_seconds_since_epoch(54321),
                    Nonce::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                    Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
                ),
                concat!(
                    "000000000000D431",                 // time
                    "100f0e0d0c0b0a090807060504030201", // nonce
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
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report() {
        roundtrip_encoding(&[
            (
                Report::new(
                    TaskId::from([u8::MIN; TaskId::ENCODED_LEN]),
                    ReportMetadata::new(
                        Time::from_seconds_since_epoch(12345),
                        Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Vec::new(),
                    ),
                    Vec::new(),
                    Vec::new(),
                ),
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // metadata
                        "0000000000003039",                 // time
                        "0102030405060708090a0b0c0d0e0f10", // nonce
                        concat!(
                            // extensions
                            "0000", // length
                        ),
                    ),
                    concat!(
                        // public_share
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
                    TaskId::from([u8::MAX; TaskId::ENCODED_LEN]),
                    ReportMetadata::new(
                        Time::from_seconds_since_epoch(54321),
                        Nonce::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                        Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
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
                        "000000000000D431",                 // time
                        "100f0e0d0c0b0a090807060504030201", // nonce
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
                    ),
                    concat!(
                        // public_share
                        "0004",     // length
                        "33323130", // opaque data
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
                    "0001", // query_type
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
                    "0001", // query_type
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
                    "0002",                                                             // query_type
                    "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                ),
            ),
            (
                Query::<FixedSize> {
                    batch_identifier: BatchId::from([8u8; 32]),
                },
                concat!(
                    "0002",                                                             // query_type
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
                        "0001", // query_type
                        concat!(
                            // batch_interval
                            "000000000000D431", // start
                            "0000000000003039", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "0000", // length
                        "",     // opaque data
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
                        "0001", // query_type
                        concat!(
                            // batch_interval
                            "000000000000BF11", // start
                            "000000000000AEB1", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "0006",         // length
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
                        "0002", // query_type
                        "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                    ),
                    concat!(
                        // aggregation_parameter
                        "0000", // length
                        "",     // opaque data
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
                        "0002", // query_type
                        "0808080808080808080808080808080808080808080808080808080808080808", // batch_id
                    ),
                    concat!(
                        // aggregation_parameter
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
        ]);
    }

    #[test]
    fn roundtrip_collect_resp() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                CollectResp::<TimeInterval> {
                    batch_identifier: (),
                    report_count: 0,
                    encrypted_aggregate_shares: Vec::new(),
                },
                concat!(
                    "0001",             // query_type
                    "0000000000000000", // report_count
                    concat!(
                        // encrypted_aggregate_shares
                        "0000", // length
                    )
                ),
            ),
            (
                CollectResp::<TimeInterval> {
                    batch_identifier: (),
                    report_count: 23,
                    encrypted_aggregate_shares: vec![
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
                    ],
                },
                concat!(
                    "0001",             // query_type
                    "0000000000000017", // report_count
                    concat!(
                        // encrypted_aggregate_shares
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
                    )
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                CollectResp::<FixedSize> {
                    batch_identifier: BatchId::from([3u8; 32]),
                    report_count: 0,
                    encrypted_aggregate_shares: Vec::new(),
                },
                concat!(
                    "0002",                                                             // query_type
                    "0303030303030303030303030303030303030303030303030303030303030303", // batch_id
                    "0000000000000000", // report_count
                    concat!(
                        // encrypted_aggregate_shares
                        "0000", // length
                    )
                ),
            ),
            (
                CollectResp::<FixedSize> {
                    batch_identifier: BatchId::from([4u8; 32]),
                    report_count: 23,
                    encrypted_aggregate_shares: vec![
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
                    ],
                },
                concat!(
                    "0002",                                                             // query_type
                    "0404040404040404040404040404040404040404040404040404040404040404", // batch_id
                    "0000000000000017", // report_count
                    concat!(
                        // encrypted_aggregate_shares
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
                    )
                ),
            ),
        ]);
    }

    #[test]
    fn roundtrip_code() {
        roundtrip_encoding(&[
            (query_type::Code::Reserved, "0000"),
            (query_type::Code::TimeInterval, "0001"),
            (query_type::Code::FixedSize, "0002"),
        ])
    }
}
