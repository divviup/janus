//! PPM protocol message definitions with serialization/deserialization support.

use crate::time::Clock;
use anyhow::anyhow;
use chrono::NaiveDateTime;
use hpke::{
    aead::{self, Aead},
    kdf::{self, Kdf},
    kem, Kem,
};
use num_enum::TryFromPrimitive;
use prio::codec::{CodecError, Decode, Encode};
use rand::{thread_rng, Rng};
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
    /// Create a duration representing the provided number of seconds.
    pub fn from_seconds(seconds: u64) -> Self {
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
    pub fn generate<C: Clock>(clock: C) -> Nonce {
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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeAeadId value {}", val).into()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, HpkeConfigId, Role, Time};
    use prio::codec::{Decode, Encode};
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
}
