//! DAP protocol types for representing time, duration, and intervals.

use crate::{Error, taskprov::TimePrecision};
use prio::codec::{CodecError, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    io::Cursor,
};

/// DAP protocol message representing a duration in terms of the task's time precision.
/// The value represents the number of time_precision intervals.
///
/// To convert between this representation and real-world durations (seconds),
/// use the conversion methods that take a [`TimePrecision`] parameter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Duration(u64);

impl Duration {
    /// A zero-length duration.
    pub const ZERO: Duration = Duration::from_time_precision_units(0);

    /// A duration that lasts for one of a task's time precision intervals.
    pub const ONE: Duration = Duration::from_time_precision_units(1);

    /// Create a duration representing the provided number of seconds, given the task's time
    /// precision.
    ///
    /// The duration will be rounded down to the nearest multiple of time_precision.
    ///
    /// # Arguments
    ///
    /// * `seconds` - Duration in seconds
    /// * `time_precision` - The task's time precision
    ///
    /// # Panics
    ///
    /// Panics if `time_precision.as_seconds()` is 0.
    pub fn from_seconds(seconds: u64, time_precision: &TimePrecision) -> Self {
        let precision_secs = time_precision.as_seconds();
        assert!(precision_secs > 0);
        Self(seconds / precision_secs)
    }

    /// Create a duration representing the provided number of hours, given the task's time
    /// precision.
    ///
    /// The duration will be rounded down to the nearest multiple of time_precision.
    ///
    /// This is a convenience method for tests. For production code with time
    /// arithmetic, use `chrono::TimeDelta` and `from_chrono`.
    ///
    /// # Arguments
    /// * `hours` - Duration in hours
    /// * `time_precision` - The task's time precision
    ///
    /// # Panics
    /// Panics if `time_precision.as_seconds()` is 0.
    ///
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_hours(hours: u64, time_precision: &TimePrecision) -> Self {
        Self::from_seconds(hours * 3600, time_precision)
    }

    /// Get the number of seconds this duration represents.
    ///
    /// # Arguments
    /// * `time_precision` - The task's time precision
    ///
    /// # Panics
    /// Panics if `time_precision.as_seconds()` is 0.
    ///
    pub fn as_seconds(&self, time_precision: &TimePrecision) -> u64 {
        self.0.saturating_mul(time_precision.as_seconds())
    }

    /// Construct a [`Duration`] from the raw number of time_precision units.
    pub const fn from_time_precision_units(units: u64) -> Self {
        Self(units)
    }

    /// Get the raw number of time_precision units.
    pub fn as_time_precision_units(&self) -> u64 {
        self.0
    }

    /// Convert this [`Duration`] into a [`chrono::TimeDelta`].
    ///
    /// Returns an error if the duration cannot be represented as a TimeDelta (e.g., the number of
    /// seconds is too large for i64 or the resulting milliseconds would overflow).
    ///
    /// # Arguments
    /// * `time_precision` - The task's time precision
    ///
    /// # Panics
    /// Panics if `time_precision.as_seconds()` is 0.
    ///
    pub fn to_chrono(&self, time_precision: &TimePrecision) -> Result<chrono::TimeDelta, Error> {
        let seconds = self.as_seconds(time_precision);
        chrono::TimeDelta::try_seconds(
            seconds
                .try_into()
                .map_err(|_| Error::IllegalTimeArithmetic("number of seconds too big for i64"))?,
        )
        .ok_or(Error::IllegalTimeArithmetic(
            "number of milliseconds too big for i64",
        ))
    }

    /// Create a [`Duration`] from a [`chrono::TimeDelta`], given the task's time precision.
    ///
    /// The duration will be rounded down to the nearest time_precision unit.
    ///
    /// # Panics
    ///
    /// Panics if the delta is negative, as DAP durations must be non-negative.
    ///
    /// # Arguments
    /// * `delta` - The chrono TimeDelta to convert
    /// * `time_precision` - The task's time precision
    ///
    /// # Panics
    /// Panics if `time_precision.as_seconds()` is 0.
    ///
    pub fn from_chrono(delta: chrono::TimeDelta, time_precision: &TimePrecision) -> Self {
        let seconds = delta.num_seconds();
        assert!(
            seconds >= 0,
            "Duration::from_chrono called with negative TimeDelta"
        );
        Self::from_seconds(seconds as u64, time_precision)
    }
}

impl Encode for Duration {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(bytes)
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
        write!(f, "{} time_precision units", self.0)
    }
}

/// DAP protocol message representing an instant in time in terms of of the task's time precision
/// The value represents the number of time_precision intervals since the Unix epoch
/// (January 1st, 1970, at 0:00:00 UTC).
///
/// To convert between this representation and real-world timestamps (seconds since epoch),
/// use the conversion methods that take a [`TimePrecision`] parameter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Time(u64);

impl Time {
    /// Construct a [`Time`] representing the instant that is a given number of seconds after
    /// January 1st, 1970, at 0:00:00 UTC (i.e., the instant with the Unix timestamp of
    /// `timestamp`), given the task's time precision.
    ///
    /// The timestamp will be rounded down to the nearest multiple of time_precision.
    ///
    /// # Arguments
    /// * `timestamp` - Unix timestamp in seconds
    /// * `time_precision` - The task's time precision
    ///
    /// # Panics
    /// Panics if `time_precision.as_seconds()` is 0.
    ///
    pub fn from_seconds_since_epoch(timestamp: u64, time_precision: &TimePrecision) -> Self {
        let precision_secs = time_precision.as_seconds();
        assert!(precision_secs > 0);
        Self(timestamp / precision_secs)
    }

    /// Get the number of seconds from January 1st, 1970, at 0:00:00 UTC to the instant represented
    /// by this [`Time`] (i.e., the Unix timestamp for the instant it represents).
    ///
    /// # Arguments
    /// * `time_precision` - The task's time precision
    ///
    /// # Panics
    /// Panics if `time_precision.as_seconds()` is 0.
    ///
    pub const fn as_seconds_since_epoch(&self, time_precision: &TimePrecision) -> u64 {
        let precision_secs = time_precision.as_seconds();
        assert!(precision_secs > 0);
        self.0.saturating_mul(precision_secs)
    }

    /// Construct a [`Time`] from the raw number of time_precision units since the Unix epoch.
    /// This is primarily for testing and internal use.
    pub const fn from_time_precision_units(units: u64) -> Self {
        Self(units)
    }

    /// Get the raw number of time_precision units since the Unix epoch.
    /// This is primarily for testing and internal use.
    pub fn as_time_precision_units(&self) -> u64 {
        self.0
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} time_precision units since the Epoch", self.0)
    }
}

impl Encode for Time {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(bytes)
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

/// DAP protocol message representing a half-open interval of time in terms of the task's time
/// precision. The start of the interval is included while the end of the interval is excluded.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Interval {
    /// The start of the interval.
    pub(crate) start: Time,
    /// The length of the interval.
    pub(crate) duration: Duration,
}

impl Interval {
    pub const EMPTY: Self = Self {
        start: Time::from_time_precision_units(0),
        duration: Duration::ZERO,
    };

    /// Create a new [`Interval`] from the provided start with a duration of 1 time_precision
    /// unit. Returns an error if the end of the interval cannot be represented as a [`Time`].
    ///
    /// This is the preferred constructor for batch bucket intervals. For intervals with
    /// arbitrary durations, use [`Interval::new`].
    pub fn minimal(start: Time) -> Result<Self, Error> {
        Self::new(start, Duration::ONE)
    }

    /// Create a new [`Interval`] from the provided start and duration. Returns an error if the end
    /// of the interval cannot be represented as a [`Time`].
    ///
    /// This constructor is for intervals with arbitrary durations (in time_precision units).
    /// For intervals of Duration::ONE, prefer [`Interval::minimal`].
    pub fn new(start: Time, duration: Duration) -> Result<Self, Error> {
        start
            .0
            .checked_add(duration.0)
            .ok_or(Error::IllegalTimeArithmetic("duration overflows time"))?;

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
}

impl Encode for Interval {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.start.encode(bytes)?;
        self.duration.encode(bytes)
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
