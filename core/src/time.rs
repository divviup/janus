//! Utilities for timestamps and durations.

use chrono::{NaiveDateTime, Utc};
use janus_messages::{Duration, Error, Interval, Time};
use std::{
    fmt::{Debug, Formatter},
    sync::{Arc, Mutex},
};

/// A clock knows what time it currently is.
pub trait Clock: 'static + Clone + Debug + Sync + Send {
    /// Get the current time.
    fn now(&self) -> Time;
}

/// A real clock returns the current time relative to the Unix epoch.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct RealClock {}

impl Clock for RealClock {
    fn now(&self) -> Time {
        Time::from_seconds_since_epoch(
            Utc::now()
                .timestamp()
                .try_into()
                .expect("invalid or out-of-range timestamp"),
        )
    }
}

impl Debug for RealClock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.now())
    }
}

/// A mock clock for use in testing. Clones are identical: all clones of a given MockClock will
/// be controlled by a controller retrieved from any of the clones.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MockClock {
    /// The time that this clock will return from [`Self::now`].
    current_time: Arc<Mutex<Time>>,
}

impl MockClock {
    pub fn new(when: Time) -> MockClock {
        MockClock {
            current_time: Arc::new(Mutex::new(when)),
        }
    }

    pub fn advance(&self, dur: Duration) {
        let mut current_time = self.current_time.lock().unwrap();
        *current_time = current_time
            .as_seconds_since_epoch()
            .checked_add(dur.as_seconds())
            .map(Time::from_seconds_since_epoch)
            .unwrap();
    }
}

impl Clock for MockClock {
    fn now(&self) -> Time {
        let current_time = self.current_time.lock().unwrap();
        *current_time
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self {
            // Sunday, September 9, 2001 1:46:40 AM UTC
            current_time: Arc::new(Mutex::new(Time::from_seconds_since_epoch(1000000000))),
        }
    }
}

/// Number of microseconds per second.
const USEC_PER_SEC: u64 = 1_000_000;

/// Extension methods on [`Duration`].
pub trait DurationExt: Sized {
    /// Add this duration with another duration.
    fn add(&self, duration: &Duration) -> Result<Self, Error>;

    /// Create a duration from a number of microseconds. The time will be rounded down to the next
    /// second.
    fn from_microseconds(microseconds: u64) -> Self;

    /// Get the number of microseconds this duration represents. Note that the precision of this
    /// type is one second, so this method will always return a multiple of 1,000,000 microseconds.
    fn as_microseconds(&self) -> Result<u64, Error>;

    /// Create a duration representing the provided number of minutes.
    fn from_minutes(minutes: u64) -> Result<Self, Error>;

    /// Create a duration representing the provided number of hours.
    fn from_hours(hours: u64) -> Result<Self, Error>;
}

impl DurationExt for Duration {
    fn add(&self, other: &Duration) -> Result<Self, Error> {
        self.as_seconds()
            .checked_add(other.as_seconds())
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
            .map(Duration::from_seconds)
    }

    fn from_microseconds(microseconds: u64) -> Self {
        Self::from_seconds(microseconds / USEC_PER_SEC)
    }

    fn as_microseconds(&self) -> Result<u64, Error> {
        self.as_seconds()
            .checked_mul(USEC_PER_SEC)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn from_minutes(minutes: u64) -> Result<Self, Error> {
        60u64
            .checked_mul(minutes)
            .map(Self::from_seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }
    fn from_hours(hours: u64) -> Result<Self, Error> {
        3600u64
            .checked_mul(hours)
            .map(Self::from_seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }
}

/// Extension methods on [`Time`].
pub trait TimeExt: Sized {
    /// Compute the start of the batch interval containing this Time, given the task time precision.
    fn to_batch_interval_start(
        &self,
        time_precision: &Duration,
    ) -> Result<Self, janus_messages::Error>;

    /// Convert this [`Time`] into a [`NaiveDateTime`], representing an instant in the UTC timezone.
    fn as_naive_date_time(&self) -> Result<NaiveDateTime, Error>;

    /// Convert a [`NaiveDateTime`] representing an instant in the UTC timezone into a [`Time`].
    fn from_naive_date_time(time: &NaiveDateTime) -> Self;

    /// Add the provided duration to this time.
    fn add(&self, duration: &Duration) -> Result<Self, Error>;

    /// Subtract the provided duration from this time.
    fn sub(&self, duration: &Duration) -> Result<Self, Error>;

    /// Get the difference between the provided `other` and `self`. `self` must be after `other`.
    fn difference(&self, other: &Self) -> Result<Duration, Error>;

    /// Returns true if this [`Time`] occurs after `time`.
    fn is_after(&self, time: &Time) -> bool;
}

impl TimeExt for Time {
    fn to_batch_interval_start(
        &self,
        time_precision: &Duration,
    ) -> Result<Self, janus_messages::Error> {
        let rem = self
            .as_seconds_since_epoch()
            .checked_rem(time_precision.as_seconds())
            .ok_or(janus_messages::Error::IllegalTimeArithmetic(
                "remainder would overflow/underflow",
            ))?;
        self.as_seconds_since_epoch()
            .checked_sub(rem)
            .map(Time::from_seconds_since_epoch)
            .ok_or(janus_messages::Error::IllegalTimeArithmetic(
                "operation would underflow",
            ))
    }

    fn as_naive_date_time(&self) -> Result<NaiveDateTime, Error> {
        NaiveDateTime::from_timestamp_opt(
            self.as_seconds_since_epoch()
                .try_into()
                .map_err(|_| Error::IllegalTimeArithmetic("number of seconds too big for i64"))?,
            0,
        )
        .ok_or(Error::IllegalTimeArithmetic(
            "number of seconds is out of range",
        ))
    }

    fn from_naive_date_time(time: &NaiveDateTime) -> Self {
        Self::from_seconds_since_epoch(time.timestamp() as u64)
    }

    fn add(&self, duration: &Duration) -> Result<Self, Error> {
        self.as_seconds_since_epoch()
            .checked_add(duration.as_seconds())
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn sub(&self, duration: &Duration) -> Result<Self, Error> {
        self.as_seconds_since_epoch()
            .checked_sub(duration.as_seconds())
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    fn difference(&self, other: &Self) -> Result<Duration, Error> {
        self.as_seconds_since_epoch()
            .checked_sub(other.as_seconds_since_epoch())
            .map(Duration::from_seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    fn is_after(&self, time: &Time) -> bool {
        self.as_seconds_since_epoch() > time.as_seconds_since_epoch()
    }
}

/// Extension methods on [`Interval`].
pub trait IntervalExt {
    /// Returns a [`Time`] representing the excluded end of this interval.
    fn end(&self) -> Time;
}

impl IntervalExt for Interval {
    fn end(&self) -> Time {
        // [`Self::new`] verified that this addition doesn't overflow.
        self.start().add(self.duration()).unwrap()
    }
}
