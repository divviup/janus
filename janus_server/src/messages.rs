//! Utilities for working with items in [`janus_messages`] that are only used in `janus_server`.

use chrono::NaiveDateTime;
use janus_messages::{Duration, Error, Interval, Time};

/// Number of microseconds per second.
const USEC_PER_SEC: u64 = 1_000_000;

/// Extension methods on [`Duration`].
pub trait DurationExt: Sized {
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
    /// Convert this [`Time`] into a [`NaiveDateTime`], representing an instant in the UTC timezone.
    fn as_naive_date_time(&self) -> Result<NaiveDateTime, Error>;

    /// Convert a [`NaiveDateTime`] representing an instant in the UTC timezone into a [`Time`].
    fn from_naive_date_time(time: NaiveDateTime) -> Self;

    /// Add the provided duration to this time.
    fn add(&self, duration: Duration) -> Result<Self, Error>;

    /// Subtract the provided duration from this time.
    fn sub(&self, duration: Duration) -> Result<Self, Error>;

    /// Get the difference between the provided `other` and `self`. `self` must be after `other`.
    fn difference(&self, other: Self) -> Result<Duration, Error>;

    /// Returns true if this [`Time`] occurs after `time`.
    fn is_after(&self, time: Time) -> bool;
}

impl TimeExt for Time {
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

    /// Convert a [`NaiveDateTime`] representing an instant in the UTC timezone into a [`Time`].
    fn from_naive_date_time(time: NaiveDateTime) -> Self {
        Self::from_seconds_since_epoch(time.timestamp() as u64)
    }

    /// Add the provided duration to this time.
    fn add(&self, duration: Duration) -> Result<Self, Error> {
        self.as_seconds_since_epoch()
            .checked_add(duration.as_seconds())
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    /// Subtract the provided duration from this time.
    fn sub(&self, duration: Duration) -> Result<Self, Error> {
        self.as_seconds_since_epoch()
            .checked_sub(duration.as_seconds())
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    /// Get the difference between the provided `other` and `self`. `self` must be after `other`.
    fn difference(&self, other: Self) -> Result<Duration, Error> {
        self.as_seconds_since_epoch()
            .checked_sub(other.as_seconds_since_epoch())
            .map(Duration::from_seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    /// Returns true if this [`Time`] occurs after `time`.
    fn is_after(&self, time: Time) -> bool {
        self.as_seconds_since_epoch() > time.as_seconds_since_epoch()
    }
}

/// Extension methods on [`Interval`].
pub(crate) trait IntervalExt {
    /// Returns a [`Time`] representing the excluded end of this interval.
    fn end(&self) -> Time;
}

impl IntervalExt for Interval {
    /// Returns a [`Time`] representing the excluded end of this interval.
    fn end(&self) -> Time {
        // [`Self::new`] verified that this addition doesn't overflow.
        self.start().add(self.duration()).unwrap()
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use janus_messages::{Nonce, Report, TaskId, Time};
    use rand::{thread_rng, Rng};

    pub(crate) fn new_dummy_report(task_id: TaskId, when: Time) -> Report {
        Report::new(
            task_id,
            Nonce::new(when, thread_rng().gen()),
            Vec::new(),
            Vec::new(),
        )
    }
}
