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

    pub fn advance(&self, dur: &Duration) {
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
    /// Convert this [`Duration`] into a [`chrono::Duration`].
    fn as_chrono_duration(&self) -> Result<chrono::Duration, Error>;

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

    /// Return a duration representing this duration rounded up to the next largest multiple of
    /// `time_precision`, or the same duration if it already a multiple.
    fn round_up(&self, time_precision: &Duration) -> Result<Self, Error>;
}

impl DurationExt for Duration {
    fn as_chrono_duration(&self) -> Result<chrono::Duration, Error> {
        Ok(chrono::Duration::seconds(
            self.as_seconds()
                .try_into()
                .map_err(|_| Error::IllegalTimeArithmetic("number of seconds too big for i64"))?,
        ))
    }

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

    fn round_up(&self, time_precision: &Duration) -> Result<Self, Error> {
        let rem = self
            .as_seconds()
            .checked_rem(time_precision.as_seconds())
            .ok_or(janus_messages::Error::IllegalTimeArithmetic(
                "remainder would overflow/underflow",
            ))?;

        // self is already aligned
        if rem == 0 {
            return Ok(*self);
        }

        let rem_inv = Self::from_seconds(time_precision.as_seconds().checked_sub(rem).ok_or(
            Error::IllegalTimeArithmetic("difference cannot be represented as u64"),
        )?);

        self.add(&rem_inv)
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
pub trait IntervalExt: Sized {
    /// Returns a [`Time`] representing the excluded end of this interval.
    fn end(&self) -> Time;

    /// Returns a new minimal [`Interval`] that contains both this interval and `other`.
    fn merge(&self, other: &Self) -> Result<Self, Error>;

    /// Returns a 0-length `[Interval]` that contains exactly the provided [`Time`].
    fn from_time(time: &Time) -> Result<Self, Error>;

    /// Returns the smallest [`Interval`] that contains this interval and whose start and duration
    /// are multiples of `time_precision`.
    fn align_to_time_precision(&self, time_precision: &Duration) -> Result<Self, Error>;
}

impl IntervalExt for Interval {
    fn end(&self) -> Time {
        // [`Self::new`] verified that this addition doesn't overflow.
        self.start().add(self.duration()).unwrap()
    }

    fn merge(&self, other: &Self) -> Result<Self, Error> {
        if self.duration() == &Duration::ZERO {
            return Ok(*other);
        }
        if other.duration() == &Duration::ZERO {
            return Ok(*self);
        }

        let max_time = std::cmp::max(self.end(), other.end());
        let min_time = std::cmp::min(self.start(), other.start());

        // This can't actually fail for any valid Intervals
        Self::new(*min_time, max_time.difference(min_time)?)
    }

    fn from_time(time: &Time) -> Result<Self, Error> {
        // Recall that Interval is defined to exclude the end of the interval, so an interval of
        // length 1 only contains its start.
        Self::new(*time, Duration::from_seconds(1))
    }

    fn align_to_time_precision(&self, time_precision: &Duration) -> Result<Self, Error> {
        // Round the interval start *down* to the time precision
        let aligned_start = self.start().to_batch_interval_start(time_precision)?;
        // Round the interval duration *up* to the time precision
        let aligned_duration = self.duration().round_up(time_precision)?;

        let aligned_interval = Self::new(aligned_start, aligned_duration)?;

        // Rounding the start down may have shifted the interval far enough to exclude the previous
        // interval's end. Extend the duration by time_precision if necessary.
        if self.end().is_after(&aligned_interval.end()) {
            let padded_duration = aligned_duration.add(time_precision)?;
            Self::new(aligned_start, padded_duration)
        } else {
            Ok(aligned_interval)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::time::{DurationExt, IntervalExt};
    use janus_messages::{Duration, Interval, Time};

    #[test]
    fn round_up_duration() {
        for (label, duration, time_precision, expected) in [
            ("already a multiple", 100, 10, Some(100)),
            ("zero time precision", 100, 0, None),
            ("rounded up", 50, 100, Some(100)),
        ] {
            let result =
                Duration::from_seconds(duration).round_up(&Duration::from_seconds(time_precision));
            match expected {
                Some(expected) => {
                    assert_eq!(Duration::from_seconds(expected), result.unwrap(), "{label}",)
                }
                None => assert!(result.is_err(), "{label}"),
            }
        }
    }

    #[test]
    fn merge_interval() {
        fn interval(start: u64, duration: u64) -> Interval {
            Interval::new(
                Time::from_seconds_since_epoch(start),
                Duration::from_seconds(duration),
            )
            .unwrap()
        }

        for (label, lhs, rhs, want) in [
            (
                "non-overlapping intervals",
                interval(0, 10),
                interval(20, 10),
                interval(0, 30),
            ),
            (
                "overlapping intervals",
                interval(0, 10),
                interval(5, 10),
                interval(0, 15),
            ),
            (
                "one interval contains the other",
                interval(0, 10),
                interval(2, 8),
                interval(0, 10),
            ),
            (
                "equal intervals",
                interval(0, 10),
                interval(0, 10),
                interval(0, 10),
            ),
            (
                "lhs empty",
                Interval::EMPTY,
                interval(0, 10),
                interval(0, 10),
            ),
            (
                "rhs empty",
                interval(0, 10),
                Interval::EMPTY,
                interval(0, 10),
            ),
            ("empty", Interval::EMPTY, Interval::EMPTY, Interval::EMPTY),
        ] {
            assert_eq!(want, lhs.merge(&rhs).unwrap(), "{label}");
        }
    }

    #[test]
    fn interval_align_to_time_precision() {
        for (label, interval_start, interval_duration, time_precision, expected) in [
            ("already aligned", 0, 100, 100, Some((0, 100))),
            ("round duration", 0, 75, 100, Some((0, 100))),
            ("round both", 25, 75, 100, Some((0, 100))),
            ("round start, pad duration", 25, 100, 100, Some((0, 200))),
        ] {
            let interval = Interval::new(
                Time::from_seconds_since_epoch(interval_start),
                Duration::from_seconds(interval_duration),
            )
            .unwrap();
            let time_precision = Duration::from_seconds(time_precision);

            let result = interval.align_to_time_precision(&time_precision);

            match expected {
                Some((expected_start, expected_duration)) => {
                    let result = result.unwrap();
                    let expected = Interval::new(
                        Time::from_seconds_since_epoch(expected_start),
                        Duration::from_seconds(expected_duration),
                    )
                    .unwrap();
                    assert_eq!(result, expected, "{label}");
                    assert!(
                        result.start().as_seconds_since_epoch()
                            <= interval.start().as_seconds_since_epoch(),
                        "{label}"
                    );
                    assert!(
                        result.end().as_seconds_since_epoch()
                            >= interval.end().as_seconds_since_epoch(),
                        "{label}"
                    );
                }
                None => assert!(result.is_err(), "{label}"),
            }
        }
    }
}
