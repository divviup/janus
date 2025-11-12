//! Utilities for timestamps and durations.

use chrono::{DateTime, NaiveDateTime, Utc};
use janus_messages::{Duration, Error, Interval, Time};
use std::{
    fmt::{Debug, Formatter},
    sync::{Arc, Mutex},
};

/// A clock knows what time it currently is.
pub trait Clock: 'static + Clone + Debug + Sync + Send {
    /// Get the current time.
    fn now(&self) -> Time;

    /// Get the current time, truncated to the provided time precision. The answer will
    /// be between now and now()-time_precision.
    #[cfg(feature = "test-util")]
    fn now_aligned_to_precision(&self, time_precision: &Duration) -> Time {
        let seconds = self.now().as_seconds_since_epoch();
        // These unwraps are unsafe, and must only be used for tests.
        let rem = seconds.checked_rem(time_precision.as_seconds()).unwrap();

        seconds
            .checked_sub(rem)
            .map(Time::from_seconds_since_epoch)
            .unwrap()
    }
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

    pub fn set(&self, when: Time) {
        let mut current_time = self.current_time.lock().unwrap();
        *current_time = when;
    }

    pub fn advance(&self, dur: chrono::TimeDelta) {
        let mut current_time = self.current_time.lock().unwrap();
        *current_time = current_time.add_timedelta(&dur).unwrap();
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

/// Extension methods on [`Duration`] for working with DAP time precision validation.
pub trait DurationExt: Sized {
    /// Confirm that this duration is a multiple of the task time precision.
    fn validate_precision(self, time_precision: &Duration) -> Result<Self, Error>;
}

impl DurationExt for Duration {
    fn validate_precision(self, time_precision: &Duration) -> Result<Self, Error> {
        let is_multiple_of_time_precision = self
            .as_seconds()
            .checked_rem(time_precision.as_seconds())
            .ok_or(Error::IllegalTimeArithmetic("remainder cannot be zero"))
            .is_ok_and(|rem| rem == 0);

        if is_multiple_of_time_precision {
            Ok(self)
        } else {
            Err(Error::InvalidParameter(
                "duration is not a multiple of the time precision",
            ))
        }
    }
}

/// Extension methods on [`chrono::TimeDelta`] for working with DAP durations.
pub trait TimeDeltaExt: Sized {
    /// Add two [`chrono::TimeDelta`] values.
    fn add(&self, other: &chrono::TimeDelta) -> Result<chrono::TimeDelta, Error>;

    /// Create a [`chrono::TimeDelta`] from a number of microseconds.
    fn from_microseconds(microseconds: u64) -> chrono::TimeDelta;

    /// Get the number of microseconds this [`chrono::TimeDelta`] represents, rounded to second precision.
    fn as_microseconds(&self) -> Result<u64, Error>;

    /// Create a [`chrono::TimeDelta`] representing the provided number of minutes.
    fn from_minutes(minutes: u64) -> Result<chrono::TimeDelta, Error>;

    /// Create a [`chrono::TimeDelta`] representing the provided number of hours.
    fn from_hours(hours: u64) -> Result<chrono::TimeDelta, Error>;

    /// Create a [`chrono::TimeDelta`] from an unsigned number of seconds.
    ///
    /// This is a convenience method that safely converts u64 seconds to i64,
    /// returning an error if the value is too large to represent.
    fn try_seconds_unsigned(seconds: u64) -> Result<chrono::TimeDelta, Error>;

    /// Return a [`chrono::TimeDelta`] representing this time delta rounded up to the next largest multiple of
    /// `time_precision`, or the same time delta if it's already a multiple.
    fn round_up(&self, time_precision: &chrono::TimeDelta) -> Result<chrono::TimeDelta, Error>;

    /// Confirm that this time delta is a multiple of the task time precision.
    fn validate_precision(self, time_precision: &chrono::TimeDelta) -> Result<Self, Error>;
}

impl TimeDeltaExt for chrono::TimeDelta {
    fn add(&self, other: &chrono::TimeDelta) -> Result<chrono::TimeDelta, Error> {
        self.checked_add(other)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn from_microseconds(microseconds: u64) -> chrono::TimeDelta {
        chrono::TimeDelta::microseconds((microseconds as i64).max(0))
    }

    fn as_microseconds(&self) -> Result<u64, Error> {
        <i64 as TryInto<u64>>::try_into(self.num_seconds())
            .map_err(|_| Error::IllegalTimeArithmetic("time delta is negative or too large"))?
            .checked_mul(USEC_PER_SEC)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn from_minutes(minutes: u64) -> Result<chrono::TimeDelta, Error> {
        60i64
            .checked_mul(
                minutes
                    .try_into()
                    .map_err(|_| Error::IllegalTimeArithmetic("minutes value too large"))?,
            )
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
            .map(chrono::TimeDelta::try_seconds)?
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn from_hours(hours: u64) -> Result<chrono::TimeDelta, Error> {
        let seconds: i64 = 3600i64
            .checked_mul(
                hours
                    .try_into()
                    .map_err(|_| Error::IllegalTimeArithmetic("hours value too large"))?,
            )
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))?;
        chrono::TimeDelta::try_seconds(seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn try_seconds_unsigned(seconds: u64) -> Result<chrono::TimeDelta, Error> {
        let seconds_i64: i64 = seconds
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("seconds value too large for i64"))?;
        chrono::TimeDelta::try_seconds(seconds_i64)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn round_up(&self, time_precision: &chrono::TimeDelta) -> Result<chrono::TimeDelta, Error> {
        let rem = self
            .num_seconds()
            .checked_rem(time_precision.num_seconds())
            .ok_or(Error::IllegalTimeArithmetic(
                "remainder would overflow/underflow",
            ))?;

        // time delta is already aligned
        if rem == 0 {
            return Ok(*self);
        }

        let rem_inv =
            time_precision
                .num_seconds()
                .checked_sub(rem)
                .ok_or(Error::IllegalTimeArithmetic(
                    "difference cannot be represented as u64",
                ))?;

        chrono::TimeDelta::try_seconds(
            self.num_seconds()
                .checked_add(rem_inv)
                .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))?,
        )
        .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn validate_precision(self, time_precision: &chrono::TimeDelta) -> Result<Self, Error> {
        let is_multiple_of_time_precision = self
            .num_seconds()
            .checked_rem(time_precision.num_seconds())
            .ok_or(Error::IllegalTimeArithmetic("remainder cannot be zero"))
            .is_ok_and(|rem| rem == 0);

        if is_multiple_of_time_precision {
            Ok(self)
        } else {
            Err(Error::InvalidParameter(
                "time delta is not a multiple of the time precision",
            ))
        }
    }
}

/// Extension methods on [`Time`].
pub trait TimeExt: Sized {
    /// Compute the start of the batch interval containing this Time, given the task time precision.
    fn to_batch_interval_start(
        &self,
        time_precision: &Duration,
    ) -> Result<Self, janus_messages::Error>;

    /// Confirm that the time is a multiple of the task time precision.
    fn validate_precision(self, time_precision: &Duration) -> Result<Self, janus_messages::Error>;

    /// Convert this [`Time`] into a [`NaiveDateTime`], representing an instant in the UTC timezone.
    fn as_naive_date_time(&self) -> Result<NaiveDateTime, Error>;

    /// Convert a [`NaiveDateTime`] representing an instant in the UTC timezone into a [`Time`].
    fn from_naive_date_time(time: &NaiveDateTime) -> Self;

    /// Add the provided duration to this time.
    fn add_timedelta(&self, timedelta: &chrono::TimeDelta) -> Result<Self, Error>;

    /// Subtract the provided timedelta from this time.
    fn sub_timedelta(&self, timedelta: &chrono::TimeDelta) -> Result<Self, Error>;
    /// Add the provided duration to this time.
    fn add_duration(&self, duration: &Duration) -> Result<Self, Error>;

    /// Subtract the provided duration from this time.
    fn sub_duration(&self, duration: &Duration) -> Result<Self, Error>;

    /// Get the difference between the provided `other` and `self`. `self` must be after `other`.
    fn difference_as_time_delta(&self, other: &Self) -> Result<chrono::TimeDelta, Error>;

    /// Get the difference between the provided `other` and `self` using saturating arithmetic. If
    /// `self` is before `other`, the result is zero.
    fn saturating_difference(&self, other: &Self) -> Duration;

    /// Returns true if and only if this [`Time`] occurs before `time`.
    fn is_before(&self, time: &Time) -> bool;

    /// Returns true if and only if this [`Time`] occurs after `time`.
    fn is_after(&self, time: &Time) -> bool;
}

impl TimeExt for Time {
    fn to_batch_interval_start(
        &self,
        time_precision: &Duration,
    ) -> Result<Self, janus_messages::Error> {
        // This function will return an error if and only if `time_precision` is 0.
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

    fn validate_precision(self, time_precision: &Duration) -> Result<Self, janus_messages::Error> {
        let is_multiple_of_time_precision = self
            .as_seconds_since_epoch()
            .checked_rem(time_precision.as_seconds())
            .ok_or(janus_messages::Error::IllegalTimeArithmetic(
                "remainder cannot be zero",
            ))
            .is_ok_and(|rem| rem == 0);

        if is_multiple_of_time_precision {
            Ok(self)
        } else {
            Err(janus_messages::Error::InvalidParameter(
                "timestamp is not a multiple of the time precision",
            ))
        }
    }

    fn as_naive_date_time(&self) -> Result<NaiveDateTime, Error> {
        DateTime::<Utc>::from_timestamp(
            self.as_seconds_since_epoch()
                .try_into()
                .map_err(|_| Error::IllegalTimeArithmetic("number of seconds too big for i64"))?,
            0,
        )
        .ok_or(Error::IllegalTimeArithmetic(
            "number of seconds is out of range",
        ))
        .map(|dt| dt.naive_utc())
    }

    fn from_naive_date_time(time: &NaiveDateTime) -> Self {
        Self::from_seconds_since_epoch(time.and_utc().timestamp() as u64)
    }

    fn add_timedelta(&self, timedelta: &chrono::TimeDelta) -> Result<Self, Error> {
        let seconds: u64 = timedelta
            .num_seconds()
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("timedelta is negative or too large"))?;
        self.as_seconds_since_epoch()
            .checked_add(seconds)
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn sub_timedelta(&self, timedelta: &chrono::TimeDelta) -> Result<Self, Error> {
        let seconds: u64 = timedelta
            .num_seconds()
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("timedelta is negative or too large"))?;
        self.as_seconds_since_epoch()
            .checked_sub(seconds)
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    fn add_duration(&self, duration: &Duration) -> Result<Self, Error> {
        let seconds = duration.as_seconds();
        self.as_seconds_since_epoch()
            .checked_add(seconds)
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn sub_duration(&self, duration: &Duration) -> Result<Self, Error> {
        let seconds = duration.as_seconds();
        self.as_seconds_since_epoch()
            .checked_sub(seconds)
            .map(Self::from_seconds_since_epoch)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    fn difference_as_time_delta(&self, other: &Self) -> Result<chrono::TimeDelta, Error> {
        let diff = self
            .as_seconds_since_epoch()
            .checked_sub(other.as_seconds_since_epoch())
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))?;
        let diff_i64: i64 = diff
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("difference too large"))?;
        chrono::TimeDelta::try_seconds(diff_i64)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn saturating_difference(&self, other: &Self) -> Duration {
        Duration::from_seconds(
            self.as_seconds_since_epoch()
                .saturating_sub(other.as_seconds_since_epoch()),
        )
    }

    fn is_before(&self, time: &Time) -> bool {
        self.as_seconds_since_epoch() < time.as_seconds_since_epoch()
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

    // Returns a new minimal [`Interval`] that contains both this interval and the given time.
    fn merged_with(&self, time: &Time) -> Result<Self, Error>;

    /// Returns the smallest [`Interval`] that contains this interval and whose start and duration
    /// are multiples of `time_precision`.
    fn align_to_time_precision(&self, time_precision: &Duration) -> Result<Self, Error>;

    /// Confirm that this interval's start and duration are both multiples of the task time precision.
    fn validate_precision(self, time_precision: &Duration) -> Result<Self, janus_messages::Error>;
}

impl IntervalExt for Interval {
    fn end(&self) -> Time {
        // Unwrap safety: [`Self::new`] verified that this addition doesn't overflow.
        self.start().add_duration(self.duration()).unwrap()
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
        let diff = max_time.difference_as_time_delta(min_time)?;
        Self::new(*min_time, Duration::from_chrono(diff))
    }

    fn merged_with(&self, time: &Time) -> Result<Self, Error> {
        self.merge(&Self::new(*time, Duration::from_seconds(1))?)
    }

    fn align_to_time_precision(&self, time_precision: &Duration) -> Result<Self, Error> {
        // Round the interval start *down* to the time precision
        let aligned_start = self.start().to_batch_interval_start(time_precision)?;
        // Round the interval duration *up* to the time precision
        let duration_td = self.duration().to_chrono()?;
        let precision_td = time_precision.to_chrono()?;
        let aligned_duration_td = duration_td.round_up(&precision_td)?;
        let aligned_duration = Duration::from_chrono(aligned_duration_td);

        let aligned_interval = Self::new(aligned_start, aligned_duration)?;

        // Rounding the start down may have shifted the interval far enough to exclude the previous
        // interval's end. Extend the duration by time_precision if necessary.
        if self.end().is_after(&aligned_interval.end()) {
            let padded_duration_td = aligned_duration_td.add(&precision_td)?;
            let padded_duration = Duration::from_chrono(padded_duration_td);
            Self::new(aligned_start, padded_duration)
        } else {
            Ok(aligned_interval)
        }
    }

    fn validate_precision(self, time_precision: &Duration) -> Result<Self, janus_messages::Error> {
        self.start().validate_precision(time_precision)?;
        self.duration().validate_precision(time_precision)?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::time::{Clock, IntervalExt, MockClock, TimeDeltaExt, TimeExt};
    use janus_messages::{Duration, Interval, Time};

    #[test]
    fn round_up_duration() {
        for (label, duration, time_precision, expected) in [
            ("already a multiple", 100, 10, Some(100)),
            ("zero time precision", 100, 0, None),
            ("rounded up", 50, 100, Some(100)),
        ] {
            let duration_td = chrono::TimeDelta::try_seconds(duration).unwrap();
            let precision_td = chrono::TimeDelta::try_seconds(time_precision).unwrap();
            let result = duration_td.round_up(&precision_td);
            match expected {
                Some(expected) => {
                    assert_eq!(expected, result.unwrap().num_seconds(), "{label}",)
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
    fn interval_merge() {
        for (label, i1_start, i1_dur, i2_start, i2_dur, expected) in [
            ("contiguous", 0, 100, 100, 100, Some((0, 200))),
            ("gap", 0, 100, 200, 100, Some((0, 300))),
            ("i1 zero duration", 0, 0, 200, 100, Some((200, 100))),
            ("i2 zero duration", 0, 100, 200, 0, Some((0, 100))),
        ] {
            let i1 = Interval::new(
                Time::from_seconds_since_epoch(i1_start),
                Duration::from_seconds(i1_dur),
            )
            .unwrap();
            let i2 = Interval::new(
                Time::from_seconds_since_epoch(i2_start),
                Duration::from_seconds(i2_dur),
            )
            .unwrap();
            let result = i1.merge(&i2);
            match expected {
                Some((expected_start, expected_duration)) => {
                    let result = result.unwrap();
                    let expected = Interval::new(
                        Time::from_seconds_since_epoch(expected_start),
                        Duration::from_seconds(expected_duration),
                    )
                    .unwrap();
                    assert_eq!(result, expected, "{label}");
                }
                None => assert!(result.is_err(), "{label}"),
            }
        }
    }

    #[test]
    fn interval_merged_with() {
        for (label, i1_start, i1_dur, i2, expected) in [
            ("contiguous aligned", 0, 100, 200, Some((0, 201))),
            ("contiguous unaligned", 0, 100, 234, Some((0, 235))),
            ("gap aligned", 0, 100, 200, Some((0, 201))),
            ("gap wider aligned", 0, 100, 300, Some((0, 301))),
            ("gap wider unaligned", 0, 100, 1010, Some((0, 1011))),
            ("overlap", 0, 100, 0, Some((0, 100))),
        ] {
            let i1 = Interval::new(
                Time::from_seconds_since_epoch(i1_start),
                Duration::from_seconds(i1_dur),
            )
            .unwrap();
            let result = i1.merged_with(&Time::from_seconds_since_epoch(i2));
            match expected {
                Some((expected_start, expected_duration)) => {
                    let result = result.unwrap();
                    let expected = Interval::new(
                        Time::from_seconds_since_epoch(expected_start),
                        Duration::from_seconds(expected_duration),
                    )
                    .unwrap();
                    assert_eq!(result, expected, "{label}");
                }
                None => assert!(result.is_err(), "{label}"),
            }
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
                    assert!(
                        result.validate_precision(&time_precision).is_ok(),
                        "{label} precision is not correct"
                    );
                }
                None => assert!(result.is_err(), "{label}"),
            }
        }
    }

    #[test]
    fn interval_validate_time_precision() {
        for (label, interval_start, interval_duration, time_precision, expected) in [
            ("already aligned", 0, 100, 10, true),
            ("unaligned durations are bad", 0, 75, 10, false),
            ("unaligned starts are bad", 25, 100, 10, false),
            ("unaligned everything is bad", 15, 35, 10, false),
        ] {
            let interval = Interval::new(
                Time::from_seconds_since_epoch(interval_start),
                Duration::from_seconds(interval_duration),
            )
            .unwrap();
            let time_precision = Duration::from_seconds(time_precision);
            let result = interval.validate_precision(&time_precision);

            assert_eq!(expected, result.is_ok(), "{label}");
        }
    }

    #[test]
    fn validate_time_precision() {
        for (label, timestamp, timestamp_precision, expected) in [
            ("aligned", 1533415320, 60, true),
            ("off by 1", 1533415321, 60, false),
            ("aligned large", 1533414000, 6000, true),
            ("off by 100", 1533414100, 6000, false),
            ("zero time precision", 1533414000, 0, false),
            ("zero time on a zero timestamp", 0, 0, false),
        ] {
            let time = Time::from_seconds_since_epoch(timestamp);
            let precision = Duration::from_seconds(timestamp_precision);

            let result = time.validate_precision(&precision);
            match expected {
                true => assert!(result.is_ok(), "{label}"),
                false => assert!(result.is_err(), "{label}"),
            }
        }
    }

    #[test]
    fn now_aligned_to_precision() {
        for (label, timestamp, timestamp_precision, expected) in [
            ("aligned", 1533415320, 60, 1533415320),
            ("off by 1", 1533415321, 60, 1533415320),
            ("aligned large", 1533414000, 6000, 1533414000),
            ("off by 100", 1533414100, 6000, 1533414000),
        ] {
            let clock = MockClock::new(Time::from_seconds_since_epoch(timestamp));
            let precision = Duration::from_seconds(timestamp_precision);

            let result = clock
                .now_aligned_to_precision(&precision)
                .as_seconds_since_epoch();
            assert_eq!(expected, result, "{label}");
        }
    }
}
