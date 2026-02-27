//! Utilities for timestamps and durations.

use std::{
    fmt::{Debug, Formatter},
    sync::{Arc, Mutex},
};

use chrono::{DateTime, TimeDelta, Utc};
use janus_messages::{Duration, Error, Interval, Time, taskprov::TimePrecision};

/// A clock knows what time it currently is.
pub trait Clock: 'static + Clone + Debug + Sync + Send {
    /// Get the current time.
    fn now(&self) -> DateTime<Utc>;

    /// Get the [`chrono::TimeDelta`] elapsed since the provided time according to this clock's
    /// current time.
    fn elapsed(&self, since: DateTime<Utc>) -> TimeDelta {
        self.now() - since
    }
}

/// A real clock returns the current time relative to the Unix epoch.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct RealClock {}

impl Clock for RealClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
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
    current_time: Arc<Mutex<u64>>,
}

impl MockClock {
    pub fn new(when: u64) -> MockClock {
        MockClock {
            current_time: Arc::new(Mutex::new(when)),
        }
    }

    pub fn set(&self, when: u64) {
        let mut current_time = self.current_time.lock().unwrap();
        *current_time = when;
    }

    pub fn advance(&self, dur: TimeDelta) {
        assert!(
            dur.num_seconds() >= 0,
            "MockClock::advance called with negative TimeDelta (time cannot go backward)"
        );
        let mut current_time = self.current_time.lock().unwrap();
        *current_time = current_time
            .checked_add(dur.num_seconds().try_into().expect("Duration overflow"))
            .expect("MockClock overflow");
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        let current_time = self.current_time.lock().unwrap();
        DateTime::<Utc>::from_timestamp_secs(
            (*current_time).try_into().expect("MockClock overflow"),
        )
        .expect("DateTime Overflow")
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self {
            // Sunday, September 9, 2001 1:46:40 AM UTC
            current_time: Arc::new(Mutex::new(1000000000)),
        }
    }
}

/// Number of microseconds per second.
const USEC_PER_SEC: u64 = 1_000_000;

/// Extension methods on [`chrono::TimeDelta`] for working with DAP durations.
pub trait TimeDeltaExt: Sized {
    /// Add two [`chrono::TimeDelta`] values.
    fn add(&self, other: &TimeDelta) -> Result<TimeDelta, Error>;

    /// Create a [`chrono::TimeDelta`] from a number of microseconds.
    fn from_microseconds(microseconds: u64) -> TimeDelta;

    /// Get the number of microseconds this [`chrono::TimeDelta`] represents, rounded to second
    /// precision.
    fn as_microseconds(&self) -> Result<u64, Error>;

    /// Create a [`chrono::TimeDelta`] representing the provided number of minutes.
    fn from_minutes(minutes: u64) -> Result<TimeDelta, Error>;

    /// Create a [`chrono::TimeDelta`] representing the provided number of hours.
    fn from_hours(hours: u64) -> Result<TimeDelta, Error>;

    /// Create a [`chrono::TimeDelta`] from an unsigned number of seconds.
    ///
    /// This is a convenience method that safely converts u64 seconds to i64,
    /// returning an error if the value is too large to represent.
    fn try_seconds_unsigned(seconds: u64) -> Result<TimeDelta, Error>;

    /// Return a [`chrono::TimeDelta`] representing this time delta rounded up to the next
    /// largest multiple of `time_precision`, or the same time delta if it's already a
    /// multiple.
    fn round_up(&self, time_precision: &TimeDelta) -> Result<TimeDelta, Error>;

    /// Confirm that this time delta is a multiple of the task time precision.
    fn validate_precision(self, time_precision: &TimeDelta) -> Result<Self, Error>;
}

impl TimeDeltaExt for TimeDelta {
    fn add(&self, other: &TimeDelta) -> Result<TimeDelta, Error> {
        self.checked_add(other)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn from_microseconds(microseconds: u64) -> TimeDelta {
        TimeDelta::microseconds((microseconds as i64).max(0))
    }

    fn as_microseconds(&self) -> Result<u64, Error> {
        u64::try_from(self.num_seconds())
            .map_err(|_| Error::IllegalTimeArithmetic("time delta is negative or too large"))?
            .checked_mul(USEC_PER_SEC)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn from_minutes(minutes: u64) -> Result<TimeDelta, Error> {
        60i64
            .checked_mul(
                minutes
                    .try_into()
                    .map_err(|_| Error::IllegalTimeArithmetic("minutes value too large"))?,
            )
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
            .map(TimeDelta::try_seconds)?
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn from_hours(hours: u64) -> Result<TimeDelta, Error> {
        let seconds: i64 = 3600i64
            .checked_mul(
                hours
                    .try_into()
                    .map_err(|_| Error::IllegalTimeArithmetic("hours value too large"))?,
            )
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))?;
        TimeDelta::try_seconds(seconds)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn try_seconds_unsigned(seconds: u64) -> Result<TimeDelta, Error> {
        let seconds_i64: i64 = seconds
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("seconds value too large for i64"))?;
        TimeDelta::try_seconds(seconds_i64)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn round_up(&self, time_precision: &TimeDelta) -> Result<TimeDelta, Error> {
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

        TimeDelta::try_seconds(
            self.num_seconds()
                .checked_add(rem_inv)
                .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))?,
        )
        .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn validate_precision(self, time_precision: &TimeDelta) -> Result<Self, Error> {
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

/// Extension methods to bridge between [`chrono::DateTime<Utc>`] and [`Time`].
pub trait DateTimeExt {
    /// Convert this [`DateTime<Utc>`] into a [`Time`].
    fn to_time(&self, time_precision: &TimePrecision) -> Time;

    /// Get the timestamp as seconds since the Unix epoch.
    fn as_seconds_since_epoch(&self) -> u64;

    /// Add a [`Duration`] to this [`DateTime<Utc>`].
    fn add_duration(
        &self,
        duration: &Duration,
        time_precision: &TimePrecision,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Add a [`TimeDelta`] to this [`DateTime<Utc>`].
    fn add_timedelta(&self, timedelta: &TimeDelta) -> Result<Self, Error>
    where
        Self: Sized;

    /// Subtract a [`TimeDelta`] from this [`DateTime<Utc>`].
    fn sub_timedelta(&self, timedelta: &TimeDelta) -> Result<Self, Error>
    where
        Self: Sized;

    /// Returns true if and only if this [`DateTime<Utc>`] occurs after the given [`Time`].
    fn is_after(&self, time: &Time, time_precision: &TimePrecision) -> bool;

    /// Returns true if and only if this [`DateTime<Utc>`] occurs before the given [`Time`].
    fn is_before(&self, time: &Time, time_precision: &TimePrecision) -> bool;

    /// Get the difference between this [`DateTime<Utc>`] and the provided `other` [`Time`].
    /// Returns `self - other`. `self` must be after `other`.
    fn difference_as_time_delta(
        &self,
        other: &Time,
        time_precision: &TimePrecision,
    ) -> Result<TimeDelta, Error>;

    /// Get the difference between the provided `other` [`DateTime<Utc>`] and this
    /// [`DateTime<Utc>`] using saturating arithmetic. If `self` is before `other`, the result
    /// is zero.
    fn saturating_difference(&self, other: &Self, time_precision: &TimePrecision) -> Duration;
}

impl DateTimeExt for DateTime<Utc> {
    fn to_time(&self, time_precision: &TimePrecision) -> Time {
        // Unwrap safety: Negative timestamps only happen during overflow
        Time::from_seconds_since_epoch(
            self.timestamp()
                .try_into()
                .expect("timestamp must be non-negative"),
            time_precision,
        )
    }

    fn as_seconds_since_epoch(&self) -> u64 {
        // Unwrap safety: Negative timestamps only happen during overflow
        self.timestamp()
            .try_into()
            .expect("timestamp must be non-negative")
    }

    fn add_duration(
        &self,
        duration: &Duration,
        time_precision: &TimePrecision,
    ) -> Result<Self, Error> {
        let seconds = duration.as_seconds(time_precision);
        let delta = TimeDelta::try_seconds(seconds.try_into().map_err(|_| {
            Error::IllegalTimeArithmetic("duration seconds value too large for i64")
        })?)
        .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))?;
        self.checked_add_signed(delta)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn add_timedelta(&self, timedelta: &TimeDelta) -> Result<Self, Error> {
        self.checked_add_signed(*timedelta)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn sub_timedelta(&self, timedelta: &TimeDelta) -> Result<Self, Error> {
        self.checked_sub_signed(*timedelta)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    fn is_after(&self, time: &Time, time_precision: &TimePrecision) -> bool {
        self.as_seconds_since_epoch() > time.as_seconds_since_epoch(time_precision)
    }

    fn is_before(&self, time: &Time, time_precision: &TimePrecision) -> bool {
        self.as_seconds_since_epoch() < time.as_seconds_since_epoch(time_precision)
    }

    fn difference_as_time_delta(
        &self,
        other: &Time,
        time_precision: &TimePrecision,
    ) -> Result<TimeDelta, Error> {
        let diff = self
            .as_seconds_since_epoch()
            .checked_sub(other.as_seconds_since_epoch(time_precision))
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))?;
        let diff_i64: i64 = diff
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("difference too large"))?;
        TimeDelta::try_seconds(diff_i64)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn saturating_difference(&self, other: &Self, time_precision: &TimePrecision) -> Duration {
        Duration::from_seconds(
            self.as_seconds_since_epoch()
                .saturating_sub(u64::try_from(other.timestamp()).unwrap_or_default()),
            time_precision,
        )
    }
}

/// Extension methods on [`Time`].
pub trait TimeExt: Sized {
    /// Convert this [`Time`] into a [`DateTime<Utc>`].
    fn as_date_time(&self, time_precision: TimePrecision) -> Result<DateTime<Utc>, Error>;

    /// Convert a [`DateTime<Utc>`] into a [`Time`].
    fn from_date_time(time: DateTime<Utc>, time_precision: TimePrecision) -> Self;

    /// Add the provided timedelta to this time.
    fn add_timedelta(
        &self,
        timedelta: &TimeDelta,
        time_precision: &TimePrecision,
    ) -> Result<Self, Error>;

    /// Subtract the provided timedelta from this time.
    fn sub_timedelta(
        &self,
        timedelta: &TimeDelta,
        time_precision: &TimePrecision,
    ) -> Result<Self, Error>;

    /// Add the provided duration to this time.
    fn add_duration(&self, duration: &Duration) -> Result<Self, Error>;

    /// Subtract the provided duration from this time.
    fn sub_duration(&self, duration: &Duration) -> Result<Self, Error>;

    /// Get the difference between the provided `other` and `self`. `self` must be after `other`.
    fn difference_as_time_delta(
        &self,
        other: &Self,
        time_precision: &TimePrecision,
    ) -> Result<TimeDelta, Error>;

    /// Get the difference between the provided `other` and `self` using saturating arithmetic. If
    /// `self` is before `other`, the result is zero.
    fn saturating_difference(&self, other: &Self) -> Duration;

    /// Returns true if and only if this [`Time`] occurs before `time`.
    fn is_before(&self, time: &Time) -> bool;

    /// Returns true if and only if this [`Time`] occurs after `time`.
    fn is_after(&self, time: &Time) -> bool;

    /// Compute the start of the batch interval containing this `Time`, given the duration of the
    /// batch intervals in the task. For example:
    ///
    /// ```no-compile
    /// assert_eq!(
    ///     Time::from_time_precision_units(17)
    ///         .to_batch_interval_start(Duration::from_time_precision_units(4)),
    ///     Time::from_time_precision_units(16),
    /// );
    /// ```
    ///
    /// This is irrespective of whatever time precision the two values are in. But for the
    /// computation to be meaningful, they should use the same time precision.
    fn to_batch_interval_start(&self, batch_interval_duration: Duration) -> Self;
}

impl TimeExt for Time {
    fn as_date_time(&self, time_precision: TimePrecision) -> Result<DateTime<Utc>, Error> {
        let seconds = self.as_seconds_since_epoch(&time_precision);
        DateTime::<Utc>::from_timestamp(
            seconds
                .try_into()
                .map_err(|_| Error::IllegalTimeArithmetic("number of seconds too big for i64"))?,
            0,
        )
        .ok_or(Error::IllegalTimeArithmetic(
            "number of seconds is out of range",
        ))
    }

    fn from_date_time(time: DateTime<Utc>, time_precision: TimePrecision) -> Self {
        Self::from_seconds_since_epoch(
            time.timestamp()
                .try_into()
                .expect("timestamp cannot be converted to u64"),
            &time_precision,
        )
    }

    fn add_timedelta(
        &self,
        timedelta: &TimeDelta,
        time_precision: &TimePrecision,
    ) -> Result<Self, Error> {
        let seconds: u64 = timedelta
            .num_seconds()
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("timedelta is negative or too large"))?;
        let precision_secs = time_precision.as_seconds();
        if precision_secs == 0 {
            return Err(Error::IllegalTimeArithmetic("time_precision is zero"));
        }
        let units = seconds / precision_secs;
        self.as_time_precision_units()
            .checked_add(units)
            .map(Self::from_time_precision_units)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn sub_timedelta(
        &self,
        timedelta: &TimeDelta,
        time_precision: &TimePrecision,
    ) -> Result<Self, Error> {
        let seconds: u64 = timedelta
            .num_seconds()
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("timedelta is negative or too large"))?;
        let precision_secs = time_precision.as_seconds();
        if precision_secs == 0 {
            return Err(Error::IllegalTimeArithmetic("time_precision is zero"));
        }
        let units = seconds / precision_secs;
        self.as_time_precision_units()
            .checked_sub(units)
            .map(Self::from_time_precision_units)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    fn add_duration(&self, duration: &Duration) -> Result<Self, Error> {
        self.as_time_precision_units()
            .checked_add(duration.as_time_precision_units())
            .map(Self::from_time_precision_units)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn sub_duration(&self, duration: &Duration) -> Result<Self, Error> {
        self.as_time_precision_units()
            .checked_sub(duration.as_time_precision_units())
            .map(Self::from_time_precision_units)
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))
    }

    fn difference_as_time_delta(
        &self,
        other: &Self,
        time_precision: &TimePrecision,
    ) -> Result<TimeDelta, Error> {
        let diff_units = self
            .as_time_precision_units()
            .checked_sub(other.as_time_precision_units())
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))?;
        let diff_seconds = diff_units
            .checked_mul(time_precision.as_seconds())
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))?;
        let diff_i64: i64 = diff_seconds
            .try_into()
            .map_err(|_| Error::IllegalTimeArithmetic("difference too large"))?;
        TimeDelta::try_seconds(diff_i64)
            .ok_or(Error::IllegalTimeArithmetic("operation would overflow"))
    }

    fn saturating_difference(&self, other: &Self) -> Duration {
        Duration::from_time_precision_units(
            self.as_time_precision_units()
                .saturating_sub(other.as_time_precision_units()),
        )
    }

    fn is_before(&self, time: &Time) -> bool {
        self.as_time_precision_units() < time.as_time_precision_units()
    }

    fn is_after(&self, time: &Time) -> bool {
        self.as_time_precision_units() > time.as_time_precision_units()
    }

    fn to_batch_interval_start(&self, batch_interval_duration: Duration) -> Self {
        let batch_interval_units = batch_interval_duration.as_time_precision_units();
        Self::from_time_precision_units(
            (self.as_time_precision_units() / batch_interval_units) * batch_interval_units,
        )
    }
}

/// Extension methods on [`Interval`].
pub trait IntervalExt: Sized {
    /// Returns a [`Time`] representing the excluded end of this interval.
    fn end(&self) -> Time;

    /// Returns a new minimal [`Interval`] that contains both this interval and `other`.
    fn merge(&self, other: &Self) -> Result<Self, Error>;

    /// Returns a new minimal [`Interval`] that contains both this interval and the given time.
    fn merged_with(&self, time: &Time) -> Result<Self, Error>;
}

impl IntervalExt for Interval {
    fn end(&self) -> Time {
        // Unwrap safety: [`Self::new_with_duration`] verified that this addition doesn't overflow.
        self.start().add_duration(&self.duration()).unwrap()
    }

    fn merge(&self, other: &Self) -> Result<Self, Error> {
        if self.duration() == Duration::ZERO {
            return Ok(*other);
        }
        if other.duration() == Duration::ZERO {
            return Ok(*self);
        }

        let max_time = std::cmp::max(self.end(), other.end());
        let min_time = std::cmp::min(self.start(), other.start());

        let diff_units = max_time
            .as_time_precision_units()
            .checked_sub(min_time.as_time_precision_units())
            .ok_or(Error::IllegalTimeArithmetic("operation would underflow"))?;
        Self::new(min_time, Duration::from_time_precision_units(diff_units))
    }

    fn merged_with(&self, time: &Time) -> Result<Self, Error> {
        self.merge(&Self::new(*time, Duration::ONE)?)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeDelta, Utc};
    use janus_messages::{Duration, Interval, Time, taskprov::TimePrecision};

    use crate::time::{DateTimeExt, IntervalExt, TimeDeltaExt, TimeExt};

    const TEST_TIME_PRECISION: TimePrecision = TimePrecision::from_seconds(1);

    #[test]
    fn round_up_duration() {
        for (label, duration, time_precision, expected) in [
            ("already a multiple", 100, 10, Some(100)),
            ("zero time precision", 100, 0, None),
            ("rounded up", 50, 100, Some(100)),
        ] {
            let duration_td = TimeDelta::seconds(duration);
            let precision_td = TimeDelta::seconds(time_precision);
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
                Time::from_seconds_since_epoch(start, &TEST_TIME_PRECISION),
                Duration::from_seconds(duration, &TEST_TIME_PRECISION),
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
                Time::from_seconds_since_epoch(i1_start, &TEST_TIME_PRECISION),
                Duration::from_seconds(i1_dur, &TEST_TIME_PRECISION),
            )
            .unwrap();
            let i2 = Interval::new(
                Time::from_seconds_since_epoch(i2_start, &TEST_TIME_PRECISION),
                Duration::from_seconds(i2_dur, &TEST_TIME_PRECISION),
            )
            .unwrap();
            let result = i1.merge(&i2);
            match expected {
                Some((expected_start, expected_duration)) => {
                    let result = result.unwrap();
                    let expected = Interval::new(
                        Time::from_seconds_since_epoch(expected_start, &TEST_TIME_PRECISION),
                        Duration::from_seconds(expected_duration, &TEST_TIME_PRECISION),
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
                Time::from_seconds_since_epoch(i1_start, &TEST_TIME_PRECISION),
                Duration::from_seconds(i1_dur, &TEST_TIME_PRECISION),
            )
            .unwrap();
            let result = i1.merged_with(&Time::from_seconds_since_epoch(i2, &TEST_TIME_PRECISION));
            match expected {
                Some((expected_start, expected_duration)) => {
                    let result = result.unwrap();
                    let expected = Interval::new(
                        Time::from_seconds_since_epoch(expected_start, &TEST_TIME_PRECISION),
                        Duration::from_seconds(expected_duration, &TEST_TIME_PRECISION),
                    )
                    .unwrap();
                    assert_eq!(result, expected, "{label}");
                }
                None => assert!(result.is_err(), "{label}"),
            }
        }
    }

    #[test]
    fn to_time_converts_correctly() {
        for (label, timestamp_secs, expected_secs) in [
            ("epoch", 0, 0),
            ("year 2000", 946684800, 946684800),
            ("y2038", 2147483647, 2147483647), // 2038-01-19
            ("in the year 2525", 17514169200, 17514169200),
        ] {
            let dt = DateTime::<Utc>::from_timestamp(timestamp_secs, 0).unwrap();
            let time = dt.to_time(&TEST_TIME_PRECISION);
            assert_eq!(
                time.as_seconds_since_epoch(&TEST_TIME_PRECISION),
                expected_secs,
                "{label}: timestamp mismatch"
            );
        }
    }

    #[test]
    fn time_to_batch_interval_start() {
        for (label, time_in, expected) in [
            ("aligned", 16, 16),
            ("not aligned bigger than batch interval", 17, 16),
            ("not aligned smaller than batch interval", 15, 0),
        ] {
            assert_eq!(
                Time::from_time_precision_units(time_in)
                    .to_batch_interval_start(Duration::from_time_precision_units(16)),
                Time::from_time_precision_units(expected),
                "{label}: failure"
            )
        }
    }

    #[test]
    fn add_duration_success() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let duration = Duration::from_seconds(3600, &TEST_TIME_PRECISION);

        let result = dt.add_duration(&duration, &TEST_TIME_PRECISION).unwrap();
        assert_eq!(result.timestamp(), 1000000000 + 3600);
    }

    #[test]
    fn add_duration_large_value_error() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        // Duration value too large to convert to i64 for TimeDelta
        let duration = Duration::from_seconds(i64::MAX as u64 + 1, &TEST_TIME_PRECISION);

        let result = dt.add_duration(&duration, &TEST_TIME_PRECISION);
        assert!(
            result.is_err(),
            "should error when duration value too large for i64"
        );
    }

    #[test]
    fn add_timedelta_success() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let delta = TimeDelta::seconds(7200);

        let result = dt.add_timedelta(&delta).unwrap();
        assert_eq!(result.timestamp(), 1000000000 + 7200);
    }

    #[test]
    fn add_timedelta_negative() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let delta = TimeDelta::seconds(-3600);

        let result = dt.add_timedelta(&delta).unwrap();
        assert_eq!(result.timestamp(), 1000000000 - 3600);
    }

    #[test]
    fn sub_timedelta_success() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let delta = TimeDelta::seconds(3600);

        let result = dt.sub_timedelta(&delta).unwrap();
        assert_eq!(result.timestamp(), 1000000000 - 3600);
    }

    #[test]
    fn sub_timedelta_large_negative_value() {
        // Test subtracting a very large timedelta that would underflow DateTime range
        let dt = DateTime::<Utc>::from_timestamp(0, 0).unwrap(); // is smol
        let delta = TimeDelta::try_seconds(100000000000).unwrap(); // is big

        assert!(
            dt.sub_timedelta(&delta).is_ok(),
            "should handle large subtraction gracefully"
        );
    }

    #[test]
    fn time_comparisons() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let time = Time::from_seconds_since_epoch(999999999, &TEST_TIME_PRECISION);

        assert!(
            dt.is_after(&time, &TEST_TIME_PRECISION),
            "dt should be after time"
        );

        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let time = Time::from_seconds_since_epoch(1000000001, &TEST_TIME_PRECISION);

        assert!(
            !dt.is_after(&time, &TEST_TIME_PRECISION),
            "dt should not be after time"
        );

        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let time = Time::from_seconds_since_epoch(1000000000, &TEST_TIME_PRECISION);

        assert!(
            !dt.is_after(&time, &TEST_TIME_PRECISION),
            "dt should not be after an equal time"
        );
        assert!(
            !dt.is_before(&time, &TEST_TIME_PRECISION),
            "dt should not be before an equal time"
        );
    }

    #[test]
    fn difference_as_time_delta_underflow() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let time = Time::from_seconds_since_epoch(1000000001, &TEST_TIME_PRECISION);

        let result = dt.difference_as_time_delta(&time, &TEST_TIME_PRECISION);
        assert!(result.is_err(), "should error when dt is before time");
    }

    #[test]
    fn saturating_difference_positive() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let time = DateTime::<Utc>::from_timestamp(999999000, 0).unwrap();

        let duration = dt.saturating_difference(&time, &TEST_TIME_PRECISION);
        assert_eq!(duration.as_seconds(&TEST_TIME_PRECISION), 1000);
    }

    #[test]
    fn saturating_difference_negative_returns_zero() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let time = DateTime::<Utc>::from_timestamp(1000000100, 0).unwrap(); // time is after dt

        let duration = dt.saturating_difference(&time, &TEST_TIME_PRECISION);
        assert_eq!(
            duration.as_seconds(&TEST_TIME_PRECISION),
            0,
            "should saturate to zero"
        );
    }

    #[test]
    fn saturating_difference_equal_returns_zero() {
        let dt = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();
        let time = DateTime::<Utc>::from_timestamp(1000000000, 0).unwrap();

        let duration = dt.saturating_difference(&time, &TEST_TIME_PRECISION);
        assert_eq!(duration.as_seconds(&TEST_TIME_PRECISION), 0);
    }
}
