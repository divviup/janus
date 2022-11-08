//! Utilities for timestamps and durations.

use chrono::Utc;
use janus_messages::{Duration, Time};
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

/// Extension methods on [`Time`].
pub trait TimeExt: Sized {
    /// Compute the start of the batch interval containing this Time, given the task time precision.
    fn to_batch_interval_start(
        &self,
        time_precision: &Duration,
    ) -> Result<Self, janus_messages::Error>;
}

impl TimeExt for Time {
    /// Compute the start of the batch interval containing this Time, given the task time precision.
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
}
