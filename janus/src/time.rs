//! Utilities for timestamps and durations.

use crate::message::Time;
use chrono::{naive::NaiveDateTime, Utc};
use std::fmt::{Debug, Formatter};

/// A clock knows what time it currently is.
pub trait Clock: 'static + Clone + Copy + Debug + Sync + Send {
    /// Get the current time.
    fn now(&self) -> Time;
}

/// A real clock returns the current time relative to the Unix epoch.
#[derive(Clone, Copy, Default)]
pub struct RealClock {}

impl Clock for RealClock {
    fn now(&self) -> Time {
        Time::from_naive_date_time(NaiveDateTime::from_timestamp(Utc::now().timestamp(), 0))
    }
}

impl Debug for RealClock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.now())
    }
}
