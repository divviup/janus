//! Utilities for timestamps and durations.

use crate::message::Time;
use chrono::Utc;
use std::fmt::{Debug, Formatter};

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
