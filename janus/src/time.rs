//! Utilities for timestamps and durations.

use crate::message::Time;
use async_trait::async_trait;
use chrono::Utc;
use std::{
    fmt::{Debug, Formatter},
    future::Future,
    time::{Duration, Instant},
};
use tokio::time::{interval_at, sleep, timeout, Interval, MissedTickBehavior};

/// Error type indicating that a timeout elapsed.
#[derive(Debug)]
pub struct Elapsed;

/// A clock knows what time it currently is.
#[async_trait]
pub trait Clock: 'static + Clone + Debug + Sync + Send {
    /// Return type of `interval` and `interval_at`. This produces a series of ticks with a given
    /// amount of time between each tick.
    type Interval: ClockInterval;

    /// Get the current wall clock time.
    fn now(&self) -> Time;

    /// Get the current time from a monotonic clock, for use with timers.
    fn now_monotonic(&self) -> Instant;

    /// Wraps a future in a timeout, either returning the future's output or cancelling the future
    /// and returning an error.
    async fn timeout<O, F>(&self, duration: Duration, future: F) -> Result<O, Elapsed>
    where
        F: Future<Output = O> + Send;

    /// Create a [`Self::Interval`] that will produce ticks at a regular interval, with the first tick
    /// happening at `start`.
    fn interval_at(&self, start: Instant, period: Duration) -> Self::Interval;

    /// Create a [`Self::Interval`] that will produce ticks at a regular interval.
    fn interval(&self, period: Duration) -> Self::Interval {
        self.interval_at(self.now_monotonic(), period)
    }

    /// Wait for `duration`.
    async fn sleep(&self, duration: Duration);
}

/// Produces a series of ticks with a given amount of time between each tick.
#[async_trait]
pub trait ClockInterval: 'static + Debug + Send + Sync {
    async fn tick(&mut self);
    fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior);
}

/// A real clock returns the current time relative to the Unix epoch.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct RealClock {}

#[async_trait]
impl Clock for RealClock {
    type Interval = Interval;

    fn now(&self) -> Time {
        Time::from_seconds_since_epoch(
            Utc::now()
                .timestamp()
                .try_into()
                .expect("invalid or out-of-range timestamp"),
        )
    }

    fn now_monotonic(&self) -> Instant {
        Instant::now()
    }

    async fn timeout<O, F>(&self, duration: Duration, future: F) -> Result<O, Elapsed>
    where
        F: Future<Output = O> + Send,
    {
        timeout(duration, future).await.map_err(|_| Elapsed)
    }

    fn interval_at(&self, start: Instant, period: Duration) -> Self::Interval {
        interval_at(start.into(), period)
    }

    async fn sleep(&self, duration: Duration) {
        sleep(duration).await
    }
}

impl Debug for RealClock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.now())
    }
}

#[async_trait]
impl ClockInterval for Interval {
    async fn tick(&mut self) {
        self.tick().await;
    }

    fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
        self.set_missed_tick_behavior(behavior);
    }
}
