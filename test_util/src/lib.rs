use assert_matches::assert_matches;
use async_trait::async_trait;
use janus::{
    message::{Duration, Nonce, Time},
    time::{Clock, ClockInterval, Elapsed},
};
use prio::{
    codec::Encode,
    vdaf::{self, VdafError},
};
use rand::{thread_rng, Rng};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use std::{
    future::Future,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration as StdDuration, Instant},
};
use tokio::{
    select,
    sync::{
        broadcast::{self, Sender},
        Mutex,
    },
    time::MissedTickBehavior,
};

/// The Janus database schema.
pub static SCHEMA: &str = include_str!("../../db/schema.sql");

/// This macro injects definitions of `DbHandle` and `ephemeral_datastore()`, for use in tests.
/// It should be invoked once per binary target, and then `ephemeral_datastore()` can be called
/// to set up a database for test purposes. This depends on `janus_server::datastore::Datastore`,
/// `janus_server::datastore::Crypter`, and `janus_server::time::Clock` already being imported into
/// scope, and it expects the following crates to be available: `deadpool_postgres`, `lazy_static`,
/// `ring`, `testcontainers`, `tokio_postgres`, and `tracing`.
#[macro_export]
macro_rules! define_ephemeral_datastore {
    () => {
        ::lazy_static::lazy_static! {
            static ref CONTAINER_CLIENT: ::testcontainers::clients::Cli = ::testcontainers::clients::Cli::default();
        }

        /// DbHandle represents a handle to a running (ephemeral) database. Dropping this value
        /// causes the database to be shut down & cleaned up.
        pub struct DbHandle {
            _db_container: ::testcontainers::Container<'static, ::testcontainers::images::postgres::Postgres>,
            connection_string: String,
            datastore_key_bytes: Vec<u8>,
        }

        impl DbHandle {
            pub fn connection_string(&self) -> &str {
                &self.connection_string
            }

            pub fn datastore_key_bytes(&self) -> &[u8] {
                &self.datastore_key_bytes
            }
        }

        impl Drop for DbHandle {
            fn drop(&mut self) {
                ::tracing::trace!(connection_string = %self.connection_string, "Dropping ephemeral Postgres container");
            }
        }

        /// ephemeral_datastore creates a new Datastore instance backed by an ephemeral database which
        /// has the Janus schema applied but is otherwise empty.
        ///
        /// Dropping the second return value causes the database to be shut down & cleaned up.
        pub async fn ephemeral_datastore<C: Clock>(clock: C) -> (Datastore<C>, DbHandle) {
            // Start an instance of Postgres running in a container.
            let db_container =
                CONTAINER_CLIENT.run(::testcontainers::RunnableImage::from(::testcontainers::images::postgres::Postgres::default()).with_tag("14-alpine"));

            // Create a connection pool whose clients will talk to our newly-running instance of Postgres.
            const POSTGRES_DEFAULT_PORT: u16 = 5432;
            // TODO (issue #109): `get_host_port` does not specify what host IP address the port is
            // associated with, but empirically we see it is the port for 127.0.0.1, and not
            // [::1]. We will hardcode 127.0.0.1 (instead of localhost) until a host IP is
            // exposed via the API.
            let connection_string = format!(
                "postgres://postgres:postgres@127.0.0.1:{}/postgres",
                db_container.get_host_port(POSTGRES_DEFAULT_PORT)
            );
            ::tracing::trace!("Postgres container is up with URL {}", connection_string);
            let cfg = <::tokio_postgres::Config as std::str::FromStr>::from_str(&connection_string).unwrap();
            let conn_mgr = ::deadpool_postgres::Manager::new(cfg, ::tokio_postgres::NoTls);
            let pool = ::deadpool_postgres::Pool::builder(conn_mgr).build().unwrap();

            // Create a crypter with a random (ephemeral) key.
            let datastore_key_bytes = ::janus_test_util::generate_aead_key_bytes();
            let datastore_key =
                ::ring::aead::LessSafeKey::new(::ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &datastore_key_bytes).unwrap());
            let crypter = Crypter::new(vec![datastore_key]);

            // Connect to the database & run our schema.
            let client = pool.get().await.unwrap();
            client.batch_execute(::janus_test_util::SCHEMA).await.unwrap();

            (
                Datastore::new(pool, crypter, clock),
                DbHandle {
                    _db_container: db_container,
                    connection_string,
                    datastore_key_bytes,
                },
            )
        }
    };
}

pub fn generate_aead_key_bytes() -> Vec<u8> {
    let mut key_bytes = vec![0u8; AES_128_GCM.key_len()];
    thread_rng().fill(&mut key_bytes[..]);
    key_bytes
}

pub fn generate_aead_key() -> LessSafeKey {
    let unbound_key = UnboundKey::new(&AES_128_GCM, &generate_aead_key_bytes()).unwrap();
    LessSafeKey::new(unbound_key)
}

#[derive(Debug)]
struct MockClockInner {
    /// The times that the clock will return from [`MockClock::now`] and
    /// [`MockClock::now_monotonic`], and a broadcast channel to wake up tasks that are
    /// currently sleeping.
    current_times: Mutex<(Time, Instant, Sender<()>)>,
    /// A second copy of the times that the clock will return, behind a non-async mutex. This is
    /// necessary to enable interior mutability while still having `now()` and `now_monotonic()` be
    /// non-async functions, and simultaneously allowing them to be called from within the Tokio
    /// runtime.
    ///
    /// Updates to the times will be coordinated by first locking the async mutex, then locking the
    /// non-async mutex, and updating both sets of times together. Reads from `now()` and
    /// `now_monotonic()` only lock this non-async mutex. We know these reads will be consistent
    /// with other tasks'/threads' view of the world, since updates only happen when both mutexes
    /// are locked simultaneously. (Note that these methods cannot use tokio::sync::Mutex::lock
    /// without changing Clock's API because they are not async, and they cannot use
    /// tokio::sync::Mutex::blocking_lock because it calls block_on, which can't be used from a
    /// Tokio runtime thread)
    current_times_std_mutex: StdMutex<(Time, Instant)>,
    /// Records for each task that is currently waiting for the clock's time to be advanced past a
    /// given instant, and a broadcast channel to notify any tasks waiting in
    /// `wait_for_sleeping_taskss()`.
    waiting_tasks: Mutex<(Vec<Instant>, Sender<()>)>,
}

/// A mock clock for use in testing. Clones are identical: all clones of a given MockClock will
/// be controlled by a controller retrieved from any of the clones.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MockClock {
    /// Inner state of the mock clock, wrapped in a smart pointer.
    inner: Arc<MockClockInner>,
}

impl MockClock {
    pub fn new(when: Time) -> MockClock {
        // Note that we use Instant::now() as an arbitrary starting place for the monotonic clock.
        // Both times will advance in conjunction when `advance()` is called. The real current
        // time otherwise has no influence on the `MockClock`.
        let monotonic_time = Instant::now();

        let time_update_sender = broadcast::channel(10).0;
        let time_tokio_mutex = Mutex::new((when, monotonic_time, time_update_sender));
        let time_std_mutex = StdMutex::new((when, monotonic_time));
        let waiter_update_sender = broadcast::channel(10).0;
        let waiting_tasks_mutex = Mutex::new((vec![], waiter_update_sender));
        MockClock {
            inner: Arc::new(MockClockInner {
                current_times: time_tokio_mutex,
                current_times_std_mutex: time_std_mutex,
                waiting_tasks: waiting_tasks_mutex,
            }),
        }
    }

    /// Advance the time by a given amount, and wake up "sleeping" threads as is appropriate.
    pub async fn advance(&self, dur: Duration) {
        // Acquire both Tokio mutex locks. (This is the only method that locks more than one of our
        // three mutexes simultaneously, so there's no risk of deadlock)
        let mut current_times_guard = self.inner.current_times.lock().await;
        let mut waiting_tasks_guard = self.inner.waiting_tasks.lock().await;

        // Increment both current times.
        current_times_guard.0 = current_times_guard.0.add(dur).unwrap();
        current_times_guard.1 += StdDuration::from_secs(dur.as_seconds());

        // Update the times in the std::sync::Mutex, so that we can read it from now().
        *self.inner.current_times_std_mutex.lock().unwrap() =
            (current_times_guard.0, current_times_guard.1);

        // Remove tasks waiting on timers that will now be expired from our accounting.
        // wait_for_sleeping_tasks() will immediately return 0 if all timers have expired, no
        // matter in what order different tasks execute.
        waiting_tasks_guard
            .0
            .retain(|sleep_deadline| current_times_guard.1 < *sleep_deadline);

        // Send a notification to all tasks waiting in a sleep to check the current time again.
        let _ = current_times_guard.2.send(());
    }

    /// Helper function to sleep until the clock is advanced past a given instant.
    ///
    /// If `report_to_test_driver` is true, this task will be included in the accounting for
    /// `wait_for_sleeping_tasks()`.
    async fn sleep_until(&self, instant: Instant, report_to_test_driver: bool) {
        let mut receiver = {
            let current_times_guard = self.inner.current_times.lock().await;
            // Do an early-out check if the timer has already expired. This will avoid spuriously
            // increasing the number of waiting tasks for a very brief window.
            if current_times_guard.1 >= instant {
                return;
            }
            current_times_guard.2.subscribe()
        };

        if report_to_test_driver {
            // Record that this task is sleeping, and notify any tasks in `wait_for_sleeping_tasks()`.
            let mut waiting_tasks_guard = self.inner.waiting_tasks.lock().await;
            waiting_tasks_guard.0.push(instant);
            let _ = waiting_tasks_guard.1.send(());
        }

        loop {
            // Wait for the clock to be advanced.
            receiver.recv().await.unwrap();
            let current_times_guard = self.inner.current_times.lock().await;
            if current_times_guard.1 >= instant {
                break;
            }
        }
    }

    /// Wait for a given number of tasks to be sleeping.
    pub async fn wait_for_sleeping_tasks(&self, num_tasks: usize) {
        let mut receiver = {
            let waiting_tasks_guard = self.inner.waiting_tasks.lock().await;
            // Early-out check
            if waiting_tasks_guard.0.len() >= num_tasks {
                return;
            }
            waiting_tasks_guard.1.subscribe()
        };

        loop {
            // Wait to be notified that another task is sleeping.
            receiver.recv().await.unwrap();
            let waiting_tasks_guard = self.inner.waiting_tasks.lock().await;
            if waiting_tasks_guard.0.len() >= num_tasks {
                break;
            }
        }
    }
}

#[async_trait]
impl Clock for MockClock {
    type Interval = MockInterval;

    fn now(&self) -> Time {
        let current_times = self.inner.current_times_std_mutex.lock().unwrap();
        current_times.0
    }

    fn now_monotonic(&self) -> Instant {
        let current_times = self.inner.current_times_std_mutex.lock().unwrap();
        current_times.1
    }

    async fn timeout<O, F>(&self, duration: StdDuration, future: F) -> Result<O, Elapsed>
    where
        F: Future<Output = O> + Send,
    {
        let deadline = self.now_monotonic() + duration;
        select! {
            _ = self.sleep_until(deadline, false) => {
                Err(Elapsed)
            }
            output = future => {
                Ok(output)
            }
        }
    }

    fn interval_at(&self, start: Instant, period: StdDuration) -> Self::Interval {
        MockInterval {
            next_tick: start,
            period,
            clock: self.clone(),
        }
    }

    async fn sleep(&self, duration: StdDuration) {
        let deadline = self.now_monotonic() + duration;
        self.sleep_until(deadline, true).await;
    }
}

impl Default for MockClock {
    fn default() -> Self {
        // Sunday, September 9, 2001 1:46:40 AM UTC
        Self::new(Time::from_seconds_since_epoch(1000000000))
    }
}

/// An interval used in conjunction with the [`MockClock`].
#[derive(Debug)]
pub struct MockInterval {
    next_tick: Instant,
    period: StdDuration,
    clock: MockClock,
}

#[async_trait]
impl ClockInterval for MockInterval {
    async fn tick(&mut self) {
        self.clock.sleep_until(self.next_tick, true).await;
        self.next_tick += self.period;
    }

    fn set_missed_tick_behavior(&mut self, _behavior: MissedTickBehavior) {
        // Ignore this setting, because time doesn't advance smoothly with a MockClock.
    }
}

/// A type alias for [`prio::vdaf::PrepareTransition`] that derives the appropriate generic types
/// based on a single aggregator parameter.
// TODO(brandon): change libprio-rs' PrepareTransition to be generic only on a vdaf::Aggregator.
pub type PrepareTransition<V> = vdaf::PrepareTransition<
    <V as vdaf::Aggregator>::PrepareStep,
    <V as vdaf::Aggregator>::PrepareMessage,
    <V as vdaf::Vdaf>::OutputShare,
>;

/// A transcript of a VDAF run. All fields are indexed by natural role index (i.e., index 0 =
/// leader, index 1 = helper).
pub struct VdafTranscript<V: vdaf::Aggregator>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    pub input_shares: Vec<V::InputShare>,
    pub transitions: Vec<Vec<PrepareTransition<V>>>,
    pub combined_messages: Vec<V::PrepareMessage>,
}

/// run_vdaf runs a VDAF state machine from sharding through to generating an output share,
/// returning a "transcript" of all states & messages.
pub fn run_vdaf<V: vdaf::Aggregator + vdaf::Client>(
    vdaf: &V,
    public_param: &V::PublicParam,
    verify_params: &[V::VerifyParam],
    aggregation_param: &V::AggregationParam,
    nonce: Nonce,
    measurement: &V::Measurement,
) -> VdafTranscript<V>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    assert_eq!(vdaf.num_aggregators(), verify_params.len());

    // Shard inputs into input shares, and initialize the initial PrepareTransitions.
    let input_shares = vdaf.shard(public_param, measurement).unwrap();
    let mut prep_trans: Vec<Vec<PrepareTransition<V>>> = input_shares
        .iter()
        .zip(verify_params)
        .map(|(input_share, verify_param)| {
            let prep_step = vdaf.prepare_init(
                verify_param,
                aggregation_param,
                &nonce.get_encoded(),
                input_share,
            )?;
            let prep_trans = vdaf.prepare_step(prep_step, None);
            Ok(vec![prep_trans])
        })
        .collect::<Result<Vec<Vec<PrepareTransition<V>>>, VdafError>>()
        .unwrap();
    let mut combined_prep_msgs = Vec::new();

    // Repeatedly step the VDAF until we reach a terminal state.
    loop {
        // Gather messages from last round & combine them into next round's message; if any
        // participants have reached a terminal state (Finish or Fail), we are done.
        let mut prep_msgs = Vec::new();
        for pts in &prep_trans {
            match pts.last().unwrap() {
                PrepareTransition::<V>::Continue(_, prep_msg) => prep_msgs.push(prep_msg.clone()),
                _ => {
                    return VdafTranscript {
                        input_shares,
                        transitions: prep_trans,
                        combined_messages: combined_prep_msgs,
                    }
                }
            }
        }
        let combined_prep_msg = vdaf.prepare_preprocess(prep_msgs).unwrap();
        combined_prep_msgs.push(combined_prep_msg.clone());

        // Compute each participant's next transition.
        for pts in &mut prep_trans {
            let prep_step = assert_matches!(pts.last().unwrap(), PrepareTransition::<V>::Continue(prep_step, _) => prep_step).clone();
            pts.push(vdaf.prepare_step(prep_step, Some(combined_prep_msg.clone())));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MockClock;
    use assert_matches::assert_matches;
    use futures::future::poll_immediate;
    use janus::{
        message::Duration,
        time::{Clock, ClockInterval},
    };
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread::sleep,
        time::Duration as StdDuration,
    };

    #[tokio::test]
    async fn mock_clock_sleep() {
        let clock = MockClock::default();
        let mut handle = tokio::spawn({
            let clock = clock.clone();
            async move {
                clock.sleep(StdDuration::from_secs(3)).await;
            }
        });
        clock.wait_for_sleeping_tasks(1).await;
        clock.advance(Duration::from_seconds(1)).await;
        clock.wait_for_sleeping_tasks(1).await;
        sleep(StdDuration::from_millis(100));
        assert_matches!(poll_immediate(&mut handle).await, None);
        clock.advance(Duration::from_seconds(1)).await;
        clock.wait_for_sleeping_tasks(1).await;
        sleep(StdDuration::from_millis(100));
        assert_matches!(poll_immediate(&mut handle).await, None);
        clock.advance(Duration::from_seconds(1)).await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn mock_clock_interval() {
        let clock = MockClock::default();
        let counter = Arc::new(AtomicUsize::new(0));
        let handle = tokio::spawn({
            let counter = Arc::clone(&counter);
            let mut interval = clock.interval(StdDuration::from_secs(5));
            async move {
                loop {
                    interval.tick().await;
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        clock.wait_for_sleeping_tasks(1).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_seconds(2)).await;
        clock.wait_for_sleeping_tasks(1).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_seconds(3)).await;
        clock.wait_for_sleeping_tasks(1).await;
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        handle.abort();
        let _ = handle.await;
    }
}
