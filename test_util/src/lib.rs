use assert_matches::assert_matches;
use janus::{
    message::{Duration, Nonce, Time},
    time::Clock,
};
use prio::{
    codec::Encode,
    vdaf::{self, VdafError},
};
use rand::{thread_rng, Rng};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use std::sync::{Arc, Mutex};

pub mod dummy_vdaf;

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
            let connection_string = format!(
                "postgres://postgres:postgres@127.0.0.1:{}/postgres",
                db_container.get_host_port_ipv4(POSTGRES_DEFAULT_PORT)
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
        *current_time = current_time.add(dur).unwrap();
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

/// A type alias for [`prio::vdaf::PrepareTransition`] that derives the appropriate generic types
/// based on a single aggregator parameter.
// TODO(https://github.com/divviup/libprio-rs/issues/231): change libprio-rs' PrepareTransition to be generic only on a vdaf::Aggregator.
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
