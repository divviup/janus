use chrono::NaiveDate;
use janus::{message::Time, time::Clock};
use rand::{thread_rng, Rng};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};

/// The Janus database schema.
pub static SCHEMA: &str = include_str!("../../db/schema.sql");

/// This macro injects definitions of `DbHandle` and `ephemeral_datastore()`, for use in tests.
/// It should be invoked once per binary target, and then `ephemeral_datastore()` can be called
/// to set up a database for test purposes. This depends on `janus_server::datastore::Datastore`
/// and `janus_server::datastore::Crypter` already being imported into scope, and it expects the
/// following crates to be available: `deadpool_postgres`, `lazy_static`, `ring`, `testcontainers`,
/// `tokio_postgres`, and `tracing`.
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
        pub async fn ephemeral_datastore() -> (Datastore, DbHandle) {
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
            let datastore_key_bytes = ::test_util::generate_aead_key_bytes();
            let datastore_key =
                ::ring::aead::LessSafeKey::new(::ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &datastore_key_bytes).unwrap());
            let crypter = Crypter::new(vec![datastore_key]);

            // Connect to the database & run our schema.
            let client = pool.get().await.unwrap();
            client.batch_execute(::test_util::SCHEMA).await.unwrap();

            (
                Datastore::new(pool, crypter),
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

/// A mock clock for use in testing.
#[derive(Clone, Copy, Debug)]
pub struct MockClock {
    /// The time that this clock will always return from [`Self::now`]
    current_time: Time,
}

impl MockClock {
    /// Create a new [`MockClock`] that will always return the provided [`Time`].
    pub fn new(current_time: Time) -> Self {
        Self { current_time }
    }
}

impl Clock for MockClock {
    fn now(&self) -> Time {
        self.current_time
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self {
            current_time: Time::from_naive_date_time(
                NaiveDate::from_ymd(2001, 9, 9).and_hms(1, 46, 40),
            ),
        }
    }
}
