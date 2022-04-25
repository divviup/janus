use rand::{thread_rng, Rng};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};

/// This macro injects definitions of `DbHandle` and `ephemeral_datastore()`, for use in tests.
/// It should be invoked once per binary target, and then `ephemeral_datastore()` can be called
/// to set up a database for test purposes. This depends on `janus_server::datastore::Datastore`
/// and `janus_server::datastore::Crypter` already being imported into scope, and it expects the
/// following crates to be available: `deadpool_postgres`, `lazy_static`, `ring`, `testcontainers`,
/// and `tokio_postgres`.
///
/// If invoking from within `janus_server`, with `--cfg=test`, use
/// `define_ephemeral_datastore!(true)`, and the VDAF enum in Postgres will be updated with
/// unit test-only variants. Otherwise, use `define_ephemeral_datastore!(false)`.
#[macro_export]
macro_rules! define_ephemeral_datastore {
    ($with_fake_vdaf:literal) => {
        const SCHEMA: &str = include_str!("../../db/schema.sql");

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
            let connection_string = format!(
                "postgres://postgres:postgres@localhost:{}/postgres",
                db_container.get_host_port(POSTGRES_DEFAULT_PORT)
            );
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
            client.batch_execute(SCHEMA).await.unwrap();

            // Test-only DB schema modifications.
            if $with_fake_vdaf {
                client
                    .batch_execute(
                        "ALTER TYPE VDAF_IDENTIFIER ADD VALUE 'FAKE';
                        ALTER TYPE VDAF_IDENTIFIER ADD VALUE 'FAKE_FAILS_PREP_INIT';
                        ALTER TYPE VDAF_IDENTIFIER ADD VALUE 'FAKE_FAILS_PREP_STEP';",
                    )
                    .await
                    .unwrap();
            }

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
