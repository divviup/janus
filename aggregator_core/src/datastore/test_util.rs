use crate::{
    datastore::{Crypter, Datastore, Transaction},
    test_util::noop_meter,
};
use backoff::{future::retry, ExponentialBackoffBuilder};
use chrono::NaiveDateTime;
use deadpool_postgres::{Manager, Pool, Timeouts};
use janus_core::{
    test_util::testcontainers::Postgres,
    time::{Clock, MockClock, TimeExt},
};
use janus_messages::Time;
use rand::{distributions::Standard, random, thread_rng, Rng};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use sqlx::{
    migrate::{Migrate, Migrator},
    Connection, PgConnection,
};
use std::{
    env,
    path::PathBuf,
    str::FromStr,
    sync::mpsc,
    sync::{Arc, Weak},
    thread::JoinHandle,
    time::Duration,
};
use testcontainers::{core::Mount, runners::AsyncRunner, ContainerRequest, ImageExt};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt},
    join,
    sync::{
        oneshot::{self, Sender},
        Mutex,
    },
};
use tokio_postgres::{connect, Config, NoTls};
use tracing::trace;

use super::SUPPORTED_SCHEMA_VERSIONS;

pub struct EphemeralDatabase {
    db_thread: Option<JoinHandle<()>>,
    db_thread_shutdown: Option<Sender<()>>,
    port_number: u16,
    cleanup_tx: mpsc::Sender<String>,
}

impl EphemeralDatabase {
    pub async fn shared() -> Arc<Self> {
        static EPHEMERAL_DATABASE: Mutex<Weak<EphemeralDatabase>> = Mutex::const_new(Weak::new());

        let mut g = EPHEMERAL_DATABASE.lock().await;
        if let Some(ephemeral_database) = g.upgrade() {
            return ephemeral_database;
        }

        let ephemeral_database = Arc::new(EphemeralDatabase::start().await);
        *g = Arc::downgrade(&ephemeral_database);
        ephemeral_database
    }

    async fn start() -> Self {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (port_tx, port_rx) = oneshot::channel();

        // Hack: run testcontainer logic under its own thread with its own tokio runtime, to avoid
        // deadlocking the main runtime when waiting for logs to finish in the Drop implementation.
        let db_thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let should_log = env::var_os("JANUS_TEST_DUMP_POSTGRESQL_LOGS").is_some();
                    let mut configuration = Vec::from(["max_connections=200"]);
                    if should_log {
                        configuration.append(&mut Vec::from([
                            // Enable logging of query plans.
                            "shared_preload_libraries=auto_explain",
                            "log_min_messages=LOG",
                            "auto_explain.log_min_duration=0",
                            "auto_explain.log_analyze=true",
                        ]))
                    }

                    // Start an instance of Postgres running in a container.
                    let db_container = ContainerRequest::from(Postgres::default())
                        .with_cmd(Self::postgres_configuration(&configuration))
                        .with_mount(Mount::tmpfs_mount("/var/lib/postgresql/data"))
                        .start()
                        .await
                        .unwrap();

                    let stdout = db_container.stdout(true);
                    let stderr = db_container.stderr(true);
                    let log_consumer_handle = should_log.then(|| {
                        tokio::spawn(async move {
                            join!(buffer_printer(stdout), buffer_printer(stderr));
                        })
                    });

                    const POSTGRES_DEFAULT_PORT: u16 = 5432;
                    let port_number = db_container
                        .get_host_port_ipv4(POSTGRES_DEFAULT_PORT)
                        .await
                        .unwrap();
                    trace!("Postgres container is up with port {port_number}");

                    // Send port information, which frees this function to continue.
                    port_tx.send(port_number).unwrap();

                    // Wait for shutdown to be signalled.
                    shutdown_rx.await.unwrap();

                    // Shutdown container and Wait for log consumers to stop.
                    db_container.stop().await.unwrap();
                    if let Some(log_consumer_handle) = log_consumer_handle {
                        log_consumer_handle.await.unwrap();
                    }
                })
        });

        let port_number = port_rx.await.unwrap();

        // Make a best-effort attempt to delete databases created for datastores, once they are no
        // longer needed. This may fail if the container hosting the database server is deleted
        // faster, which would make this moot.
        let (cleanup_tx, cleanup_rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            let handle = runtime.handle();

            let connection_string =
                format!("postgres://postgres:postgres@127.0.0.1:{port_number}/postgres");

            while let Ok(name) = cleanup_rx.recv() {
                let connection_string = connection_string.clone();
                handle.spawn({
                    let handle = handle.clone();
                    async move {
                        let Ok((client, connection)) =
                            tokio_postgres::connect(&connection_string, NoTls).await
                        else {
                            return;
                        };
                        handle.spawn(async move {
                            let _ = connection.await;
                        });

                        let _ = client.execute(&format!("DROP DATABASE {name}"), &[]).await;
                    }
                });
            }
        });

        Self {
            db_thread: Some(db_thread),
            db_thread_shutdown: Some(shutdown_tx),
            port_number,
            cleanup_tx,
        }
    }

    fn connection_string(&self, db_name: &str) -> String {
        format!(
            "postgres://postgres:postgres@127.0.0.1:{}/{db_name}",
            self.port_number
        )
    }

    fn postgres_configuration<'a>(settings: &[&'a str]) -> Vec<&'a str> {
        settings
            .iter()
            .flat_map(|setting| ["-c", setting])
            .collect::<Vec<_>>()
    }

    fn drop_database(&self, name: String) {
        let _ = self.cleanup_tx.send(name);
    }
}

async fn buffer_printer(buffer: std::pin::Pin<Box<dyn AsyncBufRead + Send>>) {
    let mut lines = buffer.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        println!("{}", line);
    }
}

impl Drop for EphemeralDatabase {
    fn drop(&mut self) {
        self.db_thread_shutdown.take().map(|tx| tx.send(()));
        self.db_thread.take().map(|thread| thread.join());
    }
}

/// EphemeralDatastore represents an ephemeral datastore instance. It has methods allowing
/// creation of Datastores, as well as the ability to retrieve the underlying connection pool.
///
/// Dropping the EphemeralDatastore will cause it to be shut down & cleaned up.
pub struct EphemeralDatastore {
    db: Arc<EphemeralDatabase>,
    connection_string: String,
    pool: Pool,
    datastore_key_bytes: Vec<u8>,
    migrator: Migrator,
    db_name: String,
}

pub const TEST_DATASTORE_MAX_TRANSACTION_RETRIES: u64 = 1000;

impl EphemeralDatastore {
    /// Creates a Datastore instance based on this EphemeralDatastore. All returned Datastore
    /// instances will refer to the same underlying durable state.
    pub async fn datastore<C: Clock>(&self, clock: C) -> Datastore<C> {
        Datastore::new(
            self.pool(),
            self.crypter(),
            clock,
            &noop_meter(),
            TEST_DATASTORE_MAX_TRANSACTION_RETRIES,
        )
        .await
        .unwrap()
    }

    pub async fn datastore_with_max_transaction_retries<C: Clock>(
        &self,
        clock: C,
        max_transaction_retries: u64,
    ) -> Datastore<C> {
        Datastore::new(
            self.pool(),
            self.crypter(),
            clock,
            &noop_meter(),
            max_transaction_retries,
        )
        .await
        .unwrap()
    }

    /// Retrieves the connection pool used for this EphemeralDatastore. Typically, this would be
    /// used only by tests which need to run custom SQL.
    pub fn pool(&self) -> Pool {
        self.pool.clone()
    }

    /// Retrieves the connection string used to connect to this EphemeralDatastore.
    pub fn connection_string(&self) -> &str {
        &self.connection_string
    }

    /// Get the bytes of the key used to encrypt sensitive datastore values.
    pub fn datastore_key_bytes(&self) -> &[u8] {
        &self.datastore_key_bytes
    }

    /// Construct a [`Crypter`] for managing encrypted values in this datastore.
    pub fn crypter(&self) -> Crypter {
        let datastore_key =
            LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &self.datastore_key_bytes).unwrap());
        Crypter::new(Vec::from([datastore_key]))
    }

    pub async fn downgrade(&self, target: i64) {
        let mut connection = PgConnection::connect(&self.connection_string)
            .await
            .unwrap();

        let current_version = connection
            .list_applied_migrations()
            .await
            .unwrap()
            .iter()
            .max_by(|a, b| a.version.cmp(&b.version))
            .unwrap()
            .version;
        if target >= current_version {
            panic!(
                "target version ({}) must be less than the current database version ({})",
                target, current_version,
            );
        }

        // Run down migrations one at a time to provide better context when
        // one fails.
        for v in (target..current_version).rev() {
            self.migrator
                .undo(&mut connection, v)
                .await
                .unwrap_or_else(|e| panic!("failed to downgrade to version {}: {}", v, e));
        }
    }
}

impl Drop for EphemeralDatastore {
    fn drop(&mut self) {
        self.db.drop_database(self.db_name.clone());
    }
}

/// Builder to configure a new [`EphemeralDatastore`].
pub struct EphemeralDatastoreBuilder {
    schema_version: i64,
    database_pool_wait_timeout: Option<Duration>,
    database_pool_create_timeout: Option<Duration>,
    database_pool_recycle_timeout: Option<Duration>,
}

impl Default for EphemeralDatastoreBuilder {
    fn default() -> Self {
        Self {
            schema_version: *SUPPORTED_SCHEMA_VERSIONS
                .iter()
                .max()
                .expect("SUPPORTED_SCHEMA_VERSIONS is empty"),
            database_pool_wait_timeout: Some(Duration::from_secs(10)),
            database_pool_create_timeout: Some(Duration::from_secs(10)),
            database_pool_recycle_timeout: Some(Duration::from_secs(10)),
        }
    }
}

impl EphemeralDatastoreBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_schema_version(mut self, schema_version: i64) -> Self {
        self.schema_version = schema_version;
        self
    }

    pub fn with_database_pool_wait_timeout(
        mut self,
        database_pool_wait_timeout: Option<Duration>,
    ) -> Self {
        self.database_pool_wait_timeout = database_pool_wait_timeout;
        self
    }

    pub fn with_database_pool_create_timeout(
        mut self,
        database_pool_create_timeout: Option<Duration>,
    ) -> Self {
        self.database_pool_create_timeout = database_pool_create_timeout;
        self
    }

    pub fn with_database_pool_recycle_timeout(
        mut self,
        database_pool_recycle_timeout: Option<Duration>,
    ) -> Self {
        self.database_pool_recycle_timeout = database_pool_recycle_timeout;
        self
    }

    pub async fn build(self) -> EphemeralDatastore {
        let db = EphemeralDatabase::shared().await;
        let db_name = format!("janus_test_{}", hex::encode(random::<[u8; 16]>()));
        trace!("Creating ephemeral postgres datastore {db_name}");

        // Create Postgres DB.
        //
        // Since this is the first connection we're establishing since the container has been created,
        // retry this a few times. The database may not be ready yet.
        let backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(500))
            .with_max_interval(Duration::from_millis(500))
            .with_max_elapsed_time(Some(Duration::from_secs(5)))
            .build();
        let (client, conn) = retry(backoff, || {
            let connection_string = db.connection_string("postgres");
            async move {
                connect(&connection_string, NoTls)
                    .await
                    .map_err(|err| backoff::Error::Transient {
                        err,
                        retry_after: None,
                    })
            }
        })
        .await
        .unwrap();

        tokio::spawn(async move { conn.await.unwrap() }); // automatically stops after Client is dropped
        client
            .batch_execute(&format!("CREATE DATABASE {db_name}"))
            .await
            .unwrap();

        let connection_string = db.connection_string(&db_name);

        let mut connection = PgConnection::connect(&connection_string).await.unwrap();

        // We deliberately avoid using sqlx::migrate! or other compile-time macros to ensure that
        // changes to the migration scripts will be picked up by every run of the tests.
        let migrations_path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
            .join("../db");
        let mut migrator = Migrator::new(migrations_path).await.unwrap();

        migrator.migrations = migrator
            .migrations
            .iter()
            .filter(|migration| migration.version <= self.schema_version)
            .cloned()
            .collect();

        migrator.run(&mut connection).await.unwrap();

        // Create a connection pool for the newly-created database.
        let cfg = Config::from_str(&connection_string).unwrap();
        let conn_mgr = Manager::new(cfg, NoTls);
        let pool = Pool::builder(conn_mgr)
            .runtime(deadpool::Runtime::Tokio1)
            .timeouts(Timeouts {
                wait: self.database_pool_wait_timeout,
                create: self.database_pool_create_timeout,
                recycle: self.database_pool_recycle_timeout,
            })
            .build()
            .unwrap();

        EphemeralDatastore {
            db,
            connection_string,
            pool,
            datastore_key_bytes: generate_aead_key_bytes(),
            migrator,
            db_name,
        }
    }
}

/// Create a new, empty EphemeralDatastore with all schema migrations up to the specified version
/// applied to it.
pub async fn ephemeral_datastore_schema_version(schema_version: i64) -> EphemeralDatastore {
    EphemeralDatastoreBuilder::new()
        .with_schema_version(schema_version)
        .build()
        .await
}

/// Creates a new, empty EphemeralDatastore with all schema migrations applied to it.
pub async fn ephemeral_datastore() -> EphemeralDatastore {
    EphemeralDatastoreBuilder::new().build().await
}

/// Creates a new, empty EphemeralDatabase by applying all available schema migrations,
/// then downgrading to the target schema version.
pub async fn ephemeral_datastore_schema_version_by_downgrade(
    schema_version: i64,
) -> EphemeralDatastore {
    let datastore = ephemeral_datastore().await;
    datastore.downgrade(schema_version).await;
    datastore
}

pub fn generate_aead_key_bytes() -> Vec<u8> {
    thread_rng()
        .sample_iter(Standard)
        .take(AES_128_GCM.key_len())
        .collect()
}

pub fn generate_aead_key() -> LessSafeKey {
    let unbound_key = UnboundKey::new(&AES_128_GCM, &generate_aead_key_bytes()).unwrap();
    LessSafeKey::new(unbound_key)
}

impl Transaction<'_, MockClock> {
    /// Verify that every row in `table` has the expected `created_at` and `updated_by` columns. The
    /// `created_at` time is checked against the transaction's clock's current time.
    /// If `updated_at` is true, then also check that column. Panics if any column is missing or
    /// otherwise invalid.
    pub async fn check_timestamp_columns(
        &self,
        table: &str,
        expected_updated_by: &str,
        updated_at: bool,
    ) {
        self.check_timestamp_columns_at_create_time(
            table,
            expected_updated_by,
            self.clock.now(),
            updated_at,
        )
        .await
    }

    /// Verify that every row in `table` has the expected `created_at` and `updated_by` columns. The
    /// `created_at` time is checked against `expected_created_at`.
    ///
    /// If `updated_at` is true, then also check that column. Panics if any column is missing or
    /// otherwise invalid.
    pub async fn check_timestamp_columns_at_create_time(
        &self,
        table: &str,
        expected_updated_by: &str,
        expected_created_at: Time,
        updated_at: bool,
    ) {
        for row in self
            .query(
                &format!(
                    "SELECT created_at, updated_by{} FROM {table}",
                    if updated_at { ", updated_at" } else { "" }
                ),
                &[],
            )
            .await
            .unwrap()
        {
            assert_eq!(
                expected_created_at.as_naive_date_time().unwrap(),
                row.get::<_, NaiveDateTime>("created_at")
            );
            // We check the updated_at value against the transaction clock's current time. This only
            // works if the clock is a MockClock, and even then doesn't work in those tests that
            // advance time, but it's a good enough check in most cases that the clock has advanced
            // as expected.
            if updated_at {
                assert_eq!(
                    self.clock.now().as_naive_date_time().unwrap(),
                    row.get::<_, NaiveDateTime>("updated_at"),
                );
            }
            assert_eq!(expected_updated_by, row.get::<_, &str>("updated_by"));
        }
    }
}
