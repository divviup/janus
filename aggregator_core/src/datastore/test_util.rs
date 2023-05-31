use crate::datastore::{Crypter, Datastore};
use deadpool_postgres::{Manager, Pool};
use janus_core::time::Clock;
use lazy_static::lazy_static;
use rand::{distributions::Standard, random, thread_rng, Rng};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use sqlx::{
    migrate::{Migrate, Migrator},
    Connection, PgConnection,
};
use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Barrier, Weak},
    thread::{self, JoinHandle},
};
use testcontainers::{images::postgres::Postgres, RunnableImage};
use tokio::sync::{oneshot, Mutex};
use tokio_postgres::{connect, Config, NoTls};
use tracing::trace;

struct EphemeralDatabase {
    port_number: u16,
    shutdown_barrier: Arc<Barrier>,
    join_handle: Option<JoinHandle<()>>,
}

impl EphemeralDatabase {
    async fn shared() -> Arc<Self> {
        // (once Weak::new is stabilized as a const function, replace this with a normal static
        // variable)
        lazy_static! {
            static ref EPHEMERAL_DATABASE: Mutex<Weak<EphemeralDatabase>> = Mutex::new(Weak::new());
        }

        let mut g = EPHEMERAL_DATABASE.lock().await;
        if let Some(ephemeral_database) = g.upgrade() {
            return ephemeral_database;
        }

        let ephemeral_database = Arc::new(EphemeralDatabase::start().await);
        *g = Arc::downgrade(&ephemeral_database);
        ephemeral_database
    }

    async fn start() -> Self {
        let (port_tx, port_rx) = oneshot::channel();
        let shutdown_barrier = Arc::new(Barrier::new(2));
        let join_handle = thread::spawn({
            let shutdown_barrier = Arc::clone(&shutdown_barrier);
            move || {
                // Start an instance of Postgres running in a container.
                let container_client = testcontainers::clients::Cli::default();
                let db_container = container_client
                    .run(RunnableImage::from(Postgres::default()).with_tag("14-alpine"));
                const POSTGRES_DEFAULT_PORT: u16 = 5432;
                let port_number = db_container.get_host_port_ipv4(POSTGRES_DEFAULT_PORT);
                trace!("Postgres container is up with port {port_number}");
                port_tx.send(port_number).unwrap();

                // Wait for the barrier as a shutdown signal.
                shutdown_barrier.wait();
                trace!("Shutting down Postgres container with port {port_number}");
            }
        });
        let port_number = port_rx.await.unwrap();

        Self {
            port_number,
            shutdown_barrier,
            join_handle: Some(join_handle),
        }
    }

    fn connection_string(&self, db_name: &str) -> String {
        format!(
            "postgres://postgres:postgres@127.0.0.1:{}/{db_name}",
            self.port_number
        )
    }
}

impl Drop for EphemeralDatabase {
    fn drop(&mut self) {
        // Wait on the shutdown barrier, which will cause the container-management thread to
        // begin shutdown. Then wait for the container-management thread itself to terminate.
        // This guarantees container shutdown finishes before dropping the EphemeralDatabase
        // completes.
        self.shutdown_barrier.wait();
        self.join_handle.take().unwrap().join().unwrap();
    }
}

/// EphemeralDatastore represents an ephemeral datastore instance. It has methods allowing
/// creation of Datastores, as well as the ability to retrieve the underlying connection pool.
///
/// Dropping the EphemeralDatastore will cause it to be shut down & cleaned up.
pub struct EphemeralDatastore {
    _db: Arc<EphemeralDatabase>,
    connection_string: String,
    pool: Pool,
    datastore_key_bytes: Vec<u8>,
    migrator: Migrator,
}

impl EphemeralDatastore {
    /// Creates a Datastore instance based on this EphemeralDatastore. All returned Datastore
    /// instances will refer to the same underlying durable state.
    pub async fn datastore<C: Clock>(&self, clock: C) -> Datastore<C> {
        Datastore::new(self.pool(), self.crypter(), clock)
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
            if let Err(e) = self.migrator.undo(&mut connection, v).await {
                panic!("failed to downgrade to version {}: {}", v, e);
            }
        }
    }
}

/// Create a new, empty EphemeralDatastore with all schema migrations up to the specified version
/// applied to it.
pub async fn ephemeral_datastore_max_schema_version(max_schema_version: i64) -> EphemeralDatastore {
    let db = EphemeralDatabase::shared().await;
    let db_name = format!("janus_test_{}", hex::encode(random::<[u8; 16]>()));
    trace!("Creating ephemeral postgres datastore {db_name}");

    // Create Postgres DB.
    let (client, conn) = connect(&db.connection_string("postgres"), NoTls)
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
        .filter(|migration| migration.version <= max_schema_version)
        .cloned()
        .collect();

    migrator.run(&mut connection).await.unwrap();

    // Create a connection pool for the newly-created database.
    let cfg = Config::from_str(&connection_string).unwrap();
    let conn_mgr = Manager::new(cfg, NoTls);
    let pool = Pool::builder(conn_mgr).build().unwrap();

    EphemeralDatastore {
        _db: db,
        connection_string,
        pool,
        datastore_key_bytes: generate_aead_key_bytes(),
        migrator,
    }
}

/// Creates a new, empty EphemeralDatastore with all schema migrations applied to it.
pub async fn ephemeral_datastore() -> EphemeralDatastore {
    ephemeral_datastore_max_schema_version(i64::MAX).await
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
