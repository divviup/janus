//! Janus datastore (durable storage) implementation.

use self::models::{
    AcquiredAggregationJob, AcquiredCollectionJob, AggregateShareJob, AggregationJob,
    AggregatorRole, AuthenticationTokenType, Batch, BatchAggregation, CollectionJob,
    CollectionJobState, CollectionJobStateCode, GlobalHpkeKeypair, HpkeKeyState,
    LeaderStoredReport, Lease, LeaseToken, OutstandingBatch, ReportAggregation,
    ReportAggregationState, ReportAggregationStateCode, SqlInterval,
};
use crate::{
    query_type::{AccumulableQueryType, CollectableQueryType},
    task::{self, Task},
    taskprov::{self, PeerAggregator},
    SecretBytes,
};
use anyhow::anyhow;
use chrono::NaiveDateTime;
use futures::future::try_join_all;
use janus_core::{
    hpke::{HpkeKeypair, HpkePrivateKey},
    task::{AuthenticationToken, VdafInstance},
    time::{Clock, TimeExt},
};
use janus_messages::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode},
    query_type::{FixedSize, QueryType, TimeInterval},
    AggregationJobId, BatchId, CollectionJobId, Duration, Extension, HpkeCiphertext, HpkeConfig,
    HpkeConfigId, Interval, ReportId, ReportIdChecksum, ReportMetadata, ReportShare, Role, TaskId,
    Time,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    KeyValue,
};
use postgres_types::{FromSql, Json, ToSql};
use prio::vdaf;
use rand::random;
use ring::aead::{self, LessSafeKey, AES_128_GCM};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::{Debug, Display},
    future::Future,
    io::Cursor,
    mem::size_of,
    ops::RangeInclusive,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration as StdDuration, Instant},
};
use tokio::{sync::Barrier, try_join};
use tokio_postgres::{error::SqlState, row::RowIndex, IsolationLevel, Row, Statement, ToStatement};
use tracing::error;
use url::Url;

pub mod models;
#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util;
#[cfg(test)]
mod tests;

// TODO(#196): retry network-related & other transient failures once we know what they look like

/// This macro stamps out an array of schema versions supported by this version of Janus and an
/// [`rstest_reuse`][1] template that can be applied to tests to have them run against all supported
/// schema versions.
///
/// [1]: https://docs.rs/rstest_reuse/latest/rstest_reuse/
macro_rules! supported_schema_versions {
    ( $i_latest:literal $(,)? $( $i:literal ),* ) => {
        const SUPPORTED_SCHEMA_VERSIONS: &[i64] = &[$i_latest, $($i),*];

        #[cfg(test)]
        #[rstest_reuse::template]
        #[rstest::rstest]
        // Test the latest supported schema version.
        #[case(ephemeral_datastore_schema_version($i_latest))]
        // Test the remaining supported schema versions.
        $(#[case(ephemeral_datastore_schema_version($i))])*
        // Test the remaining supported schema versions by taking a
        // database at the latest schema and downgrading it.
        $(#[case(ephemeral_datastore_schema_version_by_downgrade($i))])*
        async fn schema_versions_template(
            #[future(awt)]
            #[case]
            ephemeral_datastore: EphemeralDatastore,
        ) {
            // This is an rstest template and never gets run.
        }
    }
}

// List of schema versions that this version of Janus can safely run on. If any other schema
// version is seen, [`Datastore::new`] fails.
//
// Note that the latest supported version must be first in the list.
supported_schema_versions!(2);

/// Datastore represents a datastore for Janus, with support for transactional reads and writes.
/// In practice, Datastore instances are currently backed by a PostgreSQL database.
pub struct Datastore<C: Clock> {
    pool: deadpool_postgres::Pool,
    crypter: Crypter,
    clock: C,
    transaction_status_counter: Counter<u64>,
    rollback_error_counter: Counter<u64>,
    transaction_duration_histogram: Histogram<f64>,
}

impl<C: Clock> Debug for Datastore<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Datastore")
    }
}

impl<C: Clock> Datastore<C> {
    /// `new` creates a new Datastore using the provided connection pool. An error is returned if
    /// the current database migration version is not supported by this version of Janus.
    pub async fn new(
        pool: deadpool_postgres::Pool,
        crypter: Crypter,
        clock: C,
        meter: &Meter,
    ) -> Result<Datastore<C>, Error> {
        Self::new_with_supported_versions(pool, crypter, clock, meter, SUPPORTED_SCHEMA_VERSIONS)
            .await
    }

    async fn new_with_supported_versions(
        pool: deadpool_postgres::Pool,
        crypter: Crypter,
        clock: C,
        meter: &Meter,
        supported_schema_versions: &[i64],
    ) -> Result<Datastore<C>, Error> {
        let datastore = Self::new_without_supported_versions(pool, crypter, clock, meter).await;

        let (current_version, migration_description) = datastore
            .run_tx_with_name("check schema version", |tx| {
                Box::pin(async move { tx.get_current_schema_migration_version().await })
            })
            .await?;

        if !supported_schema_versions.contains(&current_version) {
            return Err(Error::DbState(format!(
                "unsupported schema version {current_version} / {migration_description}"
            )));
        }

        Ok(datastore)
    }

    /// Creates a new datastore using the provided connection pool.
    pub async fn new_without_supported_versions(
        pool: deadpool_postgres::Pool,
        crypter: Crypter,
        clock: C,
        meter: &Meter,
    ) -> Datastore<C> {
        let transaction_status_counter = meter
            .u64_counter("janus_database_transactions")
            .with_description("Count of database transactions run, with their status.")
            .init();
        let rollback_error_counter = meter
            .u64_counter("janus_database_rollback_errors")
            .with_description(concat!(
                "Count of errors received when rolling back a database transaction, ",
                "with their PostgreSQL error code.",
            ))
            .init();
        let transaction_duration_histogram = meter
            .f64_histogram("janus_database_transaction_duration_seconds")
            .with_description("Duration of database transactions.")
            .init();

        Self {
            pool,
            crypter,
            clock,
            transaction_status_counter,
            rollback_error_counter,
            transaction_duration_histogram,
        }
    }

    /// run_tx runs a transaction, whose body is determined by the given function. The transaction
    /// is committed if the body returns a successful value, and rolled back if the body returns an
    /// error value.
    ///
    /// The datastore will automatically retry some failures (e.g. serialization failures) by
    /// rolling back & retrying with a new transaction, so the given function should support being
    /// called multiple times. Values read from the transaction should not be considered as
    /// "finalized" until the transaction is committed, i.e. after `run_tx` is run to completion.
    pub fn run_tx<'s, F, T>(&'s self, f: F) -> impl Future<Output = Result<T, Error>> + 's
    where
        F: 's,
        T: 's,
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        self.run_tx_with_name("default", f)
    }

    /// See [`Datastore::run_tx`]. This method additionally allows specifying a name for the
    /// transaction, for use in database-related metrics.
    #[tracing::instrument(level = "trace", skip(self, f))]
    pub async fn run_tx_with_name<F, T>(&self, name: &'static str, f: F) -> Result<T, Error>
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        loop {
            let before = Instant::now();
            let (rslt, retry) = self.run_tx_once(&f).await;
            let elapsed = before.elapsed();
            self.transaction_duration_histogram
                .record(elapsed.as_secs_f64(), &[KeyValue::new("tx", name)]);
            let status = match (rslt.as_ref(), retry) {
                (_, true) => "retry",
                (Ok(_), _) => "success",
                (Err(Error::Db(_)), _) | (Err(Error::Pool(_)), _) => "error_db",
                (Err(_), _) => "error_other",
            };
            self.transaction_status_counter.add(
                1,
                &[KeyValue::new("status", status), KeyValue::new("tx", name)],
            );
            if retry {
                continue;
            }
            return rslt;
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    async fn run_tx_once<F, T>(&self, f: &F) -> (Result<T, Error>, bool)
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        // Open transaction.
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(err) => return (Err(err.into()), false),
        };
        let raw_tx = match client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await
        {
            Ok(raw_tx) => raw_tx,
            Err(err) => return (Err(err.into()), false),
        };
        let tx = Transaction {
            raw_tx,
            crypter: &self.crypter,
            clock: &self.clock,
            retry: AtomicBool::new(false),
            op_group: Mutex::new(Arc::new(Mutex::new(OperationGroup::Running(0)))),
        };

        // Run user-provided function with the transaction, then commit/rollback based on result.
        let rslt = f(&tx).await;
        let (raw_tx, retry) = (tx.raw_tx, tx.retry);
        let rslt = match (rslt, retry.load(Ordering::Relaxed)) {
            // Commit.
            (Ok(val), false) => match check_error(&retry, raw_tx.commit().await) {
                Ok(()) => Ok(val),
                Err(err) => Err(err.into()),
            },

            // Rollback.
            (rslt, _) => {
                if let Err(rollback_err) = check_error(&retry, raw_tx.rollback().await) {
                    error!("Couldn't roll back transaction: {rollback_err}");
                    self.rollback_error_counter.add(
                        1,
                        &[KeyValue::new(
                            "code",
                            rollback_err
                                .code()
                                .map(SqlState::code)
                                .unwrap_or("N/A")
                                .to_string(),
                        )],
                    );
                };
                // We return `rslt` unconditionally here: it will either be an error, or we have the
                // retry flag set so that even if `rslt` is a success we will be retrying the entire
                // transaction & the result of this attempt doesn't matter.
                rslt
            }
        };
        (rslt, retry.load(Ordering::Relaxed))
    }

    /// Write a task into the datastore.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        self.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
    }
}

fn check_error<T>(
    retry: &AtomicBool,
    rslt: Result<T, tokio_postgres::Error>,
) -> Result<T, tokio_postgres::Error> {
    if let Err(err) = &rslt {
        if is_retryable_error(err) {
            retry.store(true, Ordering::Relaxed);
        }
    }
    rslt
}

fn is_retryable_error(err: &tokio_postgres::Error) -> bool {
    err.code().map_or(false, |code| {
        code == &SqlState::T_R_SERIALIZATION_FAILURE || code == &SqlState::T_R_DEADLOCK_DETECTED
    })
}

fn is_transaction_abort_error(err: &tokio_postgres::Error) -> bool {
    err.code()
        .map_or(false, |code| code == &SqlState::IN_FAILED_SQL_TRANSACTION)
}

/// Transaction represents an ongoing datastore transaction.
pub struct Transaction<'a, C: Clock> {
    raw_tx: deadpool_postgres::Transaction<'a>,
    crypter: &'a Crypter,
    clock: &'a C,

    retry: AtomicBool,
    op_group: Mutex<Arc<Mutex<OperationGroup>>>, // locking discipline: outer lock before inner lock
}

enum OperationGroup {
    Running(usize),         // current operation count
    Draining(Arc<Barrier>), // barrier to wait upon to complete drain
}

impl<C: Clock> Transaction<'_, C> {
    // For some error modes, Postgres will return an error to the caller & then fail all future
    // statements within the same transaction with an "in failed SQL transaction" error. This
    // effectively means one statement will receive a "root cause" error and then all later
    // statements will receive an "in failed SQL transaction" error. In a pipelined scenario, if our
    // code is processing the results of these statements concurrently--e.g. because they are part
    // of a `try_join!`/`try_join_all` group--we might receive & handle one of the "in failed SQL
    // transaction" errors before we handle the "root cause" error, which might cause the "root
    // cause" error's future to be cancelled before we evaluate it. If the "root cause" error would
    // trigger a retry, this would mean we would skip a DB-based retry when one was warranted.
    //
    // To fix this problem, we (internally) wrap all direct DB operations in `run_op`. This function
    // groups concurrent database operations into "operation groups", which allow us to wait for all
    // operations in the group to complete (this waiting operation is called "draining"). If we ever
    // observe an "in failed SQL transaction" error, we drain the operation group before returning.
    // Under the assumption that the "root cause" error is concurrent with the "in failed SQL
    // transactions" errors, this guarantees we will evaluate the "root cause" error for retry
    // before any errors make their way out of the transaction code.
    async fn run_op<T>(
        &self,
        op: impl Future<Output = Result<T, tokio_postgres::Error>>,
    ) -> Result<T, tokio_postgres::Error> {
        // Enter.
        //
        // Before we can run the operation, we need to join this operation into an operation group.
        // Retrieve the current operation group & join it.
        let op_group = {
            let mut tx_op_group = self.op_group.lock().unwrap();
            let new_tx_op_group = {
                let mut op_group = tx_op_group.lock().unwrap();
                match &*op_group {
                    OperationGroup::Running(op_count) => {
                        // If the current op group is running, join it by incrementing the operation
                        // count.
                        *op_group = OperationGroup::Running(*op_count + 1);
                        None
                    }

                    OperationGroup::Draining { .. } => {
                        // If the current op group is draining, we can't join it; instead, create a
                        // new op group to join, and store it as the transaction's current operation
                        // group.
                        Some(Arc::new(Mutex::new(OperationGroup::Running(1))))
                    }
                }
            };
            if let Some(new_tx_op_group) = new_tx_op_group {
                *tx_op_group = new_tx_op_group;
            }
            Arc::clone(&tx_op_group)
        };

        // Run operation, and check if error triggers a retry or requires a drain.
        let rslt = check_error(&self.retry, op.await);
        let needs_drain = rslt
            .as_ref()
            .err()
            .map_or(false, is_transaction_abort_error);

        // Exit.
        //
        // Before we are done running the operation, we have to leave the operation group. If the
        // operation group is running, we just need to decrement the count. If the operation group
        // is draining (because this or another operation encountered an error which requires a
        // drain), we have to wait until all operations in the group are ready to finish.
        let barrier = {
            let mut op_group = op_group.lock().unwrap();
            match &*op_group {
                OperationGroup::Running(op_count) => {
                    if needs_drain {
                        // If the operation group is running & we have determined we need to drain
                        // the operation group, change the operation group to Draining & wait on the
                        // barrier.
                        let barrier = Arc::new(Barrier::new(*op_count));
                        *op_group = OperationGroup::Draining(Arc::clone(&barrier));
                        Some(barrier)
                    } else {
                        // If the operation group is running & we don't need a drain, just decrement
                        // the operation count.
                        *op_group = OperationGroup::Running(op_count - 1);
                        None
                    }
                }

                // If the operation group is already draining, wait on the barrier.
                OperationGroup::Draining(barrier) => Some(Arc::clone(barrier)),
            }
        };
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        rslt
    }

    async fn execute<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.run_op(self.raw_tx.execute(statement, params)).await
    }

    async fn prepare_cached(&self, query: &str) -> Result<Statement, tokio_postgres::Error> {
        self.run_op(self.raw_tx.prepare_cached(query)).await
    }

    async fn query<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.run_op(self.raw_tx.query(statement, params)).await
    }

    async fn query_one<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.run_op(self.raw_tx.query_one(statement, params)).await
    }

    async fn query_opt<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, tokio_postgres::Error>
    where
        T: ?Sized + ToStatement,
    {
        self.run_op(self.raw_tx.query_opt(statement, params)).await
    }

    /// Calling this method will force the transaction to eventually be rolled back and retried; all
    /// datastore writes in this try will be lost. Calling this method does not interrupt or
    /// otherwise directly affect the transaction-processing callback; the caller may wish to e.g.
    /// use an error or some other signalling method to cause the callback to terminate.
    ///
    /// There is no upper limit on the number of retries a single transaction may incur.
    pub fn retry(&self) {
        self.retry.store(true, Ordering::Relaxed);
    }

    /// Returns the current schema version of the datastore and the description of the migration
    /// script that applied it.
    async fn get_current_schema_migration_version(&self) -> Result<(i64, String), Error> {
        let stmt = self
            .prepare_cached(
                "SELECT version, description FROM _sqlx_migrations
                WHERE success = TRUE ORDER BY version DESC LIMIT(1)",
            )
            .await?;
        let row = self.query_one(&stmt, &[]).await?;

        let version = row.try_get("version")?;
        let description = row.try_get("description")?;

        Ok((version, description))
    }

    /// Writes a task into the datastore.
    #[tracing::instrument(skip(self, task), fields(task_id = ?task.id()), err)]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        let endpoints: Vec<_> = task
            .aggregator_endpoints()
            .iter()
            .map(Url::as_str)
            .collect();

        // Main task insert.
        let stmt = self
            .prepare_cached(
                "INSERT INTO tasks (
                    task_id, aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, report_expiry_age, min_batch_size,
                    time_precision, tolerable_clock_skew, collector_hpke_config)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT DO NOTHING",
            )
            .await?;
        check_insert(
            self.execute(
                &stmt,
                &[
                    /* task_id */ &task.id().as_ref(),
                    /* aggregator_role */ &AggregatorRole::from_role(*task.role())?,
                    /* aggregator_endpoints */ &endpoints,
                    /* query_type */ &Json(task.query_type()),
                    /* vdaf */ &Json(task.vdaf()),
                    /* max_batch_query_count */
                    &i64::try_from(task.max_batch_query_count())?,
                    /* task_expiration */
                    &task
                        .task_expiration()
                        .map(Time::as_naive_date_time)
                        .transpose()?,
                    /* report_expiry_age */
                    &task
                        .report_expiry_age()
                        .map(Duration::as_seconds)
                        .map(i64::try_from)
                        .transpose()?,
                    /* min_batch_size */ &i64::try_from(task.min_batch_size())?,
                    /* time_precision */
                    &i64::try_from(task.time_precision().as_seconds())?,
                    /* tolerable_clock_skew */
                    &i64::try_from(task.tolerable_clock_skew().as_seconds())?,
                    /* collector_hpke_config */
                    &task
                        .collector_hpke_config()
                        .map(|config| config.get_encoded()),
                ],
            )
            .await?,
        )?;

        // Aggregator auth tokens.
        let mut aggregator_auth_token_ords = Vec::new();
        let mut aggregator_auth_token_types = Vec::new();
        let mut aggregator_auth_tokens = Vec::new();
        for (ord, token) in task.aggregator_auth_tokens().iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_aggregator_auth_token = self.crypter.encrypt(
                "task_aggregator_auth_tokens",
                &row_id,
                "token",
                token.as_ref(),
            )?;

            aggregator_auth_token_ords.push(ord);
            aggregator_auth_token_types.push(AuthenticationTokenType::from(token));
            aggregator_auth_tokens.push(encrypted_aggregator_auth_token);
        }
        let stmt = self
            .prepare_cached(
                "INSERT INTO task_aggregator_auth_tokens (task_id, ord, type, token)
                SELECT
                    (SELECT id FROM tasks WHERE task_id = $1),
                    * FROM UNNEST($2::BIGINT[], $3::AUTH_TOKEN_TYPE[], $4::BYTEA[])",
            )
            .await?;
        let aggregator_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* ords */ &aggregator_auth_token_ords,
            /* token_types */ &aggregator_auth_token_types,
            /* tokens */ &aggregator_auth_tokens,
        ];
        let aggregator_auth_tokens_future = self.execute(&stmt, aggregator_auth_tokens_params);

        // Collector auth tokens.
        let mut collector_auth_token_ords = Vec::new();
        let mut collector_auth_token_types = Vec::new();
        let mut collector_auth_tokens = Vec::new();
        for (ord, token) in task.collector_auth_tokens().iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_collector_auth_token = self.crypter.encrypt(
                "task_collector_auth_tokens",
                &row_id,
                "token",
                token.as_ref(),
            )?;

            collector_auth_token_ords.push(ord);
            collector_auth_token_types.push(AuthenticationTokenType::from(token));
            collector_auth_tokens.push(encrypted_collector_auth_token);
        }
        let stmt = self
            .prepare_cached(
                "INSERT INTO task_collector_auth_tokens (task_id, ord, type, token)
                SELECT
                    (SELECT id FROM tasks WHERE task_id = $1),
                    * FROM UNNEST($2::BIGINT[], $3::AUTH_TOKEN_TYPE[], $4::BYTEA[])",
            )
            .await?;
        let collector_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* ords */ &collector_auth_token_ords,
            /* token_types */ &collector_auth_token_types,
            /* tokens */ &collector_auth_tokens,
        ];
        let collector_auth_tokens_future = self.execute(&stmt, collector_auth_tokens_params);

        // HPKE keys.
        let mut hpke_config_ids: Vec<i16> = Vec::new();
        let mut hpke_configs: Vec<Vec<u8>> = Vec::new();
        let mut hpke_private_keys: Vec<Vec<u8>> = Vec::new();
        for hpke_keypair in task.hpke_keys().values() {
            let mut row_id = [0u8; TaskId::LEN + size_of::<u8>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id().as_ref());
            row_id[TaskId::LEN..]
                .copy_from_slice(&u8::from(*hpke_keypair.config().id()).to_be_bytes());

            let encrypted_hpke_private_key = self.crypter.encrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                hpke_keypair.private_key().as_ref(),
            )?;

            hpke_config_ids.push(u8::from(*hpke_keypair.config().id()) as i16);
            hpke_configs.push(hpke_keypair.config().get_encoded());
            hpke_private_keys.push(encrypted_hpke_private_key);
        }
        let stmt = self
            .prepare_cached(
                "INSERT INTO task_hpke_keys (task_id, config_id, config, private_key)
                SELECT
                    (SELECT id FROM tasks WHERE task_id = $1),
                    * FROM UNNEST($2::SMALLINT[], $3::BYTEA[], $4::BYTEA[])",
            )
            .await?;
        let hpke_configs_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* config_id */ &hpke_config_ids,
            /* configs */ &hpke_configs,
            /* private_keys */ &hpke_private_keys,
        ];
        let hpke_configs_future = self.execute(&stmt, hpke_configs_params);

        // VDAF verification keys.
        let mut vdaf_verify_keys: Vec<Vec<u8>> = Vec::new();
        for vdaf_verify_key in task.vdaf_verify_keys() {
            let encrypted_vdaf_verify_key = self.crypter.encrypt(
                "task_vdaf_verify_keys",
                task.id().as_ref(),
                "vdaf_verify_key",
                vdaf_verify_key.as_ref(),
            )?;
            vdaf_verify_keys.push(encrypted_vdaf_verify_key);
        }
        let stmt = self
            .prepare_cached(
                "INSERT INTO task_vdaf_verify_keys (task_id, vdaf_verify_key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BYTEA[])",
            )
            .await?;
        let vdaf_verify_keys_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id().as_ref(),
            /* vdaf_verify_keys */ &vdaf_verify_keys,
        ];
        let vdaf_verify_keys_future = self.execute(&stmt, vdaf_verify_keys_params);

        try_join!(
            aggregator_auth_tokens_future,
            collector_auth_tokens_future,
            hpke_configs_future,
            vdaf_verify_keys_future
        )?;

        Ok(())
    }

    /// Deletes a task from the datastore, along with all related data (client reports,
    /// aggregations, etc).
    #[tracing::instrument(skip(self))]
    pub async fn delete_task(&self, task_id: &TaskId) -> Result<(), Error> {
        // Deletion of other data implemented via ON DELETE CASCADE.
        let stmt = self
            .prepare_cached("DELETE FROM tasks WHERE task_id = $1")
            .await?;
        check_single_row_mutation(
            self.execute(&stmt, &[/* task_id */ &task_id.as_ref()])
                .await?,
        )?;
        Ok(())
    }

    /// Fetch the task parameters corresponing to the provided `task_id`.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_task(&self, task_id: &TaskId) -> Result<Option<Task>, Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_ref()];
        let stmt = self
            .prepare_cached(
                "SELECT aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, report_expiry_age, min_batch_size,
                    time_precision, tolerable_clock_skew, collector_hpke_config
                FROM tasks WHERE task_id = $1",
            )
            .await?;
        let task_row = self.query_opt(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT ord, type, token FROM task_aggregator_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.query(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT ord, type, token FROM task_collector_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.query(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT config_id, config, private_key FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let hpke_key_rows = self.query(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT vdaf_verify_key FROM task_vdaf_verify_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let vdaf_verify_key_rows = self.query(&stmt, params);

        let (
            task_row,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_key_rows,
            vdaf_verify_key_rows,
        ) = try_join!(
            task_row,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_key_rows,
            vdaf_verify_key_rows,
        )?;
        task_row
            .map(|task_row| {
                self.task_from_rows(
                    task_id,
                    &task_row,
                    &aggregator_auth_token_rows,
                    &collector_auth_token_rows,
                    &hpke_key_rows,
                    &vdaf_verify_key_rows,
                )
            })
            .transpose()
    }

    /// Fetch all the tasks in the database.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_tasks(&self) -> Result<Vec<Task>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT task_id, aggregator_role, aggregator_endpoints, query_type, vdaf,
                    max_batch_query_count, task_expiration, report_expiry_age, min_batch_size,
                    time_precision, tolerable_clock_skew, collector_hpke_config
                FROM tasks",
            )
            .await?;
        let task_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks
                    WHERE tasks.id = task_aggregator_auth_tokens.task_id),
                ord, type, token FROM task_aggregator_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks
                    WHERE tasks.id = task_collector_auth_tokens.task_id),
                ord, type, token FROM task_collector_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_hpke_keys.task_id),
                config_id, config, private_key FROM task_hpke_keys",
            )
            .await?;
        let hpke_config_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks
                    WHERE tasks.id = task_vdaf_verify_keys.task_id),
                vdaf_verify_key FROM task_vdaf_verify_keys",
            )
            .await?;
        let vdaf_verify_key_rows = self.query(&stmt, &[]);

        let (
            task_rows,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_config_rows,
            vdaf_verify_key_rows,
        ) = try_join!(
            task_rows,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
            hpke_config_rows,
            vdaf_verify_key_rows
        )?;

        let mut task_row_by_id = Vec::new();
        for row in task_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            task_row_by_id.push((task_id, row));
        }

        let mut aggregator_auth_token_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in aggregator_auth_token_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            aggregator_auth_token_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut collector_auth_token_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in collector_auth_token_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            collector_auth_token_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut hpke_config_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in hpke_config_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            hpke_config_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        let mut vdaf_verify_key_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in vdaf_verify_key_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            vdaf_verify_key_rows_by_task_id
                .entry(task_id)
                .or_default()
                .push(row);
        }

        task_row_by_id
            .into_iter()
            .map(|(task_id, row)| {
                self.task_from_rows(
                    &task_id,
                    &row,
                    &aggregator_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &collector_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &hpke_config_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    &vdaf_verify_key_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                )
            })
            .collect::<Result<_, _>>()
    }

    /// Construct a [`Task`] from the contents of the provided (tasks) `Row`,
    /// `hpke_aggregator_auth_tokens` rows, and `task_hpke_keys` rows.
    ///
    /// agg_auth_token_rows must be sorted in ascending order by `ord`.
    fn task_from_rows(
        &self,
        task_id: &TaskId,
        row: &Row,
        aggregator_auth_token_rows: &[Row],
        collector_auth_token_rows: &[Row],
        hpke_key_rows: &[Row],
        vdaf_verify_key_rows: &[Row],
    ) -> Result<Task, Error> {
        // Scalar task parameters.
        let aggregator_role: AggregatorRole = row.get("aggregator_role");
        let endpoints = row
            .get::<_, Vec<String>>("aggregator_endpoints")
            .into_iter()
            .map(|endpoint| Ok(Url::parse(&endpoint)?))
            .collect::<Result<_, Error>>()?;
        let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
        let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
        let max_batch_query_count = row.get_bigint_and_convert("max_batch_query_count")?;
        let task_expiration = row
            .get::<_, Option<NaiveDateTime>>("task_expiration")
            .as_ref()
            .map(Time::from_naive_date_time);
        let report_expiry_age = row
            .get_nullable_bigint_and_convert("report_expiry_age")?
            .map(Duration::from_seconds);
        let min_batch_size = row.get_bigint_and_convert("min_batch_size")?;
        let time_precision = Duration::from_seconds(row.get_bigint_and_convert("time_precision")?);
        let tolerable_clock_skew =
            Duration::from_seconds(row.get_bigint_and_convert("tolerable_clock_skew")?);
        let collector_hpke_config = row
            .get::<_, Option<Vec<u8>>>("collector_hpke_config")
            .map(|config| HpkeConfig::get_decoded(&config))
            .transpose()?;

        // Aggregator authentication tokens.
        let mut aggregator_auth_tokens = Vec::new();
        for row in aggregator_auth_token_rows {
            let ord: i64 = row.get("ord");
            let auth_token_type: AuthenticationTokenType = row.get("type");
            let encrypted_aggregator_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            aggregator_auth_tokens.push(auth_token_type.as_authentication(
                &self.crypter.decrypt(
                    "task_aggregator_auth_tokens",
                    &row_id,
                    "token",
                    &encrypted_aggregator_auth_token,
                )?,
            )?);
        }

        // Collector authentication tokens.
        let mut collector_auth_tokens = Vec::new();
        for row in collector_auth_token_rows {
            let ord: i64 = row.get("ord");
            let auth_token_type: AuthenticationTokenType = row.get("type");
            let encrypted_collector_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            collector_auth_tokens.push(auth_token_type.as_authentication(
                &self.crypter.decrypt(
                    "task_collector_auth_tokens",
                    &row_id,
                    "token",
                    &encrypted_collector_auth_token,
                )?,
            )?);
        }

        // HPKE keys.
        let mut hpke_keypairs = Vec::new();
        for row in hpke_key_rows {
            let config_id = u8::try_from(row.get::<_, i16>("config_id"))?;
            let config = HpkeConfig::get_decoded(row.get("config"))?;
            let encrypted_private_key: Vec<u8> = row.get("private_key");

            let mut row_id = [0u8; TaskId::LEN + size_of::<u8>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&config_id.to_be_bytes());

            let private_key = HpkePrivateKey::new(self.crypter.decrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                &encrypted_private_key,
            )?);

            hpke_keypairs.push(HpkeKeypair::new(config, private_key));
        }

        // VDAF verify keys.
        let mut vdaf_verify_keys = Vec::new();
        for row in vdaf_verify_key_rows {
            let encrypted_vdaf_verify_key: Vec<u8> = row.get("vdaf_verify_key");
            vdaf_verify_keys.push(SecretBytes::new(self.crypter.decrypt(
                "task_vdaf_verify_keys",
                task_id.as_ref(),
                "vdaf_verify_key",
                &encrypted_vdaf_verify_key,
            )?));
        }

        let task = Task::new_without_validation(
            *task_id,
            endpoints,
            query_type,
            vdaf,
            aggregator_role.as_role(),
            vdaf_verify_keys,
            max_batch_query_count,
            task_expiration,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
            collector_hpke_config,
            aggregator_auth_tokens,
            collector_auth_tokens,
            hpke_keypairs,
        );
        // Trial validation through all known schemes. This is a workaround to avoid extending the
        // schema to track the provenance of tasks. If we do end up implementing a task provenance
        // column anyways, we can simplify this logic.
        task.validate().or_else(|error| {
            taskprov::Task(task.clone())
                .validate()
                .map_err(|taskprov_error| {
                    error!(
                        %task_id,
                        %error,
                        %taskprov_error,
                        ?task,
                        "task has failed all available validation checks",
                    );
                    // Choose some error to bubble up to the caller. Either way this error
                    // occurring is an indication of a bug, which we'll need to go into the
                    // logs for.
                    error
                })
        })?;

        Ok(task)
    }

    /// Retrieves report & report aggregation metrics for a given task: either a tuple
    /// `Some((report_count, report_aggregation_count))`, or None if the task does not exist.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_task_metrics(&self, task_id: &TaskId) -> Result<Option<(u64, u64)>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT
                    (SELECT COUNT(*) FROM tasks WHERE task_id = $1) AS task_count,
                    (SELECT COUNT(*) FROM client_reports
                     JOIN tasks ON tasks.id = client_reports.task_id
                     WHERE tasks.task_id = $1
                       AND client_reports.client_timestamp >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)) AS report_count,
                    (SELECT COUNT(*) FROM aggregation_jobs
                     JOIN tasks ON tasks.id = aggregation_jobs.task_id
                     RIGHT JOIN report_aggregations ON report_aggregations.aggregation_job_id = aggregation_jobs.id
                     WHERE tasks.task_id = $1
                       AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)) AS report_aggregation_count",
            )
            .await?;
        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;

        let task_count: u64 = row.get_bigint_and_convert("task_count")?;
        if task_count == 0 {
            return Ok(None);
        }

        Ok(Some((
            row.get_bigint_and_convert("report_count")?,
            row.get_bigint_and_convert("report_aggregation_count")?,
        )))
    }

    /// Retrieves task IDs, optionally after some specified lower bound. This method returns tasks
    /// IDs in lexicographic order, but may not retrieve the IDs of all tasks in a single call. To
    /// retrieve additional task IDs, make additional calls to this method while specifying the
    /// `lower_bound` parameter to be the last task ID retrieved from the previous call.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_task_ids(&self, lower_bound: Option<TaskId>) -> Result<Vec<TaskId>, Error> {
        let lower_bound = lower_bound.map(|task_id| task_id.as_ref().to_vec());
        let stmt = self
            .prepare_cached(
                "SELECT task_id FROM tasks
                WHERE task_id > $1 OR $1 IS NULL
                ORDER BY task_id
                LIMIT 5000",
            )
            .await?;
        self.query(&stmt, &[/* task_id */ &lower_bound])
            .await?
            .into_iter()
            .map(|row| Ok(TaskId::get_decoded(row.get("task_id"))?))
            .collect()
    }

    /// get_client_report retrieves a client report by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_client_report<const SEED_SIZE: usize, A>(
        &self,
        vdaf: &A,
        task_id: &TaskId,
        report_id: &ReportId,
    ) -> Result<Option<LeaderStoredReport<SEED_SIZE, A>>, Error>
    where
        A: vdaf::Aggregator<SEED_SIZE>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    client_reports.client_timestamp,
                    client_reports.extensions,
                    client_reports.public_share,
                    client_reports.leader_input_share,
                    client_reports.helper_encrypted_input_share
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1
                  AND client_reports.report_id = $2
                  AND client_reports.client_timestamp >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* report_id */ &report_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| Self::client_report_from_row(vdaf, *task_id, *report_id, row))
        .transpose()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_report_metadatas_for_task(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<ReportMetadata>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT
                    client_reports.report_id, client_reports.client_timestamp,
                    client_reports.extensions
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1
                  AND client_reports.client_timestamp >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let encoded_extensions: Vec<u8> = row.get("extensions");
            let extensions: Vec<Extension> =
                decode_u16_items(&(), &mut Cursor::new(&encoded_extensions))?;

            Ok(ReportMetadata::new(
                row.get_bytea_and_convert::<ReportId>("report_id")?,
                Time::from_naive_date_time(&row.get("client_timestamp")),
                extensions,
            ))
        })
        .collect()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_client_reports_for_task<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        vdaf: &A,
        task_id: &TaskId,
    ) -> Result<Vec<LeaderStoredReport<SEED_SIZE, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    client_reports.report_id,
                    client_reports.client_timestamp,
                    client_reports.extensions,
                    client_reports.public_share,
                    client_reports.leader_input_share,
                    client_reports.helper_encrypted_input_share
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1
                  AND client_reports.client_timestamp >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            Self::client_report_from_row(
                vdaf,
                *task_id,
                row.get_bytea_and_convert::<ReportId>("report_id")?,
                row,
            )
        })
        .collect()
    }

    fn client_report_from_row<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>(
        vdaf: &A,
        task_id: TaskId,
        report_id: ReportId,
        row: Row,
    ) -> Result<LeaderStoredReport<SEED_SIZE, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
    {
        let time = Time::from_naive_date_time(&row.get("client_timestamp"));

        let encoded_extensions: Vec<u8> = row.get("extensions");
        let extensions: Vec<Extension> =
            decode_u16_items(&(), &mut Cursor::new(&encoded_extensions))?;

        let encoded_public_share: Vec<u8> = row.get("public_share");
        let public_share = A::PublicShare::get_decoded_with_param(&vdaf, &encoded_public_share)?;

        let encoded_leader_input_share: Vec<u8> = row.get("leader_input_share");
        let leader_input_share = A::InputShare::get_decoded_with_param(
            &(vdaf, Role::Leader.index().unwrap()),
            &encoded_leader_input_share,
        )?;

        let encoded_helper_input_share: Vec<u8> = row.get("helper_encrypted_input_share");
        let helper_encrypted_input_share =
            HpkeCiphertext::get_decoded(&encoded_helper_input_share)?;

        Ok(LeaderStoredReport::new(
            task_id,
            ReportMetadata::new(report_id, time, extensions),
            public_share,
            leader_input_share,
            helper_encrypted_input_share,
        ))
    }

    /// `get_unaggregated_client_report_ids_for_task` returns some report IDs corresponding to
    /// unaggregated client reports for the task identified by the given task ID. Returned client
    /// reports are marked as aggregation-started: the caller must either create an aggregation job
    /// with, or call `mark_reports_unaggregated` on each returned report as part of the same
    /// transaction.
    ///
    /// This should only be used with VDAFs that have an aggregation parameter of the unit type. It
    /// relies on this assumption to find relevant reports without consulting collection jobs. For
    /// VDAFs that do have a different aggregation parameter,
    /// `get_unaggregated_client_report_ids_by_collect_for_task` should be used instead.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_ids_for_task(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<(ReportId, Time)>, Error> {
        // TODO(#269): allow the number of returned results to be controlled?
        let stmt = self
            .prepare_cached(
                "WITH unaggregated_reports AS (
                    SELECT client_reports.id FROM client_reports
                    JOIN tasks ON tasks.id = client_reports.task_id
                    WHERE tasks.task_id = $1
                      AND client_reports.aggregation_started = FALSE
                      AND client_reports.client_timestamp >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    ORDER BY client_timestamp DESC
                    FOR UPDATE OF client_reports SKIP LOCKED
                    LIMIT 5000
                )
                UPDATE client_reports SET aggregation_started = TRUE
                WHERE id IN (SELECT id FROM unaggregated_reports)
                RETURNING report_id, client_timestamp",
            )
            .await?;
        let rows = self
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;

        rows.into_iter()
            .map(|row| {
                let report_id = row.get_bytea_and_convert::<ReportId>("report_id")?;
                let time = Time::from_naive_date_time(&row.get("client_timestamp"));
                Ok((report_id, time))
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// `mark_reports_unaggregated` resets the aggregation-started flag on the given client reports,
    /// so that they may once again be returned by `get_unaggregated_client_report_ids_for_task`. It
    /// should generally only be called on report IDs returned from
    /// `get_unaggregated_client_report_ids_for_task`, as part of the same transaction, for any
    /// client reports that are not added to an aggregation job.
    #[tracing::instrument(skip(self, report_ids), err)]
    pub async fn mark_reports_unaggregated(
        &self,
        task_id: &TaskId,
        report_ids: &[ReportId],
    ) -> Result<(), Error> {
        let report_ids: Vec<_> = report_ids.iter().map(ReportId::get_encoded).collect();
        let stmt = self
            .prepare_cached(
                "UPDATE client_reports
                SET aggregation_started = false
                FROM tasks
                WHERE client_reports.task_id = tasks.id
                  AND tasks.task_id = $1
                  AND client_reports.report_id IN (SELECT * FROM UNNEST($2::BYTEA[]))
                  AND client_reports.client_timestamp >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        let row_count = self
            .execute(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* report_ids */ &report_ids,
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        if TryInto::<usize>::try_into(row_count)? != report_ids.len() {
            return Err(Error::MutationTargetNotFound);
        }
        Ok(())
    }

    #[cfg(feature = "test-util")]
    pub async fn mark_report_aggregated(
        &self,
        task_id: &TaskId,
        report_id: &ReportId,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "UPDATE client_reports
                SET aggregation_started = TRUE
                FROM tasks
                WHERE client_reports.task_id = tasks.id
                  AND tasks.task_id = $1
                  AND client_reports.report_id = $2
                  AND client_reports.client_timestamp >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* report_id */ &report_id.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?;
        Ok(())
    }

    /// Determines whether the given task includes any client reports which have not yet started the
    /// aggregation process in the given interval.
    #[tracing::instrument(skip(self), err)]
    pub async fn interval_has_unaggregated_reports(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
    ) -> Result<bool, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT EXISTS(
                    SELECT 1 FROM client_reports
                    JOIN tasks ON tasks.id = client_reports.task_id
                    WHERE tasks.task_id = $1
                    AND client_reports.client_timestamp <@ $2::TSRANGE
                    AND client_reports.client_timestamp >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    AND client_reports.aggregation_started = FALSE
                ) AS unaggregated_report_exists",
            )
            .await?;
        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_interval */ &SqlInterval::from(batch_interval),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        Ok(row.get("unaggregated_report_exists"))
    }

    /// Return the number of reports in the provided task whose timestamp falls within the provided
    /// interval, regardless of whether the reports have been aggregated or collected. Applies only
    /// to time-interval queries.
    #[tracing::instrument(skip(self), err)]
    pub async fn count_client_reports_for_interval(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
    ) -> Result<u64, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT COUNT(1) AS count
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1
                  AND client_reports.client_timestamp >= lower($2::TSRANGE)
                  AND client_reports.client_timestamp < upper($2::TSRANGE)
                  AND client_reports.client_timestamp >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_interval */ &SqlInterval::from(batch_interval),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        Ok(row
            .get::<_, Option<i64>>("count")
            .unwrap_or_default()
            .try_into()?)
    }

    /// Return the number of reports in the provided task & batch, regardless of whether the reports
    /// have been aggregated or collected. Applies only to fixed-size queries.
    #[tracing::instrument(skip(self), err)]
    pub async fn count_client_reports_for_batch_id(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<u64, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT COUNT(DISTINCT report_aggregations.client_report_id) AS count
                FROM report_aggregations
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregation_jobs.batch_id = $2
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_id */ &batch_id.get_encoded(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        Ok(row
            .get::<_, Option<i64>>("count")
            .unwrap_or_default()
            .try_into()?)
    }

    /// `put_client_report` stores a client report, the associated plaintext leader input share and
    /// the associated encrypted helper share. Returns `Ok(())` if the write succeeds, or if there
    /// was already a row in the table matching `new_report`. Returns an error if something goes
    /// wrong or if the report ID is already in use with different values.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_client_report<const SEED_SIZE: usize, A>(
        &self,
        vdaf: &A,
        new_report: &LeaderStoredReport<SEED_SIZE, A>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<SEED_SIZE>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
    {
        let encoded_public_share = new_report.public_share().get_encoded();
        let encoded_leader_share = new_report.leader_input_share().get_encoded();
        let encoded_helper_share = new_report.helper_encrypted_input_share().get_encoded();
        let mut encoded_extensions = Vec::new();
        encode_u16_items(
            &mut encoded_extensions,
            &(),
            new_report.metadata().extensions(),
        );

        let stmt = self
            .prepare_cached(
                "INSERT INTO client_reports (
                    task_id,
                    report_id,
                    client_timestamp,
                    extensions,
                    public_share,
                    leader_input_share,
                    helper_encrypted_input_share
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
                RETURNING COALESCE(client_timestamp < COALESCE($3::TIMESTAMP - (SELECT report_expiry_age FROM tasks WHERE task_id = $1) * '1 second'::INTERVAL, '-infinity'::TIMESTAMP), FALSE) AS is_expired",
            )
            .await?;
        let rows = self
            .query(
                &stmt,
                &[
                    /* task_id */ new_report.task_id().as_ref(),
                    /* report_id */ new_report.metadata().id().as_ref(),
                    /* client_timestamp */
                    &new_report.metadata().time().as_naive_date_time()?,
                    /* extensions */ &encoded_extensions,
                    /* public_share */ &encoded_public_share,
                    /* leader_input_share */ &encoded_leader_share,
                    /* helper_encrypted_input_share */ &encoded_helper_share,
                ],
            )
            .await?;
        let row_count = rows.len().try_into()?;

        if let Some(row) = rows.into_iter().next() {
            if row.get("is_expired") {
                let stmt = self
                    .prepare_cached(
                        "DELETE FROM client_reports
                            USING tasks
                            WHERE client_reports.task_id = tasks.id
                              AND tasks.task_id = $1
                              AND client_reports.report_id = $2",
                    )
                    .await?;
                self.execute(
                    &stmt,
                    &[
                        /* task_id */ new_report.task_id().as_ref(),
                        /* report_id */ new_report.metadata().id().as_ref(),
                    ],
                )
                .await?;
            }

            return Ok(());
        }

        check_insert(row_count)
    }

    /// put_report_share stores a report share, given its associated task ID.
    ///
    /// This method is intended for use by aggregators acting in the helper role; notably, it does
    /// not store extensions, public_share, or input_shares, as these are not required to be stored
    /// for the helper workflow (and the helper never observes the entire set of encrypted input
    /// shares, so it could not record the full client report in any case).
    ///
    /// Returns `Err(Error::MutationTargetAlreadyExists)` if an attempt to mutate an existing row
    /// (e.g., changing the timestamp for a known report ID) is detected.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_share(
        &self,
        task_id: &TaskId,
        report_share: &ReportShare,
    ) -> Result<(), Error> {
        let mut encoded_extensions = Vec::new();
        encode_u16_items(
            &mut encoded_extensions,
            &(),
            report_share.metadata().extensions(),
        );

        // On conflict, we update the row, but only if the incoming client timestamp (excluded)
        // matches the existing one. This lets us detect whether there's a row with a mismatching
        // timestamp through the number of rows modified by the statement.
        let stmt = self
            .prepare_cached(
                "INSERT INTO client_reports (task_id, report_id, client_timestamp, extensions)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4)
                ON CONFLICT (task_id, report_id) DO UPDATE
                  SET client_timestamp = client_reports.client_timestamp
                    WHERE excluded.client_timestamp = client_reports.client_timestamp",
            )
            .await?;
        check_insert(
            self.execute(
                &stmt,
                &[
                    /* task_id */ &task_id.get_encoded(),
                    /* report_id */ &report_share.metadata().id().as_ref(),
                    /* client_timestamp */
                    &report_share.metadata().time().as_naive_date_time()?,
                    /* extensions */ &encoded_extensions,
                ],
            )
            .await?,
        )
    }

    /// get_aggregation_job retrieves an aggregation job by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_job<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Option<AggregationJob<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregation_param, batch_id, client_timestamp_interval, state
                FROM aggregation_jobs
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregation_jobs.aggregation_job_id = $2
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| Self::aggregation_job_from_row(task_id, aggregation_job_id, &row))
        .transpose()
    }

    /// get_aggregation_jobs_for_task returns all aggregation jobs for a given task ID.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_jobs_for_task<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<AggregationJob<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregation_job_id, aggregation_param, batch_id, client_timestamp_interval,
                    state
                FROM aggregation_jobs
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            Self::aggregation_job_from_row(
                task_id,
                &row.get_bytea_and_convert::<AggregationJobId>("aggregation_job_id")?,
                &row,
            )
        })
        .collect()
    }

    fn aggregation_job_from_row<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        row: &Row,
    ) -> Result<AggregationJob<SEED_SIZE, Q, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Ok(AggregationJob::new(
            *task_id,
            *aggregation_job_id,
            A::AggregationParam::get_decoded(row.get("aggregation_param"))?,
            Q::PartialBatchIdentifier::get_decoded(row.get::<_, &[u8]>("batch_id"))?,
            row.get::<_, SqlInterval>("client_timestamp_interval")
                .as_interval(),
            row.get("state"),
        ))
    }

    /// acquire_incomplete_aggregation_jobs retrieves & acquires the IDs of unclaimed incomplete
    /// aggregation jobs. At most `maximum_acquire_count` jobs are acquired. The job is acquired
    /// with a "lease" that will time out; the desired duration of the lease is a parameter, and the
    /// returned lease provides the absolute timestamp at which the lease is no longer live.
    #[tracing::instrument(skip(self), err)]
    pub async fn acquire_incomplete_aggregation_jobs(
        &self,
        lease_duration: &StdDuration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredAggregationJob>>, Error> {
        let now = self.clock.now().as_naive_date_time()?;
        let lease_expiry_time = add_naive_date_time_duration(&now, lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        // TODO(#224): verify that this query is efficient. I am not sure if we would currently
        // scan over every (in-progress, not-leased) aggregation job for tasks where we are in the
        // HELPER role.
        // We generate the token on the DB to allow each acquired job to receive its own distinct
        // token. This is not strictly necessary as we only care about token collisions on a
        // per-row basis.
        let stmt = self
            .prepare_cached(
                "WITH incomplete_jobs AS (
                    SELECT aggregation_jobs.id FROM aggregation_jobs
                    JOIN tasks ON tasks.id = aggregation_jobs.task_id
                    WHERE tasks.aggregator_role = 'LEADER'
                    AND aggregation_jobs.state = 'IN_PROGRESS'
                    AND aggregation_jobs.lease_expiry <= $2
                    AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    FOR UPDATE OF aggregation_jobs SKIP LOCKED LIMIT $3
                )
                UPDATE aggregation_jobs SET
                    lease_expiry = $1,
                    lease_token = gen_random_bytes(16),
                    lease_attempts = lease_attempts + 1
                FROM tasks
                WHERE tasks.id = aggregation_jobs.task_id
                AND aggregation_jobs.id IN (SELECT id FROM incomplete_jobs)
                RETURNING tasks.task_id, tasks.query_type, tasks.vdaf,
                          aggregation_jobs.aggregation_job_id, aggregation_jobs.lease_token,
                          aggregation_jobs.lease_attempts",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* lease_expiry */ &lease_expiry_time,
                /* now */ &now,
                /* limit */ &maximum_acquire_count,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            let aggregation_job_id =
                row.get_bytea_and_convert::<AggregationJobId>("aggregation_job_id")?;
            let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
            let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
            let lease_token = row.get_bytea_and_convert::<LeaseToken>("lease_token")?;
            let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
            Ok(Lease::new(
                AcquiredAggregationJob::new(task_id, aggregation_job_id, query_type, vdaf),
                lease_expiry_time,
                lease_token,
                lease_attempts,
            ))
        })
        .collect()
    }

    /// release_aggregation_job releases an acquired (via e.g. acquire_incomplete_aggregation_jobs)
    /// aggregation job. It returns an error if the aggregation job has no current lease.
    #[tracing::instrument(skip(self), err)]
    pub async fn release_aggregation_job(
        &self,
        lease: &Lease<AcquiredAggregationJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "UPDATE aggregation_jobs
                SET lease_expiry = TIMESTAMP '-infinity',
                    lease_token = NULL,
                    lease_attempts = 0
                FROM tasks
                WHERE tasks.id = aggregation_jobs.task_id
                  AND tasks.task_id = $1
                  AND aggregation_jobs.aggregation_job_id = $2
                  AND aggregation_jobs.lease_expiry = $3
                  AND aggregation_jobs.lease_token = $4
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($5::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* task_id */ &lease.leased().task_id().as_ref(),
                    /* aggregation_job_id */
                    &lease.leased().aggregation_job_id().as_ref(),
                    /* lease_expiry */ &lease.lease_expiry_time(),
                    /* lease_token */ &lease.lease_token().as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )
    }

    /// put_aggregation_job stores an aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregation_job<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        aggregation_job: &AggregationJob<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "INSERT INTO aggregation_jobs
                    (task_id, aggregation_job_id, aggregation_param, batch_id,
                    client_timestamp_interval, state)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6)
                ON CONFLICT DO NOTHING
                RETURNING COALESCE(UPPER(client_timestamp_interval) < COALESCE($7::TIMESTAMP - (SELECT report_expiry_age FROM tasks WHERE task_id = $1) * '1 second'::INTERVAL, '-infinity'::TIMESTAMP), FALSE) AS is_expired",
            )
            .await?;
        let rows = self
            .query(
                &stmt,
                &[
                    /* task_id */ &aggregation_job.task_id().as_ref(),
                    /* aggregation_job_id */ &aggregation_job.id().as_ref(),
                    /* aggregation_param */
                    &aggregation_job.aggregation_parameter().get_encoded(),
                    /* batch_id */
                    &aggregation_job.partial_batch_identifier().get_encoded(),
                    /* client_timestamp_interval */
                    &SqlInterval::from(aggregation_job.client_timestamp_interval()),
                    /* state */ &aggregation_job.state(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        let row_count = rows.len().try_into()?;

        if let Some(row) = rows.into_iter().next() {
            // We got a row back, meaning we wrote an aggregation job. We check that it wasn't
            // expired per the task's report_expiry_age, but otherwise we are done.
            if row.get("is_expired") {
                let stmt = self
                    .prepare_cached(
                        "DELETE FROM aggregation_jobs
                        USING tasks
                        WHERE aggregation_jobs.task_id = tasks.id
                          AND tasks.task_id = $1
                          AND aggregation_jobs.aggregation_job_id = $2",
                    )
                    .await?;
                self.execute(
                    &stmt,
                    &[
                        /* task_id */ &aggregation_job.task_id().as_ref(),
                        /* aggregation_job_id */ &aggregation_job.id().as_ref(),
                    ],
                )
                .await?;
                return Ok(());
            }
        }

        check_insert(row_count)
    }

    /// update_aggregation_job updates a stored aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_aggregation_job<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        aggregation_job: &AggregationJob<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "UPDATE aggregation_jobs
                SET state = $1
                FROM tasks
                WHERE tasks.task_id = $2
                  AND aggregation_jobs.aggregation_job_id = $3
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($4::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */ &aggregation_job.state(),
                    /* task_id */ &aggregation_job.task_id().as_ref(),
                    /* aggregation_job_id */ &aggregation_job.id().as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )
    }

    /// Check whether the report has ever been aggregated with the given parameter, for an
    /// aggregation job besides the given one.
    #[tracing::instrument(skip(self), err)]
    pub async fn check_other_report_aggregation_exists<const SEED_SIZE: usize, A>(
        &self,
        task_id: &TaskId,
        report_id: &ReportId,
        aggregation_param: &A::AggregationParam,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<bool, Error>
    where
        A: vdaf::Aggregator<SEED_SIZE>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT 1 FROM report_aggregations
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND report_aggregations.client_report_id = $2
                  AND aggregation_jobs.aggregation_param = $3
                  AND aggregation_jobs.aggregation_job_id != $4
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($5::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        Ok(self
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* report_id */ &report_id.as_ref(),
                    /* aggregation_param */ &aggregation_param.get_encoded(),
                    /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await
            .map(|row| row.is_some())?)
    }

    /// get_report_aggregation gets a report aggregation by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregation<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
    ) -> Result<Option<ReportAggregation<SEED_SIZE, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    report_aggregations.client_timestamp, report_aggregations.ord,
                    report_aggregations.state, report_aggregations.prep_state,
                    report_aggregations.prep_msg, report_aggregations.error_code
                FROM report_aggregations
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregation_jobs.aggregation_job_id = $2
                  AND report_aggregations.client_report_id = $3
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($4::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                /* report_id */ &report_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| {
            Self::report_aggregation_from_row(
                vdaf,
                role,
                task_id,
                aggregation_job_id,
                report_id,
                &row,
            )
        })
        .transpose()
    }

    /// get_report_aggregations_for_aggregation_job retrieves all report aggregations associated
    /// with a given aggregation job, ordered by their natural ordering.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregations_for_aggregation_job<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Vec<ReportAggregation<SEED_SIZE, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    report_aggregations.client_report_id, report_aggregations.client_timestamp,
                    report_aggregations.ord, report_aggregations.state,
                    report_aggregations.prep_state, report_aggregations.prep_msg,
                    report_aggregations.error_code
                FROM report_aggregations
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregation_jobs.aggregation_job_id = $2
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                ORDER BY report_aggregations.ord ASC",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            Self::report_aggregation_from_row(
                vdaf,
                role,
                task_id,
                aggregation_job_id,
                &row.get_bytea_and_convert::<ReportId>("client_report_id")?,
                &row,
            )
        })
        .collect()
    }

    /// get_report_aggregations_for_task retrieves all report aggregations associated with a given
    /// task.
    #[cfg(feature = "test-util")]
    pub async fn get_report_aggregations_for_task<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
    ) -> Result<Vec<ReportAggregation<SEED_SIZE, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregation_jobs.aggregation_job_id, report_aggregations.client_report_id,
                    report_aggregations.client_timestamp, report_aggregations.ord,
                    report_aggregations.state, report_aggregations.prep_state,
                    report_aggregations.prep_msg, report_aggregations.error_code
                FROM report_aggregations
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            Self::report_aggregation_from_row(
                vdaf,
                role,
                task_id,
                &row.get_bytea_and_convert::<AggregationJobId>("aggregation_job_id")?,
                &row.get_bytea_and_convert::<ReportId>("client_report_id")?,
                &row,
            )
        })
        .collect()
    }

    fn report_aggregation_from_row<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>(
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
        row: &Row,
    ) -> Result<ReportAggregation<SEED_SIZE, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
    {
        let time = Time::from_naive_date_time(&row.get("client_timestamp"));
        let ord: u64 = row.get_bigint_and_convert("ord")?;
        let state: ReportAggregationStateCode = row.get("state");
        let prep_state_bytes: Option<Vec<u8>> = row.get("prep_state");
        let prep_msg_bytes: Option<Vec<u8>> = row.get("prep_msg");
        let error_code: Option<i16> = row.get("error_code");

        let error_code = match error_code {
            Some(c) => {
                let c: u8 = c.try_into().map_err(|err| {
                    Error::DbState(format!("couldn't convert error_code value: {err}"))
                })?;
                Some(c.try_into().map_err(|err| {
                    Error::DbState(format!("couldn't convert error_code value: {err}"))
                })?)
            }
            None => None,
        };

        let agg_state = match state {
            ReportAggregationStateCode::Start => ReportAggregationState::Start,

            ReportAggregationStateCode::Waiting => {
                let agg_index = role.index().ok_or_else(|| {
                    Error::User(anyhow!("unexpected role: {}", role.as_str()).into())
                })?;
                let prep_state = A::PrepareState::get_decoded_with_param(
                    &(vdaf, agg_index),
                    &prep_state_bytes.ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state WAITING but prep_state is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let prep_msg = prep_msg_bytes
                    .map(|bytes| A::PrepareMessage::get_decoded_with_param(&prep_state, &bytes))
                    .transpose()?;

                ReportAggregationState::Waiting(prep_state, prep_msg)
            }

            ReportAggregationStateCode::Finished => ReportAggregationState::Finished,

            ReportAggregationStateCode::Failed => {
                ReportAggregationState::Failed(error_code.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state FAILED but error_code is NULL".to_string(),
                    )
                })?)
            }
        };

        Ok(ReportAggregation::new(
            *task_id,
            *aggregation_job_id,
            *report_id,
            time,
            ord,
            agg_state,
        ))
    }

    /// put_report_aggregation stores aggregation data for a single report.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_aggregation<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>(
        &self,
        report_aggregation: &ReportAggregation<SEED_SIZE, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareState: Encode,
    {
        let encoded_state_values = report_aggregation.state().encoded_values_from_state();

        let stmt = self
            .prepare_cached(
                "INSERT INTO report_aggregations
                    (aggregation_job_id, client_report_id, client_timestamp, ord, state, prep_state,
                     prep_msg, error_code)
                SELECT aggregation_jobs.id, $3, $4, $5, $6, $7, $8, $9
                FROM aggregation_jobs
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregation_job_id = $2
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($10::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                ON CONFLICT DO NOTHING",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &report_aggregation.task_id().as_ref(),
                /* aggregation_job_id */ &report_aggregation.aggregation_job_id().as_ref(),
                /* client_report_id */ &report_aggregation.report_id().as_ref(),
                /* client_timestamp */ &report_aggregation.time().as_naive_date_time()?,
                /* ord */ &TryInto::<i64>::try_into(report_aggregation.ord())?,
                /* state */ &report_aggregation.state().state_code(),
                /* prep_state */ &encoded_state_values.prep_state,
                /* prep_msg */ &encoded_state_values.prep_msg,
                /* error_code */ &encoded_state_values.report_share_err,
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn update_report_aggregation<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>(
        &self,
        report_aggregation: &ReportAggregation<SEED_SIZE, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareState: Encode,
    {
        let encoded_state_values = report_aggregation.state().encoded_values_from_state();

        let stmt = self
            .prepare_cached(
                "UPDATE report_aggregations
                SET state = $1, prep_state = $2, prep_msg = $3, error_code = $4
                FROM aggregation_jobs, tasks
                WHERE report_aggregations.aggregation_job_id = aggregation_jobs.id
                  AND aggregation_jobs.task_id = tasks.id
                  AND aggregation_jobs.aggregation_job_id = $5
                  AND tasks.task_id = $6
                  AND report_aggregations.client_report_id = $7
                  AND report_aggregations.client_timestamp = $8
                  AND report_aggregations.ord = $9
                  AND UPPER(aggregation_jobs.client_timestamp_interval) >= COALESCE($10::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */
                    &report_aggregation.state().state_code(),
                    /* prep_state */ &encoded_state_values.prep_state,
                    /* prep_msg */ &encoded_state_values.prep_msg,
                    /* error_code */ &encoded_state_values.report_share_err,
                    /* aggregation_job_id */
                    &report_aggregation.aggregation_job_id().as_ref(),
                    /* task_id */ &report_aggregation.task_id().as_ref(),
                    /* client_report_id */ &report_aggregation.report_id().as_ref(),
                    /* client_timestamp */ &report_aggregation.time().as_naive_date_time()?,
                    /* ord */ &TryInto::<i64>::try_into(report_aggregation.ord())?,
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )
    }

    /// Returns the collection job for the provided ID, or `None` if no such collection job exists.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_collection_job<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<CollectionJob<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    tasks.task_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs
                JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE collection_jobs.collection_job_id = $1
                  AND COALESCE(LOWER(collection_jobs.batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = collection_jobs.task_id AND batches.batch_identifier = collection_jobs.batch_identifier AND batches.aggregation_param = collection_jobs.aggregation_param))) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* collection_job_id */ &collection_job_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            let batch_identifier = Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
            Self::collection_job_from_row(task_id, batch_identifier, *collection_job_id, &row)
        })
        .transpose()
    }

    /// If a collect job corresponding to the provided values exists, its ID is returned, which may
    /// then be used to construct a collection job URI. If that collect job does not exist, returns
    /// `Ok(None)`.
    #[tracing::instrument(skip(self, aggregation_parameter), err)]
    pub async fn get_collection_job_id<const L: usize, Q: QueryType, A: vdaf::Aggregator<L>>(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Option<CollectionJobId>, Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT collection_job_id FROM collection_jobs
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                  AND batch_identifier = $2
                  AND aggregation_param = $3",
            )
            .await?;
        let row = self
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* batch_identifier */ &batch_identifier.get_encoded(),
                    /* aggregation_param */ &aggregation_parameter.get_encoded(),
                ],
            )
            .await?;

        row.map(|row| row.get_bytea_and_convert::<CollectionJobId>("collection_job_id"))
            .transpose()
    }

    /// Returns all collection jobs for the given task which include the given timestamp. Applies
    /// only to time-interval tasks.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_collection_jobs_including_time<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        timestamp: &Time,
    ) -> Result<Vec<CollectionJob<SEED_SIZE, TimeInterval, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        // TODO(#1553): write unit test
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collection_jobs.batch_interval @> $2::TIMESTAMP
                  AND LOWER(collection_jobs.batch_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* timestamp */ &timestamp.as_naive_date_time()?,
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            Self::collection_job_from_row(*task_id, batch_identifier, collection_job_id, &row)
        })
        .collect()
    }

    /// Returns all collection jobs for the given task whose collect intervals intersect with the
    /// given interval. Applies only to time-interval tasks.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_collection_jobs_intersecting_interval<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        batch_interval: &Interval,
    ) -> Result<Vec<CollectionJob<SEED_SIZE, TimeInterval, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        // TODO(#1553): write unit test
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collection_jobs.batch_interval && $2
                  AND LOWER(collection_jobs.batch_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_interval */ &SqlInterval::from(batch_interval),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            Self::collection_job_from_row::<SEED_SIZE, TimeInterval, A>(
                *task_id,
                batch_identifier,
                collection_job_id,
                &row,
            )
        })
        .collect()
    }

    /// Retrieves all collection jobs for the given batch ID. Multiple collection jobs may be
    /// returned with distinct aggregation parameters. Applies only to fixed-size tasks.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_collection_jobs_by_batch_id<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<Vec<CollectionJob<SEED_SIZE, FixedSize, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        // TODO(#1553): write unit test
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs
                JOIN tasks ON tasks.id = collection_jobs.task_id
                JOIN batches ON batches.task_id = collection_jobs.task_id
                            AND batches.batch_identifier = collection_jobs.batch_identifier
                WHERE tasks.task_id = $1
                  AND collection_jobs.batch_identifier = $2
                  AND UPPER(batches.client_timestamp_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_id */ &batch_id.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            Self::collection_job_from_row(*task_id, *batch_id, collection_job_id, &row)
        })
        .collect()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_collection_jobs_for_task<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<CollectionJob<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    collection_jobs.collection_job_id,
                    collection_jobs.batch_identifier,
                    collection_jobs.aggregation_param,
                    collection_jobs.state,
                    collection_jobs.report_count,
                    collection_jobs.helper_aggregate_share,
                    collection_jobs.leader_aggregate_share
                FROM collection_jobs
                JOIN tasks ON tasks.id = collection_jobs.task_id
                WHERE tasks.task_id = $1
                  AND COALESCE(LOWER(collection_jobs.batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = collection_jobs.task_id AND batches.batch_identifier = collection_jobs.batch_identifier AND batches.aggregation_param = collection_jobs.aggregation_param))) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            let batch_identifier = Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
            Self::collection_job_from_row(*task_id, batch_identifier, collection_job_id, &row)
        })
        .collect()
    }

    fn collection_job_from_row<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        collection_job_id: CollectionJobId,
        row: &Row,
    ) -> Result<CollectionJob<SEED_SIZE, Q, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
        let state: CollectionJobStateCode = row.get("state");
        let report_count: Option<i64> = row.get("report_count");
        let helper_aggregate_share_bytes: Option<Vec<u8>> = row.get("helper_aggregate_share");
        let leader_aggregate_share_bytes: Option<Vec<u8>> = row.get("leader_aggregate_share");

        let state = match state {
            CollectionJobStateCode::Start => CollectionJobState::Start,

            CollectionJobStateCode::Collectable => CollectionJobState::Collectable,

            CollectionJobStateCode::Finished => {
                let report_count = u64::try_from(report_count.ok_or_else(|| {
                    Error::DbState(
                        "collection job in state FINISHED but report_count is NULL".to_string(),
                    )
                })?)?;
                let encrypted_helper_aggregate_share = HpkeCiphertext::get_decoded(
                    &helper_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collection job in state FINISHED but helper_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let leader_aggregate_share = A::AggregateShare::try_from(
                    &leader_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collection job is in state FINISHED but leader_aggregate_share is \
                         NULL"
                                .to_string(),
                        )
                    })?,
                )
                .map_err(|err| {
                    Error::DbState(format!("could not parse leader_aggregate_share: {:?}", err))
                })?;
                CollectionJobState::Finished {
                    report_count,
                    encrypted_helper_aggregate_share,
                    leader_aggregate_share,
                }
            }

            CollectionJobStateCode::Abandoned => CollectionJobState::Abandoned,

            CollectionJobStateCode::Deleted => CollectionJobState::Deleted,
        };

        Ok(CollectionJob::new(
            task_id,
            collection_job_id,
            batch_identifier,
            aggregation_param,
            state,
        ))
    }

    /// Stores a new collection job.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_collection_job<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        collection_job: &CollectionJob<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: Debug,
    {
        let batch_interval =
            Q::to_batch_interval(collection_job.batch_identifier()).map(SqlInterval::from);

        let stmt = self
            .prepare_cached(
                "INSERT INTO collection_jobs
                    (collection_job_id, task_id, batch_identifier, batch_interval,
                    aggregation_param, state)
                VALUES ($1, (SELECT id FROM tasks WHERE task_id = $2), $3, $4, $5, $6)
                ON CONFLICT DO NOTHING
                RETURNING COALESCE(COALESCE(LOWER(batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = collection_jobs.task_id AND batches.batch_identifier = collection_jobs.batch_identifier AND batches.aggregation_param = collection_jobs.aggregation_param))) < COALESCE($7::TIMESTAMP - (SELECT report_expiry_age FROM tasks WHERE task_id = $2) * '1 second'::INTERVAL, '-infinity'::TIMESTAMP), FALSE) AS is_expired",
            )
            .await?;

        let rows = self
            .query(
                &stmt,
                &[
                    /* collection_job_id */ collection_job.id().as_ref(),
                    /* task_id */ collection_job.task_id().as_ref(),
                    /* batch_identifier */ &collection_job.batch_identifier().get_encoded(),
                    /* batch_interval */ &batch_interval,
                    /* aggregation_param */
                    &collection_job.aggregation_parameter().get_encoded(),
                    /* state */
                    &collection_job.state().collection_job_state_code(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        let row_count = rows.len().try_into()?;

        if let Some(row) = rows.into_iter().next() {
            // We got a row back, meaning we wrote a collection job. We check that it wasn't expired
            // per the task's report_expiry_age, but otherwise we are done.
            if row.get("is_expired") {
                let stmt = self
                    .prepare_cached(
                        "DELETE FROM collection_jobs
                        USING tasks
                        WHERE collection_jobs.task_id = tasks.id
                          AND tasks.task_id = $1
                          AND collection_jobs.collection_job_id = $2",
                    )
                    .await?;
                self.execute(
                    &stmt,
                    &[
                        /* task_id */ collection_job.task_id().as_ref(),
                        /* collection_job_id */ collection_job.id().as_ref(),
                    ],
                )
                .await?;
                return Ok(());
            }
        }

        check_insert(row_count)
    }

    /// acquire_incomplete_collection_jobs retrieves & acquires the IDs of unclaimed incomplete
    /// collection jobs. At most `maximum_acquire_count` jobs are acquired. The job is acquired with
    /// a "lease" that will time out; the desired duration of the lease is a parameter, and the
    /// lease expiration time is returned.
    #[tracing::instrument(skip(self), err)]
    pub async fn acquire_incomplete_collection_jobs(
        &self,
        lease_duration: &StdDuration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredCollectionJob>>, Error> {
        let now = self.clock.now().as_naive_date_time()?;
        let lease_expiry_time = add_naive_date_time_duration(&now, lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        let stmt = self
            .prepare_cached(
                "WITH incomplete_jobs AS (
                    SELECT collection_jobs.id, tasks.task_id, tasks.query_type, tasks.vdaf
                    FROM collection_jobs
                    JOIN tasks ON tasks.id = collection_jobs.task_id
                    WHERE tasks.aggregator_role = 'LEADER'
                      AND collection_jobs.state = 'COLLECTABLE'
                      AND collection_jobs.lease_expiry <= $2
                      AND COALESCE(LOWER(collection_jobs.batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = collection_jobs.task_id AND batches.batch_identifier = collection_jobs.batch_identifier AND batches.aggregation_param = collection_jobs.aggregation_param))) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    FOR UPDATE OF collection_jobs SKIP LOCKED LIMIT $3
                )
                UPDATE collection_jobs SET
                    lease_expiry = $1,
                    lease_token = gen_random_bytes(16),
                    lease_attempts = lease_attempts + 1
                FROM incomplete_jobs
                WHERE collection_jobs.id = incomplete_jobs.id
                RETURNING incomplete_jobs.task_id, incomplete_jobs.query_type, incomplete_jobs.vdaf,
                          collection_jobs.collection_job_id, collection_jobs.id,
                          collection_jobs.lease_token, collection_jobs.lease_attempts",
            )
            .await?;

        self.query(
            &stmt,
            &[
                /* lease_expiry */ &lease_expiry_time,
                /* now */ &now,
                /* limit */ &maximum_acquire_count,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            let collection_job_id =
                row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
            let query_type = row.try_get::<_, Json<task::QueryType>>("query_type")?.0;
            let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
            let lease_token = row.get_bytea_and_convert::<LeaseToken>("lease_token")?;
            let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
            Ok(Lease::new(
                AcquiredCollectionJob::new(task_id, collection_job_id, query_type, vdaf),
                lease_expiry_time,
                lease_token,
                lease_attempts,
            ))
        })
        .collect()
    }

    /// release_collection_job releases an acquired (via e.g. acquire_incomplete_collection_jobs)
    /// collect job. It returns an error if the collection job has no current lease.
    #[tracing::instrument(skip(self), err)]
    pub async fn release_collection_job(
        &self,
        lease: &Lease<AcquiredCollectionJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "UPDATE collection_jobs
                SET lease_expiry = TIMESTAMP '-infinity',
                    lease_token = NULL,
                    lease_attempts = 0
                FROM tasks
                WHERE tasks.id = collection_jobs.task_id
                  AND tasks.task_id = $1
                  AND collection_jobs.collection_job_id = $2
                  AND collection_jobs.lease_expiry = $3
                  AND collection_jobs.lease_token = $4
                  AND COALESCE(LOWER(collection_jobs.batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = collection_jobs.task_id AND batches.batch_identifier = collection_jobs.batch_identifier AND batches.aggregation_param = collection_jobs.aggregation_param))) >= COALESCE($5::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* task_id */ &lease.leased().task_id().as_ref(),
                    /* collection_job_id */ &lease.leased().collection_job_id().as_ref(),
                    /* lease_expiry */ &lease.lease_expiry_time(),
                    /* lease_token */ &lease.lease_token().as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )
    }

    /// Updates an existing collection job.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_collection_job<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        collection_job: &CollectionJob<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let (report_count, leader_aggregate_share, helper_aggregate_share) = match collection_job
            .state()
        {
            CollectionJobState::Start => {
                return Err(Error::InvalidParameter(
                    "cannot update collection job into START state",
                ));
            }
            CollectionJobState::Finished {
                report_count,
                encrypted_helper_aggregate_share,
                leader_aggregate_share,
            } => {
                let report_count: Option<i64> = Some(i64::try_from(*report_count)?);
                let leader_aggregate_share: Option<Vec<u8>> = Some(leader_aggregate_share.into());
                let helper_aggregate_share = Some(encrypted_helper_aggregate_share.get_encoded());

                (report_count, leader_aggregate_share, helper_aggregate_share)
            }
            CollectionJobState::Collectable
            | CollectionJobState::Abandoned
            | CollectionJobState::Deleted => (None, None, None),
        };

        let stmt = self
            .prepare_cached(
                "UPDATE collection_jobs SET
                    state = $1,
                    report_count = $2,
                    leader_aggregate_share = $3,
                    helper_aggregate_share = $4
                FROM tasks
                WHERE tasks.id = collection_jobs.task_id
                  AND tasks.task_id = $5
                  AND collection_job_id = $6
                  AND COALESCE(LOWER(collection_jobs.batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = collection_jobs.task_id AND batches.batch_identifier = collection_jobs.batch_identifier AND batches.aggregation_param = collection_jobs.aggregation_param))) >= COALESCE($7::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;

        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */ &collection_job.state().collection_job_state_code(),
                    /* report_count */ &report_count,
                    /* leader_aggregate_share */ &leader_aggregate_share,
                    /* helper_aggregate_share */ &helper_aggregate_share,
                    /* task_id */ &collection_job.task_id().as_ref(),
                    /* collection_job_id */ &collection_job.id().as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )
    }

    /// Retrieves an existing batch aggregation.
    #[tracing::instrument(skip(self, aggregation_parameter), err)]
    pub async fn get_batch_aggregation<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
        ord: u64,
    ) -> Result<Option<BatchAggregation<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    batch_aggregations.state, aggregate_share, report_count,
                    batch_aggregations.client_timestamp_interval, checksum
                FROM batch_aggregations
                JOIN tasks ON tasks.id = batch_aggregations.task_id
                JOIN batches ON batches.task_id = batch_aggregations.task_id
                            AND batches.batch_identifier = batch_aggregations.batch_identifier
                            AND batches.aggregation_param = batch_aggregations.aggregation_param
                WHERE tasks.task_id = $1
                  AND batch_aggregations.batch_identifier = $2
                  AND batch_aggregations.aggregation_param = $3
                  AND ord = $4
                  AND UPPER(batches.client_timestamp_interval) >= COALESCE($5::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;

        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
                /* aggregation_param */ &aggregation_parameter.get_encoded(),
                /* ord */ &TryInto::<i64>::try_into(ord)?,
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| {
            Self::batch_aggregation_from_row(
                *task_id,
                batch_identifier.clone(),
                aggregation_parameter.clone(),
                ord,
                row,
            )
        })
        .transpose()
    }

    /// Retrieves all batch aggregations stored for a given batch, identified by task ID, batch
    /// identifier, and aggregation parameter.
    #[tracing::instrument(skip(self, aggregation_parameter), err)]
    pub async fn get_batch_aggregations_for_batch<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Vec<BatchAggregation<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    ord, batch_aggregations.state, aggregate_share, report_count,
                    batch_aggregations.client_timestamp_interval, checksum
                FROM batch_aggregations
                JOIN tasks ON tasks.id = batch_aggregations.task_id
                JOIN batches ON batches.task_id = batch_aggregations.task_id
                            AND batches.batch_identifier = batch_aggregations.batch_identifier
                            AND batches.aggregation_param = batch_aggregations.aggregation_param
                WHERE tasks.task_id = $1
                  AND batch_aggregations.batch_identifier = $2
                  AND batch_aggregations.aggregation_param = $3
                  AND UPPER(batches.client_timestamp_interval) >= COALESCE($4::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;

        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
                /* aggregation_param */ &aggregation_parameter.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            Self::batch_aggregation_from_row(
                *task_id,
                batch_identifier.clone(),
                aggregation_parameter.clone(),
                row.get_bigint_and_convert("ord")?,
                row,
            )
        })
        .collect()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_batch_aggregations_for_task<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<BatchAggregation<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    batch_aggregations.batch_identifier, batch_aggregations.aggregation_param, ord,
                    batch_aggregations.state, aggregate_share, report_count,
                    batch_aggregations.client_timestamp_interval, checksum
                FROM batch_aggregations
                JOIN tasks ON tasks.id = batch_aggregations.task_id
                JOIN batches ON batches.task_id = batch_aggregations.task_id
                            AND batches.batch_identifier = batch_aggregations.batch_identifier
                            AND batches.aggregation_param = batch_aggregations.aggregation_param
                WHERE tasks.task_id = $1
                  AND UPPER(batches.client_timestamp_interval) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;

        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            let ord = row.get_bigint_and_convert("ord")?;

            Self::batch_aggregation_from_row(
                *task_id,
                batch_identifier,
                aggregation_param,
                ord,
                row,
            )
        })
        .collect()
    }

    fn batch_aggregation_from_row<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_parameter: A::AggregationParam,
        ord: u64,
        row: Row,
    ) -> Result<BatchAggregation<SEED_SIZE, Q, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let state = row.get("state");
        let aggregate_share = row
            .get::<_, Option<Vec<u8>>>("aggregate_share")
            .as_ref()
            .map(|bytes| A::AggregateShare::try_from(bytes))
            .transpose()
            .map_err(|_| Error::DbState("aggregate_share couldn't be parsed".to_string()))?;
        let report_count = row.get_bigint_and_convert("report_count")?;
        let client_timestamp_interval = row
            .get::<_, SqlInterval>("client_timestamp_interval")
            .as_interval();
        let checksum = ReportIdChecksum::get_decoded(row.get("checksum"))?;
        Ok(BatchAggregation::new(
            task_id,
            batch_identifier,
            aggregation_parameter,
            ord,
            state,
            aggregate_share,
            report_count,
            client_timestamp_interval,
            checksum,
        ))
    }

    /// Store a new `batch_aggregations` row in the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_batch_aggregation<
        const SEED_SIZE: usize,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        batch_aggregation: &BatchAggregation<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: Debug,
        A::AggregateShare: Debug,
    {
        let batch_interval =
            Q::to_batch_interval(batch_aggregation.batch_identifier()).map(SqlInterval::from);

        let stmt = self
            .prepare_cached(
                "INSERT INTO batch_aggregations (
                    task_id, batch_identifier, batch_interval, aggregation_param, ord, state,
                    aggregate_share, report_count, client_timestamp_interval, checksum
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT DO NOTHING
                RETURNING COALESCE(UPPER((SELECT client_timestamp_interval FROM batches WHERE task_id = batch_aggregations.task_id AND batch_identifier = batch_aggregations.batch_identifier AND aggregation_param = batch_aggregations.aggregation_param)) < COALESCE($11::TIMESTAMP - (SELECT report_expiry_age FROM tasks WHERE task_id = $1) * '1 second'::INTERVAL, '-infinity'::TIMESTAMP), FALSE) AS is_expired",
            )
            .await?;
        let rows = self
            .query(
                &stmt,
                &[
                    /* task_id */ &batch_aggregation.task_id().as_ref(),
                    /* batch_identifier */
                    &batch_aggregation.batch_identifier().get_encoded(),
                    /* batch_interval */ &batch_interval,
                    /* aggregation_param */
                    &batch_aggregation.aggregation_parameter().get_encoded(),
                    /* ord */ &TryInto::<i64>::try_into(batch_aggregation.ord())?,
                    /* state */ &batch_aggregation.state(),
                    /* aggregate_share */
                    &batch_aggregation.aggregate_share().map(Into::into),
                    /* report_count */ &i64::try_from(batch_aggregation.report_count())?,
                    /* client_timestamp_interval */
                    &SqlInterval::from(batch_aggregation.client_timestamp_interval()),
                    /* checksum */ &batch_aggregation.checksum().get_encoded(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        let row_count = rows.len().try_into()?;

        if let Some(row) = rows.into_iter().next() {
            // We got a row back, meaning we wrote an outstanding batch. We check that it wasn't
            // expired per the task's report_expiry_age, but otherwise we are done.
            if row.get("is_expired") {
                let stmt = self
                    .prepare_cached(
                        "DELETE FROM batch_aggregations
                        USING tasks
                        WHERE batch_aggregations.task_id = tasks.id
                          AND tasks.task_id = $1
                          AND batch_aggregations.batch_identifier = $2
                          AND batch_aggregations.aggregation_param = $3",
                    )
                    .await?;
                self.execute(
                    &stmt,
                    &[
                        /* task_id */ &batch_aggregation.task_id().as_ref(),
                        /* batch_identifier */
                        &batch_aggregation.batch_identifier().get_encoded(),
                        /* aggregation_param */
                        &batch_aggregation.aggregation_parameter().get_encoded(),
                    ],
                )
                .await?;
                return Ok(());
            }
        }

        check_insert(row_count)
    }

    /// Update an existing `batch_aggregations` row with the values from the provided batch
    /// aggregation.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_batch_aggregation<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        batch_aggregation: &BatchAggregation<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: Debug,
        A::AggregateShare: Debug,
    {
        let stmt = self
            .prepare_cached(
                "UPDATE batch_aggregations
                SET
                    state = $1,
                    aggregate_share = $2,
                    report_count = $3,
                    client_timestamp_interval = $4,
                    checksum = $5
                FROM tasks, batches
                WHERE tasks.id = batch_aggregations.task_id
                  AND batches.task_id = batch_aggregations.task_id
                  AND batches.batch_identifier = batch_aggregations.batch_identifier
                  AND batches.aggregation_param = batch_aggregations.aggregation_param
                  AND tasks.task_id = $6
                  AND batch_aggregations.batch_identifier = $7
                  AND batch_aggregations.aggregation_param = $8
                  AND ord = $9
                  AND UPPER(batches.client_timestamp_interval) >= COALESCE($10::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */ &batch_aggregation.state(),
                    /* aggregate_share */
                    &batch_aggregation.aggregate_share().map(Into::into),
                    /* report_count */ &i64::try_from(batch_aggregation.report_count())?,
                    /* client_timestamp_interval */
                    &SqlInterval::from(batch_aggregation.client_timestamp_interval()),
                    /* checksum */ &batch_aggregation.checksum().get_encoded(),
                    /* task_id */ &batch_aggregation.task_id().as_ref(),
                    /* batch_identifier */
                    &batch_aggregation.batch_identifier().get_encoded(),
                    /* aggregation_param */
                    &batch_aggregation.aggregation_parameter().get_encoded(),
                    /* ord */ &TryInto::<i64>::try_into(batch_aggregation.ord())?,
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )?;

        Ok(())
    }

    /// Fetch an [`AggregateShareJob`] from the datastore corresponding to given parameters, or
    /// `None` if no such job exists.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregate_share_job<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Option<AggregateShareJob<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let stmt = self
            .prepare_cached(
                "SELECT helper_aggregate_share, report_count, checksum
                FROM aggregate_share_jobs
                JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND batch_identifier = $2
                  AND aggregation_param = $3
                  AND COALESCE(LOWER(aggregate_share_jobs.batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = aggregate_share_jobs.task_id AND batches.batch_identifier = aggregate_share_jobs.batch_identifier AND batches.aggregation_param = aggregate_share_jobs.aggregation_param))) >= COALESCE($4::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
                /* aggregation_param */ &aggregation_parameter.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| {
            Self::aggregate_share_job_from_row(
                task_id,
                batch_identifier.clone(),
                aggregation_parameter.clone(),
                &row,
            )
        })
        .transpose()
    }

    /// Returns all aggregate share jobs for the given task which include the given timestamp.
    /// Applies only to time-interval tasks.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregate_share_jobs_including_time<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        timestamp: &Time,
    ) -> Result<Vec<AggregateShareJob<SEED_SIZE, TimeInterval, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_identifier,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs
                JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval @> $2::TIMESTAMP
                  AND LOWER(aggregate_share_jobs.batch_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* timestamp */ &timestamp.as_naive_date_time()?,
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::aggregate_share_job_from_row(task_id, batch_identifier, aggregation_param, &row)
        })
        .collect()
    }

    /// Returns all aggregate share jobs for the given task whose collect intervals intersect with
    /// the given interval. Applies only to time-interval tasks.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregate_share_jobs_intersecting_interval<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        interval: &Interval,
    ) -> Result<Vec<AggregateShareJob<SEED_SIZE, TimeInterval, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_identifier,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs
                JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval && $2
                  AND LOWER(aggregate_share_jobs.batch_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* interval */ &SqlInterval::from(interval),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Interval::get_decoded(row.get("batch_identifier"))?;
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::aggregate_share_job_from_row(task_id, batch_identifier, aggregation_param, &row)
        })
        .collect()
    }

    /// Returns all aggregate share jobs for the given task with the given batch identifier.
    /// Multiple aggregate share jobs may be returned with distinct aggregation parameters.
    /// Applies only to fixed-size tasks.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregate_share_jobs_by_batch_id<
        const SEED_SIZE: usize,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<Vec<AggregateShareJob<SEED_SIZE, FixedSize, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_identifier = $2
                  AND UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = aggregate_share_jobs.task_id AND batches.batch_identifier = aggregate_share_jobs.batch_identifier AND batches.aggregation_param = aggregate_share_jobs.aggregation_param)) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* batch_id */ &batch_id.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::aggregate_share_job_from_row(task_id, *batch_id, aggregation_param, &row)
        })
        .collect()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_aggregate_share_jobs_for_task<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<AggregateShareJob<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_identifier,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs
                JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND COALESCE(LOWER(aggregate_share_jobs.batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = aggregate_share_jobs.task_id AND batches.batch_identifier = aggregate_share_jobs.batch_identifier AND batches.aggregation_param = aggregate_share_jobs.aggregation_param))) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ &task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
            let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::aggregate_share_job_from_row(task_id, batch_identifier, aggregation_param, &row)
        })
        .collect()
    }

    fn aggregate_share_job_from_row<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        task_id: &TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_param: A::AggregationParam,
        row: &Row,
    ) -> Result<AggregateShareJob<SEED_SIZE, Q, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let helper_aggregate_share =
            A::AggregateShare::try_from(&row.get::<_, Vec<u8>>("helper_aggregate_share")).map_err(
                |err| Error::DbState(format!("could not parse leader_aggregate_share: {:?}", err)),
            )?;
        Ok(AggregateShareJob::new(
            *task_id,
            batch_identifier,
            aggregation_param,
            helper_aggregate_share,
            row.get_bigint_and_convert("report_count")?,
            ReportIdChecksum::get_decoded(row.get("checksum"))?,
        ))
    }

    /// Put an `aggregate_share_job` row into the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregate_share_job<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        aggregate_share_job: &AggregateShareJob<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let batch_interval =
            Q::to_batch_interval(aggregate_share_job.batch_identifier()).map(SqlInterval::from);

        let stmt = self
            .prepare_cached(
                "INSERT INTO aggregate_share_jobs (
                    task_id, batch_identifier, batch_interval, aggregation_param,
                    helper_aggregate_share, report_count, checksum
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
                RETURNING COALESCE(COALESCE(LOWER(batch_interval), UPPER((SELECT client_timestamp_interval FROM batches WHERE batches.task_id = aggregate_share_jobs.task_id AND batches.batch_identifier = aggregate_share_jobs.batch_identifier AND batches.aggregation_param = aggregate_share_jobs.aggregation_param))) < COALESCE($8::TIMESTAMP - (SELECT report_expiry_age FROM tasks WHERE task_id = $1) * '1 second'::INTERVAL, '-infinity'::TIMESTAMP), FALSE) AS is_expired",
            )
            .await?;
        let rows = self
            .query(
                &stmt,
                &[
                    /* task_id */ &aggregate_share_job.task_id().as_ref(),
                    /* batch_identifier */
                    &aggregate_share_job.batch_identifier().get_encoded(),
                    /* batch_interval */ &batch_interval,
                    /* aggregation_param */
                    &aggregate_share_job.aggregation_parameter().get_encoded(),
                    /* helper_aggregate_share */
                    &aggregate_share_job.helper_aggregate_share().into(),
                    /* report_count */ &i64::try_from(aggregate_share_job.report_count())?,
                    /* checksum */ &aggregate_share_job.checksum().get_encoded(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        let row_count = rows.len().try_into()?;

        if let Some(row) = rows.into_iter().next() {
            // We got a row back, meaning we wrote a collection job. We check that it wasn't expired
            // per the task's report_expiry_age, but otherwise we are done.
            if row.get("is_expired") {
                let stmt = self
                    .prepare_cached(
                        "DELETE FROM aggregate_share_jobs
                        USING tasks
                        WHERE aggregate_share_jobs.task_id = tasks.id
                          AND tasks.task_id = $1
                          AND aggregate_share_jobs.batch_identifier = $2
                          AND aggregate_share_jobs.aggregation_param = $3",
                    )
                    .await?;
                self.execute(
                    &stmt,
                    &[
                        /* task_id */ aggregate_share_job.task_id().as_ref(),
                        /* batch_identifier */
                        &aggregate_share_job.batch_identifier().get_encoded(),
                        /* aggregation_param */
                        &aggregate_share_job.aggregation_parameter().get_encoded(),
                    ],
                )
                .await?;
                return Ok(());
            }
        }

        check_insert(row_count)
    }

    /// Writes an outstanding batch. (This method does not take an [`OutstandingBatch`] as several
    /// of the included values are read implicitly.)
    #[tracing::instrument(skip(self), err)]
    pub async fn put_outstanding_batch(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
        time_bucket_start: &Option<Time>,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "INSERT INTO outstanding_batches (task_id, batch_id, time_bucket_start)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3)
                ON CONFLICT DO NOTHING
                RETURNING COALESCE(UPPER((SELECT client_timestamp_interval FROM batches WHERE task_id = outstanding_batches.task_id AND batch_identifier = outstanding_batches.batch_id)) < COALESCE($4::TIMESTAMP - (SELECT report_expiry_age FROM tasks WHERE task_id = $1) * '1 second'::INTERVAL, '-infinity'::TIMESTAMP), FALSE) AS is_expired",
            )
            .await?;
        let rows = self
            .query(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_id */ batch_id.as_ref(),
                    /* time_bucket_start */
                    &time_bucket_start
                        .as_ref()
                        .map(Time::as_naive_date_time)
                        .transpose()?,
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        let row_count = rows.len().try_into()?;

        if let Some(row) = rows.into_iter().next() {
            // We got a row back, meaning we wrote an outstanding batch. We check that it wasn't
            // expired per the task's report_expiry_age, but otherwise we are done.
            if row.get("is_expired") {
                let stmt = self
                    .prepare_cached(
                        "DELETE FROM outstanding_batches
                        USING tasks
                        WHERE outstanding_batches.task_id = tasks.id
                          AND tasks.task_id = $1
                          AND outstanding_batches.batch_id = $2",
                    )
                    .await?;
                self.execute(
                    &stmt,
                    &[
                        /* task_id */ task_id.as_ref(),
                        /* batch_id */ batch_id.as_ref(),
                    ],
                )
                .await?;
                return Ok(());
            }
        }

        check_insert(row_count)
    }

    /// Retrieves all [`OutstandingBatch`]es for a given task and time bucket, if applicable.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_outstanding_batches(
        &self,
        task_id: &TaskId,
        time_bucket_start: &Option<Time>,
    ) -> Result<Vec<OutstandingBatch>, Error> {
        let rows = if let Some(time_bucket_start) = time_bucket_start {
            let stmt = self
                .prepare_cached(
                    "SELECT batch_id FROM outstanding_batches
                    JOIN tasks ON tasks.id = outstanding_batches.task_id
                    JOIN batches ON batches.task_id = outstanding_batches.task_id
                                AND batches.batch_identifier = outstanding_batches.batch_id
                    WHERE tasks.task_id = $1
                    AND time_bucket_start = $2
                    AND UPPER(batches.client_timestamp_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
                )
                .await?;
            self.query(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* time_bucket_start */ &time_bucket_start.as_naive_date_time()?,
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?
        } else {
            let stmt = self
                .prepare_cached(
                    "SELECT batch_id FROM outstanding_batches
                    JOIN tasks ON tasks.id = outstanding_batches.task_id
                    JOIN batches ON batches.task_id = outstanding_batches.task_id
                                AND batches.batch_identifier = outstanding_batches.batch_id
                    WHERE tasks.task_id = $1
                    AND time_bucket_start IS NULL
                    AND UPPER(batches.client_timestamp_interval) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
                )
                .await?;
            self.query(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?
        };

        try_join_all(rows.into_iter().map(|row| async move {
            let batch_id = BatchId::get_decoded(row.get("batch_id"))?;
            let size = self.read_batch_size(task_id, &batch_id).await?;
            Ok(OutstandingBatch::new(*task_id, batch_id, size))
        }))
        .await
    }

    // Return value is an inclusive range [min_size, max_size], where:
    //  * min_size is the minimum possible number of reports included in the batch, i.e. all report
    //    aggregations in the batch which have reached the FINISHED state.
    //  * max_size is the maximum possible number of reports included in the batch, i.e. all report
    //    aggregations in the batch which are in a non-failure state (START/WAITING/FINISHED).
    async fn read_batch_size(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<RangeInclusive<usize>, Error> {
        // TODO(#1467): fix this to work in presence of GC.
        let stmt = self
            .prepare_cached(
                "WITH batch_report_aggregation_statuses AS
                    (SELECT report_aggregations.state, COUNT(*) AS count FROM report_aggregations
                     JOIN aggregation_jobs
                        ON report_aggregations.aggregation_job_id = aggregation_jobs.id
                     WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                     AND aggregation_jobs.batch_id = $2
                     GROUP BY report_aggregations.state)
                SELECT
                    (SELECT SUM(count)::BIGINT FROM batch_report_aggregation_statuses
                     WHERE state IN ('FINISHED')) AS min_size,
                    (SELECT SUM(count)::BIGINT FROM batch_report_aggregation_statuses
                     WHERE state IN ('START', 'WAITING', 'FINISHED')) AS max_size",
            )
            .await?;

        let row = self
            .query_one(
                &stmt,
                &[
                    /* task_id */ task_id.as_ref(),
                    /* batch_id */ batch_id.as_ref(),
                ],
            )
            .await?;

        Ok(RangeInclusive::new(
            row.get::<_, Option<i64>>("min_size")
                .unwrap_or_default()
                .try_into()?,
            row.get::<_, Option<i64>>("max_size")
                .unwrap_or_default()
                .try_into()?,
        ))
    }

    /// Deletes an outstanding batch.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_outstanding_batch(
        &self,
        task_id: &TaskId,
        batch_id: &BatchId,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "DELETE FROM outstanding_batches
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                  AND batch_id = $2",
            )
            .await?;

        self.execute(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_id */ batch_id.as_ref(),
            ],
        )
        .await?;
        Ok(())
    }

    /// Retrieves an outstanding batch for the given task with at least the given number of
    /// successfully-aggregated reports.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_filled_outstanding_batch(
        &self,
        task_id: &TaskId,
        min_report_count: u64,
    ) -> Result<Option<BatchId>, Error> {
        // TODO(#1467): fix this to work in presence of GC.
        let stmt = self
            .prepare_cached(
                "WITH batches AS (
                    SELECT
                        outstanding_batches.batch_id AS batch_id,
                        SUM(batch_aggregations.report_count) AS count
                    FROM outstanding_batches
                    JOIN tasks ON tasks.id = outstanding_batches.task_id
                    JOIN batch_aggregations
                      ON batch_aggregations.task_id = outstanding_batches.task_id
                     AND batch_aggregations.batch_identifier = outstanding_batches.batch_id
                    JOIN batches
                      ON batches.task_id = outstanding_batches.task_id
                     AND batches.batch_identifier = outstanding_batches.batch_id
                    WHERE tasks.task_id = $1
                      AND UPPER(batches.client_timestamp_interval) >= COALESCE($3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    GROUP BY outstanding_batches.batch_id
                )
                SELECT batch_id FROM batches WHERE count >= $2::BIGINT LIMIT 1",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* min_report_count */ &i64::try_from(min_report_count)?,
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| Ok(BatchId::get_decoded(row.get("batch_id"))?))
        .transpose()
    }

    /// Puts a `batch` into the datastore. Returns `MutationTargetAlreadyExists` if the batch is
    /// already stored.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_batch<
        const SEED_SIZE: usize,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        batch: &Batch<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "INSERT INTO batches
                    (task_id, batch_identifier, batch_interval, aggregation_param, state,
                    outstanding_aggregation_jobs, client_timestamp_interval)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
                RETURNING COALESCE(UPPER(COALESCE(batch_interval, client_timestamp_interval)) < COALESCE($8::TIMESTAMP - (SELECT report_expiry_age FROM tasks WHERE task_id = $1) * '1 second'::INTERVAL, '-infinity'::TIMESTAMP), FALSE) AS is_expired",
            )
            .await?;
        let rows = self
            .query(
                &stmt,
                &[
                    /* task_id */ &batch.task_id().as_ref(),
                    /* batch_identifier */ &batch.batch_identifier().get_encoded(),
                    /* batch_interval */
                    &Q::to_batch_interval(batch.batch_identifier()).map(SqlInterval::from),
                    /* aggregation_param */ &batch.aggregation_parameter().get_encoded(),
                    /* state */ &batch.state(),
                    /* outstanding_aggregation_jobs */
                    &i64::try_from(batch.outstanding_aggregation_jobs())?,
                    /* client_timestamp_interval */
                    &SqlInterval::from(batch.client_timestamp_interval()),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?;
        let row_count = rows.len().try_into()?;

        if let Some(row) = rows.into_iter().next() {
            // We got a row back, meaning we wrote a batch. We check that it wasn't expired per the
            // task's report_expiry_age, but otherwise we are done.
            if row.get("is_expired") {
                let stmt = self
                    .prepare_cached(
                        "DELETE FROM batches
                        USING tasks
                        WHERE batches.task_id = tasks.id
                          AND tasks.task_id = $1
                          AND batches.batch_identifier = $2
                          AND batches.aggregation_param = $3",
                    )
                    .await?;
                self.execute(
                    &stmt,
                    &[
                        /* task_id */ &batch.task_id().as_ref(),
                        /* batch_identifier */ &batch.batch_identifier().get_encoded(),
                        /* aggregation_param */ &batch.aggregation_parameter().get_encoded(),
                    ],
                )
                .await?;
                return Ok(());
            }
        }

        check_insert(row_count)
    }

    /// Updates a given `batch` in the datastore. Returns `MutationTargetNotFound` if no such batch
    /// is currently stored.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_batch<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        batch: &Batch<SEED_SIZE, Q, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "UPDATE batches
                SET state = $1, outstanding_aggregation_jobs = $2, client_timestamp_interval = $3
                FROM tasks
                WHERE batches.task_id = tasks.id
                  AND tasks.task_id = $4
                  AND batch_identifier = $5
                  AND aggregation_param = $6
                  AND UPPER(COALESCE(batch_interval, client_timestamp_interval)) >= COALESCE($7::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */ &batch.state(),
                    /* outstanding_aggregation_jobs */
                    &i64::try_from(batch.outstanding_aggregation_jobs())?,
                    /* client_timestamp_interval */
                    &SqlInterval::from(batch.client_timestamp_interval()),
                    /* task_id */ &batch.task_id().as_ref(),
                    /* batch_identifier */ &batch.batch_identifier().get_encoded(),
                    /* aggregation_param */ &batch.aggregation_parameter().get_encoded(),
                    /* now */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )
    }

    /// Gets a given `batch` from the datastore, based on the primary key. Returns `None` if no such
    /// batch is stored in the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_batch<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>(
        &self,
        task_id: &TaskId,
        batch_identifier: &Q::BatchIdentifier,
        aggregation_parameter: &A::AggregationParam,
    ) -> Result<Option<Batch<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT state, outstanding_aggregation_jobs, client_timestamp_interval FROM batches
                JOIN tasks ON tasks.id = batches.task_id
                WHERE tasks.task_id = $1
                  AND batch_identifier = $2
                  AND aggregation_param = $3
                  AND UPPER(COALESCE(batch_interval, client_timestamp_interval)) >= COALESCE($4::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query_opt(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* batch_identifier */ &batch_identifier.get_encoded(),
                /* aggregation_param */ &aggregation_parameter.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .map(|row| {
            Self::batch_from_row(
                *task_id,
                batch_identifier.clone(),
                aggregation_parameter.clone(),
                row,
            )
        })
        .transpose()
    }

    #[cfg(feature = "test-util")]
    pub async fn get_batches_for_task<
        const SEED_SIZE: usize,
        Q: QueryType,
        A: vdaf::Aggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<Batch<SEED_SIZE, Q, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .prepare_cached(
                "SELECT
                    batch_identifier, aggregation_param, state, outstanding_aggregation_jobs,
                    client_timestamp_interval
                FROM batches
                JOIN tasks ON tasks.id = batches.task_id
                WHERE tasks.task_id = $1
                  AND UPPER(COALESCE(batch_interval, client_timestamp_interval)) >= COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)",
            )
            .await?;
        self.query(
            &stmt,
            &[
                /* task_id */ task_id.as_ref(),
                /* now */ &self.clock.now().as_naive_date_time()?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            let batch_identifier = Q::BatchIdentifier::get_decoded(row.get("batch_identifier"))?;
            let aggregation_parameter =
                A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
            Self::batch_from_row(*task_id, batch_identifier, aggregation_parameter, row)
        })
        .collect()
    }

    fn batch_from_row<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_parameter: A::AggregationParam,
        row: Row,
    ) -> Result<Batch<SEED_SIZE, Q, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let state = row.get("state");
        let outstanding_aggregation_jobs = row
            .get::<_, i64>("outstanding_aggregation_jobs")
            .try_into()?;
        let client_timestamp_interval = row
            .get::<_, SqlInterval>("client_timestamp_interval")
            .as_interval();
        Ok(Batch::new(
            task_id,
            batch_identifier,
            aggregation_parameter,
            state,
            outstanding_aggregation_jobs,
            client_timestamp_interval,
        ))
    }

    /// Deletes old client reports for a given task, that is, client reports whose timestamp is
    /// older than the task's report expiry age. Up to `limit` client reports will be deleted.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_expired_client_reports(
        &self,
        task_id: &TaskId,
        limit: u64,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "WITH client_reports_to_delete AS (
                    SELECT client_reports.id FROM client_reports
                    JOIN tasks ON tasks.id = client_reports.task_id
                    WHERE tasks.task_id = $1
                      AND client_reports.client_timestamp < COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    LIMIT $3
                )
                DELETE FROM client_reports
                USING client_reports_to_delete
                WHERE client_reports.id = client_reports_to_delete.id",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &task_id.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
                /* limit */ &i64::try_from(limit)?,
            ],
        )
        .await?;
        Ok(())
    }

    /// Deletes old aggregation artifacts (aggregation jobs/report aggregations) for a given task,
    /// that is, aggregation artifacts for which the aggregation job's maximum client timestamp is
    /// older than the task's report expiry age. Up to `limit` aggregation jobs will be deleted,
    /// along with all related aggregation artifacts.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_expired_aggregation_artifacts(
        &self,
        task_id: &TaskId,
        limit: u64,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "WITH aggregation_jobs_to_delete AS (
                    SELECT aggregation_jobs.id FROM aggregation_jobs
                    JOIN tasks ON tasks.id = aggregation_jobs.task_id
                    WHERE tasks.task_id = $1
                      AND UPPER(aggregation_jobs.client_timestamp_interval) < COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    LIMIT $3
                ),
                deleted_report_aggregations AS (
                    DELETE FROM report_aggregations
                    WHERE aggregation_job_id IN (SELECT id FROM aggregation_jobs_to_delete)
                )
                DELETE FROM aggregation_jobs
                WHERE id IN (SELECT id FROM aggregation_jobs_to_delete)",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &task_id.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
                /* limit */ &i64::try_from(limit)?,
            ],
        )
        .await?;
        Ok(())
    }

    /// Deletes old collection artifacts (batches/outstanding batches/batch aggregations/collection
    /// jobs/aggregate share jobs) for a given task per the following policy:
    ///
    /// * batches, batch_aggregations, and outstanding_batches will be considered part of the same
    ///   entity for purposes of GC, and will be considered eligible for GC once the maximum of the
    ///   batch interval (for time-interval) or client_timestamp_interval (for fixed-size) of the
    ///   batches row is older than report_expiry_age.
    /// * collection_jobs and aggregate_share_jobs use the same rule to determine GC-eligiblity, but
    ///   this rule is query type-specific.
    ///   * For time-interval tasks, collection_jobs and aggregate_share_jobs are considered
    ///     eligible for GC if the minimum of the collection interval is older than
    ///     report_expiry_age. (The minimum is used instead of the maximum to ensure that collection
    ///     jobs are not GC'ed after their underlying aggregation information from
    ///     batch_aggregations.)
    ///   * For fixed-size tasks, collection_jobs and aggregate_share_jobs are considered eligible
    ///     for GC if the related batch is eligible for GC.
    ///
    /// Up to `limit` batches will be deleted, along with all related collection artifacts.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_expired_collection_artifacts(
        &self,
        task_id: &TaskId,
        limit: u64,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "WITH batches_to_delete AS (
                    SELECT batches.task_id, batch_identifier, aggregation_param
                    FROM batches
                    JOIN tasks ON tasks.id = batches.task_id
                    WHERE tasks.task_id = $1
                      AND UPPER(COALESCE(batch_interval, client_timestamp_interval)) < COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                    LIMIT $3
                ),
                deleted_batch_aggregations AS (
                    DELETE FROM batch_aggregations
                    USING batches_to_delete
                    WHERE batch_aggregations.task_id = batches_to_delete.task_id
                      AND batch_aggregations.batch_identifier = batches_to_delete.batch_identifier
                      AND batch_aggregations.aggregation_param = batches_to_delete.aggregation_param
                ),
                deleted_outstanding_batches AS (
                    DELETE FROM outstanding_batches
                    USING batches_to_delete
                    WHERE outstanding_batches.task_id = batches_to_delete.task_id
                      AND outstanding_batches.batch_id = batches_to_delete.batch_identifier
                ),
                deleted_collection_jobs AS (
                    DELETE FROM collection_jobs
                    USING batches_to_delete, tasks
                    WHERE tasks.id = collection_jobs.task_id
                      AND tasks.task_id = $1
                      AND (LOWER(batch_interval) < COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                        OR (collection_jobs.task_id = batches_to_delete.task_id AND collection_jobs.batch_identifier = batches_to_delete.batch_identifier AND collection_jobs.aggregation_param = batches_to_delete.aggregation_param))
                ),
                deleted_aggregate_share_jobs AS (
                    DELETE FROM aggregate_share_jobs
                    USING batches_to_delete,tasks
                    WHERE tasks.id = aggregate_share_jobs.task_id
                      AND tasks.task_id = $1
                      AND (LOWER(batch_interval) < COALESCE($2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL, '-infinity'::TIMESTAMP)
                        OR (aggregate_share_jobs.task_id = batches_to_delete.task_id AND aggregate_share_jobs.batch_identifier = batches_to_delete.batch_identifier AND aggregate_share_jobs.aggregation_param = batches_to_delete.aggregation_param))
                )
                DELETE FROM batches
                USING batches_to_delete
                WHERE batches.task_id = batches_to_delete.task_id
                  AND batches.batch_identifier = batches_to_delete.batch_identifier
                  AND batches.aggregation_param = batches_to_delete.aggregation_param",
            )
            .await?;
        self.execute(
            &stmt,
            &[
                /* task_id */ &task_id.get_encoded(),
                /* now */ &self.clock.now().as_naive_date_time()?,
                /* limit */ &i64::try_from(limit)?,
            ],
        )
        .await?;
        Ok(())
    }

    /// Retrieve all global HPKE keypairs.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_global_hpke_keypairs(&self) -> Result<Vec<GlobalHpkeKeypair>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT config_id, config, private_key, state, updated_at FROM global_hpke_keys;",
            )
            .await?;
        let hpke_key_rows = self.query(&stmt, &[]).await?;

        hpke_key_rows
            .iter()
            .map(|row| self.global_hpke_keypair_from_row(row))
            .collect()
    }

    /// Retrieve a global HPKE keypair by config ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_global_hpke_keypair(
        &self,
        config_id: &HpkeConfigId,
    ) -> Result<Option<GlobalHpkeKeypair>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT config_id, config, private_key, state, updated_at FROM global_hpke_keys
                    WHERE config_id = $1;",
            )
            .await?;
        self.query_opt(&stmt, &[&(u8::from(*config_id) as i16)])
            .await?
            .map(|row| self.global_hpke_keypair_from_row(&row))
            .transpose()
    }

    fn global_hpke_keypair_from_row(&self, row: &Row) -> Result<GlobalHpkeKeypair, Error> {
        let config = HpkeConfig::get_decoded(row.get("config"))?;
        let config_id = u8::try_from(row.get::<_, i16>("config_id"))?;

        let encrypted_private_key: Vec<u8> = row.get("private_key");
        let private_key = HpkePrivateKey::new(self.crypter.decrypt(
            "global_hpke_keys",
            &config_id.to_be_bytes(),
            "private_key",
            &encrypted_private_key,
        )?);
        Ok(GlobalHpkeKeypair::new(
            HpkeKeypair::new(config, private_key),
            row.get("state"),
            Time::from_naive_date_time(&row.get("updated_at")),
        ))
    }

    /// Unconditionally and fully drop a keypair. This is a dangerous operation,
    /// since report shares encrypted with this key will no longer be decryptable.
    #[tracing::instrument(skip(self), err)]
    pub async fn delete_global_hpke_keypair(&self, config_id: &HpkeConfigId) -> Result<(), Error> {
        let stmt = self
            .prepare_cached("DELETE FROM global_hpke_keys WHERE config_id = $1;")
            .await?;
        check_single_row_mutation(
            self.execute(&stmt, &[&(u8::from(*config_id) as i16)])
                .await?,
        )
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn set_global_hpke_keypair_state(
        &self,
        config_id: &HpkeConfigId,
        state: &HpkeKeyState,
    ) -> Result<(), Error> {
        let stmt = self
            .prepare_cached(
                "UPDATE global_hpke_keys SET state = $1, updated_at = $2 WHERE config_id = $3;",
            )
            .await?;
        check_single_row_mutation(
            self.execute(
                &stmt,
                &[
                    /* state */ state,
                    /* updated_at */ &self.clock.now().as_naive_date_time()?,
                    /* config_id */ &(u8::from(*config_id) as i16),
                ],
            )
            .await?,
        )
    }

    // Inserts a new global HPKE keypair and places it in the [`HpkeKeyState::Pending`] state.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_global_hpke_keypair(&self, hpke_keypair: &HpkeKeypair) -> Result<(), Error> {
        let hpke_config_id = u8::from(*hpke_keypair.config().id()) as i16;
        let hpke_config = hpke_keypair.config().get_encoded();
        let encrypted_hpke_private_key = self.crypter.encrypt(
            "global_hpke_keys",
            &u8::from(*hpke_keypair.config().id()).to_be_bytes(),
            "private_key",
            hpke_keypair.private_key().as_ref(),
        )?;

        let stmt = self
            .prepare_cached(
                "INSERT INTO global_hpke_keys (config_id, config, private_key, updated_at)
                    VALUES ($1, $2, $3, $4);",
            )
            .await?;
        check_insert(
            self.execute(
                &stmt,
                &[
                    /* config_id */ &hpke_config_id,
                    /* config */ &hpke_config,
                    /* private_key */ &encrypted_hpke_private_key,
                    /* updated_at */ &self.clock.now().as_naive_date_time()?,
                ],
            )
            .await?,
        )
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn get_taskprov_peer_aggregators(&self) -> Result<Vec<PeerAggregator>, Error> {
        let stmt = self
            .prepare_cached(
                "SELECT id, endpoint, role, verify_key_init, collector_hpke_config,
                        report_expiry_age, tolerable_clock_skew
                    FROM taskprov_peer_aggregators",
            )
            .await?;
        let peer_aggregator_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT p.id FROM taskprov_peer_aggregators AS p 
                    WHERE p.id = a.peer_aggregator_id) AS peer_id,
                ord, type, token FROM taskprov_aggregator_auth_tokens AS a
                    ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.query(&stmt, &[]);

        let stmt = self
            .prepare_cached(
                "SELECT (SELECT p.id FROM taskprov_peer_aggregators AS p 
                    WHERE p.id = a.peer_aggregator_id) AS peer_id,
                ord, type, token FROM taskprov_collector_auth_tokens AS a
                    ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.query(&stmt, &[]);

        let (peer_aggregator_rows, aggregator_auth_token_rows, collector_auth_token_rows) = try_join!(
            peer_aggregator_rows,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
        )?;

        let mut aggregator_auth_token_rows_by_peer_id: HashMap<i64, Vec<Row>> = HashMap::new();
        for row in aggregator_auth_token_rows {
            aggregator_auth_token_rows_by_peer_id
                .entry(row.get("peer_id"))
                .or_default()
                .push(row);
        }

        let mut collector_auth_token_rows_by_peer_id: HashMap<i64, Vec<Row>> = HashMap::new();
        for row in collector_auth_token_rows {
            collector_auth_token_rows_by_peer_id
                .entry(row.get("peer_id"))
                .or_default()
                .push(row);
        }

        peer_aggregator_rows
            .into_iter()
            .map(|row| (row.get("id"), row))
            .map(|(peer_id, peer_aggregator_row)| {
                self.taskprov_peer_aggregator_from_rows(
                    &peer_aggregator_row,
                    &aggregator_auth_token_rows_by_peer_id
                        .remove(&peer_id)
                        .unwrap_or_default(),
                    &collector_auth_token_rows_by_peer_id
                        .remove(&peer_id)
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn get_taskprov_peer_aggregator(
        &self,
        aggregator_url: &Url,
        role: &Role,
    ) -> Result<Option<PeerAggregator>, Error> {
        let aggregator_url = aggregator_url.as_str();
        let role = AggregatorRole::from_role(*role)?;
        let params: &[&(dyn ToSql + Sync)] = &[&aggregator_url, &role];

        let stmt = self
            .prepare_cached(
                "SELECT id, endpoint, role, verify_key_init, collector_hpke_config,
                        report_expiry_age, tolerable_clock_skew
                    FROM taskprov_peer_aggregators WHERE endpoint = $1 AND role = $2",
            )
            .await?;
        let peer_aggregator_row = self.query_opt(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT ord, type, token FROM taskprov_aggregator_auth_tokens
                    WHERE peer_aggregator_id = (SELECT id FROM taskprov_peer_aggregators
                        WHERE endpoint = $1 AND role = $2)
                    ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.query(&stmt, params);

        let stmt = self
            .prepare_cached(
                "SELECT ord, type, token FROM taskprov_collector_auth_tokens
                    WHERE peer_aggregator_id = (SELECT id FROM taskprov_peer_aggregators
                        WHERE endpoint = $1 AND role = $2)
                    ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.query(&stmt, params);

        let (peer_aggregator_row, aggregator_auth_token_rows, collector_auth_token_rows) = try_join!(
            peer_aggregator_row,
            aggregator_auth_token_rows,
            collector_auth_token_rows,
        )?;
        peer_aggregator_row
            .map(|peer_aggregator_row| {
                self.taskprov_peer_aggregator_from_rows(
                    &peer_aggregator_row,
                    &aggregator_auth_token_rows,
                    &collector_auth_token_rows,
                )
            })
            .transpose()
    }

    fn taskprov_peer_aggregator_from_rows(
        &self,
        peer_aggregator_row: &Row,
        aggregator_auth_token_rows: &[Row],
        collector_auth_token_rows: &[Row],
    ) -> Result<PeerAggregator, Error> {
        let endpoint = Url::parse(peer_aggregator_row.get::<_, &str>("endpoint"))?;
        let endpoint_bytes = endpoint.as_str().as_ref();
        let role: AggregatorRole = peer_aggregator_row.get("role");
        let report_expiry_age = peer_aggregator_row
            .get_nullable_bigint_and_convert("report_expiry_age")?
            .map(Duration::from_seconds);
        let tolerable_clock_skew = Duration::from_seconds(
            peer_aggregator_row.get_bigint_and_convert("tolerable_clock_skew")?,
        );
        let collector_hpke_config =
            HpkeConfig::get_decoded(peer_aggregator_row.get("collector_hpke_config"))?;

        let encrypted_verify_key_init: Vec<u8> = peer_aggregator_row.get("verify_key_init");
        let verify_key_init = self
            .crypter
            .decrypt(
                "taskprov_peer_aggregator",
                endpoint_bytes,
                "verify_key_init",
                &encrypted_verify_key_init,
            )?
            .as_slice()
            .try_into()?;

        let decrypt_tokens = |rows: &[Row], table| -> Result<Vec<_>, Error> {
            rows.iter()
                .map(|row| {
                    let ord: i64 = row.get("ord");
                    let auth_token_type: AuthenticationTokenType = row.get("type");
                    let encrypted_token: Vec<u8> = row.get("token");

                    let mut row_id = Vec::new();
                    row_id.extend_from_slice(endpoint_bytes);
                    row_id.extend_from_slice(&role.as_role().get_encoded());
                    row_id.extend_from_slice(&ord.to_be_bytes());

                    auth_token_type.as_authentication(&self.crypter.decrypt(
                        table,
                        &row_id,
                        "token",
                        &encrypted_token,
                    )?)
                })
                .collect()
        };

        let aggregator_auth_tokens = decrypt_tokens(
            aggregator_auth_token_rows,
            "taskprov_aggregator_auth_tokens",
        )?;
        let collector_auth_tokens =
            decrypt_tokens(collector_auth_token_rows, "taskprov_collector_auth_tokens")?;

        Ok(PeerAggregator::new(
            endpoint,
            role.as_role(),
            verify_key_init,
            collector_hpke_config,
            report_expiry_age,
            tolerable_clock_skew,
            aggregator_auth_tokens,
            collector_auth_tokens,
        ))
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn put_taskprov_peer_aggregator(
        &self,
        peer_aggregator: &PeerAggregator,
    ) -> Result<(), Error> {
        let endpoint = peer_aggregator.endpoint().as_str();
        let role = &AggregatorRole::from_role(*peer_aggregator.role())?;
        let encrypted_verify_key_init = self.crypter.encrypt(
            "taskprov_peer_aggregator",
            endpoint.as_ref(),
            "verify_key_init",
            peer_aggregator.verify_key_init().as_ref(),
        )?;

        let stmt = self
            .prepare_cached(
                "INSERT INTO taskprov_peer_aggregators (
                    endpoint, role, verify_key_init, tolerable_clock_skew, report_expiry_age,
                    collector_hpke_config
                ) VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT DO NOTHING",
            )
            .await?;
        check_insert(
            self.execute(
                &stmt,
                &[
                    /* endpoint */ &endpoint,
                    /* role */ role,
                    /* verify_key_init */ &encrypted_verify_key_init,
                    /* tolerable_clock_skew */
                    &i64::try_from(peer_aggregator.tolerable_clock_skew().as_seconds())?,
                    /* report_expiry_age */
                    &peer_aggregator
                        .report_expiry_age()
                        .map(Duration::as_seconds)
                        .map(i64::try_from)
                        .transpose()?,
                    /* collector_hpke_config */
                    &peer_aggregator.collector_hpke_config().get_encoded(),
                ],
            )
            .await?,
        )?;

        let encrypt_tokens = |tokens: &[AuthenticationToken], table| -> Result<_, Error> {
            let mut ords = Vec::new();
            let mut types = Vec::new();
            let mut encrypted_tokens = Vec::new();
            for (ord, token) in tokens.iter().enumerate() {
                let ord = i64::try_from(ord)?;

                let mut row_id = Vec::new();
                row_id.extend_from_slice(endpoint.as_ref());
                row_id.extend_from_slice(&role.as_role().get_encoded());
                row_id.extend_from_slice(&ord.to_be_bytes());

                let encrypted_auth_token =
                    self.crypter
                        .encrypt(table, &row_id, "token", token.as_ref())?;

                ords.push(ord);
                types.push(AuthenticationTokenType::from(token));
                encrypted_tokens.push(encrypted_auth_token);
            }
            Ok((ords, types, encrypted_tokens))
        };

        let (aggregator_auth_token_ords, aggregator_auth_token_types, aggregator_auth_tokens) =
            encrypt_tokens(
                peer_aggregator.aggregator_auth_tokens(),
                "taskprov_aggregator_auth_tokens",
            )?;
        let stmt = self
            .prepare_cached(
                "INSERT INTO taskprov_aggregator_auth_tokens (peer_aggregator_id, ord, type, token)
                SELECT
                    (SELECT id FROM taskprov_peer_aggregators WHERE endpoint = $1 AND role = $2),
                    * FROM UNNEST($3::BIGINT[], $4::AUTH_TOKEN_TYPE[], $5::BYTEA[])",
            )
            .await?;
        let aggregator_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* endpoint */ &endpoint,
            /* role */ role,
            /* ords */ &aggregator_auth_token_ords,
            /* token_types */ &aggregator_auth_token_types,
            /* tokens */ &aggregator_auth_tokens,
        ];
        let aggregator_auth_tokens_future = self.execute(&stmt, aggregator_auth_tokens_params);

        let (collector_auth_token_ords, collector_auth_token_types, collector_auth_tokens) =
            encrypt_tokens(
                peer_aggregator.collector_auth_tokens(),
                "taskprov_collector_auth_tokens",
            )?;
        let stmt = self
            .prepare_cached(
                "INSERT INTO taskprov_collector_auth_tokens (peer_aggregator_id, ord, type, token)
                SELECT
                    (SELECT id FROM taskprov_peer_aggregators WHERE endpoint = $1 AND role = $2),
                    * FROM UNNEST($3::BIGINT[], $4::AUTH_TOKEN_TYPE[], $5::BYTEA[])",
            )
            .await?;
        let collector_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* endpoint */ &endpoint,
            /* role */ role,
            /* ords */ &collector_auth_token_ords,
            /* token_types */ &collector_auth_token_types,
            /* tokens */ &collector_auth_tokens,
        ];
        let collector_auth_tokens_future = self.execute(&stmt, collector_auth_tokens_params);

        try_join!(aggregator_auth_tokens_future, collector_auth_tokens_future)?;
        Ok(())
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn delete_taskprov_peer_aggregator(
        &self,
        aggregator_url: &Url,
        role: &Role,
    ) -> Result<(), Error> {
        let aggregator_url = aggregator_url.as_str();
        let role = AggregatorRole::from_role(*role)?;

        // Deletion of other data implemented via ON DELETE CASCADE.
        let stmt = self
            .prepare_cached(
                "DELETE FROM taskprov_peer_aggregators WHERE endpoint = $1 AND role = $2",
            )
            .await?;
        check_single_row_mutation(self.execute(&stmt, &[&aggregator_url, &role]).await?)
    }
}

fn check_insert(row_count: u64) -> Result<(), Error> {
    match row_count {
        0 => Err(Error::MutationTargetAlreadyExists),
        1 => Ok(()),
        _ => panic!(
            "insert which should have affected at most one row instead affected {row_count} rows"
        ),
    }
}

fn check_single_row_mutation(row_count: u64) -> Result<(), Error> {
    match row_count {
        0 => Err(Error::MutationTargetNotFound),
        1 => Ok(()),
        _ => panic!(
            "update which should have affected at most one row instead affected {row_count} rows"
        ),
    }
}

/// Add a [`std::time::Duration`] to a [`chrono::NaiveDateTime`].
fn add_naive_date_time_duration(
    time: &NaiveDateTime,
    duration: &StdDuration,
) -> Result<NaiveDateTime, Error> {
    time.checked_add_signed(
        chrono::Duration::from_std(*duration)
            .map_err(|_| Error::TimeOverflow("overflow converting duration to signed duration"))?,
    )
    .ok_or(Error::TimeOverflow("overflow adding duration to time"))
}

/// Extensions for [`tokio_postgres::row::Row`]
trait RowExt {
    /// Get an integer of type `P` from the row, then attempt to convert it to the desired integer
    /// type `T`.
    fn get_postgres_integer_and_convert<'a, P, I, T>(&'a self, idx: I) -> Result<T, Error>
    where
        P: FromSql<'a>,
        I: RowIndex + Display,
        T: TryFrom<P, Error = std::num::TryFromIntError>;

    /// Get a PostgreSQL `BIGINT` from the row, which is represented in Rust as
    /// i64 ([1]), then attempt to convert it to the desired integer type `T`.
    ///
    /// [1]: https://docs.rs/postgres-types/latest/postgres_types/trait.FromSql.html
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        self.get_postgres_integer_and_convert::<i64, I, T>(idx)
    }

    /// Like [`Self::get_bigint_and_convert`] but handles nullable columns.
    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to convert it to `T`.
    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: Debug;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to decode a `T` value from it.
    fn get_bytea_and_decode<T, P>(
        &self,
        idx: &'static str,
        decoding_parameter: &P,
    ) -> Result<T, Error>
    where
        T: ParameterizedDecode<P>;
}

impl RowExt for Row {
    fn get_postgres_integer_and_convert<'a, P, I, T>(&'a self, idx: I) -> Result<T, Error>
    where
        P: FromSql<'a>,
        I: RowIndex + Display,
        T: TryFrom<P, Error = std::num::TryFromIntError>,
    {
        let postgres_integer: P = self.try_get(idx)?;
        Ok(T::try_from(postgres_integer)?)
    }

    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: Option<i64> = self.try_get(idx)?;
        Ok(bigint.map(|bigint| T::try_from(bigint)).transpose()?)
    }

    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let encoded: Vec<u8> = self.try_get(idx)?;
        T::try_from(&encoded)
            .map_err(|err| Error::DbState(format!("{idx} stored in database is invalid: {err:?}")))
    }

    fn get_bytea_and_decode<T, P>(
        &self,
        idx: &'static str,
        decoding_parameter: &P,
    ) -> Result<T, Error>
    where
        T: ParameterizedDecode<P>,
    {
        let encoded: Vec<u8> = self.try_get(idx)?;
        T::get_decoded_with_param(decoding_parameter, &encoded)
            .map_err(|err| Error::DbState(format!("{idx} stored in database is invalid: {err:?}")))
    }
}

/// A Crypter allows a Datastore to encrypt/decrypt sensitive values stored to the datastore. Values
/// are cryptographically bound to the specific location in the datastore in which they are stored.
/// Rollback protection is not provided.
pub struct Crypter {
    keys: Vec<LessSafeKey>,
}

impl Crypter {
    // The internal serialized format of a Crypter encrypted value is:
    //   ciphertext || tag || nonce
    // (the `ciphertext || tag` portion is as returned from `seal_in_place_append_tag`)

    /// Creates a new Crypter instance, using the given set of keys. The first key in the provided
    /// vector is considered to be the "primary" key, used for encryption operations; any of the
    /// provided keys can be used for decryption operations.
    ///
    /// The keys must be for the AES-128-GCM algorithm.
    pub fn new(keys: Vec<LessSafeKey>) -> Self {
        assert!(!keys.is_empty());
        for key in &keys {
            assert_eq!(key.algorithm(), &AES_128_GCM);
        }
        Self { keys }
    }

    fn encrypt(
        &self,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // It is safe to unwrap the key because we have already validated that keys is nonempty
        // in Crypter::new.
        Self::encrypt_with_key(self.keys.first().unwrap(), table, row, column, value)
    }

    fn encrypt_with_key(
        key: &LessSafeKey,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Generate a random nonce, compute AAD.
        let nonce_bytes: [u8; aead::NONCE_LEN] = random();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let aad = aead::Aad::from(Self::aad_bytes_for(table, row, column)?);

        // Encrypt, append nonce.
        let mut result = value.to_vec();
        key.seal_in_place_append_tag(nonce, aad, &mut result)?;
        result.extend(nonce_bytes);
        Ok(result)
    }

    fn decrypt(
        &self,
        table: &str,
        row: &[u8],
        column: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if value.len() < aead::NONCE_LEN {
            return Err(Error::Crypt);
        }

        // TODO(https://github.com/rust-lang/rust/issues/90091): use `rsplit_array_ref` once it is stabilized.
        let (ciphertext_and_tag, nonce_bytes) = value.split_at(value.len() - aead::NONCE_LEN);
        let nonce_bytes: [u8; aead::NONCE_LEN] = nonce_bytes.try_into().unwrap();
        let aad_bytes = Self::aad_bytes_for(table, row, column)?;

        for key in &self.keys {
            let mut ciphertext_and_tag = ciphertext_and_tag.to_vec();
            if let Ok(plaintext) = key.open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_bytes),
                aead::Aad::from(aad_bytes.clone()),
                &mut ciphertext_and_tag,
            ) {
                let len = plaintext.len();
                ciphertext_and_tag.truncate(len);
                return Ok(ciphertext_and_tag);
            }
        }
        Err(Error::Crypt)
    }

    fn aad_bytes_for(table: &str, row: &[u8], column: &str) -> Result<Vec<u8>, Error> {
        // AAD computation is based on (table, row, column).
        // The serialized AAD is:
        //   (length of table) || table || (length of row) || row || (length of column) || column.
        // Lengths are expressed as 8-byte unsigned integers.

        let aad_length = 3 * size_of::<u64>() + table.len() + row.len() + column.len();
        let mut aad_bytes = Vec::with_capacity(aad_length);
        aad_bytes.extend_from_slice(&u64::try_from(table.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(table.as_ref());
        aad_bytes.extend_from_slice(&u64::try_from(row.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(row);
        aad_bytes.extend_from_slice(&u64::try_from(column.len())?.to_be_bytes());
        aad_bytes.extend_from_slice(column.as_ref());
        assert_eq!(aad_bytes.len(), aad_length);

        Ok(aad_bytes)
    }
}

/// Error represents a datastore-level error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the underlying database library.
    #[error("DB error: {0}")]
    Db(#[from] tokio_postgres::Error),
    #[error("DB pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
    #[error("crypter error")]
    Crypt,
    /// An attempt was made to mutate an entity that does not exist.
    #[error("not found in datastore")]
    MutationTargetNotFound,
    /// An attempt was made to insert an entity that already exists.
    #[error("already in datastore")]
    MutationTargetAlreadyExists,
    /// The database was in an unexpected state.
    #[error("inconsistent database state: {0}")]
    DbState(String),
    /// An error from decoding a value stored encoded in the underlying database.
    #[error("decoding error: {0}")]
    Decode(#[from] CodecError),
    #[error("base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// An arbitrary error returned from the user callback; unrelated to DB internals. This error
    /// will never be generated by the datastore library itself.
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid task parameters: {0}")]
    Task(#[from] task::Error),
    #[error("integer conversion failed: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Message(#[from] janus_messages::Error),
    /// An invalid parameter was provided.
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    /// An error occurred while manipulating timestamps or durations.
    #[error("{0}")]
    TimeOverflow(&'static str),
    #[error("batch already collected")]
    AlreadyCollected,
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::Crypt
    }
}
