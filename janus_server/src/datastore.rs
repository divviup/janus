//! Janus datastore (durable storage) implementation.

use self::models::{
    AcquiredAggregationJob, AcquiredCollectJob, AggregateShareJob, AggregationJob, AggregatorRole,
    BatchUnitAggregation, CollectJob, CollectJobState, CollectJobStateCode, Lease, LeaseToken,
    ReportAggregation, ReportAggregationState, ReportAggregationStateCode,
};
#[cfg(test)]
use crate::aggregator::aggregation_job_creator::VdafHasAggregationParameter;
use crate::{
    message::{AggregateShareReq, AggregationJobId, ReportShare},
    task::{self, Task, VdafInstance},
    SecretBytes,
};
use anyhow::anyhow;
use futures::try_join;
use janus_core::{
    hpke::HpkePrivateKey,
    message::{
        query_type::TimeInterval, Duration, Extension, HpkeCiphertext, HpkeConfig, Interval, Nonce,
        NonceChecksum, Report, ReportMetadata, Role, TaskId, Time,
    },
    task::AuthenticationToken,
    time::Clock,
};
use opentelemetry::{metrics::BoundCounter, KeyValue};
use postgres_types::{Json, ToSql};
use prio::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode},
    vdaf,
};
use rand::random;
use ring::aead::{self, LessSafeKey, AES_128_GCM};
use std::{
    collections::HashMap, convert::TryFrom, fmt::Display, future::Future, io::Cursor, mem::size_of,
    pin::Pin,
};
use tokio_postgres::{error::SqlState, row::RowIndex, IsolationLevel, Row};
use url::Url;
use uuid::Uuid;

// TODO(#533): update indices used by queries looking up reports by (task_id, nonce) to drop nonce_time
// TODO(#196): retry network-related & other transient failures once we know what they look like

/// Datastore represents a datastore for Janus, with support for transactional reads and writes.
/// In practice, Datastore instances are currently backed by a PostgreSQL database.
pub struct Datastore<C: Clock> {
    pool: deadpool_postgres::Pool,
    crypter: Crypter,
    clock: C,
    transaction_success_counter: BoundCounter<u64>,
    transaction_error_conflict_counter: BoundCounter<u64>,
    transaction_error_db_counter: BoundCounter<u64>,
    transaction_error_other_counter: BoundCounter<u64>,
}

impl<C: Clock> Datastore<C> {
    /// new creates a new Datastore using the given Client for backing storage. It is assumed that
    /// the Client is connected to a database with a compatible version of the Janus database schema.
    pub fn new(pool: deadpool_postgres::Pool, crypter: Crypter, clock: C) -> Datastore<C> {
        let meter = opentelemetry::global::meter("janus_server");
        let transaction_status_counter = meter
            .u64_counter("janus_database_transactions_total")
            .with_description("Count of database transactions run, with their status.")
            .init();

        let transaction_success_counter =
            transaction_status_counter.bind(&[KeyValue::new("status", "success")]);
        transaction_success_counter.add(0);
        let transaction_error_conflict_counter =
            transaction_status_counter.bind(&[KeyValue::new("status", "error_conflict")]);
        transaction_error_conflict_counter.add(0);
        let transaction_error_db_counter =
            transaction_status_counter.bind(&[KeyValue::new("status", "error_db")]);
        transaction_error_db_counter.add(0);
        let transaction_error_other_counter =
            transaction_status_counter.bind(&[KeyValue::new("status", "error_other")]);
        transaction_error_other_counter.add(0);

        Self {
            pool,
            crypter,
            clock,
            transaction_success_counter,
            transaction_error_conflict_counter,
            transaction_error_db_counter,
            transaction_error_other_counter,
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
    pub async fn run_tx<F, T>(&self, f: F) -> Result<T, Error>
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        loop {
            let rslt = self.run_tx_once(&f).await;
            match rslt.as_ref() {
                Ok(_) => self.transaction_success_counter.add(1),
                Err(err) if err.is_serialization_failure() => {
                    self.transaction_error_conflict_counter.add(1);
                    continue;
                }
                Err(Error::Db(_)) | Err(Error::Pool(_)) => self.transaction_error_db_counter.add(1),
                Err(_) => self.transaction_error_other_counter.add(1),
            }
            return rslt;
        }
    }

    #[tracing::instrument(skip(self, f), err)]
    async fn run_tx_once<F, T>(&self, f: &F) -> Result<T, Error>
    where
        for<'a> F:
            Fn(&'a Transaction<C>) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        // Open transaction.
        let mut client = self.pool.get().await?;
        let tx = Transaction {
            tx: client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
                .await?,
            crypter: &self.crypter,
            clock: &self.clock,
        };

        // Run user-provided function with the transaction.
        let rslt = f(&tx).await?;

        // Commit.
        tx.tx.commit().await?;
        Ok(rslt)
    }

    /// Write a task into the datastore.
    #[cfg(feature = "test-util")]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        self.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
    }
}

/// Transaction represents an ongoing datastore transaction.
pub struct Transaction<'a, C: Clock> {
    tx: deadpool_postgres::Transaction<'a>,
    crypter: &'a Crypter,
    clock: &'a C,
}

impl<C: Clock> Transaction<'_, C> {
    /// Writes a task into the datastore.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_task(&self, task: &Task) -> Result<(), Error> {
        let aggregator_role = AggregatorRole::from_role(task.role)?;

        let endpoints: Vec<&str> = task
            .aggregator_endpoints
            .iter()
            .map(|url| url.as_str())
            .collect();

        let max_batch_lifetime = i64::try_from(task.max_batch_lifetime)?;
        let min_batch_size = i64::try_from(task.min_batch_size)?;
        let min_batch_duration = i64::try_from(task.min_batch_duration.as_seconds())?;
        let tolerable_clock_skew = i64::try_from(task.tolerable_clock_skew.as_seconds())?;

        // Main task insert.
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO tasks (task_id, aggregator_role, aggregator_endpoints, vdaf,
                max_batch_lifetime, min_batch_size, min_batch_duration, tolerable_clock_skew,
                collector_hpke_config)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    &task.id.as_ref(),                         // task_id
                    &aggregator_role,                          // aggregator_role
                    &endpoints,                                // aggregator_endpoints
                    &Json(&task.vdaf),                         // vdaf
                    &max_batch_lifetime,                       // max batch lifetime
                    &min_batch_size,                           // min batch size
                    &min_batch_duration,                       // min batch duration
                    &tolerable_clock_skew,                     // tolerable clock skew
                    &task.collector_hpke_config.get_encoded(), // collector hpke config
                ],
            )
            .await?;

        // Aggregator auth tokens.
        let mut aggregator_auth_token_ords = Vec::new();
        let mut aggregator_auth_tokens = Vec::new();
        for (ord, token) in task.aggregator_auth_tokens.iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_aggregator_auth_token = self.crypter.encrypt(
                "task_aggregator_auth_tokens",
                &row_id,
                "token",
                token.as_bytes(),
            )?;

            aggregator_auth_token_ords.push(ord);
            aggregator_auth_tokens.push(encrypted_aggregator_auth_token);
        }
        let stmt = self.tx.prepare_cached(
                "INSERT INTO task_aggregator_auth_tokens (task_id, ord, token)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BIGINT[], $3::BYTEA[])"
            )
            .await?;
        let aggregator_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id.as_ref(),
            /* ords */ &aggregator_auth_token_ords,
            /* tokens */ &aggregator_auth_tokens,
        ];
        let aggregator_auth_tokens_future = self.tx.execute(&stmt, aggregator_auth_tokens_params);

        // Collector auth tokens.
        let mut collector_auth_token_ords = Vec::new();
        let mut collector_auth_tokens = Vec::new();
        for (ord, token) in task.collector_auth_tokens.iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_collector_auth_token = self.crypter.encrypt(
                "task_collector_auth_tokens",
                &row_id,
                "token",
                token.as_bytes(),
            )?;

            collector_auth_token_ords.push(ord);
            collector_auth_tokens.push(encrypted_collector_auth_token);
        }
        let stmt = self.tx.prepare_cached(
            "INSERT INTO task_collector_auth_tokens (task_id, ord, token)
            SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BIGINT[], $3::BYTEA[])"
        ).await?;
        let collector_auth_tokens_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id.as_ref(),
            /* ords */ &collector_auth_token_ords,
            /* tokens */ &collector_auth_tokens,
        ];
        let collector_auth_tokens_future = self.tx.execute(&stmt, collector_auth_tokens_params);

        // HPKE keys.
        let mut hpke_config_ids: Vec<i16> = Vec::new();
        let mut hpke_configs: Vec<Vec<u8>> = Vec::new();
        let mut hpke_private_keys: Vec<Vec<u8>> = Vec::new();
        for (hpke_config, hpke_private_key) in task.hpke_keys.values() {
            let mut row_id = [0u8; TaskId::LEN + size_of::<u8>()];
            row_id[..TaskId::LEN].copy_from_slice(task.id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&u8::from(*hpke_config.id()).to_be_bytes());

            let encrypted_hpke_private_key = self.crypter.encrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                hpke_private_key.as_ref(),
            )?;

            hpke_config_ids.push(u8::from(*hpke_config.id()) as i16);
            hpke_configs.push(hpke_config.get_encoded());
            hpke_private_keys.push(encrypted_hpke_private_key);
        }
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO task_hpke_keys (task_id, config_id, config, private_key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::SMALLINT[], $3::BYTEA[], $4::BYTEA[])",
            )
            .await?;
        let hpke_configs_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id.as_ref(),
            /* config_id */ &hpke_config_ids,
            /* configs */ &hpke_configs,
            /* private_keys */ &hpke_private_keys,
        ];
        let hpke_configs_future = self.tx.execute(&stmt, hpke_configs_params);

        // VDAF verification keys.
        let mut vdaf_verify_keys: Vec<Vec<u8>> = Vec::new();
        for vdaf_verify_key in task.vdaf_verify_keys() {
            let encrypted_vdaf_verify_key = self.crypter.encrypt(
                "task_vdaf_verify_keys",
                task.id.as_ref(),
                "vdaf_verify_key",
                vdaf_verify_key.as_bytes(),
            )?;
            vdaf_verify_keys.push(encrypted_vdaf_verify_key);
        }
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO task_vdaf_verify_keys (task_id, vdaf_verify_key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BYTEA[])",
            )
            .await?;
        let vdaf_verify_keys_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id.as_ref(),
            /* vdaf_verify_keys */ &vdaf_verify_keys,
        ];
        let vdaf_verify_keys_future = self.tx.execute(&stmt, vdaf_verify_keys_params);

        try_join!(
            aggregator_auth_tokens_future,
            collector_auth_tokens_future,
            hpke_configs_future,
            vdaf_verify_keys_future
        )?;

        Ok(())
    }

    /// Deletes a task from the datastore. Fails if there is any data related to the task, such as
    /// client reports, aggregations, etc.
    #[tracing::instrument(skip(self))]
    pub async fn delete_task(&self, task_id: TaskId) -> Result<(), Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_ref()];

        // Clean up dependent tables first.
        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_aggregator_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_aggregator_auth_tokens_future = self.tx.execute(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_collector_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_collector_auth_tokens_future = self.tx.execute(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_hpke_keys_future = self.tx.execute(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "DELETE FROM task_vdaf_verify_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let task_vdaf_verify_keys_future = self.tx.execute(&stmt, params);

        try_join!(
            task_aggregator_auth_tokens_future,
            task_collector_auth_tokens_future,
            task_hpke_keys_future,
            task_vdaf_verify_keys_future,
        )?;

        // Then clean up tasks table itself.
        let stmt = self
            .tx
            .prepare_cached("DELETE FROM tasks WHERE task_id = $1")
            .await?;
        check_single_row_mutation(self.tx.execute(&stmt, params).await?)?;
        Ok(())
    }

    /// Fetch the task parameters corresponing to the provided `task_id`.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_task(&self, task_id: TaskId) -> Result<Option<Task>, Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_ref()];
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregator_role, aggregator_endpoints, vdaf, max_batch_lifetime,
                min_batch_size, min_batch_duration, tolerable_clock_skew, collector_hpke_config
                FROM tasks WHERE task_id = $1",
            )
            .await?;
        let task_row = self.tx.query_opt(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT ord, token FROM task_aggregator_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.tx.query(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT ord, token FROM task_collector_auth_tokens
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.tx.query(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT config_id, config, private_key FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let hpke_key_rows = self.tx.query(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT vdaf_verify_key FROM task_vdaf_verify_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let vdaf_verify_key_rows = self.tx.query(&stmt, params);

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
                    task_row,
                    aggregator_auth_token_rows,
                    collector_auth_token_rows,
                    hpke_key_rows,
                    vdaf_verify_key_rows,
                )
            })
            .transpose()
    }

    /// Fetch all the tasks in the database.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_tasks(&self) -> Result<Vec<Task>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT task_id, aggregator_role, aggregator_endpoints, vdaf,
                max_batch_lifetime, min_batch_size, min_batch_duration,
                tolerable_clock_skew, collector_hpke_config 
                FROM tasks",
            )
            .await?;
        let task_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_aggregator_auth_tokens.task_id),
                ord, token FROM task_aggregator_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let aggregator_auth_token_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_collector_auth_tokens.task_id),
                ord, token FROM task_collector_auth_tokens ORDER BY ord ASC",
            )
            .await?;
        let collector_auth_token_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_hpke_keys.task_id),
                config_id, config, private_key FROM task_hpke_keys",
            )
            .await?;
        let hpke_config_rows = self.tx.query(&stmt, &[]);

        let stmt = self.tx.prepare_cached(
            "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_vdaf_verify_keys.task_id),
            vdaf_verify_key FROM task_vdaf_verify_keys"
        ).await?;
        let vdaf_verify_key_rows = self.tx.query(&stmt, &[]);

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
                    task_id,
                    row,
                    aggregator_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    collector_auth_token_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    hpke_config_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    vdaf_verify_key_rows_by_task_id
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
        task_id: TaskId,
        row: Row,
        aggregator_auth_token_rows: Vec<Row>,
        collector_auth_token_rows: Vec<Row>,
        hpke_key_rows: Vec<Row>,
        vdaf_verify_key_rows: Vec<Row>,
    ) -> Result<Task, Error> {
        // Scalar task parameters.
        let aggregator_role: AggregatorRole = row.get("aggregator_role");
        let endpoints: Vec<String> = row.get("aggregator_endpoints");
        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| Ok(Url::parse(&endpoint)?))
            .collect::<Result<_, Error>>()?;
        let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
        let max_batch_lifetime = row.get_bigint_and_convert("max_batch_lifetime")?;
        let min_batch_size = row.get_bigint_and_convert("min_batch_size")?;
        let min_batch_duration =
            Duration::from_seconds(row.get_bigint_and_convert("min_batch_duration")?);
        let tolerable_clock_skew =
            Duration::from_seconds(row.get_bigint_and_convert("tolerable_clock_skew")?);
        let collector_hpke_config = HpkeConfig::get_decoded(row.get("collector_hpke_config"))?;

        // Aggregator authentication tokens.
        let mut aggregator_auth_tokens = Vec::new();
        for row in aggregator_auth_token_rows {
            let ord: i64 = row.get("ord");
            let encrypted_aggregator_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            aggregator_auth_tokens.push(AuthenticationToken::from(self.crypter.decrypt(
                "task_aggregator_auth_tokens",
                &row_id,
                "token",
                &encrypted_aggregator_auth_token,
            )?));
        }

        // Collector authentication tokens.
        let mut collector_auth_tokens = Vec::new();
        for row in collector_auth_token_rows {
            let ord: i64 = row.get("ord");
            let encrypted_collector_auth_token: Vec<u8> = row.get("token");

            let mut row_id = [0u8; TaskId::LEN + size_of::<i64>()];
            row_id[..TaskId::LEN].copy_from_slice(task_id.as_ref());
            row_id[TaskId::LEN..].copy_from_slice(&ord.to_be_bytes());

            collector_auth_tokens.push(AuthenticationToken::from(self.crypter.decrypt(
                "task_collector_auth_tokens",
                &row_id,
                "token",
                &encrypted_collector_auth_token,
            )?));
        }

        // HPKE keys.
        let mut hpke_configs = Vec::new();
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

            hpke_configs.push((config, private_key));
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

        Ok(Task::new(
            task_id,
            endpoints,
            vdaf,
            aggregator_role.as_role(),
            vdaf_verify_keys,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            tolerable_clock_skew,
            collector_hpke_config,
            aggregator_auth_tokens,
            collector_auth_tokens,
            hpke_configs,
        )?)
    }

    /// get_client_report retrieves a client report by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_client_report(
        &self,
        task_id: TaskId,
        nonce: Nonce,
    ) -> Result<Option<Report>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.nonce_time, client_reports.extensions, client_reports.input_shares
                FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1 AND client_reports.nonce_rand = $2",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* nonce_rand */ &nonce.as_ref(),
                ],
            )
            .await?
            .map(|row| {
                let time = Time::from_naive_date_time(row.get("nonce_time"));

                let encoded_extensions: Vec<u8> = row.get("extensions");
                let extensions: Vec<Extension> =
                    decode_u16_items(&(), &mut Cursor::new(&encoded_extensions))?;

                let encoded_input_shares: Vec<u8> = row.get("input_shares");
                let input_shares: Vec<HpkeCiphertext> =
                    decode_u16_items(&(), &mut Cursor::new(&encoded_input_shares))?;

                Ok(Report::new(
                    task_id,
                    ReportMetadata::new(nonce, time, extensions),
                    Vec::new(), // TODO(#473): fill out public_share once possible
                    input_shares,
                ))
            })
            .transpose()
    }

    /// `get_unaggregated_client_report_nonces_for_task` returns some nonces corresponding to
    /// unaggregated client reports for the task identified by the given task ID.
    ///
    /// This should only be used with VDAFs that have an aggregation parameter of the unit type.
    /// It relies on this assumption to find relevant reports without consulting collect jobs. For
    /// VDAFs that do have a different aggregation parameter,
    /// `get_unaggregated_client_report_nonces_by_collect_for_task` should be used instead.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_nonces_for_task(
        &self,
        task_id: TaskId,
    ) -> Result<Vec<(Time, Nonce)>, Error> {
        // We choose to return the newest client reports first (LIFO). The goal is to maintain
        // throughput even if we begin to fall behind enough that reports are too old to be
        // aggregated.
        //
        // See https://medium.com/swlh/fifo-considered-harmful-793b76f98374 &
        // https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.376.5966&rep=rep1&type=pdf.

        // TODO(#269): allow the number of returned results to be controlled?

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT nonce_time, nonce_rand FROM client_reports
                LEFT JOIN report_aggregations ON report_aggregations.client_report_id = client_reports.id
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND report_aggregations.id IS NULL
                ORDER BY nonce_time DESC LIMIT 5000",
            )
            .await?;
        let rows = self.tx.query(&stmt, &[&task_id.as_ref()]).await?;

        rows.into_iter()
            .map(|row| {
                let time = Time::from_naive_date_time(row.get("nonce_time"));
                let nonce_bytes: [u8; Nonce::LEN] = row
                    .get::<_, Vec<u8>>("nonce_rand")
                    .try_into()
                    .map_err(|err| {
                        Error::DbState(format!("couldn't convert nonce_rand value: {err:?}"))
                    })?;
                let nonce = Nonce::from(nonce_bytes);
                Ok((time, nonce))
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    /// `get_unaggregated_client_report_nonces_by_collect_for_task` returns pairs of nonces and
    /// aggregation parameters, corresponding to client reports that have not yet been aggregated,
    /// or not aggregated with a certain aggregation parameter, and for which there are collect
    /// jobs, for a given task.
    ///
    /// This should only be used with VDAFs with a non-unit type aggregation parameter. If a VDAF
    /// has the unit type as its aggregation parameter, then
    /// `get_unaggregated_client_report_nonces_for_task` should be used instead. In such cases, it
    /// is not necessary to wait for a collect job to arrive before preparing reports.
    #[cfg(test)]
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_nonces_by_collect_for_task<const L: usize, A>(
        &self,
        task_id: TaskId,
    ) -> Result<Vec<(Time, Nonce, A::AggregationParam)>, Error>
    where
        A: vdaf::Aggregator<L> + VdafHasAggregationParameter,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        // TODO(#269): allow the number of returned results to be controlled?
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT DISTINCT nonce_time, nonce_rand, collect_jobs.aggregation_param
                FROM collect_jobs
                INNER JOIN client_reports
                ON collect_jobs.task_id = client_reports.task_id
                AND client_reports.nonce_time <@ collect_jobs.batch_interval
                LEFT JOIN (
                    SELECT report_aggregations.id, report_aggregations.client_report_id,
                        aggregation_jobs.aggregation_param
                    FROM report_aggregations
                    INNER JOIN aggregation_jobs
                    ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                    WHERE aggregation_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                ) AS report_aggs
                ON report_aggs.client_report_id = client_reports.id
                AND report_aggs.aggregation_param = collect_jobs.aggregation_param
                WHERE client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND collect_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND collect_jobs.state = 'START'
                AND report_aggs.id IS NULL
                ORDER BY nonce_time DESC LIMIT 5000",
            )
            .await?;
        let rows = self.tx.query(&stmt, &[&task_id.as_ref()]).await?;

        rows.into_iter()
            .map(|row| {
                let time = Time::from_naive_date_time(row.get("nonce_time"));
                let nonce_bytes: [u8; Nonce::LEN] = row
                    .get::<_, Vec<u8>>("nonce_rand")
                    .try_into()
                    .map_err(|err| {
                        Error::DbState(format!("couldn't convert nonce_rand value: {0:?}", err))
                    })?;
                let nonce = Nonce::from(nonce_bytes);
                let agg_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Ok((time, nonce, agg_param))
            })
            .collect::<Result<Vec<(Time, Nonce, A::AggregationParam)>, Error>>()
    }

    /// put_client_report stores a client report.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_client_report(&self, report: &Report) -> Result<(), Error> {
        let time = report.metadata().time();
        let nonce = report.metadata().nonce();

        let mut encoded_extensions = Vec::new();
        encode_u16_items(&mut encoded_extensions, &(), report.metadata().extensions());

        let mut encoded_input_shares = Vec::new();
        encode_u16_items(
            &mut encoded_input_shares,
            &(),
            report.encrypted_input_shares(),
        );

        let stmt = self.tx.prepare_cached(
            "INSERT INTO client_reports (task_id, nonce_time, nonce_rand, extensions, input_shares)
            VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5)"
        ).await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &&report.task_id().get_encoded(),
                    /* nonce_time */ &time.as_naive_date_time(),
                    /* nonce_rand */ &nonce.as_ref(),
                    /* extensions */ &encoded_extensions,
                    /* input_shares */ &encoded_input_shares,
                ],
            )
            .await?;
        Ok(())
    }

    /// check_report_share_exists checks if a report share has been recorded in the datastore, given
    /// its associated task ID & nonce.
    ///
    /// This method is intended for use by aggregators acting in the helper role.
    #[tracing::instrument(skip(self), err)]
    pub async fn check_report_share_exists(
        &self,
        task_id: TaskId,
        nonce: Nonce,
    ) -> Result<bool, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT 1 FROM client_reports JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1
                  AND client_reports.nonce_rand = $2",
            )
            .await?;
        Ok(self
            .tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* nonce_rand */ &nonce.as_ref(),
                ],
            )
            .await
            .map(|row| row.is_some())?)
    }

    /// put_report_share stores a report share, given its associated task ID.
    ///
    /// This method is intended for use by aggregators acting in the helper role; notably, it does
    /// not store extensions or input_shares, as these are not required to be stored for the helper
    /// workflow (and the helper never observes the entire set of encrypted input shares, so it
    /// could not record the full client report in any case).
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_share(
        &self,
        task_id: TaskId,
        report_share: &ReportShare,
    ) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO client_reports (task_id, nonce_time, nonce_rand)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &task_id.get_encoded(),
                    /* nonce_time */ &report_share.metadata().time().as_naive_date_time(),
                    /* nonce_rand */ &report_share.metadata().nonce().as_ref(),
                ],
            )
            .await?;
        Ok(())
    }

    /// get_aggregation_job retrieves an aggregation job by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
    ) -> Result<Option<AggregationJob<L, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregation_jobs.aggregation_param, aggregation_jobs.state
                FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1 AND aggregation_jobs.aggregation_job_id = $2",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                ],
            )
            .await?
            .map(|row| Self::aggregation_job_from_row(task_id, aggregation_job_id, row))
            .transpose()
    }

    /// get_aggregation_jobs_for_task_id returns all aggregation jobs for a given task ID.
    #[cfg(feature = "test-util")]
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_jobs_for_task_id<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: TaskId,
    ) -> Result<Vec<AggregationJob<L, A>>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregation_job_id, aggregation_param, state
                FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE tasks.task_id = $1",
            )
            .await?;
        self.tx
            .query(&stmt, &[/* task_id */ &task_id.as_ref()])
            .await?
            .into_iter()
            .map(|row| {
                let aggregation_job_id =
                    AggregationJobId::get_decoded(row.get("aggregation_job_id"))?;
                Self::aggregation_job_from_row(task_id, aggregation_job_id, row)
            })
            .collect()
    }

    fn aggregation_job_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        row: Row,
    ) -> Result<AggregationJob<L, A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
        let state = row.get("state");

        Ok(AggregationJob {
            aggregation_job_id,
            task_id,
            aggregation_param,
            state,
        })
    }

    /// acquire_incomplete_aggregation_jobs retrieves & acquires the IDs of unclaimed incomplete
    /// aggregation jobs. At most `maximum_acquire_count` jobs are acquired. The job is acquired
    /// with a "lease" that will time out; the desired duration of the lease is a parameter, and the
    /// returned lease provides the absolute timestamp at which the lease is no longer live.
    pub async fn acquire_incomplete_aggregation_jobs(
        &self,
        lease_duration: Duration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredAggregationJob>>, Error> {
        let now = self.clock.now();
        let lease_expiry_time = now.add(lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        // TODO(#224): verify that this query is efficient. I am not sure if we would currently
        // scan over every (in-progress, not-leased) aggregation job for tasks where we are in the
        // HELPER role.
        // We generate the token on the DB to allow each acquired job to receive its own distinct
        // token. This is not strictly necessary as we only care about token collisions on a
        // per-row basis.
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE aggregation_jobs SET lease_expiry = $1, lease_token = gen_random_bytes(16), lease_attempts = lease_attempts + 1
                    FROM tasks
                    WHERE tasks.id = aggregation_jobs.task_id
                    AND aggregation_jobs.id IN (SELECT aggregation_jobs.id FROM aggregation_jobs
                        JOIN tasks on tasks.id = aggregation_jobs.task_id
                        WHERE tasks.aggregator_role = 'LEADER'
                        AND aggregation_jobs.state = 'IN_PROGRESS'
                        AND aggregation_jobs.lease_expiry <= $2
                        ORDER BY aggregation_jobs.id DESC LIMIT $3)
                    RETURNING tasks.task_id, tasks.vdaf, aggregation_jobs.aggregation_job_id, aggregation_jobs.lease_token, aggregation_jobs.lease_attempts",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* lease_expiry */ &lease_expiry_time.as_naive_date_time(),
                    /* now */ &now.as_naive_date_time(),
                    /* limit */ &maximum_acquire_count,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let task_id = TaskId::get_decoded(row.get("task_id"))?;
                let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
                let aggregation_job_id =
                    AggregationJobId::get_decoded(row.get("aggregation_job_id"))?;
                let lease_token_bytes: Vec<u8> = row.get("lease_token");
                let lease_token =
                    LeaseToken::new(lease_token_bytes.try_into().map_err(|err| {
                        Error::DbState(format!("lease_token invalid: {:?}", err))
                    })?);
                let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
                Ok(Lease {
                    leased: AcquiredAggregationJob {
                        vdaf,
                        task_id,
                        aggregation_job_id,
                    },
                    lease_expiry_time,
                    lease_token,
                    lease_attempts,
                })
            })
            .collect()
    }

    /// release_aggregation_job releases an acquired (via e.g. acquire_incomplete_aggregation_jobs)
    /// aggregation job. It returns an error if the aggregation job has no current lease.
    pub async fn release_aggregation_job(
        &self,
        lease: &Lease<AcquiredAggregationJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE aggregation_jobs SET lease_expiry = TIMESTAMP '-infinity', lease_token = NULL, lease_attempts = 0
                FROM tasks
                WHERE tasks.id = aggregation_jobs.task_id
                  AND tasks.task_id = $1
                  AND aggregation_jobs.aggregation_job_id = $2
                  AND aggregation_jobs.lease_expiry = $3
                  AND aggregation_jobs.lease_token = $4",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* task_id */ &lease.leased().task_id.as_ref(),
                        /* aggregation_job_id */
                        &lease.leased().aggregation_job_id.as_ref(),
                        /* lease_expiry */ &lease.lease_expiry_time().as_naive_date_time(),
                        /* lease_token */ &lease.lease_token.as_bytes(),
                    ],
                )
                .await?,
        )
    }

    /// put_aggregation_job stores an aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregation_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        aggregation_job: &AggregationJob<L, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self.tx.prepare_cached(
            "INSERT INTO aggregation_jobs (aggregation_job_id, task_id, aggregation_param, state)
            VALUES ($1, (SELECT id FROM tasks WHERE task_id = $2), $3, $4)"
        ).await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* aggregation_job_id */ &aggregation_job.aggregation_job_id.as_ref(),
                    /* task_id */ &aggregation_job.task_id.as_ref(),
                    /* aggregation_param */ &aggregation_job.aggregation_param.get_encoded(),
                    /* state */ &aggregation_job.state,
                ],
            )
            .await?;
        Ok(())
    }

    /// update_aggregation_job updates a stored aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_aggregation_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        aggregation_job: &AggregationJob<L, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE aggregation_jobs SET aggregation_param = $1, state = $2
                WHERE aggregation_job_id = $3 AND task_id = (SELECT id FROM tasks WHERE task_id = $4)",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* aggregation_param */
                        &aggregation_job.aggregation_param.get_encoded(),
                        /* state */ &aggregation_job.state,
                        /* aggregation_job_id */
                        &aggregation_job.aggregation_job_id.as_ref(),
                        /* task_id */ &aggregation_job.task_id.as_ref(),
                    ],
                )
                .await?,
        )
    }

    /// get_report_aggregation gets a report aggregation by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        vdaf: &A,
        role: Role,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        nonce: Nonce,
    ) -> Result<Option<ReportAggregation<L, A>>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.nonce_time, client_reports.nonce_rand,
                report_aggregations.ord, report_aggregations.state, report_aggregations.prep_state,
                report_aggregations.prep_msg, report_aggregations.out_share, report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                WHERE report_aggregations.aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1)
                  AND client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $2)
                  AND client_reports.nonce_rand = $3",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                    /* task_id */ &task_id.as_ref(),
                    /* nonce_rand */ &nonce.as_ref(),
                ],
            )
            .await?
            .map(|row| report_aggregation_from_row(vdaf, role, task_id, aggregation_job_id, row))
            .transpose()
    }

    /// get_report_aggregations_for_aggregation_job retrieves all report aggregations associated
    /// with a given aggregation job, ordered by their natural ordering.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregations_for_aggregation_job<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        vdaf: &A,
        role: Role,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
    ) -> Result<Vec<ReportAggregation<L, A>>, Error>
    where
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.nonce_time, client_reports.nonce_rand,
                report_aggregations.ord, report_aggregations.state, report_aggregations.prep_state,
                report_aggregations.prep_msg, report_aggregations.out_share, report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                WHERE report_aggregations.aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1)
                  AND client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $2)
                ORDER BY report_aggregations.ord ASC"
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* aggregation_job_id */ &aggregation_job_id.as_ref(),
                    /* task_id */ &task_id.as_ref(),
                ],
            )
            .await?
            .into_iter()
            .map(|row| report_aggregation_from_row(vdaf, role, task_id, aggregation_job_id, row))
            .collect()
    }

    /// put_report_aggregation stores aggregation data for a single report.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        report_aggregation: &ReportAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::PrepareState: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_state_values = report_aggregation.state.encoded_values_from_state();

        let stmt = self.tx.prepare_cached(
            "INSERT INTO report_aggregations
            (aggregation_job_id, client_report_id, ord, state, prep_state, prep_msg, out_share, error_code)
            VALUES ((SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1),
                    (SELECT id FROM client_reports
                     WHERE task_id = (SELECT id FROM tasks WHERE task_id = $2)
                     AND nonce_rand = $3),
                    $4, $5, $6, $7, $8, $9)"
        ).await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* aggregation_job_id */
                    &report_aggregation.aggregation_job_id.as_ref(),
                    /* task_id */ &report_aggregation.task_id.as_ref(),
                    /* nonce_rand */ &report_aggregation.nonce.as_ref(),
                    /* ord */ &report_aggregation.ord,
                    /* state */ &report_aggregation.state.state_code(),
                    /* prep_state */ &encoded_state_values.prep_state,
                    /* prep_msg */ &encoded_state_values.prep_msg,
                    /* out_share */ &encoded_state_values.output_share,
                    /* error_code */ &encoded_state_values.report_share_err,
                ],
            )
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn update_report_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        report_aggregation: &ReportAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::PrepareState: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_state_values = report_aggregation.state.encoded_values_from_state();

        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE report_aggregations SET ord = $1, state = $2, prep_state = $3,
                prep_msg = $4, out_share = $5, error_code = $6
                WHERE aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $7)
                AND client_report_id = (SELECT id FROM client_reports
                    WHERE task_id = (SELECT id FROM tasks WHERE task_id = $8)
                    AND nonce_rand = $9)")
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* ord */ &report_aggregation.ord,
                        /* state */ &report_aggregation.state.state_code(),
                        /* prep_state */ &encoded_state_values.prep_state,
                        /* prep_msg */ &encoded_state_values.prep_msg,
                        /* out_share */ &encoded_state_values.output_share,
                        /* error_code */ &encoded_state_values.report_share_err,
                        /* aggregation_job_id */
                        &report_aggregation.aggregation_job_id.as_ref(),
                        /* task_id */ &report_aggregation.task_id.as_ref(),
                        /* nonce_rand */ &report_aggregation.nonce.as_ref(),
                    ],
                )
                .await?,
        )
    }

    /// Returns the task ID for the provided collect job ID, or `None` if no such collect job
    /// exists.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn get_collect_job_task_id(
        &self,
        collect_job_id: Uuid,
    ) -> Result<Option<TaskId>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT task_id FROM tasks
                WHERE id = (SELECT task_id FROM collect_jobs WHERE collect_job_id = $1)",
            )
            .await?;
        self.tx
            .query_opt(&stmt, &[&collect_job_id])
            .await?
            .map(|row| TaskId::get_decoded(row.get("task_id")).map_err(Error::from))
            .transpose()
    }

    /// Returns the collect job for the provided UUID, or `None` if no such collect job exists.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn get_collect_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        collect_job_id: Uuid,
    ) -> Result<Option<CollectJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    tasks.task_id,
                    collect_jobs.batch_interval,
                    collect_jobs.aggregation_param,
                    collect_jobs.state,
                    collect_jobs.helper_aggregate_share,
                    collect_jobs.leader_aggregate_share
                FROM collect_jobs JOIN tasks ON tasks.id = collect_jobs.task_id
                WHERE collect_jobs.collect_job_id = $1",
            )
            .await?;
        self.tx
            .query_opt(&stmt, &[&collect_job_id])
            .await?
            .map(|row| {
                let task_id = TaskId::get_decoded(row.get("task_id"))?;
                Self::collect_job_from_row(task_id, collect_job_id, row)
            })
            .transpose()
    }

    /// If a collect job corresponding to the provided values exists, its UUID is returned, which
    /// may then be used to construct a collect job URI. If that collect job does not exist, returns
    /// `Ok(None)`.
    #[tracing::instrument(skip(self, encoded_aggregation_parameter), err)]
    pub(crate) async fn get_collect_job_id(
        &self,
        task_id: TaskId,
        batch_interval: Interval,
        encoded_aggregation_parameter: &[u8],
    ) -> Result<Option<Uuid>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT collect_job_id FROM collect_jobs
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND batch_interval = $2 AND aggregation_param = $3",
            )
            .await?;
        let row = self
            .tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    &batch_interval,
                    /* aggregation_param */ &encoded_aggregation_parameter,
                ],
            )
            .await?;

        Ok(row.map(|row| row.get("collect_job_id")))
    }

    /// Returns all collect jobs for the given task which include the given timestamp.
    pub(crate) async fn find_collect_jobs_including_time<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        task_id: TaskId,
        timestamp: Time,
    ) -> Result<Vec<CollectJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    collect_jobs.collect_job_id,
                    collect_jobs.batch_interval,
                    collect_jobs.aggregation_param,
                    collect_jobs.state,
                    collect_jobs.helper_aggregate_share,
                    collect_jobs.leader_aggregate_share
                FROM collect_jobs JOIN tasks ON tasks.id = collect_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collect_jobs.batch_interval @> $2::TIMESTAMP",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* timestamp */ &timestamp.as_naive_date_time(),
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let collect_job_id = row.get("collect_job_id");
                Self::collect_job_from_row(task_id, collect_job_id, row)
            })
            .collect()
    }

    /// Returns all collect jobs for the given task whose collect intervals intersect with the given
    /// interval.
    pub(crate) async fn find_collect_jobs_jobs_intersecting_interval<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: TaskId,
        interval: Interval,
    ) -> Result<Vec<CollectJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    collect_jobs.collect_job_id,
                    collect_jobs.batch_interval,
                    collect_jobs.aggregation_param,
                    collect_jobs.state,
                    collect_jobs.helper_aggregate_share,
                    collect_jobs.leader_aggregate_share
                FROM collect_jobs JOIN tasks ON tasks.id = collect_jobs.task_id
                WHERE tasks.task_id = $1
                  AND collect_jobs.batch_interval && $2",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* interval */ &interval,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let collect_job_id = row.get("collect_job_id");
                Self::collect_job_from_row(task_id, collect_job_id, row)
            })
            .collect()
    }

    fn collect_job_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        task_id: TaskId,
        collect_job_id: Uuid,
        row: Row,
    ) -> Result<CollectJob<L, A>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let batch_interval = row.try_get("batch_interval")?;
        let aggregation_param = A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
        let state: CollectJobStateCode = row.get("state");
        let helper_aggregate_share_bytes: Option<Vec<u8>> = row.get("helper_aggregate_share");
        let leader_aggregate_share_bytes: Option<Vec<u8>> = row.get("leader_aggregate_share");

        let state = match state {
            CollectJobStateCode::Start => CollectJobState::Start,

            CollectJobStateCode::Finished => {
                let encrypted_helper_aggregate_share = HpkeCiphertext::get_decoded(
                    &helper_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collect job in state FINISHED but helper_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let leader_aggregate_share = A::AggregateShare::try_from(
                    &leader_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collect job is in state FINISHED but leader_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )
                .map_err(|err| {
                    Error::DbState(format!(
                        "leader_aggregate_share stored in database is invalid: {}",
                        err
                    ))
                })?;
                CollectJobState::Finished {
                    encrypted_helper_aggregate_share,
                    leader_aggregate_share,
                }
            }

            CollectJobStateCode::Abandoned => CollectJobState::Abandoned,
        };

        Ok(CollectJob {
            collect_job_id,
            task_id,
            batch_interval,
            aggregation_param,
            state,
        })
    }

    /// Constructs and stores a new collect job for the provided values, and returns the UUID that
    /// was assigned.
    // TODO(#242): update this function to take a CollectJob.
    #[tracing::instrument(skip(self, encoded_aggregation_parameter), err)]
    pub(crate) async fn put_collect_job(
        &self,
        task_id: TaskId,
        batch_interval: Interval,
        encoded_aggregation_parameter: &[u8],
    ) -> Result<Uuid, Error> {
        let collect_job_id = Uuid::new_v4();

        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO collect_jobs (
                    collect_job_id, task_id, batch_interval,
                    aggregation_param, state
                )
                VALUES ($1, (SELECT id FROM tasks WHERE task_id = $2), $3, $4, 'START')",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* collect_job_id */ &collect_job_id,
                    /* task_id */ &task_id.as_ref(),
                    &batch_interval,
                    /* aggregation_param */ &encoded_aggregation_parameter,
                ],
            )
            .await?;

        Ok(collect_job_id)
    }

    /// acquire_incomplete_collect_jobs retrieves & acquires the IDs of unclaimed incomplete collect
    /// jobs. At most `maximum_acquire_count` jobs are acquired. The job is acquired with a "lease"
    /// that will time out; the desired duration of the lease is a parameter, and the lease
    /// expiration time is returned.
    pub async fn acquire_incomplete_collect_jobs(
        &self,
        lease_duration: Duration,
        maximum_acquire_count: usize,
    ) -> Result<Vec<Lease<AcquiredCollectJob>>, Error> {
        let now = self.clock.now();
        let lease_expiry_time = now.add(lease_duration)?;
        let maximum_acquire_count: i64 = maximum_acquire_count.try_into()?;

        let stmt = self
            .tx
            .prepare_cached(
                r#"
WITH updated as (
    UPDATE collect_jobs SET lease_expiry = $1, lease_token = gen_random_bytes(16), lease_attempts = lease_attempts + 1
    FROM tasks
    WHERE collect_jobs.id IN (
        SELECT collect_jobs.id FROM collect_jobs
        -- Join on aggregation jobs with matching task ID and aggregation parameter
        INNER JOIN aggregation_jobs
            ON collect_jobs.aggregation_param = aggregation_jobs.aggregation_param
            AND collect_jobs.task_id = aggregation_jobs.task_id
        -- Join on report aggregations with matching aggregation job ID
        INNER JOIN report_aggregations
            ON report_aggregations.aggregation_job_id = aggregation_jobs.id
        -- Join on reports whose nonce falls within the collect job batch interval and which are
        -- included in an aggregation job
        INNER JOIN client_reports
            ON client_reports.id = report_aggregations.client_report_id
            AND client_reports.nonce_time <@ collect_jobs.batch_interval
        WHERE
            -- Constraint for tasks table in FROM position
            tasks.id = collect_jobs.task_id
            -- Only acquire collect jobs in a non-terminal state.
            AND collect_jobs.state = 'START'
            -- Do not acquire collect jobs with an unexpired lease
            AND collect_jobs.lease_expiry <= $2
        GROUP BY collect_jobs.id
        -- Do not acquire collect jobs where any associated aggregation jobs are not finished
        HAVING bool_and(aggregation_jobs.state != 'IN_PROGRESS')
        -- Honor maximum_acquire_count *after* winnowing down to runnable collect jobs
        LIMIT $3
    )
    RETURNING tasks.task_id, tasks.vdaf, collect_jobs.collect_job_id, collect_jobs.id, collect_jobs.lease_token, collect_jobs.lease_attempts
)
SELECT task_id, vdaf, collect_job_id, lease_token, lease_attempts FROM updated
-- TODO (#174): revisit collect job queueing behavior implied by this ORDER BY
ORDER BY id DESC
"#,
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* lease_expiry */ &lease_expiry_time.as_naive_date_time(),
                    /* now */ &now.as_naive_date_time(),
                    /* limit */ &maximum_acquire_count,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let task_id = TaskId::get_decoded(row.get("task_id"))?;
                let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
                let collect_job_id = row.get("collect_job_id");
                let lease_token_bytes: Vec<u8> = row.get("lease_token");
                let lease_token =
                    LeaseToken::new(lease_token_bytes.try_into().map_err(|err| {
                        Error::DbState(format!("lease_token invalid: {:?}", err))
                    })?);
                let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;
                Ok(Lease {
                    leased: AcquiredCollectJob {
                        task_id,
                        vdaf,
                        collect_job_id,
                    },
                    lease_expiry_time,
                    lease_token,
                    lease_attempts,
                })
            })
            .collect()
    }

    /// release_collect_job releases an acquired (via e.g. acquire_incomplete_collect_jobs) collect
    /// job. It returns an error if the collect job has no current lease.
    pub async fn release_collect_job(
        &self,
        lease: &Lease<AcquiredCollectJob>,
    ) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE collect_jobs SET lease_expiry = TIMESTAMP '-infinity', lease_token = NULL, lease_attempts = 0
                FROM tasks
                WHERE tasks.id = collect_jobs.task_id
                  AND tasks.task_id = $1
                  AND collect_jobs.collect_job_id = $2
                  AND collect_jobs.lease_expiry = $3
                  AND collect_jobs.lease_token = $4",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* task_id */ &lease.leased().task_id.as_ref(),
                        /* collect_job_id */ &lease.leased().collect_job_id,
                        /* lease_expiry */ &lease.lease_expiry_time().as_naive_date_time(),
                        /* lease_token */ &lease.lease_token.as_bytes(),
                    ],
                )
                .await?,
        )
    }

    /// Updates an existing collect job with the provided aggregate shares.
    // TODO(#242): update this function to take a CollectJob.
    #[tracing::instrument(skip(self, leader_aggregate_share, helper_aggregate_share), err)]
    pub(crate) async fn update_collect_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        collect_job_id: Uuid,
        leader_aggregate_share: &A::AggregateShare,
        helper_aggregate_share: &HpkeCiphertext,
    ) -> Result<(), Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let leader_aggregate_share: Option<Vec<u8>> = Some(leader_aggregate_share.into());
        let helper_aggregate_share = Some(helper_aggregate_share.get_encoded());

        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE collect_jobs SET
                    state = 'FINISHED',
                    leader_aggregate_share = $1,
                    helper_aggregate_share = $2
                WHERE collect_job_id = $3",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        &leader_aggregate_share,
                        &helper_aggregate_share,
                        &collect_job_id,
                    ],
                )
                .await?,
        )?;

        Ok(())
    }

    /// Cancels an existing collect job.
    // TODO(#242): remove this function in lieu of update_collect_job once that method takes a CollectJob.
    pub(crate) async fn cancel_collect_job(&self, collect_job_id: Uuid) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE collect_jobs SET
                state = 'ABANDONED',
                leader_aggregate_share = NULL,
                helper_aggregate_share = NULL
            WHERE collect_job_id = $1",
            )
            .await?;
        check_single_row_mutation(self.tx.execute(&stmt, &[&collect_job_id]).await?)?;
        Ok(())
    }

    /// Store a new `batch_unit_aggregations` row in the datastore.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_batch_unit_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        batch_unit_aggregation: &BatchUnitAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        A::AggregateShare: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let unit_interval_start = batch_unit_aggregation
            .unit_interval_start
            .as_naive_date_time();
        let encoded_aggregation_param = batch_unit_aggregation.aggregation_param.get_encoded();
        let encoded_aggregate_share: Vec<u8> = (&batch_unit_aggregation.aggregate_share).into();
        let report_count = i64::try_from(batch_unit_aggregation.report_count)?;

        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO batch_unit_aggregations (task_id, unit_interval_start,
                aggregation_param, aggregate_share, report_count, checksum)
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &batch_unit_aggregation.task_id.as_ref(),
                    &unit_interval_start,
                    /* aggregation_param */ &encoded_aggregation_param,
                    /* aggregate_share */ &encoded_aggregate_share,
                    &report_count,
                    /* checksum */ &batch_unit_aggregation.checksum.get_encoded(),
                ],
            )
            .await?;

        Ok(())
    }

    /// Update an existing `batch_unit_aggregations` row with the `aggregate_share`, `checksum` and
    /// `report_count` values in `batch_unit_aggregation`.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn update_batch_unit_aggregation<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        batch_unit_aggregation: &BatchUnitAggregation<L, A>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Encode + std::fmt::Debug,
        A::AggregateShare: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_aggregate_share: Vec<u8> = (&batch_unit_aggregation.aggregate_share).into();
        let report_count = i64::try_from(batch_unit_aggregation.report_count)?;
        let encoded_checksum = batch_unit_aggregation.checksum.get_encoded();
        let unit_interval_start = batch_unit_aggregation
            .unit_interval_start
            .as_naive_date_time();
        let encoded_aggregation_param = batch_unit_aggregation.aggregation_param.get_encoded();

        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE batch_unit_aggregations
                SET aggregate_share = $1, report_count = $2, checksum = $3
                WHERE
                    task_id = (SELECT id from TASKS WHERE task_id = $4)
                    AND unit_interval_start = $5
                    AND aggregation_param = $6",
            )
            .await?;
        check_single_row_mutation(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* aggregate_share */ &encoded_aggregate_share,
                        &report_count,
                        /* checksum */ &encoded_checksum,
                        /* task_id */ &batch_unit_aggregation.task_id.as_ref(),
                        &unit_interval_start,
                        /* aggregation_param */ &encoded_aggregation_param,
                    ],
                )
                .await?,
        )?;

        Ok(())
    }

    /// Fetch all the `batch_unit_aggregations` rows whose `unit_interval_start` describes an
    /// interval that falls within the provided `interval` and whose `aggregation_param` matches.
    #[tracing::instrument(skip(self, aggregation_param), err)]
    pub(crate) async fn get_batch_unit_aggregations_for_task_in_interval<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: TaskId,
        interval: Interval,
        aggregation_param: &A::AggregationParam,
    ) -> Result<Vec<BatchUnitAggregation<L, A>>, Error>
    where
        A::AggregationParam: Encode + Clone,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let unit_interval_start = interval.start().as_naive_date_time();
        let unit_interval_end = interval.end().as_naive_date_time();
        let encoded_aggregation_param = aggregation_param.get_encoded();

        let stmt = self
            .tx
            .prepare_cached(
                "WITH tasks AS (SELECT id, min_batch_duration FROM tasks WHERE task_id = $1)
                SELECT unit_interval_start, aggregate_share, report_count, checksum
                FROM batch_unit_aggregations
                WHERE
                    task_id = (SELECT id FROM tasks)
                    AND unit_interval_start >= $2
                    AND (unit_interval_start + (SELECT min_batch_duration FROM tasks) * interval '1 second') <= $3
                    AND aggregation_param = $4",
            )
            .await?;
        let rows = self
            .tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    &unit_interval_start,
                    &unit_interval_end,
                    /* aggregation_param */ &encoded_aggregation_param,
                ],
            )
            .await?
            .iter()
            .map(|row| {
                let unit_interval_start =
                    Time::from_naive_date_time(row.get("unit_interval_start"));
                let aggregate_share = row.get_bytea_and_convert("aggregate_share")?;
                let report_count = row.get_bigint_and_convert("report_count")?;
                let checksum = NonceChecksum::get_decoded(row.get("checksum"))?;

                Ok(BatchUnitAggregation {
                    task_id,
                    unit_interval_start,
                    aggregation_param: aggregation_param.clone(),
                    aggregate_share,
                    report_count,
                    checksum,
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(rows)
    }

    /// Fetch an `aggregate_share_jobs` row from the datastore corresponding to the provided
    /// [`AggregateShareRequest`], or `None` if no such job exists.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn get_aggregate_share_job_by_request<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        request: &AggregateShareReq<TimeInterval>,
    ) -> Result<Option<AggregateShareJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT helper_aggregate_share, report_count, checksum FROM aggregate_share_jobs
                WHERE
                    task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND batch_interval = $2
                    AND aggregation_param = $3",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &request.task_id().as_ref(),
                    /* batch_interval */ &request.batch_selector().batch_interval(),
                    /* aggregation_param */ &request.aggregation_parameter(),
                ],
            )
            .await?
            .map(|row| {
                let aggregation_param =
                    A::AggregationParam::get_decoded(request.aggregation_parameter())?;
                Self::aggregate_share_job_from_row(
                    *request.task_id(),
                    *request.batch_selector().batch_interval(),
                    aggregation_param,
                    row,
                )
            })
            .transpose()
    }

    /// Returns all aggregate share jobs for the given task which include the given timestamp.
    pub(crate) async fn find_aggregate_share_jobs_including_time<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: TaskId,
        timestamp: Time,
    ) -> Result<Vec<AggregateShareJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_interval,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval @> $2::TIMESTAMP",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* timestamp */ &timestamp.as_naive_date_time(),
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let batch_interval = row.get("batch_interval");
                let aggregation_param =
                    A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Self::aggregate_share_job_from_row(task_id, batch_interval, aggregation_param, row)
            })
            .collect()
    }

    /// Returns all aggregate share jobs for the given task whose collect intervals intersect with
    /// the given interval.
    pub(crate) async fn find_aggregate_share_jobs_intersecting_interval<
        const L: usize,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        task_id: TaskId,
        interval: Interval,
    ) -> Result<Vec<AggregateShareJob<L, A>>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT
                    aggregate_share_jobs.batch_interval,
                    aggregate_share_jobs.aggregation_param,
                    aggregate_share_jobs.helper_aggregate_share,
                    aggregate_share_jobs.report_count,
                    aggregate_share_jobs.checksum
                FROM aggregate_share_jobs JOIN tasks ON tasks.id = aggregate_share_jobs.task_id
                WHERE tasks.task_id = $1
                  AND aggregate_share_jobs.batch_interval && $2",
            )
            .await?;
        self.tx
            .query(
                &stmt,
                &[
                    /* task_id */ &task_id.as_ref(),
                    /* interval */ &interval,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let batch_interval = row.get("batch_interval");
                let aggregation_param =
                    A::AggregationParam::get_decoded(row.get("aggregation_param"))?;
                Self::aggregate_share_job_from_row(task_id, batch_interval, aggregation_param, row)
            })
            .collect()
    }

    fn aggregate_share_job_from_row<const L: usize, A: vdaf::Aggregator<L>>(
        task_id: TaskId,
        batch_interval: Interval,
        aggregation_param: A::AggregationParam,
        row: Row,
    ) -> Result<AggregateShareJob<L, A>, Error>
    where
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let helper_aggregate_share = row.get_bytea_and_convert("helper_aggregate_share")?;
        let report_count = row.get_bigint_and_convert("report_count")?;
        let checksum = NonceChecksum::get_decoded(row.get("checksum"))?;

        Ok(AggregateShareJob {
            task_id,
            batch_interval,
            aggregation_param,
            helper_aggregate_share,
            report_count,
            checksum,
        })
    }

    /// Put an `aggregate_share_job` row into the datastore.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_aggregate_share_job<const L: usize, A: vdaf::Aggregator<L>>(
        &self,
        job: &AggregateShareJob<L, A>,
    ) -> Result<(), Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
    {
        let encoded_aggregation_param = job.aggregation_param.get_encoded();
        let encoded_aggregate_share: Vec<u8> = (&job.helper_aggregate_share).into();
        let report_count = i64::try_from(job.report_count)?;

        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO aggregate_share_jobs (
                    task_id, batch_interval, aggregation_param,
                    helper_aggregate_share, report_count, checksum
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &job.task_id.as_ref(),
                    /* batch_interval */ &job.batch_interval,
                    /* aggregation_param */ &encoded_aggregation_param,
                    /* aggregate_share */ &encoded_aggregate_share,
                    &report_count,
                    /* checksum */ &job.checksum.get_encoded(),
                ],
            )
            .await?;

        Ok(())
    }
}

fn check_single_row_mutation(row_count: u64) -> Result<(), Error> {
    match row_count {
        0 => Err(Error::MutationTargetNotFound),
        1 => Ok(()),
        _ => panic!(
            "update which should have affected at most one row instead affected {} rows",
            row_count
        ),
    }
}

fn report_aggregation_from_row<const L: usize, A: vdaf::Aggregator<L>>(
    vdaf: &A,
    role: Role,
    task_id: TaskId,
    aggregation_job_id: AggregationJobId,
    row: Row,
) -> Result<ReportAggregation<L, A>, Error>
where
    for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
    A::OutputShare: for<'a> TryFrom<&'a [u8]>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    let time = Time::from_naive_date_time(row.get("nonce_time"));
    let nonce_bytes: [u8; Nonce::LEN] = row
        .get::<_, Vec<u8>>("nonce_rand")
        .try_into()
        .map_err(|err| Error::DbState(format!("couldn't convert nonce_rand value: {err:?}")))?;
    let nonce = Nonce::from(nonce_bytes);
    let ord: i64 = row.get("ord");
    let state: ReportAggregationStateCode = row.get("state");
    let prep_state_bytes: Option<Vec<u8>> = row.get("prep_state");
    let prep_msg_bytes: Option<Vec<u8>> = row.get("prep_msg");
    let out_share_bytes: Option<Vec<u8>> = row.get("out_share");
    let error_code: Option<i64> = row.get("error_code");

    let error_code = match error_code {
        Some(c) => {
            let c: u8 = c.try_into().map_err(|err| {
                Error::DbState(format!("couldn't convert error_code value: {0}", err))
            })?;
            Some(c.try_into().map_err(|err| {
                Error::DbState(format!("couldn't convert error_code value: {0}", err))
            })?)
        }
        None => None,
    };

    let agg_state = match state {
        ReportAggregationStateCode::Start => ReportAggregationState::Start,
        ReportAggregationStateCode::Waiting => {
            let agg_index = role
                .index()
                .ok_or_else(|| Error::User(anyhow!("unexpected role: {}", role.as_str()).into()))?;
            let prep_state = A::PrepareState::get_decoded_with_param(
                &(vdaf, agg_index),
                &prep_state_bytes.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state WAITING but prep_state is NULL".to_string(),
                    )
                })?,
            )?;
            let prep_msg = prep_msg_bytes
                .map(|bytes| A::PrepareMessage::get_decoded_with_param(&prep_state, &bytes))
                .transpose()?;
            ReportAggregationState::Waiting(prep_state, prep_msg)
        }
        ReportAggregationStateCode::Finished => ReportAggregationState::Finished(
            A::OutputShare::try_from(&out_share_bytes.ok_or_else(|| {
                Error::DbState(
                    "report aggregation in state FINISHED but out_share is NULL".to_string(),
                )
            })?)
            .map_err(|_| Error::Decode(CodecError::Other("couldn't decode output share".into())))?,
        ),
        ReportAggregationStateCode::Failed => {
            ReportAggregationState::Failed(error_code.ok_or_else(|| {
                Error::DbState(
                    "report aggregation in state FAILED but error_code is NULL".to_string(),
                )
            })?)
        }
        ReportAggregationStateCode::Invalid => ReportAggregationState::Invalid,
    };

    Ok(ReportAggregation {
        aggregation_job_id,
        task_id,
        time,
        nonce,
        ord,
        state: agg_state,
    })
}

/// Extensions for [`tokio_postgres::row::Row`]
trait RowExt {
    /// Get a PostgreSQL `BIGINT` from the row, which is represented in Rust as
    /// i64 ([1]), then attempt to convert it to the desired integer type `T`.
    ///
    /// [1]: https://docs.rs/postgres-types/latest/postgres_types/trait.FromSql.html
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Like [`Self::get_bigint_and_convert`] but handles nullable columns.
    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Get a PostgreSQL `BYTEA` from the row and then attempt to convert it to
    /// u64, treating it as an 8 byte big endian array.
    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to convert it to `T`.
    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> <T as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> T: TryFrom<&'a [u8]>;
}

impl RowExt for Row {
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: i64 = self.try_get(idx)?;
        Ok(T::try_from(bigint)?)
    }

    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: Option<i64> = self.try_get(idx)?;
        Ok(bigint.map(|bigint| T::try_from(bigint)).transpose()?)
    }

    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display,
    {
        let encoded_u64: Vec<u8> = self.try_get(idx)?;

        // `u64::from_be_bytes` takes `[u8; 8]` and `Vec<u8>::try_into` will
        // fail unless the vector has exactly that length [1].
        //
        // [1]: https://doc.rust-lang.org/std/primitive.array.html#method.try_from-4
        Ok(u64::from_be_bytes(encoded_u64.try_into().map_err(
            // The error is just the vector that was rejected
            |_| Error::DbState("byte array in database does not have expected length".to_string()),
        )?))
    }

    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> <T as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> T: TryFrom<&'a [u8]>,
    {
        let encoded: Vec<u8> = self.try_get(idx)?;
        let decoded = T::try_from(&encoded)
            .map_err(|e| Error::DbState(format!("{} stored in database is invalid: {}", idx, e)))?;
        Ok(decoded)
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
    /// An attempt was made to mutate a row that does not exist.
    #[error("not found in datastore")]
    MutationTargetNotFound,
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
    Message(#[from] janus_core::message::Error),
}

impl Error {
    // is_serialization_failure determines if a given error corresponds to a Postgres
    // "serialization" failure, which requires the entire transaction to be aborted & retried from
    // the beginning per https://www.postgresql.org/docs/current/transaction-iso.html.
    fn is_serialization_failure(&self) -> bool {
        match self {
            // T_R_SERIALIZATION_FAILURE (40001) is documented as the error code which is always used
            // for serialization failures which require rollback-and-retry.
            Error::Db(err) => err
                .code()
                .map_or(false, |c| c == &SqlState::T_R_SERIALIZATION_FAILURE),
            _ => false,
        }
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::Crypt
    }
}

/// This module contains models used by the datastore that are not PPM messages.
pub mod models {
    use super::Error;
    use crate::{
        message::{AggregationJobId, ReportShareError},
        task::{self, VdafInstance},
    };
    use derivative::Derivative;
    use janus_core::message::{HpkeCiphertext, Interval, Nonce, NonceChecksum, Role, TaskId, Time};
    use postgres_types::{FromSql, ToSql};
    use prio::{codec::Encode, vdaf};
    use uuid::Uuid;

    // We have to manually implement [Partial]Eq for a number of types because the dervied
    // implementations don't play nice with generic fields, even if those fields are constrained to
    // themselves implement [Partial]Eq.

    /// AggregatorRole corresponds to the `AGGREGATOR_ROLE` enum in the schema.
    #[derive(Clone, Debug, ToSql, FromSql)]
    #[postgres(name = "aggregator_role")]
    pub(super) enum AggregatorRole {
        #[postgres(name = "LEADER")]
        Leader,
        #[postgres(name = "HELPER")]
        Helper,
    }

    impl AggregatorRole {
        /// If the provided [`Role`] is an aggregator, returns the corresponding
        /// [`AggregatorRole`], or `None` otherwise.
        pub(super) fn from_role(role: Role) -> Result<Self, Error> {
            match role {
                Role::Leader => Ok(Self::Leader),
                Role::Helper => Ok(Self::Helper),
                _ => Err(Error::Task(task::Error::InvalidParameter(
                    "role is not an aggregator",
                ))),
            }
        }

        /// Returns the [`Role`] corresponding to this value.
        pub(super) fn as_role(&self) -> Role {
            match self {
                Self::Leader => Role::Leader,
                Self::Helper => Role::Helper,
            }
        }
    }

    /// AggregationJob represents an aggregation job from the PPM specification.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub struct AggregationJob<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub aggregation_job_id: AggregationJobId,
        pub task_id: TaskId,
        #[derivative(Debug = "ignore")]
        pub aggregation_param: A::AggregationParam,
        pub state: AggregationJobState,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for AggregationJob<L, A>
    where
        A::AggregationParam: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.aggregation_job_id == other.aggregation_job_id
                && self.task_id == other.task_id
                && self.aggregation_param == other.aggregation_param
                && self.state == other.state
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for AggregationJob<L, A>
    where
        A::AggregationParam: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// AggregationJobState represents the state of an aggregation job. It corresponds to the
    /// AGGREGATION_JOB_STATE enum in the schema.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, ToSql, FromSql)]
    #[postgres(name = "aggregation_job_state")]
    pub enum AggregationJobState {
        #[postgres(name = "IN_PROGRESS")]
        InProgress,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "ABANDONED")]
        Abandoned,
    }

    /// LeaseToken represents an opaque value used to determine the identity of a lease.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub(super) struct LeaseToken([u8; Self::LENGTH]);

    impl LeaseToken {
        const LENGTH: usize = 16;

        pub(super) fn new(bytes: [u8; Self::LENGTH]) -> Self {
            Self(bytes)
        }

        pub(super) fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// Lease represents a time-constrained lease for exclusive access to some entity in Janus. It
    /// has an expiry after which it is no longer valid; another process can take a lease on the
    /// same entity after the expiration time.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Lease<T> {
        pub(super) leased: T,
        pub(super) lease_expiry_time: Time,
        pub(super) lease_token: LeaseToken,
        pub(super) lease_attempts: usize,
    }

    impl<T> Lease<T> {
        /// Create a new artificial lease with a random lease token, acquired for the first time;
        /// intended for use in unit tests.
        #[cfg(test)]
        pub fn new(leased: T, lease_expiry_time: Time) -> Self {
            use rand::random;
            Self {
                leased,
                lease_expiry_time,
                lease_token: LeaseToken(random()),
                lease_attempts: 1,
            }
        }

        /// Returns a reference to the leased entity.
        pub fn leased(&self) -> &T {
            &self.leased
        }

        /// Returns the lease expiry time.
        pub fn lease_expiry_time(&self) -> Time {
            self.lease_expiry_time
        }

        /// Returns the number of lease acquiries since the last successful release.
        pub fn lease_attempts(&self) -> usize {
            self.lease_attempts
        }
    }

    /// AcquiredAggregationJob represents an incomplete aggregation job whose lease has been
    /// acquired.
    #[derive(Clone, Debug, PartialOrd, Ord, Eq, PartialEq)]
    pub struct AcquiredAggregationJob {
        pub vdaf: VdafInstance,
        pub task_id: TaskId,
        pub aggregation_job_id: AggregationJobId,
    }

    /// AcquiredCollectJob represents an incomplete collect job whose lease has been acquired.
    #[derive(Clone, Debug, PartialOrd, Ord, Eq, PartialEq)]
    pub struct AcquiredCollectJob {
        pub vdaf: VdafInstance,
        pub task_id: TaskId,
        pub collect_job_id: Uuid,
    }

    /// ReportAggregation represents a the state of a single client report's ongoing aggregation.
    #[derive(Clone, Debug)]
    pub struct ReportAggregation<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub aggregation_job_id: AggregationJobId,
        pub task_id: TaskId,
        pub time: Time,
        pub nonce: Nonce,
        pub ord: i64,
        pub state: ReportAggregationState<L, A>,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for ReportAggregation<L, A>
    where
        A::PrepareState: PartialEq,
        A::PrepareMessage: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.aggregation_job_id == other.aggregation_job_id
                && self.task_id == other.task_id
                && self.time == other.time
                && self.nonce == other.nonce
                && self.ord == other.ord
                && self.state == other.state
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for ReportAggregation<L, A>
    where
        A::PrepareState: Eq,
        A::PrepareMessage: Eq,
        A::OutputShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// ReportAggregationState represents the state of a single report aggregation. It corresponds
    /// to the REPORT_AGGREGATION_STATE enum in the schema, along with the state-specific data.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub enum ReportAggregationState<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Start,
        Waiting(
            #[derivative(Debug = "ignore")] A::PrepareState,
            #[derivative(Debug = "ignore")] Option<A::PrepareMessage>,
        ),
        Finished(#[derivative(Debug = "ignore")] A::OutputShare),
        Failed(ReportShareError),
        Invalid,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> ReportAggregationState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(super) fn state_code(&self) -> ReportAggregationStateCode {
            match self {
                ReportAggregationState::Start => ReportAggregationStateCode::Start,
                ReportAggregationState::Waiting(_, _) => ReportAggregationStateCode::Waiting,
                ReportAggregationState::Finished(_) => ReportAggregationStateCode::Finished,
                ReportAggregationState::Failed(_) => ReportAggregationStateCode::Failed,
                ReportAggregationState::Invalid => ReportAggregationStateCode::Invalid,
            }
        }

        /// Returns the encoded values for the various messages which might be included in a
        /// ReportAggregationState. The order of returned values is preparation state, preparation
        /// message, output share, transition error.
        pub(super) fn encoded_values_from_state(&self) -> EncodedReportAggregationStateValues
        where
            A::PrepareState: Encode,
            for<'a> &'a A::OutputShare: Into<Vec<u8>>,
            for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        {
            let (prep_state, prep_msg, output_share, report_share_err) = match self {
                ReportAggregationState::Start => (None, None, None, None),
                ReportAggregationState::Waiting(prep_state, prep_msg) => (
                    Some(prep_state.get_encoded()),
                    prep_msg.as_ref().map(|msg| msg.get_encoded()),
                    None,
                    None,
                ),
                ReportAggregationState::Finished(output_share) => {
                    (None, None, Some(output_share.into()), None)
                }
                ReportAggregationState::Failed(report_share_err) => {
                    (None, None, None, Some(*report_share_err as i64))
                }
                ReportAggregationState::Invalid => (None, None, None, None),
            };
            EncodedReportAggregationStateValues {
                prep_state,
                prep_msg,
                output_share,
                report_share_err,
            }
        }
    }

    pub(super) struct EncodedReportAggregationStateValues {
        pub(super) prep_state: Option<Vec<u8>>,
        pub(super) prep_msg: Option<Vec<u8>>,
        pub(super) output_share: Option<Vec<u8>>,
        pub(super) report_share_err: Option<i64>,
    }

    // The private ReportAggregationStateCode exists alongside the public ReportAggregationState
    // because there is no apparent way to denote a Postgres enum literal without deriving
    // FromSql/ToSql on a Rust enum type, but it is not possible to derive FromSql/ToSql on a
    // non-C-style enum.
    #[derive(Debug, FromSql, ToSql)]
    #[postgres(name = "report_aggregation_state")]
    pub(super) enum ReportAggregationStateCode {
        #[postgres(name = "START")]
        Start,
        #[postgres(name = "WAITING")]
        Waiting,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "FAILED")]
        Failed,
        #[postgres(name = "INVALID")]
        Invalid,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for ReportAggregationState<L, A>
    where
        A::PrepareState: PartialEq,
        A::PrepareMessage: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (
                    Self::Waiting(lhs_prep_state, lhs_prep_msg),
                    Self::Waiting(rhs_prep_state, rhs_prep_msg),
                ) => lhs_prep_state == rhs_prep_state && lhs_prep_msg == rhs_prep_msg,
                (Self::Finished(lhs_out_share), Self::Finished(rhs_out_share)) => {
                    lhs_out_share == rhs_out_share
                }
                (Self::Failed(lhs_report_share_err), Self::Failed(rhs_report_share_err)) => {
                    lhs_report_share_err == rhs_report_share_err
                }
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for ReportAggregationState<L, A>
    where
        A::PrepareState: Eq,
        A::PrepareMessage: Eq,
        A::OutputShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// BatchUnitAggregation corresponds to a row in the `batch_unit_aggregations` table and
    /// represents the possibly-ongoing aggregation of the set of input shares that fall within the
    /// interval defined by `unit_interval_start` and the relevant task's `min_batch_duration`.
    /// This is the finest-grained possible aggregate share we can emit for this task, hence "batch
    /// unit". The aggregate share constructed to service a collect or aggregate share request
    /// consists of one or more `BatchUnitAggregation`s merged together.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub(crate) struct BatchUnitAggregation<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this aggregation result.
        pub(crate) task_id: TaskId,
        /// This is an aggregation over report shares whose timestamp falls within the interval
        /// starting at this time and of duration equal to the corresponding task's
        /// `min_batch_duration`. `unit_interval_start` is aligned to `min_batch_duration`.
        pub(crate) unit_interval_start: Time,
        /// The VDAF aggregation parameter used to prepare and accumulate input shares.
        #[derivative(Debug = "ignore")]
        pub(crate) aggregation_param: A::AggregationParam,
        /// The aggregate over all the input shares that have been prepared so far by this
        /// aggregator.
        #[derivative(Debug = "ignore")]
        pub(crate) aggregate_share: A::AggregateShare,
        /// The number of reports currently included in this aggregate sahre.
        pub(crate) report_count: u64,
        /// Checksum over the aggregated report shares, as described in §4.4.4.3.
        #[derivative(Debug = "ignore")]
        pub(crate) checksum: NonceChecksum,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for BatchUnitAggregation<L, A>
    where
        A::AggregationParam: PartialEq,
        A::AggregateShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.unit_interval_start == other.unit_interval_start
                && self.aggregation_param == other.aggregation_param
                && self.aggregate_share == other.aggregate_share
                && self.report_count == other.report_count
                && self.checksum == other.checksum
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for BatchUnitAggregation<L, A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// CollectJob represents a row in the `collect_jobs` table, used by leaders to represent
    /// running collect jobs and store the results of completed ones.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub(crate) struct CollectJob<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The unique identifier for the collect job.
        pub(crate) collect_job_id: Uuid,
        /// The task ID for this aggregate share.
        pub(crate) task_id: TaskId,
        /// The batch interval covered by the aggregate share.
        pub(crate) batch_interval: Interval,
        /// The VDAF aggregation parameter used to prepare and aggregate input shares.
        #[derivative(Debug = "ignore")]
        pub(crate) aggregation_param: A::AggregationParam,
        /// The current state of the collect job.
        pub(crate) state: CollectJobState<L, A>,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for CollectJob<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: PartialEq,
        CollectJobState<L, A>: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.collect_job_id == other.collect_job_id
                && self.task_id == other.task_id
                && self.batch_interval == other.batch_interval
                && self.aggregation_param == other.aggregation_param
                && self.state == other.state
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for CollectJob<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregationParam: Eq,
        CollectJobState<L, A>: Eq,
    {
    }

    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub(crate) enum CollectJobState<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Start,
        Finished {
            /// The helper's encrypted aggregate share over the input shares in the interval.
            encrypted_helper_aggregate_share: HpkeCiphertext,
            /// The leader's aggregate share over the input shares in the interval.
            #[derivative(Debug = "ignore")]
            leader_aggregate_share: A::AggregateShare,
        },
        Abandoned,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for CollectJobState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregateShare: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (
                    Self::Finished {
                        encrypted_helper_aggregate_share: self_helper_agg_share,
                        leader_aggregate_share: self_leader_agg_share,
                    },
                    Self::Finished {
                        encrypted_helper_aggregate_share: other_helper_agg_share,
                        leader_aggregate_share: other_leader_agg_share,
                    },
                ) => {
                    self_helper_agg_share == other_helper_agg_share
                        && self_leader_agg_share == other_leader_agg_share
                }
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for CollectJobState<L, A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::AggregateShare: Eq,
    {
    }

    #[derive(Debug, FromSql, ToSql)]
    #[postgres(name = "collect_job_state")]
    pub(super) enum CollectJobStateCode {
        #[postgres(name = "START")]
        Start,
        #[postgres(name = "FINISHED")]
        Finished,
        #[postgres(name = "ABANDONED")]
        Abandoned,
    }

    /// AggregateShareJob represents a row in the `aggregate_share_jobs` table, used by helpers to
    /// store the results of handling an AggregateShareReq from the leader.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub(crate) struct AggregateShareJob<const L: usize, A: vdaf::Aggregator<L>>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        /// The task ID for this aggregate share .
        pub(crate) task_id: TaskId,
        /// The batch interval covered by the aggregate share.
        pub(crate) batch_interval: Interval,
        /// The VDAF aggregation parameter used to prepare and aggregate input shares.
        #[derivative(Debug = "ignore")]
        pub(crate) aggregation_param: A::AggregationParam,
        /// The aggregate share over the input shares in the interval.
        #[derivative(Debug = "ignore")]
        pub(crate) helper_aggregate_share: A::AggregateShare,
        /// The number of reports included in the aggregate share.
        pub(crate) report_count: u64,
        /// Checksum over the aggregated report shares, as described in §4.4.4.3.
        #[derivative(Debug = "ignore")]
        pub(crate) checksum: NonceChecksum,
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> PartialEq for AggregateShareJob<L, A>
    where
        A::AggregationParam: PartialEq,
        A::AggregateShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.task_id == other.task_id
                && self.batch_interval == other.batch_interval
                && self.aggregation_param == other.aggregation_param
                && self.helper_aggregate_share == other.helper_aggregate_share
                && self.report_count == other.report_count
                && self.checksum == other.checksum
        }
    }

    impl<const L: usize, A: vdaf::Aggregator<L>> Eq for AggregateShareJob<L, A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::{Crypter, Datastore};
    use deadpool_postgres::{Manager, Pool};
    use janus_core::time::Clock;
    use lazy_static::lazy_static;
    use rand::{distributions::Standard, thread_rng, Rng};
    use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
    use std::{
        env::{self, VarError},
        process::Command,
        str::FromStr,
    };
    use testcontainers::{images::postgres::Postgres, Container, RunnableImage};
    use tokio_postgres::{Config, NoTls};
    use tracing::trace;

    /// The Janus database schema.
    pub const SCHEMA: &str = include_str!("../../db/schema.sql");

    lazy_static! {
        static ref CONTAINER_CLIENT: testcontainers::clients::Cli =
            testcontainers::clients::Cli::default();
    }

    /// DbHandle represents a handle to a running (ephemeral) database. Dropping this value
    /// causes the database to be shut down & cleaned up.
    pub struct DbHandle {
        _db_container: Container<'static, Postgres>,
        connection_string: String,
        port_number: u16,
        datastore_key_bytes: Vec<u8>,
    }

    impl DbHandle {
        /// Retrieve a datastore attached to the ephemeral database.
        pub fn datastore<C: Clock>(&self, clock: C) -> Datastore<C> {
            // Create a crypter based on the generated key bytes.
            let datastore_key =
                LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &self.datastore_key_bytes).unwrap());
            let crypter = Crypter::new(Vec::from([datastore_key]));

            Datastore::new(self.pool(), crypter, clock)
        }

        /// Retrieve a Postgres connection pool attached to the ephemeral database.
        pub fn pool(&self) -> Pool {
            let cfg = Config::from_str(&self.connection_string).unwrap();
            let conn_mgr = Manager::new(cfg, NoTls);
            Pool::builder(conn_mgr).build().unwrap()
        }

        /// Get a PostgreSQL connection string to connect to the temporary database.
        pub fn connection_string(&self) -> &str {
            &self.connection_string
        }

        /// Get the bytes of the key used to encrypt sensitive datastore values.
        pub fn datastore_key_bytes(&self) -> &[u8] {
            &self.datastore_key_bytes
        }

        /// Get the port number that the temporary database is exposed on, via the 127.0.0.1
        /// loopback interface.
        pub fn port_number(&self) -> u16 {
            self.port_number
        }

        /// Open an interactive terminal to the database in a new terminal window, and block
        /// until the user exits from the terminal. This is intended to be used while
        /// debugging tests.
        ///
        /// By default, this will invoke `gnome-terminal`, which is readily available on
        /// GNOME-based Linux distributions. To use a different terminal, set the environment
        /// variable `JANUS_SHELL_CMD` to a shell command that will open a new terminal window
        /// of your choice. This command line should include a "{}" in the position appropriate
        /// for what command the terminal should run when it opens. A `psql` invocation will
        /// be substituted in place of the "{}". Note that this shell command must not exit
        /// immediately once the terminal is spawned; it should continue running as long as the
        /// terminal is open. If the command provided exits too soon, then the test will
        /// continue running without intervention, leading to the test's database shutting
        /// down.
        ///
        /// # Example
        ///
        /// ```text
        /// JANUS_SHELL_CMD='xterm -e {}' cargo test
        /// ```
        pub fn interactive_db_terminal(&self) {
            let mut command = match env::var("JANUS_SHELL_CMD") {
                Ok(shell_cmd) => {
                    if !shell_cmd.contains("{}") {
                        panic!("JANUS_SHELL_CMD should contain a \"{{}}\" to denote where the database command should be substituted");
                    }

                    #[cfg(not(windows))]
                    let mut command = {
                        let mut command = Command::new("sh");
                        command.arg("-c");
                        command
                    };

                    #[cfg(windows)]
                    let mut command = {
                        let mut command = Command::new("cmd.exe");
                        command.arg("/c");
                        command
                    };

                    let psql_command = format!(
                        "psql --host=127.0.0.1 --user=postgres -p {}",
                        self.port_number(),
                    );
                    command.arg(shell_cmd.replacen("{}", &psql_command, 1));
                    command
                }

                Err(VarError::NotPresent) => {
                    let mut command = Command::new("gnome-terminal");
                    command.args([
                        "--wait",
                        "--",
                        "psql",
                        "--host=127.0.0.1",
                        "--user=postgres",
                        "-p",
                    ]);
                    command.arg(format!("{}", self.port_number()));
                    command
                }

                Err(VarError::NotUnicode(_)) => {
                    panic!("JANUS_SHELL_CMD contains invalid unicode data");
                }
            };
            command.spawn().unwrap().wait().unwrap();
        }
    }

    impl Drop for DbHandle {
        fn drop(&mut self) {
            trace!(connection_string = %self.connection_string, "Dropping ephemeral Postgres container");
        }
    }

    /// ephemeral_db_handle creates a new ephemeral database which has no schema & is empty.
    /// Dropping the return value causes the database to be shut down & cleaned up.
    ///
    /// Most users will want to call ephemeral_datastore() instead, which applies the Janus
    /// schema and creates a datastore.
    pub fn ephemeral_db_handle() -> DbHandle {
        // Start an instance of Postgres running in a container.
        let db_container =
            CONTAINER_CLIENT.run(RunnableImage::from(Postgres::default()).with_tag("14-alpine"));

        // Compute the Postgres connection string.
        const POSTGRES_DEFAULT_PORT: u16 = 5432;
        let port_number = db_container.get_host_port_ipv4(POSTGRES_DEFAULT_PORT);
        let connection_string = format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            port_number,
        );
        trace!("Postgres container is up with URL {}", connection_string);

        // Create a random (ephemeral) key.
        let datastore_key_bytes = generate_aead_key_bytes();

        DbHandle {
            _db_container: db_container,
            connection_string,
            port_number,
            datastore_key_bytes,
        }
    }

    /// ephemeral_datastore creates a new Datastore instance backed by an ephemeral database
    /// which has the Janus schema applied but is otherwise empty.
    ///
    /// Dropping the second return value causes the database to be shut down & cleaned up.
    pub async fn ephemeral_datastore<C: Clock>(clock: C) -> (Datastore<C>, DbHandle) {
        let db_handle = ephemeral_db_handle();
        let client = db_handle.pool().get().await.unwrap();
        client.batch_execute(SCHEMA).await.unwrap();
        (db_handle.datastore(clock), db_handle)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastore::{
            models::{AggregationJobState, CollectJobState},
            test_util::{ephemeral_datastore, generate_aead_key},
        },
        message::{BatchSelector, ReportShareError},
        task::{VdafInstance, PRIO3_AES128_VERIFY_KEY_LENGTH},
    };
    use assert_matches::assert_matches;
    use chrono::NaiveDate;
    use futures::future::try_join_all;
    use janus_core::{
        hpke::{self, associated_data_for_aggregate_share, HpkeApplicationInfo, Label},
        message::{Duration, ExtensionType, HpkeConfigId, Interval, Role, Time},
        test_util::{
            dummy_vdaf::{self, AggregationParam},
            install_test_trace_subscriber,
        },
        time::MockClock,
    };
    use prio::{
        field::{Field128, Field64},
        vdaf::{
            poplar1::{IdpfInput, Poplar1, ToyIdpf},
            prg::PrgAes128,
            prio3::{Prio3, Prio3Aes128Count},
            AggregateShare, PrepareTransition,
        },
    };
    use rand::{distributions::Standard, random, thread_rng, Rng};
    use std::{
        collections::{BTreeSet, HashMap, HashSet},
        iter, mem,
        sync::Arc,
    };

    #[tokio::test]
    async fn roundtrip_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let values = [
            (
                random(),
                janus_core::task::VdafInstance::Prio3Aes128Count,
                Role::Leader,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Prio3Aes128CountVec { length: 8 },
                Role::Leader,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Prio3Aes128CountVec { length: 64 },
                Role::Helper,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Prio3Aes128Sum { bits: 64 },
                Role::Helper,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Prio3Aes128Sum { bits: 32 },
                Role::Helper,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Prio3Aes128Histogram {
                    buckets: vec![0, 100, 200, 400],
                },
                Role::Leader,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Prio3Aes128Histogram {
                    buckets: vec![0, 25, 50, 75, 100],
                },
                Role::Leader,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Poplar1 { bits: 8 },
                Role::Helper,
            ),
            (
                random(),
                janus_core::task::VdafInstance::Poplar1 { bits: 64 },
                Role::Helper,
            ),
        ];

        // Insert tasks, check that they can be retrieved by ID.
        let mut want_tasks = HashMap::new();
        for (task_id, vdaf, role) in values {
            let task = Task::new_dummy(task_id, vdaf.into(), role);
            want_tasks.insert(task_id, task.clone());

            let err = ds
                .run_tx(|tx| Box::pin(async move { tx.delete_task(task_id).await }))
                .await
                .unwrap_err();
            assert_matches!(err, Error::MutationTargetNotFound);

            let retrieved_task = ds
                .run_tx(|tx| Box::pin(async move { tx.get_task(task_id).await }))
                .await
                .unwrap();
            assert_eq!(None, retrieved_task);

            ds.put_task(&task).await.unwrap();

            let retrieved_task = ds
                .run_tx(|tx| Box::pin(async move { tx.get_task(task_id).await }))
                .await
                .unwrap();
            assert_eq!(Some(&task), retrieved_task.as_ref());

            ds.run_tx(|tx| Box::pin(async move { tx.delete_task(task_id).await }))
                .await
                .unwrap();

            let retrieved_task = ds
                .run_tx(|tx| Box::pin(async move { tx.get_task(task_id).await }))
                .await
                .unwrap();
            assert_eq!(None, retrieved_task);

            let err = ds
                .run_tx(|tx| Box::pin(async move { tx.delete_task(task_id).await }))
                .await
                .unwrap_err();
            assert_matches!(err, Error::MutationTargetNotFound);

            // Rewrite & retrieve the task again, to test that the delete is "clean" in the sense
            // that it deletes all task-related data (& therefore does not conflict with a later
            // write to the same task_id).
            ds.put_task(&task).await.unwrap();

            let retrieved_task = ds
                .run_tx(|tx| Box::pin(async move { tx.get_task(task_id).await }))
                .await
                .unwrap();
            assert_eq!(Some(&task), retrieved_task.as_ref());
        }

        let got_tasks: HashMap<TaskId, Task> = ds
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap()
            .into_iter()
            .map(|task| (task.id, task))
            .collect();
        assert_eq!(want_tasks, got_tasks);
    }

    #[tokio::test]
    async fn roundtrip_report() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let report = Report::new(
            random(),
            ReportMetadata::new(
                Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(12345),
                vec![
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
                ],
            ),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::from([
                HpkeCiphertext::new(
                    HpkeConfigId::from(12),
                    Vec::from("encapsulated_context_0"),
                    Vec::from("payload_0"),
                ),
                HpkeCiphertext::new(
                    HpkeConfigId::from(13),
                    Vec::from("encapsulated_context_1"),
                    Vec::from("payload_1"),
                ),
            ]),
        );

        ds.run_tx(|tx| {
            let report = report.clone();
            Box::pin(async move {
                tx.put_task(&Task::new_dummy(
                    *report.task_id(),
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await?;
                tx.put_client_report(&report).await
            })
        })
        .await
        .unwrap();

        let retrieved_report = ds
            .run_tx(|tx| {
                let task_id = *report.task_id();
                let nonce = *report.metadata().nonce();
                Box::pin(async move { tx.get_client_report(task_id, nonce).await })
            })
            .await
            .unwrap();

        assert_eq!(Some(report), retrieved_report);
    }

    #[tokio::test]
    async fn report_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report(
                        random(),
                        Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        assert_eq!(rslt, None);
    }

    #[tokio::test]
    async fn get_unaggregated_client_report_nonces_for_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let when = MockClock::default()
            .now()
            .to_batch_unit_interval_start(Duration::from_seconds(1000))
            .unwrap();
        let task_id = random();
        let unrelated_task_id = random();

        let first_unaggregated_report = Report::new(
            task_id,
            ReportMetadata::new(random(), when, Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );
        let second_unaggregated_report = Report::new(
            task_id,
            ReportMetadata::new(random(), when, Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );
        let aggregated_report = Report::new(
            task_id,
            ReportMetadata::new(random(), when, Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );
        let unrelated_report = Report::new(
            unrelated_task_id,
            ReportMetadata::new(random(), when, Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );

        // Set up state.
        ds.run_tx(|tx| {
            let (
                first_unaggregated_report,
                second_unaggregated_report,
                aggregated_report,
                unrelated_report,
            ) = (
                first_unaggregated_report.clone(),
                second_unaggregated_report.clone(),
                aggregated_report.clone(),
                unrelated_report.clone(),
            );

            Box::pin(async move {
                tx.put_task(&Task::new_dummy(
                    task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await?;
                tx.put_task(&Task::new_dummy(
                    unrelated_task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await?;

                tx.put_client_report(&first_unaggregated_report).await?;
                tx.put_client_report(&second_unaggregated_report).await?;
                tx.put_client_report(&aggregated_report).await?;
                tx.put_client_report(&unrelated_report).await?;

                let aggregation_job_id = random();
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                > {
                    aggregation_job_id,
                    task_id,
                    aggregation_param: (),
                    state: AggregationJobState::InProgress,
                })
                .await?;
                tx.put_report_aggregation(
                    &ReportAggregation {
                        aggregation_job_id,
                        task_id,
                        time: *aggregated_report.metadata().time(),
                        nonce: *aggregated_report.metadata().nonce(),
                        ord: 0,
                        state: ReportAggregationState::<
                            PRIO3_AES128_VERIFY_KEY_LENGTH,
                            Prio3Aes128Count,
                        >::Start,
                    },
                )
                .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results.
        let got_reports = HashSet::from_iter(
            ds.run_tx(|tx| {
                Box::pin(async move {
                    tx.get_unaggregated_client_report_nonces_for_task(task_id)
                        .await
                })
            })
            .await
            .unwrap(),
        );

        assert_eq!(
            got_reports,
            HashSet::from([
                (
                    *first_unaggregated_report.metadata().time(),
                    *first_unaggregated_report.metadata().nonce()
                ),
                (
                    *second_unaggregated_report.metadata().time(),
                    *second_unaggregated_report.metadata().nonce()
                ),
            ]),
        );
    }

    #[tokio::test]
    async fn get_unaggregated_client_report_nonces_with_agg_param_for_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let unrelated_task_id = random();

        let first_unaggregated_report = Report::new(
            task_id,
            ReportMetadata::new(random(), Time::from_seconds_since_epoch(12345), Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );
        let second_unaggregated_report = Report::new(
            task_id,
            ReportMetadata::new(random(), Time::from_seconds_since_epoch(12346), Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );
        let aggregated_report = Report::new(
            task_id,
            ReportMetadata::new(random(), Time::from_seconds_since_epoch(12347), Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );
        let unrelated_report = Report::new(
            unrelated_task_id,
            ReportMetadata::new(random(), Time::from_seconds_since_epoch(12348), Vec::new()),
            Vec::new(), // TODO(#473): fill out public_share once possible
            Vec::new(),
        );

        // Set up state.
        ds.run_tx(|tx| {
            let (
                first_unaggregated_report,
                second_unaggregated_report,
                aggregated_report,
                unrelated_report,
            ) = (
                first_unaggregated_report.clone(),
                second_unaggregated_report.clone(),
                aggregated_report.clone(),
                unrelated_report.clone(),
            );

            Box::pin(async move {
                tx.put_task(&Task::new_dummy(task_id, VdafInstance::Fake, Role::Leader))
                    .await?;
                tx.put_task(&Task::new_dummy(
                    unrelated_task_id,
                    VdafInstance::Fake,
                    Role::Leader,
                ))
                .await?;

                tx.put_client_report(&first_unaggregated_report).await?;
                tx.put_client_report(&second_unaggregated_report).await?;
                tx.put_client_report(&aggregated_report).await?;
                tx.put_client_report(&unrelated_report).await?;

                // There are no client reports submitted under this task, so we shouldn't see
                // this aggregation parameter at all.
                tx.put_collect_job(
                    unrelated_task_id,
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    &[255],
                )
                .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results. None should be returned yet, as there are no relevant
        // collect requests.
        let got_reports = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_unaggregated_client_report_nonces_by_collect_for_task::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(task_id)
                        .await
                })
            })
            .await
            .unwrap();
        assert!(got_reports.is_empty());

        // Add collect jobs, and mark one report as having already been aggregated once.
        ds.run_tx(|tx| {
            let aggregated_report_time = *aggregated_report.metadata().time();
            let aggregated_report_nonce = *aggregated_report.metadata().nonce();
            Box::pin(async move {
                tx.put_collect_job(
                    task_id,
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    &[0],
                )
                .await?;
                tx.put_collect_job(
                    task_id,
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    &[1],
                )
                .await?;
                // No reports fall in this interval, so we shouldn't see it's aggregation
                // parameter at all.
                tx.put_collect_job(
                    task_id,
                    Interval::new(
                        Time::from_seconds_since_epoch(8 * 3600),
                        Duration::from_hours(8).unwrap(),
                    )
                    .unwrap(),
                    &[2],
                )
                .await?;

                let aggregation_job_id = random();
                tx.put_aggregation_job(&AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                    aggregation_job_id,
                    task_id,
                    aggregation_param: AggregationParam(0),
                    state: AggregationJobState::InProgress,
                })
                .await?;
                tx.put_report_aggregation(
                    &ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        time: aggregated_report_time,
                        nonce: aggregated_report_nonce,
                        ord: 0,
                        state: ReportAggregationState::Start,
                    },
                )
                .await
            })
        })
        .await
        .unwrap();

        // Run query & verify results. We should have two unaggregated reports with one parameter,
        // and three with another.
        let mut got_reports = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_unaggregated_client_report_nonces_by_collect_for_task::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(task_id)
                        .await
                })
            })
            .await
            .unwrap();

        let mut expected_reports = Vec::from([
            (
                *first_unaggregated_report.metadata().time(),
                *first_unaggregated_report.metadata().nonce(),
                AggregationParam(0),
            ),
            (
                *first_unaggregated_report.metadata().time(),
                *first_unaggregated_report.metadata().nonce(),
                AggregationParam(1),
            ),
            (
                *second_unaggregated_report.metadata().time(),
                *second_unaggregated_report.metadata().nonce(),
                AggregationParam(0),
            ),
            (
                *second_unaggregated_report.metadata().time(),
                *second_unaggregated_report.metadata().nonce(),
                AggregationParam(1),
            ),
            (
                *aggregated_report.metadata().time(),
                *aggregated_report.metadata().nonce(),
                AggregationParam(1),
            ),
        ]);
        got_reports.sort();
        expected_reports.sort();
        assert_eq!(got_reports, expected_reports);

        // Add overlapping collect jobs with repeated aggregation parameters. Make sure we don't
        // repeat result tuples, which could lead to double counting in batch unit aggregations.
        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.put_collect_job(
                    task_id,
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(16).unwrap(),
                    )
                    .unwrap(),
                    &[0],
                )
                .await?;
                tx.put_collect_job(
                    task_id,
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_hours(16).unwrap(),
                    )
                    .unwrap(),
                    &[1],
                )
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify that we get the same result.
        let mut got_reports = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_unaggregated_client_report_nonces_by_collect_for_task::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(task_id)
                        .await
                })
            })
            .await
            .unwrap();
        got_reports.sort();
        assert_eq!(got_reports, expected_reports);
    }

    #[tokio::test]
    async fn roundtrip_report_share() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let task_id = random();
        let report_share = ReportShare::new(
            ReportMetadata::new(
                Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(12345),
                Vec::from([
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
                    Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
                ]),
            ),
            Vec::from("public_share"),
            HpkeCiphertext::new(
                HpkeConfigId::from(12),
                Vec::from("encapsulated_context_0"),
                Vec::from("payload_0"),
            ),
        );

        let got_report_share_exists = ds
            .run_tx(|tx| {
                let report_share = report_share.clone();
                Box::pin(async move {
                    tx.put_task(&Task::new_dummy(
                        task_id,
                        janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                        Role::Leader,
                    ))
                    .await?;
                    let report_share_exists = tx
                        .check_report_share_exists(task_id, *report_share.metadata().nonce())
                        .await?;
                    tx.put_report_share(task_id, &report_share).await?;
                    Ok(report_share_exists)
                })
            })
            .await
            .unwrap();
        assert!(!got_report_share_exists);

        let (got_report_share_exists, got_task_id, got_extensions, got_input_shares) = ds
            .run_tx(|tx| {
                let report_share_metadata = report_share.metadata().clone();
                Box::pin(async move {
                    let report_share_exists = tx.check_report_share_exists(task_id, *report_share_metadata.nonce()).await?;

                    let time = report_share_metadata.time();
                    let nonce = report_share_metadata.nonce();
                    let row = tx
                        .tx
                        .query_one(
                            "SELECT tasks.task_id, client_reports.nonce_time, client_reports.nonce_rand, client_reports.extensions, client_reports.input_shares
                            FROM client_reports JOIN tasks ON tasks.id = client_reports.task_id
                            WHERE nonce_time = $1 AND nonce_rand = $2",
                            &[
                                /* nonce_time */ &time.as_naive_date_time(),
                                /* nonce_rand */ &nonce.as_ref()
                            ],
                        )
                        .await?;

                    let task_id = TaskId::get_decoded(row.get("task_id"))?;

                    let maybe_extensions: Option<Vec<u8>> = row.get("extensions");
                    let maybe_input_shares: Option<Vec<u8>> = row.get("input_shares");

                    Ok((report_share_exists, task_id, maybe_extensions, maybe_input_shares))
                })
            })
            .await
            .unwrap();

        assert!(got_report_share_exists);
        assert_eq!(task_id, got_task_id);
        assert!(got_extensions.is_none());
        assert!(got_input_shares.is_none());
    }

    #[tokio::test]
    async fn roundtrip_aggregation_job() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        // We use Poplar1 for this test as it has a non-trivial aggregation parameter, to allow
        // better exercising the serialization/deserialization roundtrip of the aggregation_param.
        const PRG_SEED_SIZE: usize = 16;
        type ToyPoplar1 = Poplar1<ToyIdpf<Field128>, PrgAes128, PRG_SEED_SIZE>;
        let aggregation_job = AggregationJob::<PRG_SEED_SIZE, ToyPoplar1> {
            aggregation_job_id: random(),
            task_id: random(),
            aggregation_param: BTreeSet::from([
                IdpfInput::new("abc".as_bytes(), 0).unwrap(),
                IdpfInput::new("def".as_bytes(), 1).unwrap(),
            ]),
            state: AggregationJobState::InProgress,
        };

        ds.run_tx(|tx| {
            let aggregation_job = aggregation_job.clone();
            Box::pin(async move {
                tx.put_task(&Task::new_dummy(
                    aggregation_job.task_id,
                    janus_core::task::VdafInstance::Poplar1 { bits: 64 }.into(),
                    Role::Leader,
                ))
                .await?;
                tx.put_aggregation_job(&aggregation_job).await
            })
        })
        .await
        .unwrap();

        let got_aggregation_job = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_aggregation_job(
                        aggregation_job.task_id,
                        aggregation_job.aggregation_job_id,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(Some(&aggregation_job), got_aggregation_job.as_ref());

        let mut new_aggregation_job = aggregation_job.clone();
        new_aggregation_job.state = AggregationJobState::Finished;
        ds.run_tx(|tx| {
            let new_aggregation_job = new_aggregation_job.clone();
            Box::pin(async move { tx.update_aggregation_job(&new_aggregation_job).await })
        })
        .await
        .unwrap();

        let got_aggregation_job = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_aggregation_job(
                        aggregation_job.task_id,
                        aggregation_job.aggregation_job_id,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(Some(new_aggregation_job), got_aggregation_job);
    }

    #[tokio::test]
    async fn aggregation_job_acquire_release() {
        // Setup: insert a few aggregation jobs.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const AGGREGATION_JOB_COUNT: usize = 10;
        let task_id = random();
        let mut aggregation_job_ids: Vec<_> = thread_rng()
            .sample_iter(Standard)
            .take(AGGREGATION_JOB_COUNT)
            .collect();
        aggregation_job_ids.sort();

        ds.run_tx(|tx| {
            let aggregation_job_ids = aggregation_job_ids.clone();
            Box::pin(async move {
                // Write a few aggregation jobs we expect to be able to retrieve with
                // acquire_incomplete_aggregation_jobs().
                tx.put_task(&Task::new_dummy(
                    task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await?;
                for aggregation_job_id in aggregation_job_ids {
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;
                }

                // Write an aggregation job that is finished. We don't want to retrieve this one.
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                > {
                    aggregation_job_id: random(),
                    task_id,
                    aggregation_param: (),
                    state: AggregationJobState::Finished,
                })
                .await?;

                // Write an aggregation job for a task that we are taking on the helper role for.
                // We don't want to retrieve this one, either.
                let helper_task_id = random();
                tx.put_task(&Task::new_dummy(
                    helper_task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Helper,
                ))
                .await?;
                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                > {
                    aggregation_job_id: random(),
                    task_id: helper_task_id,
                    aggregation_param: (),
                    state: AggregationJobState::InProgress,
                })
                .await
            })
        })
        .await
        .unwrap();

        // Run: run several transactions that all call acquire_incomplete_aggregation_jobs
        // concurrently. (We do things concurrently in an attempt to make sure the
        // mutual-exclusivity works properly.)
        const TX_COUNT: usize = 10;
        const LEASE_DURATION: Duration = Duration::from_seconds(300);
        const MAXIMUM_ACQUIRE_COUNT: usize = 4;

        // Sanity check constants: ensure we acquire jobs across multiple calls to exercise the
        // maximum-jobs-per-call functionality. Make sure we're attempting to acquire enough jobs
        // in total to cover the number of acquirable jobs we created.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MAXIMUM_ACQUIRE_COUNT < AGGREGATION_JOB_COUNT);
            assert!(MAXIMUM_ACQUIRE_COUNT.checked_mul(TX_COUNT).unwrap() >= AGGREGATION_JOB_COUNT);
        }

        let results = try_join_all(
            iter::repeat_with(|| {
                ds.run_tx(|tx| {
                    Box::pin(async move {
                        tx.acquire_incomplete_aggregation_jobs(
                            LEASE_DURATION,
                            MAXIMUM_ACQUIRE_COUNT,
                        )
                        .await
                    })
                })
            })
            .take(TX_COUNT),
        )
        .await
        .unwrap();

        // Verify: check that we got all of the desired aggregation jobs, with no duplication, and
        // the expected lease expiry.
        let want_expiry_time = clock.now().add(LEASE_DURATION).unwrap();
        let want_aggregation_jobs: Vec<_> = aggregation_job_ids
            .iter()
            .map(|&agg_job_id| {
                (
                    AcquiredAggregationJob {
                        task_id,
                        vdaf: janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                        aggregation_job_id: agg_job_id,
                    },
                    want_expiry_time,
                )
            })
            .collect();
        let mut got_leases = Vec::new();
        for result in results {
            assert!(result.len() <= MAXIMUM_ACQUIRE_COUNT);
            got_leases.extend(result.into_iter());
        }
        let mut got_aggregation_jobs: Vec<_> = got_leases
            .iter()
            .map(|lease| {
                assert_eq!(lease.lease_attempts(), 1);
                (lease.leased().clone(), lease.lease_expiry_time())
            })
            .collect();
        got_aggregation_jobs.sort();

        assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

        // Run: release a few jobs, then attempt to acquire jobs again.
        const RELEASE_COUNT: usize = 2;

        // Sanity check constants: ensure we release fewer jobs than we're about to acquire to
        // ensure we can acquire them in all in a single call, while leaving headroom to acquire
        // at least one unwanted job if there is a logic bug.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(RELEASE_COUNT < MAXIMUM_ACQUIRE_COUNT);
        }

        let leases_to_release: Vec<_> = got_leases.into_iter().take(RELEASE_COUNT).collect();
        let mut jobs_to_release: Vec<_> = leases_to_release
            .iter()
            .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
            .collect();
        jobs_to_release.sort();
        ds.run_tx(|tx| {
            let leases_to_release = leases_to_release.clone();
            Box::pin(async move {
                for lease in leases_to_release {
                    tx.release_aggregation_job(&lease).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        let mut got_aggregation_jobs: Vec<_> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.acquire_incomplete_aggregation_jobs(LEASE_DURATION, MAXIMUM_ACQUIRE_COUNT)
                        .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|lease| {
                assert_eq!(lease.lease_attempts(), 1);
                (lease.leased().clone(), lease.lease_expiry_time())
            })
            .collect();
        got_aggregation_jobs.sort();

        // Verify: we should have re-acquired the jobs we released.
        assert_eq!(jobs_to_release, got_aggregation_jobs);

        // Run: advance time by the lease duration (which implicitly releases the jobs), and attempt
        // to acquire aggregation jobs again.
        clock.advance(LEASE_DURATION);
        let want_expiry_time = clock.now().add(LEASE_DURATION).unwrap();
        let want_aggregation_jobs: Vec<_> = aggregation_job_ids
            .iter()
            .map(|&job_id| {
                (
                    AcquiredAggregationJob {
                        task_id,
                        vdaf: janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                        aggregation_job_id: job_id,
                    },
                    want_expiry_time,
                )
            })
            .collect();
        let mut got_aggregation_jobs: Vec<_> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    // This time, we just acquire all jobs in a single go for simplicity -- we've
                    // already tested the maximum acquire count functionality above.
                    tx.acquire_incomplete_aggregation_jobs(LEASE_DURATION, AGGREGATION_JOB_COUNT)
                        .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|lease| {
                let job = (lease.leased().clone(), lease.lease_expiry_time());
                let expected_attempts = if jobs_to_release.contains(&job) { 1 } else { 2 };
                assert_eq!(lease.lease_attempts(), expected_attempts);
                job
            })
            .collect();
        got_aggregation_jobs.sort();

        // Verify: we got all the jobs.
        assert_eq!(want_aggregation_jobs, got_aggregation_jobs);

        // Run: advance time again to release jobs, acquire a single job, modify its lease token
        // to simulate a previously-held lease, and attempt to release it. Verify that releasing
        // fails.
        clock.advance(LEASE_DURATION);
        let mut lease = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(LEASE_DURATION, 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        let original_lease_token = mem::replace(&mut lease.lease_token, LeaseToken::new(random()));
        ds.run_tx(|tx| {
            let lease = lease.clone();
            Box::pin(async move { tx.release_aggregation_job(&lease).await })
        })
        .await
        .unwrap_err();

        // Replace the original lease token and verify that we can release successfully with it in
        // place.
        lease.lease_token = original_lease_token;
        ds.run_tx(|tx| {
            let lease = lease.clone();
            Box::pin(async move { tx.release_aggregation_job(&lease).await })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn aggregation_job_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        random(),
                        random(),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(rslt, None);

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.update_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &AggregationJob {
                            aggregation_job_id: random(),
                            task_id: random(),
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        },
                    )
                    .await
                })
            })
            .await;
        assert_matches!(rslt, Err(Error::MutationTargetNotFound));
    }

    #[tokio::test]
    async fn get_aggregation_jobs_for_task_id() {
        // Setup.
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        // We use Poplar1 for this test as it has a non-trivial aggregation parameter, to allow
        // better exercising the serialization/deserialization roundtrip of the aggregation_param.
        const PRG_SEED_SIZE: usize = 16;
        type ToyPoplar1 = Poplar1<ToyIdpf<Field128>, PrgAes128, PRG_SEED_SIZE>;
        let task_id = random();
        let first_aggregation_job = AggregationJob::<PRG_SEED_SIZE, ToyPoplar1> {
            aggregation_job_id: random(),
            task_id,
            aggregation_param: BTreeSet::from([
                IdpfInput::new("abc".as_bytes(), 0).unwrap(),
                IdpfInput::new("def".as_bytes(), 1).unwrap(),
            ]),
            state: AggregationJobState::InProgress,
        };
        let second_aggregation_job = AggregationJob::<PRG_SEED_SIZE, ToyPoplar1> {
            aggregation_job_id: random(),
            task_id,
            aggregation_param: BTreeSet::from([
                IdpfInput::new("ghi".as_bytes(), 2).unwrap(),
                IdpfInput::new("jkl".as_bytes(), 3).unwrap(),
            ]),
            state: AggregationJobState::InProgress,
        };

        ds.run_tx(|tx| {
            let (first_aggregation_job, second_aggregation_job) = (
                first_aggregation_job.clone(),
                second_aggregation_job.clone(),
            );
            Box::pin(async move {
                tx.put_task(&Task::new_dummy(
                    task_id,
                    janus_core::task::VdafInstance::Poplar1 { bits: 64 }.into(),
                    Role::Leader,
                ))
                .await?;
                tx.put_aggregation_job(&first_aggregation_job).await?;
                tx.put_aggregation_job(&second_aggregation_job).await?;

                // Also write an unrelated aggregation job with a different task ID to check that it
                // is not returned.
                let unrelated_task_id = random();
                tx.put_task(&Task::new_dummy(
                    unrelated_task_id,
                    janus_core::task::VdafInstance::Poplar1 { bits: 64 }.into(),
                    Role::Leader,
                ))
                .await?;
                tx.put_aggregation_job(&AggregationJob::<PRG_SEED_SIZE, ToyPoplar1> {
                    aggregation_job_id: random(),
                    task_id: unrelated_task_id,
                    aggregation_param: BTreeSet::from([
                        IdpfInput::new("foo".as_bytes(), 10).unwrap(),
                        IdpfInput::new("bar".as_bytes(), 20).unwrap(),
                    ]),
                    state: AggregationJobState::InProgress,
                })
                .await
            })
        })
        .await
        .unwrap();

        // Run.
        let mut want_agg_jobs = vec![first_aggregation_job, second_aggregation_job];
        want_agg_jobs.sort_by_key(|agg_job| agg_job.aggregation_job_id);
        let mut got_agg_jobs = ds
            .run_tx(|tx| {
                Box::pin(async move { tx.get_aggregation_jobs_for_task_id(task_id).await })
            })
            .await
            .unwrap();
        got_agg_jobs.sort_by_key(|agg_job| agg_job.aggregation_job_id);

        // Verify.
        assert_eq!(want_agg_jobs, got_agg_jobs);
    }

    #[tokio::test]
    async fn roundtrip_report_aggregation() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let (prep_state, prep_msg, output_share) = generate_vdaf_values(vdaf.as_ref(), (), 0);

        for (ord, state) in [
            ReportAggregationState::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::Start,
            ReportAggregationState::Waiting(prep_state.clone(), None),
            ReportAggregationState::Waiting(prep_state, Some(prep_msg)),
            ReportAggregationState::Finished(output_share),
            ReportAggregationState::Failed(ReportShareError::VdafPrepError),
            ReportAggregationState::Invalid,
        ]
        .iter()
        .enumerate()
        {
            let task_id = random();
            let aggregation_job_id = random();
            let time = Time::from_seconds_since_epoch(12345);
            let nonce = Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

            let report_aggregation = ds
                .run_tx(|tx| {
                    let state = state.clone();
                    Box::pin(async move {
                        tx.put_task(&Task::new_dummy(
                            task_id,
                            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                            Role::Leader,
                        ))
                        .await?;
                        tx.put_aggregation_job(&AggregationJob::<
                            PRIO3_AES128_VERIFY_KEY_LENGTH,
                            Prio3Aes128Count,
                        > {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        })
                        .await?;
                        tx.put_report_share(
                            task_id,
                            &ReportShare::new(
                                ReportMetadata::new(nonce, time, Vec::new()),
                                Vec::from("public_share"),
                                HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            ),
                        )
                        .await?;

                        let report_aggregation = ReportAggregation {
                            aggregation_job_id,
                            task_id,
                            time,
                            nonce,
                            ord: ord as i64,
                            state: state.clone(),
                        };
                        tx.put_report_aggregation(&report_aggregation).await?;
                        Ok(report_aggregation)
                    })
                })
                .await
                .unwrap();

            let got_report_aggregation = ds
                .run_tx(|tx| {
                    let vdaf = Arc::clone(&vdaf);
                    Box::pin(async move {
                        tx.get_report_aggregation(
                            vdaf.as_ref(),
                            Role::Leader,
                            task_id,
                            aggregation_job_id,
                            nonce,
                        )
                        .await
                    })
                })
                .await
                .unwrap();
            assert_eq!(Some(&report_aggregation), got_report_aggregation.as_ref());

            let mut new_report_aggregation = report_aggregation.clone();
            new_report_aggregation.ord += 10;
            ds.run_tx(|tx| {
                let new_report_aggregation = new_report_aggregation.clone();
                Box::pin(async move { tx.update_report_aggregation(&new_report_aggregation).await })
            })
            .await
            .unwrap();

            let got_report_aggregation = ds
                .run_tx(|tx| {
                    let vdaf = Arc::clone(&vdaf);
                    Box::pin(async move {
                        tx.get_report_aggregation(
                            vdaf.as_ref(),
                            Role::Leader,
                            task_id,
                            aggregation_job_id,
                            nonce,
                        )
                        .await
                    })
                })
                .await
                .unwrap();
            assert_eq!(Some(new_report_aggregation), got_report_aggregation);
        }
    }

    #[tokio::test]
    async fn report_aggregation_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
        let vdaf = Arc::new(dummy_vdaf::Vdaf::default());

        let rslt = ds
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);
                Box::pin(async move {
                    tx.get_report_aggregation(
                        vdaf.as_ref(),
                        Role::Leader,
                        random(),
                        random(),
                        Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(rslt, None);

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.update_report_aggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(
                        &ReportAggregation {
                            aggregation_job_id: random(),
                            task_id: random(),
                            time: Time::from_seconds_since_epoch(12345),
                            nonce: Nonce::from([
                                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            ]),
                            ord: 0,
                            state: ReportAggregationState::Invalid,
                        },
                    )
                    .await
                })
            })
            .await;
        assert_matches!(rslt, Err(Error::MutationTargetNotFound));
    }

    #[tokio::test]
    async fn get_report_aggregations_for_aggregation_job() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let (prep_state, prep_msg, output_share) = generate_vdaf_values(vdaf.as_ref(), (), 0);

        let task_id = random();
        let aggregation_job_id = random();

        let report_aggregations = ds
            .run_tx(|tx| {
                let prep_msg = prep_msg.clone();
                let prep_state = prep_state.clone();
                let output_share = output_share.clone();

                Box::pin(async move {
                    tx.put_task(&Task::new_dummy(
                        task_id,
                        janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                        Role::Leader,
                    ))
                    .await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    let mut report_aggregations = Vec::new();
                    for (ord, state) in
                        [
                            ReportAggregationState::<
                                PRIO3_AES128_VERIFY_KEY_LENGTH,
                                Prio3Aes128Count,
                            >::Start,
                            ReportAggregationState::Waiting(prep_state.clone(), None),
                            ReportAggregationState::Waiting(prep_state, Some(prep_msg)),
                            ReportAggregationState::Finished(output_share),
                            ReportAggregationState::Failed(ReportShareError::VdafPrepError),
                            ReportAggregationState::Invalid,
                        ]
                        .iter()
                        .enumerate()
                    {
                        let time = Time::from_seconds_since_epoch(12345);
                        let nonce = Nonce::from((ord as u128).to_be_bytes());
                        tx.put_report_share(
                            task_id,
                            &ReportShare::new(
                                ReportMetadata::new(nonce, time, Vec::new()),
                                Vec::from("public_share"),
                                HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            ),
                        )
                        .await?;

                        let report_aggregation = ReportAggregation {
                            aggregation_job_id,
                            task_id,
                            time,
                            nonce,
                            ord: ord as i64,
                            state: state.clone(),
                        };
                        tx.put_report_aggregation(&report_aggregation).await?;
                        report_aggregations.push(report_aggregation);
                    }
                    Ok(report_aggregations)
                })
            })
            .await
            .unwrap();

        let got_report_aggregations = ds
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);
                Box::pin(async move {
                    tx.get_report_aggregations_for_aggregation_job(
                        vdaf.as_ref(),
                        Role::Leader,
                        task_id,
                        aggregation_job_id,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report_aggregations, got_report_aggregations);
    }

    #[tokio::test]
    async fn crypter() {
        let crypter = Crypter::new(vec![generate_aead_key(), generate_aead_key()]);
        let bad_key = generate_aead_key();

        const TABLE: &str = "some_table";
        const ROW: &[u8] = b"12345";
        const COLUMN: &str = "some_column";
        const PLAINTEXT: &[u8] = b"This is my plaintext value.";

        // Test that roundtripping encryption works.
        let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
        assert_eq!(PLAINTEXT, &plaintext);

        // Roundtripping encryption works even if a non-primary key was used for encryption.
        let ciphertext =
            Crypter::encrypt_with_key(crypter.keys.last().unwrap(), TABLE, ROW, COLUMN, PLAINTEXT)
                .unwrap();
        let plaintext = crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).unwrap();
        assert_eq!(PLAINTEXT, &plaintext);

        // Roundtripping encryption with an unknown key fails.
        let ciphertext =
            Crypter::encrypt_with_key(&bad_key, TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        assert!(crypter.decrypt(TABLE, ROW, COLUMN, &ciphertext).is_err());

        // Roundtripping encryption with a mismatched table, row, or column fails.
        let ciphertext = crypter.encrypt(TABLE, ROW, COLUMN, PLAINTEXT).unwrap();
        assert!(crypter
            .decrypt("wrong_table", ROW, COLUMN, &ciphertext)
            .is_err());
        assert!(crypter
            .decrypt(TABLE, b"wrong_row", COLUMN, &ciphertext)
            .is_err());
        assert!(crypter
            .decrypt(TABLE, ROW, "wrong_column", &ciphertext)
            .is_err());
    }

    #[tokio::test]
    async fn lookup_collect_job() {
        install_test_trace_subscriber();

        let task_id = random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();
        let timestamp = Time::from_seconds_since_epoch(150);
        let interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(10),
        )
        .unwrap();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.put_task(&Task::new_dummy(
                    task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await
            })
        })
        .await
        .unwrap();

        let collect_job_id = ds
            .run_tx(|tx| {
                Box::pin(async move { tx.get_collect_job_id(task_id, batch_interval, &[]).await })
            })
            .await
            .unwrap();
        assert!(collect_job_id.is_none());

        let collect_job_id = ds
            .run_tx(|tx| {
                Box::pin(async move { tx.put_collect_job(task_id, batch_interval, &[]).await })
            })
            .await
            .unwrap();

        let same_collect_job_id = ds
            .run_tx(|tx| {
                Box::pin(async move { tx.get_collect_job_id(task_id, batch_interval, &[]).await })
            })
            .await
            .unwrap()
            .unwrap();

        // Should get the same UUID for the same values.
        assert_eq!(collect_job_id, same_collect_job_id);

        // Check that we can find the collect job by timestamp.
        let (collect_jobs_by_time, collect_jobs_by_interval) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let collect_jobs_by_time = tx.find_collect_jobs_including_time::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task_id, timestamp).await?;
                    let collect_jobs_by_interval = tx.find_collect_jobs_jobs_intersecting_interval::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task_id, interval).await?;
                    Ok((collect_jobs_by_time, collect_jobs_by_interval))
                })
            })
            .await
            .unwrap();

        let want_collect_jobs = Vec::from([CollectJob::<
            PRIO3_AES128_VERIFY_KEY_LENGTH,
            Prio3Aes128Count,
        > {
            collect_job_id,
            task_id,
            batch_interval,
            aggregation_param: (),
            state: CollectJobState::Start,
        }]);

        assert_eq!(collect_jobs_by_time, want_collect_jobs);
        assert_eq!(collect_jobs_by_interval, want_collect_jobs);

        let rows = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.tx
                        .query("SELECT id FROM collect_jobs", &[])
                        .await
                        .map_err(Error::from)
                })
            })
            .await
            .unwrap();

        assert!(rows.len() == 1);

        let different_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(101),
            Duration::from_seconds(100),
        )
        .unwrap();
        let different_collect_job_id = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.put_collect_job(task_id, different_batch_interval, &[])
                        .await
                })
            })
            .await
            .unwrap();

        // New collect job should yield a new UUID.
        assert!(different_collect_job_id != collect_job_id);

        let rows = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.tx
                        .query("SELECT id FROM collect_jobs", &[])
                        .await
                        .map_err(Error::from)
                })
            })
            .await
            .unwrap();

        // A new row should be present.
        assert!(rows.len() == 2);

        // Check that we can find both collect jobs by timestamp.
        let (mut collect_jobs_by_time, mut collect_jobs_by_interval) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let collect_jobs_by_time = tx.find_collect_jobs_including_time::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task_id, timestamp).await?;
                    let collect_jobs_by_interval = tx.find_collect_jobs_jobs_intersecting_interval::
                        <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(task_id, interval).await?;
                    Ok((collect_jobs_by_time, collect_jobs_by_interval))
                })
            })
            .await
            .unwrap();
        collect_jobs_by_time.sort_by(|x, y| x.collect_job_id.cmp(&y.collect_job_id));
        collect_jobs_by_interval.sort_by(|x, y| x.collect_job_id.cmp(&y.collect_job_id));

        let mut want_collect_jobs = Vec::from([
            CollectJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count> {
                collect_job_id,
                task_id,
                batch_interval,
                aggregation_param: (),
                state: CollectJobState::Start,
            },
            CollectJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count> {
                collect_job_id: different_collect_job_id,
                task_id,
                batch_interval: different_batch_interval,
                aggregation_param: (),
                state: CollectJobState::Start,
            },
        ]);
        want_collect_jobs.sort_by(|x, y| x.collect_job_id.cmp(&y.collect_job_id));

        assert_eq!(collect_jobs_by_time, want_collect_jobs);
        assert_eq!(collect_jobs_by_interval, want_collect_jobs);
    }

    #[tokio::test]
    async fn get_collect_job_task_id() {
        install_test_trace_subscriber();

        let first_task_id = random();
        let second_task_id = random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.put_task(&Task::new_dummy(
                    first_task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await
                .unwrap();

                tx.put_task(&Task::new_dummy(
                    second_task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await
                .unwrap();

                let first_collect_job_id = tx
                    .put_collect_job(first_task_id, batch_interval, &[0, 1, 2, 3, 4])
                    .await
                    .unwrap();
                let second_collect_job_id = tx
                    .put_collect_job(second_task_id, batch_interval, &[0, 1, 2, 3, 4])
                    .await
                    .unwrap();

                assert_eq!(
                    Some(first_task_id),
                    tx.get_collect_job_task_id(first_collect_job_id)
                        .await
                        .unwrap()
                );
                assert_eq!(
                    Some(second_task_id),
                    tx.get_collect_job_task_id(second_collect_job_id)
                        .await
                        .unwrap()
                );
                assert_eq!(
                    None,
                    tx.get_collect_job_task_id(Uuid::new_v4()).await.unwrap()
                );

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn get_collect_job() {
        install_test_trace_subscriber();

        let task_id = random();
        let first_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();
        let second_batch_interval = Interval::new(
            Time::from_seconds_since_epoch(200),
            Duration::from_seconds(200),
        )
        .unwrap();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                let task = Task::new_dummy(
                    task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                );
                tx.put_task(&task).await.unwrap();

                let first_collect_job_id = tx
                    .put_collect_job(task_id, first_batch_interval, &().get_encoded())
                    .await
                    .unwrap();
                let second_collect_job_id = tx
                    .put_collect_job(task_id, second_batch_interval, &().get_encoded())
                    .await
                    .unwrap();

                let first_collect_job = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        first_collect_job_id,
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(first_collect_job.collect_job_id, first_collect_job_id);
                assert_eq!(first_collect_job.task_id, task_id);
                assert_eq!(first_collect_job.batch_interval, first_batch_interval);
                assert_eq!(first_collect_job.state, CollectJobState::Start);

                let second_collect_job = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        second_collect_job_id,
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(second_collect_job.collect_job_id, second_collect_job_id);
                assert_eq!(second_collect_job.task_id, task_id);
                assert_eq!(second_collect_job.batch_interval, second_batch_interval);
                assert_eq!(second_collect_job.state, CollectJobState::Start);

                let leader_aggregate_share = AggregateShare::from(vec![Field64::from(1)]);

                let encrypted_helper_aggregate_share = hpke::seal(
                    &task.collector_hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
                    &[0, 1, 2, 3, 4, 5],
                    &associated_data_for_aggregate_share::<TimeInterval>(
                        task.id,
                        &first_batch_interval,
                    ),
                )
                .unwrap();

                tx.update_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    first_collect_job_id,
                    &leader_aggregate_share,
                    &encrypted_helper_aggregate_share,
                )
                .await
                .unwrap();

                let first_collect_job = tx
                    .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        first_collect_job_id,
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(first_collect_job.collect_job_id, first_collect_job_id);
                assert_eq!(first_collect_job.task_id, task_id);
                assert_eq!(first_collect_job.batch_interval, first_batch_interval);
                assert_eq!(
                    first_collect_job.state,
                    CollectJobState::Finished {
                        encrypted_helper_aggregate_share,
                        leader_aggregate_share
                    }
                );

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancel_collect_job() {
        // Setup: write a collect job to the datastore.
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        let task_id = random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();

        let (collect_job_id, collect_job) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.put_task(&Task::new_dummy(
                        task_id,
                        janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                        Role::Leader,
                    ))
                    .await?;

                    let collect_job_id = tx.put_collect_job(task_id, batch_interval, &[]).await?;

                    let collect_job = tx
                        .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                            collect_job_id,
                        )
                        .await?
                        .unwrap();

                    Ok((collect_job_id, collect_job))
                })
            })
            .await
            .unwrap();

        // Verify: initial state.
        assert_eq!(
            collect_job,
            CollectJob {
                collect_job_id,
                task_id,
                batch_interval,
                aggregation_param: (),
                state: CollectJobState::Start,
            }
        );

        // Setup: cancel the collect job.
        let collect_job = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.cancel_collect_job(collect_job_id).await?;
                    let collect_job = tx
                        .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                            collect_job_id,
                        )
                        .await?
                        .unwrap();
                    Ok(collect_job)
                })
            })
            .await
            .unwrap();

        // Verify: collect job was canceled.
        assert_eq!(
            collect_job,
            CollectJob {
                collect_job_id,
                task_id,
                batch_interval,
                aggregation_param: (),
                state: CollectJobState::Abandoned,
            }
        );
    }

    #[derive(Clone)]
    struct CollectJobTestCase {
        should_be_acquired: bool,
        task_id: TaskId,
        batch_interval: Interval,
        agg_param: AggregationParam,
        collect_job_id: Option<Uuid>,
        set_aggregate_shares: bool,
    }

    #[derive(Clone)]
    struct CollectJobAcquireTestCase {
        task_ids: Vec<TaskId>,
        reports: Vec<Report>,
        aggregation_jobs: Vec<AggregationJob<0, dummy_vdaf::Vdaf>>,
        report_aggregations: Vec<ReportAggregation<0, dummy_vdaf::Vdaf>>,
        collect_job_test_cases: Vec<CollectJobTestCase>,
    }

    async fn setup_collect_job_acquire_test_case(
        ds: &Datastore<MockClock>,
        test_case: CollectJobAcquireTestCase,
    ) -> CollectJobAcquireTestCase {
        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
        ds.run_tx(|tx| {
            let mut test_case = test_case.clone();
            Box::pin(async move {
                for task_id in &test_case.task_ids {
                    tx.put_task(&Task::new_dummy(*task_id, VdafInstance::Fake, Role::Leader))
                        .await?;
                }

                for report in &test_case.reports {
                    tx.put_client_report(report).await?;
                }

                for aggregation_job in &test_case.aggregation_jobs {
                    tx.put_aggregation_job(aggregation_job).await?;
                }

                for report_aggregation in &test_case.report_aggregations {
                    tx.put_report_aggregation(report_aggregation).await?;
                }

                for test_case in test_case.collect_job_test_cases.iter_mut() {
                    let collect_job_id = tx
                        .put_collect_job(
                            test_case.task_id,
                            test_case.batch_interval,
                            &test_case.agg_param.get_encoded(),
                        )
                        .await?;

                    if test_case.set_aggregate_shares {
                        tx.update_collect_job::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(
                            collect_job_id,
                            &dummy_vdaf::AggregateShare(0),
                            &HpkeCiphertext::new(HpkeConfigId::from(0), vec![], vec![]),
                        )
                        .await?;
                    }

                    test_case.collect_job_id = Some(collect_job_id);
                }

                Ok(test_case)
            })
        })
        .await
        .unwrap()
    }

    async fn run_collect_job_acquire_test_case(
        ds: &Datastore<MockClock>,
        test_case: CollectJobAcquireTestCase,
    ) -> Vec<Lease<AcquiredCollectJob>> {
        let test_case = setup_collect_job_acquire_test_case(ds, test_case).await;

        let clock = &ds.clock;
        ds.run_tx(|tx| {
            let test_case = test_case.clone();
            let clock = clock.clone();
            Box::pin(async move {
                let collect_job_leases = tx
                    .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 10)
                    .await?;

                let mut leased_collect_jobs: Vec<_> = collect_job_leases
                    .iter()
                    .map(|lease| (lease.leased().clone(), lease.lease_expiry_time))
                    .collect();
                leased_collect_jobs.sort();

                let mut expected_collect_jobs: Vec<_> = test_case
                    .collect_job_test_cases
                    .iter()
                    .filter(|c| c.should_be_acquired)
                    .map(|c| {
                        (
                            AcquiredCollectJob {
                                vdaf: VdafInstance::Fake,
                                collect_job_id: c.collect_job_id.unwrap(),
                                task_id: c.task_id,
                            },
                            clock.now().add(Duration::from_seconds(100)).unwrap(),
                        )
                    })
                    .collect();
                expected_collect_jobs.sort();

                assert_eq!(leased_collect_jobs, expected_collect_jobs);

                Ok(collect_job_leases)
            })
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn collect_job_acquire_release_happy_path() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let reports = Vec::from([Report::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_id = random();
        let aggregation_jobs = vec![AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
            aggregation_job_id,
            aggregation_param: AggregationParam(0),
            task_id,
            state: AggregationJobState::Finished,
        }];
        let report_aggregations = vec![ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
            aggregation_job_id,
            task_id,
            time: *reports[0].metadata().time(),
            nonce: *reports[0].metadata().nonce(),
            ord: 0,
            // Doesn't matter what state the report aggregation is in
            state: ReportAggregationState::Start,
        }];

        let collect_job_test_cases = vec![CollectJobTestCase {
            should_be_acquired: true,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            set_aggregate_shares: false,
        }];

        let collect_job_leases = run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: vec![task_id],
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;

        let reacquired_jobs = ds
            .run_tx(|tx| {
                let collect_job_leases = collect_job_leases.clone();
                Box::pin(async move {
                    // Try to re-acquire collect jobs. Nothing should happen because the lease is still
                    // valid.
                    assert!(tx
                        .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 10)
                        .await
                        .unwrap()
                        .is_empty());

                    // Release the lease, then re-acquire it.
                    tx.release_collect_job(&collect_job_leases[0])
                        .await
                        .unwrap();

                    let reacquired_leases = tx
                        .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 10)
                        .await
                        .unwrap();
                    let reacquired_jobs: Vec<_> = reacquired_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    let collect_jobs: Vec<_> = collect_job_leases
                        .iter()
                        .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                        .collect();

                    assert_eq!(reacquired_jobs.len(), 1);
                    assert_eq!(reacquired_jobs, collect_jobs);

                    Ok(reacquired_leases)
                })
            })
            .await
            .unwrap();

        // Advance time by the lease duration
        clock.advance(Duration::from_seconds(100));

        ds.run_tx(|tx| {
            let reacquired_jobs = reacquired_jobs.clone();
            Box::pin(async move {
                // Re-acquire the jobs whose lease should have lapsed.
                let acquired_jobs = tx
                    .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 10)
                    .await
                    .unwrap();

                for (acquired_job, reacquired_job) in acquired_jobs.iter().zip(reacquired_jobs) {
                    assert_eq!(acquired_job.leased(), reacquired_job.leased());
                    assert_eq!(
                        acquired_job.lease_expiry_time(),
                        reacquired_job
                            .lease_expiry_time()
                            .add(Duration::from_seconds(100))
                            .unwrap(),
                    );
                }

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn collect_job_acquire_no_aggregation_job_with_task_id() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let other_task_id = random();

        let aggregation_jobs = vec![AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
            aggregation_job_id: random(),
            aggregation_param: AggregationParam(0),
            // Aggregation job task ID does not match collect job task ID
            task_id: other_task_id,
            state: AggregationJobState::Finished,
        }];

        let collect_job_test_cases = vec![CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            set_aggregate_shares: false,
        }];

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: vec![task_id, other_task_id],
                reports: vec![],
                aggregation_jobs,
                report_aggregations: vec![],
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_no_aggregation_job_with_agg_param() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let reports = vec![Report::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )];

        let aggregation_jobs = vec![AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
            aggregation_job_id: random(),
            // Aggregation job agg param does not match collect job agg param
            aggregation_param: AggregationParam(1),
            task_id,
            state: AggregationJobState::Finished,
        }];

        let collect_job_test_cases = vec![CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            set_aggregate_shares: false,
        }];

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: vec![task_id],
                reports,
                aggregation_jobs,
                report_aggregations: vec![],
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_report_shares_outside_interval() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let reports = vec![Report::new_dummy(
            task_id,
            // Report associated with the aggregation job is outside the collect job's batch
            // interval
            Time::from_seconds_since_epoch(200),
        )];
        let aggregation_job_id = random();
        let aggregation_jobs = vec![AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
            aggregation_job_id,
            aggregation_param: AggregationParam(0),
            task_id,
            state: AggregationJobState::Finished,
        }];
        let report_aggregations = vec![ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
            aggregation_job_id,
            task_id,
            time: *reports[0].metadata().time(),
            nonce: *reports[0].metadata().nonce(),
            ord: 0,
            // Shouldn't matter what state the report aggregation is in
            state: ReportAggregationState::Start,
        }];

        let collect_job_test_cases = vec![CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            set_aggregate_shares: false,
        }];

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: vec![task_id],
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_release_job_finished() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let reports = Vec::from([Report::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_id = random();
        let aggregation_jobs = Vec::from([AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
            aggregation_job_id,
            aggregation_param: AggregationParam(0),
            task_id,
            state: AggregationJobState::Finished,
        }]);

        let report_aggregations =
            Vec::from([ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id,
                task_id,
                time: *reports[0].metadata().time(),
                nonce: *reports[0].metadata().nonce(),
                ord: 0,
                state: ReportAggregationState::Start,
            }]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            // Collect job has already run to completion
            set_aggregate_shares: true,
        }]);

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: Vec::from([task_id]),
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_release_aggregation_job_in_progress() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let reports = Vec::from([
            Report::new_dummy(task_id, Time::from_seconds_since_epoch(0)),
            Report::new_dummy(task_id, Time::from_seconds_since_epoch(50)),
        ]);

        let aggregation_job_ids: [_; 2] = random();
        let aggregation_jobs = Vec::from([
            AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[0],
                aggregation_param: AggregationParam(0),
                task_id,
                state: AggregationJobState::Finished,
            },
            AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[1],
                aggregation_param: AggregationParam(0),
                task_id,
                // Aggregation job included in collect request is in progress
                state: AggregationJobState::InProgress,
            },
        ]);

        let report_aggregations = Vec::from([
            ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[0],
                task_id,
                time: *reports[0].metadata().time(),
                nonce: *reports[0].metadata().nonce(),
                ord: 0,
                state: ReportAggregationState::Start,
            },
            ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[1],
                task_id,
                time: *reports[1].metadata().time(),
                nonce: *reports[1].metadata().nonce(),
                ord: 0,
                state: ReportAggregationState::Start,
            },
        ]);

        let collect_job_test_cases = Vec::from([CollectJobTestCase {
            should_be_acquired: false,
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(100),
            )
            .unwrap(),
            agg_param: AggregationParam(0),
            collect_job_id: None,
            set_aggregate_shares: false,
        }]);

        run_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: vec![task_id],
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn collect_job_acquire_job_max() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = random();
        let reports = Vec::from([Report::new_dummy(
            task_id,
            Time::from_seconds_since_epoch(0),
        )]);
        let aggregation_job_ids: [_; 2] = random();
        let aggregation_jobs = Vec::from([
            AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[0],
                aggregation_param: AggregationParam(0),
                task_id,
                state: AggregationJobState::Finished,
            },
            AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[1],
                aggregation_param: AggregationParam(1),
                task_id,
                state: AggregationJobState::Finished,
            },
        ]);
        let report_aggregations = Vec::from([
            ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[0],
                task_id,
                time: *reports[0].metadata().time(),
                nonce: *reports[0].metadata().nonce(),
                ord: 0,
                state: ReportAggregationState::Start,
            },
            ReportAggregation::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                aggregation_job_id: aggregation_job_ids[1],
                task_id,
                time: *reports[0].metadata().time(),
                nonce: *reports[0].metadata().nonce(),
                ord: 0,
                state: ReportAggregationState::Start,
            },
        ]);

        let collect_job_test_cases = vec![
            CollectJobTestCase {
                should_be_acquired: true,
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(0),
                collect_job_id: None,
                set_aggregate_shares: false,
            },
            CollectJobTestCase {
                should_be_acquired: true,
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(100),
                )
                .unwrap(),
                agg_param: AggregationParam(1),
                collect_job_id: None,
                set_aggregate_shares: false,
            },
        ];

        let test_case = setup_collect_job_acquire_test_case(
            &ds,
            CollectJobAcquireTestCase {
                task_ids: vec![task_id],
                reports,
                aggregation_jobs,
                report_aggregations,
                collect_job_test_cases,
            },
        )
        .await;

        ds.run_tx(|tx| {
            let test_case = test_case.clone();
            let clock = clock.clone();
            Box::pin(async move {
                // Acquire a single collect job, twice. Each call should yield one job. We don't
                // care what order they are acquired in.
                let mut acquired_collect_jobs = tx
                    .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                    .await?;
                assert_eq!(acquired_collect_jobs.len(), 1);

                acquired_collect_jobs.extend(
                    tx.acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                        .await?,
                );

                assert_eq!(acquired_collect_jobs.len(), 2);

                let mut acquired_collect_jobs: Vec<_> = acquired_collect_jobs
                    .iter()
                    .map(|lease| (lease.leased().clone(), lease.lease_expiry_time()))
                    .collect();
                acquired_collect_jobs.sort();

                let mut expected_collect_jobs: Vec<_> = test_case
                    .collect_job_test_cases
                    .iter()
                    .filter(|c| c.should_be_acquired)
                    .map(|c| {
                        (
                            AcquiredCollectJob {
                                vdaf: VdafInstance::Fake,
                                collect_job_id: c.collect_job_id.unwrap(),
                                task_id: c.task_id,
                            },
                            clock.now().add(Duration::from_seconds(100)).unwrap(),
                        )
                    })
                    .collect();
                expected_collect_jobs.sort();

                assert_eq!(acquired_collect_jobs, expected_collect_jobs);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_batch_unit_aggregation() {
        install_test_trace_subscriber();

        const PRG_SEED_SIZE: usize = 16;
        type ToyPoplar1 = Poplar1<ToyIdpf<Field64>, PrgAes128, PRG_SEED_SIZE>;

        let task_id = random();
        let other_task_id = random();
        let aggregate_share = AggregateShare::from(vec![Field64::from(17)]);
        let aggregation_param = BTreeSet::from([
            IdpfInput::new("abc".as_bytes(), 0).unwrap(),
            IdpfInput::new("def".as_bytes(), 1).unwrap(),
        ]);

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            let (aggregate_share, aggregation_param) =
                (aggregate_share.clone(), aggregation_param.clone());
            Box::pin(async move {
                let mut task = Task::new_dummy(
                    task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                );
                task.min_batch_duration = Duration::from_seconds(100);
                tx.put_task(&task).await?;

                tx.put_task(&Task::new_dummy(
                    other_task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Leader,
                ))
                .await?;

                let first_batch_unit_aggregation =
                    BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(100),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: NonceChecksum::default(),
                    };

                let second_batch_unit_aggregation =
                    BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(150),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: NonceChecksum::default(),
                    };

                let third_batch_unit_aggregation =
                    BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(200),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: NonceChecksum::default(),
                    };

                // Start of this aggregation's interval is before the interval queried below.
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                    task_id,
                    unit_interval_start: Time::from_seconds_since_epoch(25),
                    aggregation_param: aggregation_param.clone(),
                    aggregate_share: aggregate_share.clone(),
                    report_count: 0,
                    checksum: NonceChecksum::default(),
                })
                .await?;

                // Following three batch units are within the interval queried below.
                tx.put_batch_unit_aggregation(&first_batch_unit_aggregation)
                    .await?;
                tx.put_batch_unit_aggregation(&second_batch_unit_aggregation)
                    .await?;

                // The end of this batch unit is exactly the end of the interval queried below.
                tx.put_batch_unit_aggregation(&third_batch_unit_aggregation)
                    .await?;
                // Aggregation parameter differs from the one queried below.
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                    task_id,
                    unit_interval_start: Time::from_seconds_since_epoch(100),
                    aggregation_param: BTreeSet::from([
                        IdpfInput::new("gh".as_bytes(), 2).unwrap(),
                        IdpfInput::new("jk".as_bytes(), 3).unwrap(),
                    ]),
                    aggregate_share: aggregate_share.clone(),
                    report_count: 0,
                    checksum: NonceChecksum::default(),
                })
                .await?;

                // End of this aggregation's interval is after the interval queried below.
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                    task_id,
                    unit_interval_start: Time::from_seconds_since_epoch(250),
                    aggregation_param: aggregation_param.clone(),
                    aggregate_share: aggregate_share.clone(),
                    report_count: 0,
                    checksum: NonceChecksum::default(),
                })
                .await?;

                // Start of this aggregation's interval is after the interval queried below.
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                    task_id,
                    unit_interval_start: Time::from_seconds_since_epoch(400),
                    aggregation_param: aggregation_param.clone(),
                    aggregate_share: aggregate_share.clone(),
                    report_count: 0,
                    checksum: NonceChecksum::default(),
                })
                .await?;

                // Task ID differs from that queried below.
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                    task_id: other_task_id,
                    unit_interval_start: Time::from_seconds_since_epoch(200),
                    aggregation_param: aggregation_param.clone(),
                    aggregate_share: aggregate_share.clone(),
                    report_count: 0,
                    checksum: NonceChecksum::default(),
                })
                .await?;

                let batch_unit_aggregations = tx
                    .get_batch_unit_aggregations_for_task_in_interval::<PRG_SEED_SIZE, ToyPoplar1>(
                        task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(50),
                            Duration::from_seconds(250),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await?;

                assert_eq!(
                    batch_unit_aggregations.len(),
                    3,
                    "{:#?}",
                    batch_unit_aggregations,
                );
                assert!(
                    batch_unit_aggregations.contains(&first_batch_unit_aggregation),
                    "{:#?}",
                    batch_unit_aggregations,
                );
                assert!(
                    batch_unit_aggregations.contains(&second_batch_unit_aggregation),
                    "{:#?}",
                    batch_unit_aggregations,
                );
                assert!(batch_unit_aggregations.contains(&third_batch_unit_aggregation));

                let updated_first_batch_unit_aggregation =
                    BatchUnitAggregation::<PRG_SEED_SIZE, ToyPoplar1> {
                        aggregate_share: AggregateShare::from(vec![Field64::from(25)]),
                        report_count: 1,
                        checksum: NonceChecksum::get_decoded(&[1; 32]).unwrap(),
                        ..first_batch_unit_aggregation
                    };

                tx.update_batch_unit_aggregation(&updated_first_batch_unit_aggregation)
                    .await?;

                let batch_unit_aggregations = tx
                    .get_batch_unit_aggregations_for_task_in_interval::<PRG_SEED_SIZE, ToyPoplar1>(
                        task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(50),
                            Duration::from_seconds(250),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await?;

                assert_eq!(
                    batch_unit_aggregations.len(),
                    3,
                    "{:#?}",
                    batch_unit_aggregations,
                );
                assert!(
                    batch_unit_aggregations.contains(&updated_first_batch_unit_aggregation),
                    "{:#?}",
                    batch_unit_aggregations,
                );
                assert!(
                    batch_unit_aggregations.contains(&second_batch_unit_aggregation),
                    "{:#?}",
                    batch_unit_aggregations,
                );
                assert!(batch_unit_aggregations.contains(&third_batch_unit_aggregation));

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roundtrip_aggregate_share_job() {
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                let task_id = random();
                let task = Task::new_dummy(
                    task_id,
                    janus_core::task::VdafInstance::Prio3Aes128Count.into(),
                    Role::Helper,
                );
                tx.put_task(&task).await?;

                let aggregate_share = AggregateShare::from(vec![Field64::from(17)]);
                let batch_interval = Interval::new(
                    Time::from_seconds_since_epoch(100),
                    Duration::from_seconds(100),
                )
                .unwrap();
                let other_batch_interval = Interval::new(
                    Time::from_seconds_since_epoch(101),
                    Duration::from_seconds(101),
                )
                .unwrap();
                let report_count = 10;
                let checksum = NonceChecksum::get_decoded(&[1; 32]).unwrap();

                let aggregate_share_job = AggregateShareJob {
                    task_id,
                    batch_interval,
                    aggregation_param: (),
                    helper_aggregate_share: aggregate_share.clone(),
                    report_count,
                    checksum,
                };

                tx.put_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    &aggregate_share_job,
                )
                .await
                .unwrap();

                let aggregate_share_job_again = tx
                    .get_aggregate_share_job_by_request::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &AggregateShareReq::new(
                            task_id,
                            BatchSelector::new_time_interval(batch_interval),
                            ().get_encoded(),
                            report_count,
                            checksum,
                        ),
                    )
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(aggregate_share_job, aggregate_share_job_again);

                assert!(tx
                    .get_aggregate_share_job_by_request::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &AggregateShareReq::new(
                            task_id,
                            BatchSelector::new_time_interval(other_batch_interval),
                            ().get_encoded(),
                            report_count,
                            checksum,
                        ),
                    )
                    .await
                    .unwrap()
                    .is_none());

                let want_aggregate_share_jobs = Vec::from([aggregate_share_job]);

                let got_aggregate_share_jobs = tx.find_aggregate_share_jobs_including_time::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                    task_id, Time::from_seconds_since_epoch(150)).await?;
                assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

                let got_aggregate_share_jobs = tx.find_aggregate_share_jobs_intersecting_interval::
                    <PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(145),
                            Duration::from_seconds(10))
                        .unwrap()).await?;
                assert_eq!(got_aggregate_share_jobs, want_aggregate_share_jobs);

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    /// generate_vdaf_values generates some arbitrary VDAF values for use in testing. It is cribbed
    /// heavily from `libprio-rs`' `run_vdaf`. The resulting values are guaranteed to be associated
    /// with the same aggregator.
    ///
    /// generate_vdaf_values assumes that the VDAF in use is one-round.
    fn generate_vdaf_values<const L: usize, A: vdaf::Aggregator<L> + vdaf::Client>(
        vdaf: &A,
        agg_param: A::AggregationParam,
        measurement: A::Measurement,
    ) -> (A::PrepareState, A::PrepareMessage, A::OutputShare)
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let input_shares = vdaf.shard(&measurement).unwrap();
        let verify_key: [u8; L] = random();

        let (mut prep_states, prep_shares): (Vec<_>, Vec<_>) = input_shares
            .iter()
            .enumerate()
            .map(|(agg_id, input_share)| {
                vdaf.prepare_init(&verify_key, agg_id, &agg_param, b"nonce", input_share)
                    .unwrap()
            })
            .unzip();
        let prep_msg = vdaf.prepare_preprocess(prep_shares).unwrap();
        let mut output_shares: Vec<A::OutputShare> = prep_states
            .iter()
            .map(|prep_state| {
                if let PrepareTransition::Finish(output_share) = vdaf
                    .prepare_step(prep_state.clone(), prep_msg.clone())
                    .unwrap()
                {
                    output_share
                } else {
                    panic!("generate_vdaf_values: VDAF returned something other than Finish")
                }
            })
            .collect();

        (prep_states.remove(0), prep_msg, output_shares.remove(0))
    }

    #[tokio::test]
    async fn roundtrip_interval_sql() {
        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;
        datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let interval = tx
                        .tx
                        .query_one(
                            "SELECT '[2020-01-01 10:00, 2020-01-01 10:30)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .get::<_, Interval>("interval");
                    let ref_interval = Interval::new(
                        Time::from_naive_date_time(
                            NaiveDate::from_ymd(2020, 1, 1).and_hms(10, 0, 0),
                        ),
                        Duration::from_minutes(30).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(interval, ref_interval);

                    let interval = tx
                        .tx
                        .query_one(
                            "SELECT '[1970-02-03 23:00, 1970-02-04 00:00)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .get::<_, Interval>("interval");
                    let ref_interval = Interval::new(
                        Time::from_naive_date_time(
                            NaiveDate::from_ymd(1970, 2, 3).and_hms(23, 0, 0),
                        ),
                        Duration::from_hours(1).unwrap(),
                    )?;
                    assert_eq!(interval, ref_interval);

                    let res = tx
                        .tx
                        .query_one(
                            "SELECT '[1969-01-01 00:00, 1970-01-01 00:00)'::tsrange AS interval",
                            &[],
                        )
                        .await?
                        .try_get::<_, Interval>("interval");
                    assert!(res.is_err());

                    let ok = tx
                        .tx
                        .query_one(
                            "SELECT (lower(interval) = '1972-07-21 05:30:00' AND
                            upper(interval) = '1972-07-21 06:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                            &[&Interval::new(
                                Time::from_naive_date_time(
                                    NaiveDate::from_ymd(1972, 7, 21).and_hms(5, 30, 0),
                                ),
                                Duration::from_minutes(30).unwrap(),
                            )
                            .unwrap()],
                        )
                        .await?
                        .get::<_, bool>("ok");
                    assert!(ok);

                    let ok = tx
                        .tx
                        .query_one(
                            "SELECT (lower(interval) = '2021-10-05 00:00:00' AND
                            upper(interval) = '2021-10-06 00:00:00' AND
                            lower_inc(interval) AND
                            NOT upper_inc(interval)) AS ok
                            FROM (VALUES ($1::tsrange)) AS temp (interval)",
                            &[&Interval::new(
                                Time::from_naive_date_time(
                                    NaiveDate::from_ymd(2021, 10, 5).and_hms(0, 0, 0),
                                ),
                                Duration::from_hours(24).unwrap(),
                            )
                            .unwrap()],
                        )
                        .await?
                        .get::<_, bool>("ok");
                    assert!(ok);

                    Ok(())
                })
            })
            .await
            .unwrap();
    }
}
