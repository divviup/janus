//! Janus datastore (durable storage) implementation.

use self::models::{
    AggregateShareJob, AggregationJob, AggregatorRole, BatchUnitAggregation, ReportAggregation,
    ReportAggregationState, ReportAggregationStateCode,
};
use crate::{
    hpke::HpkePrivateKey,
    message::{AggregateShareReq, AggregationJobId, HpkeConfig, Interval, Report, ReportShare},
    task::{self, AggregatorAuthKey, Task, Vdaf},
};
use chrono::NaiveDateTime;
use futures::try_join;
use janus::message::{Duration, Extension, HpkeCiphertext, Nonce, TaskId, Time};
use postgres_types::{Json, ToSql};
use prio::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode},
    vdaf,
};
use rand::{thread_rng, Rng};
use ring::aead::{self, LessSafeKey, AES_128_GCM};
use std::{
    collections::HashMap, convert::TryFrom, fmt::Display, future::Future, io::Cursor, mem::size_of,
    pin::Pin,
};
use tokio_postgres::{error::SqlState, row::RowIndex, IsolationLevel, Row};
use url::Url;
use uuid::Uuid;

// TODO(brandon): retry network-related & other transient failures once we know what they look like

/// Datastore represents a datastore for Janus, with support for transactional reads and writes.
/// In practice, Datastore instances are currently backed by a PostgreSQL database.
pub struct Datastore {
    pool: deadpool_postgres::Pool,
    crypter: Crypter,
}

impl Datastore {
    /// new creates a new Datastore using the given Client for backing storage. It is assumed that
    /// the Client is connected to a database with a compatible version of the Janus database schema.
    pub fn new(pool: deadpool_postgres::Pool, crypter: Crypter) -> Datastore {
        Self { pool, crypter }
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
            Fn(&'a Transaction) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
    {
        loop {
            let rslt = self.run_tx_once(&f).await;
            if let Some(err) = rslt.as_ref().err() {
                if err.is_serialization_failure() {
                    continue;
                }
            }
            return rslt;
        }
    }

    #[tracing::instrument(skip(self, f), err)]
    async fn run_tx_once<F, T>(&self, f: &F) -> Result<T, Error>
    where
        for<'a> F:
            Fn(&'a Transaction) -> Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>,
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
        };

        // Run user-provided function with the transaction.
        let rslt = f(&tx).await?;

        // Commit.
        tx.tx.commit().await?;
        Ok(rslt)
    }
}

/// Transaction represents an ongoing datastore transaction.
pub struct Transaction<'a> {
    tx: deadpool_postgres::Transaction<'a>,
    crypter: &'a Crypter,
}

impl Transaction<'_> {
    // This is pub to be used in integration tests
    #[doc(hidden)]
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

        let encrypted_vdaf_verify_param = self.crypter.encrypt(
            "tasks",
            task.id.as_bytes(),
            "vdaf_verify_param",
            &task.vdaf_verify_parameter,
        )?;

        // Main task insert.
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO tasks (task_id, aggregator_role, aggregator_endpoints, vdaf,
                vdaf_verify_param, max_batch_lifetime, min_batch_size, min_batch_duration,
                tolerable_clock_skew, collector_hpke_config)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    &task.id.as_bytes(),                       // task_id
                    &aggregator_role,                          // aggregator_role
                    &endpoints,                                // aggregator_endpoints
                    &Json(&task.vdaf),                         // vdaf
                    &encrypted_vdaf_verify_param,              // verify param
                    &max_batch_lifetime,                       // max batch lifetime
                    &min_batch_size,                           // min batch size
                    &min_batch_duration,                       // min batch duration
                    &tolerable_clock_skew,                     // tolerable clock skew
                    &task.collector_hpke_config.get_encoded(), // collector hpke config
                ],
            )
            .await?;

        // Aggregator auth keys.
        let mut agg_auth_key_ords: Vec<i64> = Vec::new();
        let mut agg_auth_keys: Vec<Vec<u8>> = Vec::new();
        for (ord, key) in task.agg_auth_keys.iter().enumerate() {
            let ord = i64::try_from(ord)?;

            let mut row_id = [0u8; TaskId::ENCODED_LEN + size_of::<i64>()];
            row_id[..TaskId::ENCODED_LEN].copy_from_slice(task.id.as_bytes());
            row_id[TaskId::ENCODED_LEN..].copy_from_slice(&ord.to_be_bytes());

            let encrypted_agg_auth_key =
                self.crypter
                    .encrypt("task_aggregator_auth_keys", &row_id, "key", key.as_ref())?;

            agg_auth_key_ords.push(ord);
            agg_auth_keys.push(encrypted_agg_auth_key);
        }
        let stmt = self.tx.prepare_cached(
                "INSERT INTO task_aggregator_auth_keys (task_id, ord, key)
                SELECT (SELECT id FROM tasks WHERE task_id = $1), * FROM UNNEST($2::BIGINT[], $3::BYTEA[])"
            )
            .await?;
        let auth_keys_params: &[&(dyn ToSql + Sync)] = &[
            /* task_id */ &task.id.as_bytes(),
            /* ords */ &agg_auth_key_ords,
            /* keys */ &agg_auth_keys,
        ];
        let auth_keys_future = self.tx.execute(&stmt, auth_keys_params);

        // HPKE keys.
        let mut hpke_config_ids: Vec<i16> = Vec::new();
        let mut hpke_configs: Vec<Vec<u8>> = Vec::new();
        let mut hpke_private_keys: Vec<Vec<u8>> = Vec::new();
        for (hpke_config, hpke_private_key) in task.hpke_keys.values() {
            let mut row_id = [0u8; TaskId::ENCODED_LEN + size_of::<u8>()];
            row_id[..TaskId::ENCODED_LEN].copy_from_slice(task.id.as_bytes());
            row_id[TaskId::ENCODED_LEN..].copy_from_slice(&u8::from(hpke_config.id).to_be_bytes());

            let encrypted_hpke_private_key = self.crypter.encrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                hpke_private_key.as_ref(),
            )?;

            hpke_config_ids.push(u8::from(hpke_config.id) as i16);
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
            /* task_id */ &task.id.as_bytes(),
            /* config_id */ &hpke_config_ids,
            /* configs */ &hpke_configs,
            /* private_keys */ &hpke_private_keys,
        ];
        let hpke_configs_future = self.tx.execute(&stmt, hpke_configs_params);

        try_join!(auth_keys_future, hpke_configs_future)?;

        Ok(())
    }

    /// Fetch the task parameters corresponing to the provided `task_id`.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn get_task(&self, task_id: TaskId) -> Result<Option<Task>, Error> {
        let params: &[&(dyn ToSql + Sync)] = &[&task_id.as_bytes()];
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregator_role, aggregator_endpoints, vdaf, vdaf_verify_param,
                max_batch_lifetime, min_batch_size, min_batch_duration, tolerable_clock_skew,
                collector_hpke_config
                FROM tasks WHERE task_id = $1",
            )
            .await?;
        let task_row = self.tx.query_opt(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT ord, key FROM task_aggregator_auth_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1) ORDER BY ord ASC",
            )
            .await?;
        let agg_auth_key_rows = self.tx.query(&stmt, params);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT config_id, config, private_key FROM task_hpke_keys
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)",
            )
            .await?;
        let hpke_key_rows = self.tx.query(&stmt, params);

        let (task_row, agg_auth_key_rows, hpke_key_rows) =
            try_join!(task_row, agg_auth_key_rows, hpke_key_rows)?;
        task_row
            .map(|task_row| {
                self.task_from_rows(task_id, task_row, agg_auth_key_rows, hpke_key_rows)
            })
            .transpose()
    }

    /// Fetch all the tasks in the database.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_tasks(&self) -> Result<Vec<Task>, Error> {
        use std::collections::HashMap;

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT task_id, aggregator_role, aggregator_endpoints, vdaf,
                vdaf_verify_param, max_batch_lifetime, min_batch_size, min_batch_duration,
                tolerable_clock_skew, collector_hpke_config 
                FROM tasks",
            )
            .await?;
        let task_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_aggregator_auth_keys.task_id),
                ord, key FROM task_aggregator_auth_keys ORDER BY ord ASC",
            )
            .await?;
        let agg_auth_key_rows = self.tx.query(&stmt, &[]);

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT (SELECT tasks.task_id FROM tasks WHERE tasks.id = task_hpke_keys.task_id),
                config_id, config, private_key FROM task_hpke_keys",
            )
            .await?;
        let hpke_config_rows = self.tx.query(&stmt, &[]);

        let (task_rows, agg_auth_key_rows, hpke_config_rows) =
            try_join!(task_rows, agg_auth_key_rows, hpke_config_rows)?;

        let mut task_row_by_id = Vec::new();
        for row in task_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            task_row_by_id.push((task_id, row));
        }

        let mut agg_auth_key_rows_by_task_id: HashMap<TaskId, Vec<Row>> = HashMap::new();
        for row in agg_auth_key_rows {
            let task_id = TaskId::get_decoded(row.get("task_id"))?;
            agg_auth_key_rows_by_task_id
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

        task_row_by_id
            .into_iter()
            .map(|(task_id, row)| {
                self.task_from_rows(
                    task_id,
                    row,
                    agg_auth_key_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                    hpke_config_rows_by_task_id
                        .remove(&task_id)
                        .unwrap_or_default(),
                )
            })
            .collect::<Result<_, _>>()
    }

    /// Construct a [`Task`] from the contents of the provided (tasks) `Row`,
    /// `hpke_aggregator_auth_keys` rows, and `task_hpke_keys` rows.
    ///
    /// agg_auth_key_rows must be sorted in ascending order by `ord`.
    fn task_from_rows(
        &self,
        task_id: TaskId,
        row: Row,
        agg_auth_key_rows: Vec<Row>,
        hpke_key_rows: Vec<Row>,
    ) -> Result<Task, Error> {
        // Scalar task parameters.
        let aggregator_role: AggregatorRole = row.get("aggregator_role");
        let endpoints: Vec<String> = row.get("aggregator_endpoints");
        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| Ok(Url::parse(&endpoint)?))
            .collect::<Result<_, Error>>()?;
        let vdaf = row.try_get::<_, Json<Vdaf>>("vdaf")?.0;
        let encrypted_vdaf_verify_param: Vec<u8> = row.get("vdaf_verify_param");
        let max_batch_lifetime = row.get_bigint_and_convert("max_batch_lifetime")?;
        let min_batch_size = row.get_bigint_and_convert("min_batch_size")?;
        let min_batch_duration =
            Duration::from_seconds(row.get_bigint_and_convert("min_batch_duration")?);
        let tolerable_clock_skew =
            Duration::from_seconds(row.get_bigint_and_convert("tolerable_clock_skew")?);
        let collector_hpke_config = HpkeConfig::get_decoded(row.get("collector_hpke_config"))?;

        let vdaf_verify_param = self.crypter.decrypt(
            "tasks",
            task_id.as_bytes(),
            "vdaf_verify_param",
            &encrypted_vdaf_verify_param,
        )?;

        // Aggregator authentication keys.
        let mut agg_auth_keys = Vec::new();
        for row in agg_auth_key_rows {
            let ord: i64 = row.get("ord");
            let encrypted_agg_auth_key: Vec<u8> = row.get("key");

            let mut row_id = [0u8; TaskId::ENCODED_LEN + size_of::<i64>()];
            row_id[..TaskId::ENCODED_LEN].copy_from_slice(task_id.as_bytes());
            row_id[TaskId::ENCODED_LEN..].copy_from_slice(&ord.to_be_bytes());

            agg_auth_keys.push(AggregatorAuthKey::new(&self.crypter.decrypt(
                "task_aggregator_auth_keys",
                &row_id,
                "key",
                &encrypted_agg_auth_key,
            )?)?);
        }

        // HPKE keys.
        let mut hpke_configs = Vec::new();
        for row in hpke_key_rows {
            let config_id = u8::try_from(row.get::<_, i16>("config_id"))?;
            let config = HpkeConfig::get_decoded(row.get("config"))?;
            let encrypted_private_key: Vec<u8> = row.get("private_key");

            let mut row_id = [0u8; TaskId::ENCODED_LEN + size_of::<u8>()];
            row_id[..TaskId::ENCODED_LEN].copy_from_slice(task_id.as_bytes());
            row_id[TaskId::ENCODED_LEN..].copy_from_slice(&config_id.to_be_bytes());

            let private_key = HpkePrivateKey::new(self.crypter.decrypt(
                "task_hpke_keys",
                &row_id,
                "private_key",
                &encrypted_private_key,
            )?);

            hpke_configs.push((config, private_key));
        }

        Ok(Task::new(
            task_id,
            endpoints,
            vdaf,
            aggregator_role.as_role(),
            vdaf_verify_param,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            tolerable_clock_skew,
            collector_hpke_config,
            agg_auth_keys,
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
                "SELECT client_reports.extensions, client_reports.input_shares FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1 AND client_reports.nonce_time = $2 AND client_reports.nonce_rand = $3",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_bytes(),
                    /* nonce_time */ &nonce.time().as_naive_date_time(),
                    /* nonce_rand */ &&nonce.rand()[..],
                ],
            )
            .await?
            .map(|row| {
                let encoded_extensions: Vec<u8> = row.get("extensions");
                let extensions: Vec<Extension> =
                    decode_u16_items(&(), &mut Cursor::new(&encoded_extensions))?;

                let encoded_input_shares: Vec<u8> = row.get("input_shares");
                let input_shares: Vec<HpkeCiphertext> =
                    decode_u16_items(&(), &mut Cursor::new(&encoded_input_shares))?;

                Ok(Report {
                    task_id,
                    nonce,
                    extensions,
                    encrypted_input_shares: input_shares,
                })
            })
            .transpose()
    }

    /// get_unaggregated_client_report_nonces_for_task returns some nonces corresponding to
    /// unaggregated client reports for the task identified by the given task ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_unaggregated_client_report_nonces_for_task(
        &self,
        task_id: TaskId,
    ) -> Result<Vec<Nonce>, Error> {
        // We choose to return the newest client reports first (LIFO). The goal is to maintain
        // throughput even if we begin to fall behind enough that reports are too old to be
        // aggregated.
        //
        // See https://medium.com/swlh/fifo-considered-harmful-793b76f98374 &
        // https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.376.5966&rep=rep1&type=pdf.

        // TODO(brandon): allow the number of returned results to be controlled?

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
        let rows = self.tx.query(&stmt, &[&task_id.as_bytes()]).await?;

        rows.into_iter()
            .map(|row| {
                let nonce_rand: Vec<u8> = row.get("nonce_rand");
                Ok(Nonce::new(
                    Time::from_naive_date_time(row.get("nonce_time")),
                    nonce_rand.try_into().map_err(|err| {
                        Error::DbState(format!("couldn't convert nonce_rand value: {0:?}", err))
                    })?,
                ))
            })
            .collect::<Result<Vec<Nonce>, Error>>()
    }

    /// put_client_report stores a client report.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_client_report(&self, report: &Report) -> Result<(), Error> {
        let nonce_time = report.nonce.time().as_naive_date_time();
        let nonce_rand = report.nonce.rand();

        let mut encoded_extensions = Vec::new();
        encode_u16_items(&mut encoded_extensions, &(), &report.extensions);

        let mut encoded_input_shares = Vec::new();
        encode_u16_items(
            &mut encoded_input_shares,
            &(),
            &report.encrypted_input_shares,
        );

        let stmt = self.tx.prepare_cached(
            "INSERT INTO client_reports (task_id, nonce_time, nonce_rand, extensions, input_shares)
            VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5)"
        ).await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &&report.task_id.get_encoded(),
                    /* nonce_time */ &nonce_time,
                    /* nonce_rand */ &&nonce_rand[..],
                    /* extensions */ &encoded_extensions,
                    /* input_shares */ &encoded_input_shares,
                ],
            )
            .await?;
        Ok(())
    }

    /// put_report_share stores a report share, given its associated task ID.
    ///
    /// This method is intended for use by the helper; notably, it does not store extensions or
    /// input_shares, as these are not required to be stored for the helper workflow (and the helper
    /// never observes the entire set of encrypted input shares, so it could not record the full
    /// client report in any case).
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_share(
        &self,
        task_id: TaskId,
        report_share: &ReportShare,
    ) -> Result<(), Error> {
        let nonce_time = report_share.nonce.time().as_naive_date_time();
        let nonce_rand = report_share.nonce.rand();

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
                    /* nonce_time */ &nonce_time,
                    /* nonce_rand */ &&nonce_rand[..],
                ],
            )
            .await?;
        Ok(())
    }

    /// get_aggregation_job retrieves an aggregation job by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_aggregation_job<A: vdaf::Aggregator>(
        &self,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
    ) -> Result<Option<AggregationJob<A>>, Error>
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
                    /* task_id */ &task_id.as_bytes(),
                    /* aggregation_job_id */ &aggregation_job_id.as_bytes(),
                ],
            )
            .await?
            .map(|row| Self::aggregation_job_from_row(task_id, aggregation_job_id, row))
            .transpose()
    }

    /// get_aggregation_jobs_for_task_id returns all aggregation jobs for a given task ID. It is
    /// intended for use in tests.
    #[tracing::instrument(skip(self), err)]
    #[doc(hidden)]
    pub async fn get_aggregation_jobs_for_task_id<A: vdaf::Aggregator>(
        &self,
        task_id: TaskId,
    ) -> Result<Vec<AggregationJob<A>>, Error>
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
            .query(&stmt, &[/* task_id */ &task_id.as_bytes()])
            .await?
            .into_iter()
            .map(|row| {
                let aggregation_job_id =
                    AggregationJobId::get_decoded(row.get("aggregation_job_id"))?;
                Self::aggregation_job_from_row(task_id, aggregation_job_id, row)
            })
            .collect()
    }

    fn aggregation_job_from_row<A: vdaf::Aggregator>(
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        row: Row,
    ) -> Result<AggregationJob<A>, Error>
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

    /// put_aggregation_job stores an aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_aggregation_job<A: vdaf::Aggregator>(
        &self,
        aggregation_job: &AggregationJob<A>,
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
                    /* aggregation_job_id */ &aggregation_job.aggregation_job_id.as_bytes(),
                    /* task_id */ &aggregation_job.task_id.as_bytes(),
                    /* aggregation_param */ &aggregation_job.aggregation_param.get_encoded(),
                    /* state */ &aggregation_job.state,
                ],
            )
            .await?;
        Ok(())
    }

    // update_aggregation_job updates a stored aggregation job.
    #[tracing::instrument(skip(self), err)]
    pub async fn update_aggregation_job<A: vdaf::Aggregator>(
        &self,
        aggregation_job: &AggregationJob<A>,
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
        check_update(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* aggregation_param */
                        &aggregation_job.aggregation_param.get_encoded(),
                        /* state */ &aggregation_job.state,
                        /* aggregation_job_id */
                        &aggregation_job.aggregation_job_id.as_bytes(),
                        /* task_id */ &aggregation_job.task_id.as_bytes(),
                    ],
                )
                .await?,
        )
    }

    /// get_report_aggregation gets a report aggregation by ID.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregation<A: vdaf::Aggregator>(
        &self,
        verify_param: &A::VerifyParam,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        nonce: Nonce,
    ) -> Result<Option<ReportAggregation<A>>, Error>
    where
        A::PrepareStep: ParameterizedDecode<A::VerifyParam>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let nonce_time = nonce.time().as_naive_date_time();
        let nonce_rand = &nonce.rand()[..];

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.nonce_time, client_reports.nonce_rand, report_aggregations.ord, report_aggregations.state, report_aggregations.vdaf_message, report_aggregations.error_code
                FROM report_aggregations
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                WHERE report_aggregations.aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1)
                  AND client_reports.task_id = (SELECT id FROM tasks WHERE task_id = $2)
                  AND client_reports.nonce_time = $3
                  AND client_reports.nonce_rand = $4",
            )
            .await?;
        self.tx
            .query_opt(
                &stmt,
                &[
                    /* aggregation_job_id */ &aggregation_job_id.as_bytes(),
                    /* task_id */ &task_id.as_bytes(),
                    /* nonce_time */ &nonce_time,
                    /* nonce_rand */ &nonce_rand,
                ],
            )
            .await?
            .map(|row| report_aggregation_from_row(verify_param, task_id, aggregation_job_id, row))
            .transpose()
    }

    /// get_report_aggregations_for_aggregation_job retrieves all report aggregations associated
    /// with a given aggregation job, ordered by their natural ordering.
    #[tracing::instrument(skip(self), err)]
    pub async fn get_report_aggregations_for_aggregation_job<A: vdaf::Aggregator>(
        &self,
        verify_param: &A::VerifyParam,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
    ) -> Result<Vec<ReportAggregation<A>>, Error>
    where
        A::PrepareStep: ParameterizedDecode<A::VerifyParam>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.nonce_time, client_reports.nonce_rand, report_aggregations.ord, report_aggregations.state, report_aggregations.vdaf_message, report_aggregations.error_code
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
                    /* aggregation_job_id */ &aggregation_job_id.as_bytes(),
                    /* task_id */ &task_id.as_bytes(),
                ],
            )
            .await?
            .into_iter()
            .map(|row| report_aggregation_from_row(verify_param, task_id, aggregation_job_id, row))
            .collect()
    }

    /// put_report_aggregation stores aggregation data for a single report.
    #[tracing::instrument(skip(self), err)]
    pub async fn put_report_aggregation<A: vdaf::Aggregator>(
        &self,
        report_aggregation: &ReportAggregation<A>,
    ) -> Result<(), Error>
    where
        A::PrepareStep: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let nonce_time = report_aggregation.nonce.time().as_naive_date_time();
        let nonce_rand = &report_aggregation.nonce.rand()[..];
        let state_code = report_aggregation.state.state_code();
        let (vdaf_message, error_code) = match &report_aggregation.state {
            ReportAggregationState::Start => (None, None),
            ReportAggregationState::Waiting(prep_step) => (Some(prep_step.get_encoded()), None),
            ReportAggregationState::Finished(output_share) => (Some(output_share.into()), None),
            ReportAggregationState::Failed(trans_err) => (None, Some(*trans_err)),
            ReportAggregationState::Invalid => (None, None),
        };
        let error_code = error_code.map(|err| err as i64);

        let stmt = self.tx.prepare_cached(
            "INSERT INTO report_aggregations (aggregation_job_id, client_report_id, ord, state, vdaf_message, error_code)
            VALUES ((SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $1),
                    (SELECT id FROM client_reports
                     WHERE task_id = (SELECT id FROM tasks WHERE task_id = $2)
                     AND nonce_time = $3 AND nonce_rand = $4),
                    $5, $6, $7, $8)"
        ).await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* aggregation_job_id */
                    &report_aggregation.aggregation_job_id.as_bytes(),
                    /* task_id */ &report_aggregation.task_id.as_bytes(),
                    /* nonce_time */ &nonce_time,
                    /* nonce_rand */ &nonce_rand,
                    /* ord */ &report_aggregation.ord,
                    /* state */ &state_code,
                    /* vdaf_message */ &vdaf_message,
                    /* error_code */ &error_code,
                ],
            )
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn update_report_aggregation<A: vdaf::Aggregator>(
        &self,
        report_aggregation: &ReportAggregation<A>,
    ) -> Result<(), Error>
    where
        A::PrepareStep: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let nonce_time = report_aggregation.nonce.time().as_naive_date_time();
        let nonce_rand = &report_aggregation.nonce.rand()[..];
        let state_code = report_aggregation.state.state_code();
        let (vdaf_message, error_code) = match &report_aggregation.state {
            ReportAggregationState::Start => (None, None),
            ReportAggregationState::Waiting(prep_step) => (Some(prep_step.get_encoded()), None),
            ReportAggregationState::Finished(output_share) => (Some(output_share.into()), None),
            ReportAggregationState::Failed(trans_err) => (None, Some(*trans_err)),
            ReportAggregationState::Invalid => (None, None),
        };
        let error_code = error_code.map(|err| err as i64);

        let stmt = self
            .tx
            .prepare_cached(
                "UPDATE report_aggregations SET ord = $1, state = $2, vdaf_message = $3, error_code = $4
                WHERE aggregation_job_id = (SELECT id FROM aggregation_jobs WHERE aggregation_job_id = $5)
                AND client_report_id = (SELECT id FROM client_reports
                    WHERE task_id = (SELECT id FROM tasks WHERE task_id = $6)
                    AND nonce_time = $7 AND nonce_rand = $8)")
            .await?;
        check_update(
            self.tx
                .execute(
                    &stmt,
                    &[
                        /* ord */ &report_aggregation.ord,
                        /* state */ &state_code,
                        /* vdaf_message */ &vdaf_message,
                        /* error_code */ &error_code,
                        /* aggregation_job_id */
                        &report_aggregation.aggregation_job_id.as_bytes(),
                        /* task_id */ &report_aggregation.task_id.as_bytes(),
                        /* nonce_time */ &nonce_time,
                        /* nonce_rand */ &nonce_rand,
                    ],
                )
                .await?,
        )
    }

    /// If a collect job corresponding to the provided values exists, its UUID is returned, which
    /// may then be used to construct a collect job URI. If that collect job does not exist, returns
    /// `Ok(None)`.
    #[tracing::instrument(skip(self, encoded_aggregation_parameter), err)]
    pub(crate) async fn get_collect_job_uuid(
        &self,
        task_id: TaskId,
        batch_interval: Interval,
        encoded_aggregation_parameter: &[u8],
    ) -> Result<Option<Uuid>, Error> {
        let batch_interval_start = batch_interval.start().as_naive_date_time();
        let batch_interval_duration = i64::try_from(batch_interval.duration().as_seconds())?;

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT collect_job_id FROM collect_jobs
                WHERE task_id = (SELECT id FROM tasks WHERE task_id = $1)
                AND batch_interval_start = $2 AND batch_interval_duration = $3
                AND aggregation_param = $4",
            )
            .await?;
        let row = self
            .tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &task_id.as_bytes(),
                    &batch_interval_start,
                    &batch_interval_duration,
                    /* aggregation_param */ &encoded_aggregation_parameter,
                ],
            )
            .await?;

        Ok(row.map(|row| row.get("collect_job_id")))
    }

    /// Constructs and stores a collect job for the provided values, and returns the UUID that was
    /// assigned.
    #[tracing::instrument(skip(self, encoded_aggregation_parameter), err)]
    pub(crate) async fn put_collect_job(
        &self,
        task_id: TaskId,
        batch_interval: Interval,
        encoded_aggregation_parameter: &[u8],
    ) -> Result<Uuid, Error> {
        let batch_interval_start = batch_interval.start().as_naive_date_time();
        let batch_interval_duration = i64::try_from(batch_interval.duration().as_seconds())?;

        let collect_job_id = Uuid::new_v4();

        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO collect_jobs (collect_job_id, task_id,
                batch_interval_start, batch_interval_duration, aggregation_param)
                VALUES ($1, (SELECT id FROM tasks WHERE task_id = $2), $3, $4, $5)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* collect_job_id */ &collect_job_id,
                    /* task_id */ &task_id.as_bytes(),
                    &batch_interval_start,
                    &batch_interval_duration,
                    /* aggregation_param */ &encoded_aggregation_parameter,
                ],
            )
            .await?;

        Ok(collect_job_id)
    }

    /// Store a new `batch_unit_aggregations` row in the datastore.
    #[cfg(test)]
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_batch_unit_aggregation<A>(
        &self,
        batch_unit_aggregation: &BatchUnitAggregation<A>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator,
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
                    /* task_id */ &batch_unit_aggregation.task_id.as_bytes(),
                    &unit_interval_start,
                    /* aggregation_param */ &encoded_aggregation_param,
                    /* aggregate_share */ &encoded_aggregate_share,
                    &report_count,
                    /* checksum */ &&batch_unit_aggregation.checksum[..],
                ],
            )
            .await?;

        Ok(())
    }

    /// Fetch all the `batch_unit_aggregations` rows whose `unit_interval_start` describes an
    /// interval that falls within the provided `interval` and whose `aggregation_param` matches.
    #[tracing::instrument(skip(self, aggregation_param), err)]
    pub(crate) async fn get_batch_unit_aggregations_for_task_in_interval<A, E>(
        &self,
        task_id: TaskId,
        interval: Interval,
        aggregation_param: &A::AggregationParam,
    ) -> Result<Vec<BatchUnitAggregation<A>>, Error>
    where
        A: vdaf::Aggregator,
        A::AggregationParam: Encode + Clone,
        E: std::fmt::Display,
        for<'a> A::AggregateShare: TryFrom<&'a [u8], Error = E>,
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
                    /* task_id */ &task_id.as_bytes(),
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
                let checksum: &[u8] = row.get("checksum");
                let checksum: [u8; 32] = checksum.try_into().map_err(|e| {
                    Error::DbState(format!(
                        "checksum byte array in database has wrong length: {}",
                        e
                    ))
                })?;

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
    pub(crate) async fn get_aggregate_share_job_by_request<A, E>(
        &self,
        request: &AggregateShareReq,
    ) -> Result<Option<AggregateShareJob<A>>, Error>
    where
        A: vdaf::Aggregator,
        E: std::fmt::Display,
        for<'a> A::AggregateShare: TryFrom<&'a [u8], Error = E>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let batch_interval_start = request.batch_interval.start().as_naive_date_time();
        let batch_interval_duration =
            i64::try_from(request.batch_interval.duration().as_seconds())?;

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT helper_aggregate_share, report_count, checksum FROM aggregate_share_jobs
                WHERE
                    task_id = (SELECT id FROM tasks WHERE task_id = $1)
                    AND batch_interval_start = $2
                    AND batch_interval_duration = $3
                    AND aggregation_param = $4",
            )
            .await?;
        let row = match self
            .tx
            .query_opt(
                &stmt,
                &[
                    /* task_id */ &request.task_id.as_bytes(),
                    &batch_interval_start,
                    &batch_interval_duration,
                    /* aggregation_param */ &request.aggregation_param,
                ],
            )
            .await?
        {
            Some(row) => row,
            None => return Ok(None),
        };

        let aggregation_param = A::AggregationParam::get_decoded(&request.aggregation_param)?;
        let helper_aggregate_share = row.get_bytea_and_convert("helper_aggregate_share")?;
        let report_count = row.get_bigint_and_convert("report_count")?;
        let checksum: [u8; 32] = row.get_bytea_and_convert("checksum")?;

        Ok(Some(AggregateShareJob {
            task_id: request.task_id,
            batch_interval: request.batch_interval,
            aggregation_param,
            helper_aggregate_share,
            report_count,
            checksum,
        }))
    }

    /// Returns a map whose keys are those values from `intervals` that fall within the batch
    /// interval described by at least one `aggregate_share_jobs` row.
    pub(crate) async fn get_aggregate_share_job_counts_for_intervals(
        &self,
        task_id: TaskId,
        intervals: &[Interval],
    ) -> Result<HashMap<Interval, u64>, Error> {
        let interval_starts: Vec<NaiveDateTime> = intervals
            .iter()
            .map(|interval| interval.start().as_naive_date_time())
            .collect();
        let interval_ends: Vec<NaiveDateTime> = intervals
            .iter()
            .map(|interval| interval.end().as_naive_date_time())
            .collect();

        let stmt = self
            .tx
            .prepare_cached(
                "WITH ranges AS (
                    SELECT tsrange(x.range_start, x.range_end) as interval
                    FROM unnest($1::TIMESTAMP[], $2::TIMESTAMP[]) AS x(range_start, range_end)
                )
                SELECT
                    COUNT(aggregate_share_jobs.batch_interval_start) as overlap_count,
                    lower(ranges.interval) as interval_start,
                    upper(ranges.interval) as interval_end
                FROM aggregate_share_jobs
                INNER JOIN ranges
                    ON tsrange(
                        aggregate_share_jobs.batch_interval_start,
                        aggregate_share_jobs.batch_interval_start + aggregate_share_jobs.batch_interval_duration * interval '1 second'
                    ) @> ranges.interval
                WHERE aggregate_share_jobs.task_id = (SELECT id FROM tasks WHERE task_id = $3)
                GROUP BY ranges.interval;"
            )
            .await?;
        let rows = self
            .tx
            .query(
                &stmt,
                &[&interval_starts, &interval_ends, &task_id.as_bytes()],
            )
            .await?;

        rows.into_iter()
            .map(|row| {
                let interval_start = Time::from_naive_date_time(row.get("interval_start"));
                let interval_end = Time::from_naive_date_time(row.get("interval_end"));
                let interval =
                    Interval::new(interval_start, interval_end.difference(interval_start)?)?;
                let overlap_count = row.get_bigint_and_convert("overlap_count")?;
                Ok((interval, overlap_count))
            })
            .collect::<Result<_, _>>()
    }

    /// Put an `aggregate_share_job` row into the datastore.
    #[tracing::instrument(skip(self), err)]
    pub(crate) async fn put_aggregate_share_job<A, E>(
        &self,
        job: &AggregateShareJob<A>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator,
        E: std::fmt::Display,
        for<'a> A::AggregateShare: TryFrom<&'a [u8], Error = E>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let batch_interval_start = job.batch_interval.start().as_naive_date_time();
        let batch_interval_duration = i64::try_from(job.batch_interval.duration().as_seconds())?;
        let encoded_aggregation_param = job.aggregation_param.get_encoded();
        let encoded_aggregate_share: Vec<u8> = (&job.helper_aggregate_share).into();
        let report_count = i64::try_from(job.report_count)?;

        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO aggregate_share_jobs (
                    task_id, batch_interval_start, batch_interval_duration, aggregation_param,
                    helper_aggregate_share, report_count, checksum
                )
                VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    /* task_id */ &job.task_id.as_bytes(),
                    &batch_interval_start,
                    &batch_interval_duration,
                    /* aggregation_param */ &encoded_aggregation_param,
                    /* aggregate_share */ &encoded_aggregate_share,
                    &report_count,
                    /* checksum */ &&job.checksum[..],
                ],
            )
            .await?;

        Ok(())
    }
}

fn check_update(row_count: u64) -> Result<(), Error> {
    match row_count {
        0 => Err(Error::MutationTargetNotFound),
        1 => Ok(()),
        _ => panic!(
            "update which should have affected at most one row instead affected {} rows",
            row_count
        ),
    }
}

fn report_aggregation_from_row<A: vdaf::Aggregator>(
    verify_param: &A::VerifyParam,
    task_id: TaskId,
    aggregation_job_id: AggregationJobId,
    row: Row,
) -> Result<ReportAggregation<A>, Error>
where
    A::PrepareStep: ParameterizedDecode<A::VerifyParam>,
    A::OutputShare: for<'a> TryFrom<&'a [u8]>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    let nonce_rand: Vec<u8> = row.get("nonce_rand");
    let nonce = Nonce::new(
        Time::from_naive_date_time(row.get("nonce_time")),
        nonce_rand.try_into().map_err(|err| {
            Error::DbState(format!("couldn't convert nonce_rand value: {0:?}", err))
        })?,
    );
    let ord: i64 = row.get("ord");
    let state: ReportAggregationStateCode = row.get("state");
    let vdaf_message_bytes: Option<Vec<u8>> = row.get("vdaf_message");
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
            ReportAggregationState::Waiting(A::PrepareStep::get_decoded_with_param(
                verify_param,
                &vdaf_message_bytes.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state WAITING but vdaf_message is NULL".to_string(),
                    )
                })?,
            )?)
        }
        ReportAggregationStateCode::Finished => ReportAggregationState::Finished(
            A::OutputShare::try_from(&vdaf_message_bytes.ok_or_else(|| {
                Error::DbState(
                    "report aggregation in state FINISHED but vdaf_message is NULL".to_string(),
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

    /// Get a PostgreSQL `BYTEA` from the row and then attempt to convert it to
    /// u64, treating it as an 8 byte big endian array.
    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to convert it to `T`.
    fn get_bytea_and_convert<T, E>(&self, idx: &'static str) -> Result<T, Error>
    where
        E: Display,
        for<'a> T: TryFrom<&'a [u8], Error = E>;
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

    fn get_bytea_and_convert<T, E>(&self, idx: &'static str) -> Result<T, Error>
    where
        E: Display,
        for<'a> T: TryFrom<&'a [u8], Error = E>,
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

#[allow(dead_code)] // TODO(brandon): remove once Crypter is used by Datastore
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
        let mut nonce_bytes = [0u8; aead::NONCE_LEN];
        thread_rng().fill(&mut nonce_bytes);
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

        // TODO(brandon): use `rsplit_array_ref` once it is stabilized. [https://github.com/rust-lang/rust/issues/90091]
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
    Message(#[from] janus::message::Error),
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
        message::{AggregationJobId, Interval, TransitionError},
        task,
    };
    use derivative::Derivative;
    use janus::message::{Nonce, Role, TaskId, Time};
    use postgres_types::{FromSql, ToSql};
    use prio::vdaf;

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
    #[derive(Clone, Debug)]
    pub struct AggregationJob<A: vdaf::Aggregator>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub aggregation_job_id: AggregationJobId,
        pub task_id: TaskId,
        pub aggregation_param: A::AggregationParam,
        pub state: AggregationJobState,
    }

    impl<A: vdaf::Aggregator> PartialEq for AggregationJob<A>
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

    impl<A: vdaf::Aggregator> Eq for AggregationJob<A>
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
    }

    /// ReportAggregation represents a the state of a single client report's ongoing aggregation.
    #[derive(Clone, Debug)]
    pub struct ReportAggregation<A: vdaf::Aggregator>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub aggregation_job_id: AggregationJobId,
        pub task_id: TaskId,
        pub nonce: Nonce,
        pub ord: i64,
        pub state: ReportAggregationState<A>,
    }

    impl<A: vdaf::Aggregator> PartialEq for ReportAggregation<A>
    where
        A::PrepareStep: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.aggregation_job_id == other.aggregation_job_id
                && self.task_id == other.task_id
                && self.nonce == other.nonce
                && self.ord == other.ord
                && self.state == other.state
        }
    }

    impl<A: vdaf::Aggregator> Eq for ReportAggregation<A>
    where
        A::PrepareStep: Eq,
        A::OutputShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// ReportAggregationState represents the state of a single report aggregation. It corresponds
    /// to the REPORT_AGGREGATION_STATE enum in the schema, along with the state-specific data.
    #[derive(Clone, Debug)]
    pub enum ReportAggregationState<A: vdaf::Aggregator>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        Start,
        Waiting(A::PrepareStep),
        Finished(A::OutputShare),
        Failed(TransitionError),
        Invalid,
    }

    impl<A: vdaf::Aggregator> ReportAggregationState<A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(super) fn state_code(&self) -> ReportAggregationStateCode {
            match self {
                ReportAggregationState::Start => ReportAggregationStateCode::Start,
                ReportAggregationState::Waiting(_) => ReportAggregationStateCode::Waiting,
                ReportAggregationState::Finished(_) => ReportAggregationStateCode::Finished,
                ReportAggregationState::Failed(_) => ReportAggregationStateCode::Failed,
                ReportAggregationState::Invalid => ReportAggregationStateCode::Invalid,
            }
        }
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

    impl<A: vdaf::Aggregator> PartialEq for ReportAggregationState<A>
    where
        A::PrepareStep: PartialEq,
        A::OutputShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Waiting(lhs_prep_step), Self::Waiting(rhs_prep_step)) => {
                    lhs_prep_step == rhs_prep_step
                }
                (Self::Finished(lhs_out_share), Self::Finished(rhs_out_share)) => {
                    lhs_out_share == rhs_out_share
                }
                (Self::Failed(lhs_trans_err), Self::Failed(rhs_trans_err)) => {
                    lhs_trans_err == rhs_trans_err
                }
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    impl<A: vdaf::Aggregator> Eq for ReportAggregationState<A>
    where
        A::PrepareStep: Eq,
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
    pub(crate) struct BatchUnitAggregation<A: vdaf::Aggregator>
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
        pub(crate) checksum: [u8; 32],
    }

    impl<A: vdaf::Aggregator> PartialEq for BatchUnitAggregation<A>
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

    impl<A: vdaf::Aggregator> Eq for BatchUnitAggregation<A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }

    /// AggregateShareJob represents a row in the `aggregate_share_jobs` table, used by helpers to
    /// store the results of handling an AggregateShareReq from the leader.
    #[derive(Clone, Derivative)]
    #[derivative(Debug)]
    pub(crate) struct AggregateShareJob<A: vdaf::Aggregator>
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
        pub(crate) checksum: [u8; 32],
    }

    impl<A: vdaf::Aggregator> PartialEq for AggregateShareJob<A>
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

    impl<A: vdaf::Aggregator> Eq for AggregateShareJob<A>
    where
        A::AggregationParam: Eq,
        A::AggregateShare: Eq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
    }
}

#[cfg(test)]
pub mod test_util {
    use super::{Crypter, Datastore};

    test_util::define_ephemeral_datastore!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregator::test_util::fake,
        datastore::{models::AggregationJobState, test_util::ephemeral_datastore},
        message::{Interval, TransitionError},
        task::{test_util::new_dummy_task, Vdaf},
        trace::test_util::install_test_trace_subscriber,
    };
    use ::test_util::generate_aead_key;
    use assert_matches::assert_matches;
    use janus::message::{Duration, ExtensionType, HpkeConfigId, Role, Time};
    use prio::{
        field::{Field128, Field64},
        vdaf::{
            poplar1::{IdpfInput, Poplar1, ToyIdpf},
            prg::PrgAes128,
            prio3::Prio3Aes128Count,
            AggregateShare, PrepareTransition,
        },
    };
    use std::collections::{BTreeSet, HashMap, HashSet};

    #[tokio::test]
    async fn roundtrip_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let values = [
            (TaskId::random(), Vdaf::Prio3Aes128Count, Role::Leader),
            (
                TaskId::random(),
                Vdaf::Prio3Aes128Sum { bits: 64 },
                Role::Helper,
            ),
            (
                TaskId::random(),
                Vdaf::Prio3Aes128Sum { bits: 32 },
                Role::Helper,
            ),
            (
                TaskId::random(),
                Vdaf::Prio3Aes128Histogram {
                    buckets: vec![0, 100, 200, 400],
                },
                Role::Leader,
            ),
            (
                TaskId::random(),
                Vdaf::Prio3Aes128Histogram {
                    buckets: vec![0, 25, 50, 75, 100],
                },
                Role::Leader,
            ),
            (TaskId::random(), Vdaf::Poplar1 { bits: 8 }, Role::Helper),
            (TaskId::random(), Vdaf::Poplar1 { bits: 64 }, Role::Helper),
        ];

        // Insert tasks, check that they can be retrieved by ID.
        let mut want_tasks = HashMap::new();
        for (task_id, vdaf, role) in values {
            let task = new_dummy_task(task_id, vdaf, role);

            ds.run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

            let retrieved_task = ds
                .run_tx(|tx| Box::pin(async move { tx.get_task(task_id).await }))
                .await
                .unwrap();
            assert_eq!(Some(&task), retrieved_task.as_ref());
            want_tasks.insert(task_id, task);
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
        let (ds, _db_handle) = ephemeral_datastore().await;

        let report = Report {
            task_id: TaskId::random(),
            nonce: Nonce::new(
                Time::from_seconds_since_epoch(12345),
                [1, 2, 3, 4, 5, 6, 7, 8],
            ),
            extensions: vec![
                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
            ],
            encrypted_input_shares: vec![
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
            ],
        };

        ds.run_tx(|tx| {
            let report = report.clone();
            Box::pin(async move {
                tx.put_task(&new_dummy_task(
                    report.task_id,
                    Vdaf::Prio3Aes128Count,
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
                Box::pin(async move { tx.get_client_report(report.task_id, report.nonce).await })
            })
            .await
            .unwrap();

        assert_eq!(Some(report), retrieved_report);
    }

    #[tokio::test]
    async fn report_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report(
                        TaskId::random(),
                        Nonce::new(
                            Time::from_seconds_since_epoch(12345),
                            [1, 2, 3, 4, 5, 6, 7, 8],
                        ),
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
        let (ds, _db_handle) = ephemeral_datastore().await;

        let task_id = TaskId::random();
        let unrelated_task_id = TaskId::random();

        let first_unaggregated_report = Report {
            task_id,
            nonce: Nonce::new(
                Time::from_seconds_since_epoch(12345),
                [1, 2, 3, 4, 5, 6, 7, 8],
            ),
            extensions: vec![],
            encrypted_input_shares: vec![],
        };
        let second_unaggregated_report = Report {
            task_id,
            nonce: Nonce::new(
                Time::from_seconds_since_epoch(12346),
                [1, 2, 3, 4, 5, 6, 7, 8],
            ),
            extensions: vec![],
            encrypted_input_shares: vec![],
        };
        let aggregated_report = Report {
            task_id,
            nonce: Nonce::new(
                Time::from_seconds_since_epoch(12347),
                [1, 2, 3, 4, 5, 6, 7, 8],
            ),
            extensions: vec![],
            encrypted_input_shares: vec![],
        };
        let unrelated_report = Report {
            task_id: unrelated_task_id,
            nonce: Nonce::new(
                Time::from_seconds_since_epoch(12348),
                [1, 2, 3, 4, 5, 6, 7, 8],
            ),
            extensions: vec![],
            encrypted_input_shares: vec![],
        };

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
                tx.put_task(&new_dummy_task(
                    task_id,
                    Vdaf::Prio3Aes128Count,
                    Role::Leader,
                ))
                .await?;
                tx.put_task(&new_dummy_task(
                    unrelated_task_id,
                    Vdaf::Prio3Aes128Count,
                    Role::Leader,
                ))
                .await?;

                tx.put_client_report(&first_unaggregated_report).await?;
                tx.put_client_report(&second_unaggregated_report).await?;
                tx.put_client_report(&aggregated_report).await?;
                tx.put_client_report(&unrelated_report).await?;

                let aggregation_job_id = AggregationJobId::random();
                tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                    aggregation_job_id,
                    task_id: unrelated_task_id,
                    aggregation_param: (),
                    state: AggregationJobState::InProgress,
                })
                .await?;
                tx.put_report_aggregation(&ReportAggregation {
                    aggregation_job_id,
                    task_id,
                    nonce: aggregated_report.nonce,
                    ord: 0,
                    state: ReportAggregationState::<Prio3Aes128Count>::Start,
                })
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
                first_unaggregated_report.nonce,
                second_unaggregated_report.nonce
            ]),
        );
    }

    #[tokio::test]
    async fn roundtrip_report_share() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let task_id = TaskId::random();
        let report_share = ReportShare {
            nonce: Nonce::new(
                Time::from_seconds_since_epoch(12345),
                [1, 2, 3, 4, 5, 6, 7, 8],
            ),
            extensions: vec![
                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_0")),
                Extension::new(ExtensionType::Tbd, Vec::from("extension_data_1")),
            ],
            encrypted_input_share: HpkeCiphertext::new(
                HpkeConfigId::from(12),
                Vec::from("encapsulated_context_0"),
                Vec::from("payload_0"),
            ),
        };

        ds.run_tx(|tx| {
            let report_share = report_share.clone();
            Box::pin(async move {
                tx.put_task(&new_dummy_task(
                    task_id,
                    Vdaf::Prio3Aes128Count,
                    Role::Leader,
                ))
                .await?;
                tx.put_report_share(task_id, &report_share).await
            })
        })
        .await
        .unwrap();

        let (got_task_id, got_extensions, got_input_shares) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let nonce_time = report_share.nonce.time().as_naive_date_time();
                    let nonce_rand = report_share.nonce.rand();
                    let row = tx
                        .tx
                        .query_one(
                            "SELECT tasks.task_id, client_reports.nonce_time, client_reports.nonce_rand, client_reports.extensions, client_reports.input_shares
                            FROM client_reports JOIN tasks ON tasks.id = client_reports.task_id
                            WHERE nonce_time = $1 AND nonce_rand = $2",
                            &[&nonce_time, &&nonce_rand[..]],
                        )
                        .await?;

                    let task_id = TaskId::get_decoded(row.get("task_id"))?;

                    let maybe_extensions: Option<Vec<u8>> = row.get("extensions");
                    let maybe_input_shares: Option<Vec<u8>> = row.get("input_shares");

                    Ok((task_id, maybe_extensions, maybe_input_shares))
                })
            })
            .await
            .unwrap();

        assert_eq!(task_id, got_task_id);
        assert!(got_extensions.is_none());
        assert!(got_input_shares.is_none());
    }

    #[tokio::test]
    async fn roundtrip_aggregation_job() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        // We use Poplar1 for this test as it has a non-trivial aggregation parameter, to allow
        // better exercising the serialization/deserialization roundtrip of the aggregation_param.
        type ToyPoplar1 = Poplar1<ToyIdpf<Field128>, PrgAes128, 16>;
        let aggregation_job = AggregationJob::<ToyPoplar1> {
            aggregation_job_id: AggregationJobId::random(),
            task_id: TaskId::random(),
            aggregation_param: BTreeSet::from([
                IdpfInput::new("abc".as_bytes(), 0).unwrap(),
                IdpfInput::new("def".as_bytes(), 1).unwrap(),
            ]),
            state: AggregationJobState::InProgress,
        };

        ds.run_tx(|tx| {
            let aggregation_job = aggregation_job.clone();
            Box::pin(async move {
                tx.put_task(&new_dummy_task(
                    aggregation_job.task_id,
                    Vdaf::Poplar1 { bits: 64 },
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
    async fn aggregation_job_not_found() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_aggregation_job::<Prio3Aes128Count>(
                        TaskId::random(),
                        AggregationJobId::random(),
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
                    tx.update_aggregation_job::<Prio3Aes128Count>(&AggregationJob {
                        aggregation_job_id: AggregationJobId::random(),
                        task_id: TaskId::random(),
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
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
        let (ds, _db_handle) = ephemeral_datastore().await;

        // We use Poplar1 for this test as it has a non-trivial aggregation parameter, to allow
        // better exercising the serialization/deserialization roundtrip of the aggregation_param.
        type ToyPoplar1 = Poplar1<ToyIdpf<Field128>, PrgAes128, 16>;
        let task_id = TaskId::random();
        let first_aggregation_job = AggregationJob::<ToyPoplar1> {
            aggregation_job_id: AggregationJobId::random(),
            task_id,
            aggregation_param: BTreeSet::from([
                IdpfInput::new("abc".as_bytes(), 0).unwrap(),
                IdpfInput::new("def".as_bytes(), 1).unwrap(),
            ]),
            state: AggregationJobState::InProgress,
        };
        let second_aggregation_job = AggregationJob::<ToyPoplar1> {
            aggregation_job_id: AggregationJobId::random(),
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
                tx.put_task(&new_dummy_task(
                    task_id,
                    Vdaf::Poplar1 { bits: 64 },
                    Role::Leader,
                ))
                .await?;
                tx.put_aggregation_job(&first_aggregation_job).await?;
                tx.put_aggregation_job(&second_aggregation_job).await?;

                // Also write an unrelated aggregation job with a different task ID to check that it
                // is not returned.
                let unrelated_task_id = TaskId::random();
                tx.put_task(&new_dummy_task(
                    unrelated_task_id,
                    Vdaf::Poplar1 { bits: 64 },
                    Role::Leader,
                ))
                .await?;
                tx.put_aggregation_job(&AggregationJob::<ToyPoplar1> {
                    aggregation_job_id: AggregationJobId::random(),
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
        let (ds, _db_handle) = ephemeral_datastore().await;

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (verify_param, prep_step, output_share) = generate_vdaf_values(vdaf, (), 0);

        for (ord, state) in [
            ReportAggregationState::<Prio3Aes128Count>::Start,
            ReportAggregationState::Waiting(prep_step),
            ReportAggregationState::Finished(output_share),
            ReportAggregationState::Failed(TransitionError::VdafPrepError),
            ReportAggregationState::Invalid,
        ]
        .iter()
        .enumerate()
        {
            let task_id = TaskId::random();
            let aggregation_job_id = AggregationJobId::random();
            let nonce = Nonce::new(
                Time::from_seconds_since_epoch(12345),
                [1, 2, 3, 4, 5, 6, 7, 8],
            );

            let report_aggregation = ds
                .run_tx(|tx| {
                    let state = state.clone();
                    Box::pin(async move {
                        tx.put_task(&new_dummy_task(
                            task_id,
                            Vdaf::Prio3Aes128Count,
                            Role::Leader,
                        ))
                        .await?;
                        tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        })
                        .await?;
                        tx.put_report_share(
                            task_id,
                            &ReportShare {
                                nonce,
                                extensions: Vec::new(),
                                encrypted_input_share: HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            },
                        )
                        .await?;

                        let report_aggregation = ReportAggregation {
                            aggregation_job_id,
                            task_id,
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
                    let verify_param = verify_param.clone();
                    Box::pin(async move {
                        tx.get_report_aggregation::<Prio3Aes128Count>(
                            &verify_param,
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
                    let verify_param = verify_param.clone();
                    Box::pin(async move {
                        tx.get_report_aggregation::<Prio3Aes128Count>(
                            &verify_param,
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
        let (ds, _db_handle) = ephemeral_datastore().await;

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_report_aggregation::<fake::Vdaf>(
                        &(),
                        TaskId::random(),
                        AggregationJobId::random(),
                        Nonce::new(
                            Time::from_seconds_since_epoch(12345),
                            [1, 2, 3, 4, 5, 6, 7, 8],
                        ),
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
                    tx.update_report_aggregation::<fake::Vdaf>(&ReportAggregation {
                        aggregation_job_id: AggregationJobId::random(),
                        task_id: TaskId::random(),
                        nonce: Nonce::new(
                            Time::from_seconds_since_epoch(12345),
                            [1, 2, 3, 4, 5, 6, 7, 8],
                        ),
                        ord: 0,
                        state: ReportAggregationState::Invalid,
                    })
                    .await
                })
            })
            .await;
        assert_matches!(rslt, Err(Error::MutationTargetNotFound));
    }

    #[tokio::test]
    async fn get_report_aggregations_for_aggregation_job() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (verify_param, prep_step, output_share) = generate_vdaf_values(vdaf, (), 0);

        let task_id = TaskId::random();
        let aggregation_job_id = AggregationJobId::random();

        let report_aggregations = ds
            .run_tx(|tx| {
                let prep_step = prep_step.clone();
                let output_share = output_share.clone();

                Box::pin(async move {
                    tx.put_task(&new_dummy_task(
                        task_id,
                        Vdaf::Prio3Aes128Count,
                        Role::Leader,
                    ))
                    .await?;
                    tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    let mut report_aggregations = Vec::new();
                    for (ord, state) in [
                        ReportAggregationState::<Prio3Aes128Count>::Start,
                        ReportAggregationState::Waiting(prep_step),
                        ReportAggregationState::Finished(output_share),
                        ReportAggregationState::Failed(TransitionError::VdafPrepError),
                        ReportAggregationState::Invalid,
                    ]
                    .iter()
                    .enumerate()
                    {
                        let nonce = Nonce::new(
                            Time::from_seconds_since_epoch(12345),
                            (ord as u64).to_be_bytes(),
                        );
                        tx.put_report_share(
                            task_id,
                            &ReportShare {
                                nonce,
                                extensions: Vec::new(),
                                encrypted_input_share: HpkeCiphertext::new(
                                    HpkeConfigId::from(12),
                                    Vec::from("encapsulated_context_0"),
                                    Vec::from("payload_0"),
                                ),
                            },
                        )
                        .await?;

                        let report_aggregation = ReportAggregation {
                            aggregation_job_id,
                            task_id,
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
                let verify_param = verify_param.clone();

                Box::pin(async move {
                    tx.get_report_aggregations_for_aggregation_job(
                        &verify_param,
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

        let task_id = TaskId::random();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(100),
            Duration::from_seconds(100),
        )
        .unwrap();

        let (ds, _db_handle) = ephemeral_datastore().await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.put_task(&new_dummy_task(
                    task_id,
                    Vdaf::Prio3Aes128Count,
                    Role::Leader,
                ))
                .await
            })
        })
        .await
        .unwrap();

        let collect_job_uuid = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_collect_job_uuid(task_id, batch_interval, &[0, 1, 2, 3, 4])
                        .await
                })
            })
            .await
            .unwrap();
        assert!(collect_job_uuid.is_none());

        let collect_job_uuid = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.put_collect_job(task_id, batch_interval, &[0, 1, 2, 3, 4])
                        .await
                })
            })
            .await
            .unwrap();

        let same_collect_job_uuid = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_collect_job_uuid(task_id, batch_interval, &[0, 1, 2, 3, 4])
                        .await
                })
            })
            .await
            .unwrap()
            .unwrap();

        // Should get the same UUID for the same values.
        assert_eq!(collect_job_uuid, same_collect_job_uuid);

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

        let different_collect_job_uuid = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.put_collect_job(
                        task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(101),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                        &[0, 1, 2, 3, 4],
                    )
                    .await
                })
            })
            .await
            .unwrap();

        // New collect job should yield a new UUID.
        assert!(different_collect_job_uuid != collect_job_uuid);

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
    }

    #[tokio::test]
    async fn roundtrip_batch_unit_aggregation() {
        install_test_trace_subscriber();

        type ToyPoplar1 = Poplar1<ToyIdpf<Field64>, PrgAes128, 16>;

        let task_id = TaskId::random();
        let other_task_id = TaskId::random();
        let aggregate_share = AggregateShare::from(vec![Field64::from(17)]);
        let aggregation_param = BTreeSet::from([
            IdpfInput::new("abc".as_bytes(), 0).unwrap(),
            IdpfInput::new("def".as_bytes(), 1).unwrap(),
        ]);

        let (ds, _db_handle) = ephemeral_datastore().await;

        let batch_unit_aggregations: Vec<BatchUnitAggregation<ToyPoplar1>> = ds
            .run_tx(|tx| {
                let (aggregate_share, aggregation_param) =
                    (aggregate_share.clone(), aggregation_param.clone());
                Box::pin(async move {
                    let mut task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Leader);
                    task.min_batch_duration = Duration::from_seconds(100);
                    tx.put_task(&task).await?;

                    tx.put_task(&new_dummy_task(
                        other_task_id,
                        Vdaf::Prio3Aes128Count,
                        Role::Leader,
                    ))
                    .await?;

                    // Start of this aggregation's interval is before the interval queried below.
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(25),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    // Following three batch units are within the interval queried below.
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(100),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(150),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    // The end of this batch unit is exactly the end of the interval queried below.
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(200),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    // Aggregation parameter differs from the one queried below.
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(100),
                        aggregation_param: BTreeSet::from([
                            IdpfInput::new("gh".as_bytes(), 2).unwrap(),
                            IdpfInput::new("jk".as_bytes(), 3).unwrap(),
                        ]),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    // End of this aggregation's interval is after the interval queried below.
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(250),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    // Start of this aggregation's interval is after the interval queried below.
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(400),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    // Task ID differs from that queried below.
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<ToyPoplar1> {
                        task_id: other_task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(200),
                        aggregation_param: aggregation_param.clone(),
                        aggregate_share: aggregate_share.clone(),
                        report_count: 0,
                        checksum: [0; 32],
                    })
                    .await?;

                    tx.get_batch_unit_aggregations_for_task_in_interval::<ToyPoplar1, _>(
                        task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(50),
                            Duration::from_seconds(250),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await
                })
            })
            .await
            .unwrap();

        assert_eq!(
            batch_unit_aggregations.len(),
            3,
            "{:#?}",
            batch_unit_aggregations,
        );
        assert!(
            batch_unit_aggregations.contains(&BatchUnitAggregation {
                task_id,
                unit_interval_start: Time::from_seconds_since_epoch(100),
                aggregation_param: aggregation_param.clone(),
                aggregate_share: aggregate_share.clone(),
                report_count: 0,
                checksum: [0u8; 32],
            }),
            "{:#?}",
            batch_unit_aggregations,
        );
        assert!(
            batch_unit_aggregations.contains(&BatchUnitAggregation {
                task_id,
                unit_interval_start: Time::from_seconds_since_epoch(150),
                aggregation_param: aggregation_param.clone(),
                aggregate_share: aggregate_share.clone(),
                report_count: 0,
                checksum: [0u8; 32],
            }),
            "{:#?}",
            batch_unit_aggregations,
        );
    }

    #[tokio::test]
    async fn roundtrip_aggregate_share_job() {
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore().await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                let task_id = TaskId::random();
                let task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Helper);
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
                let checksum = [1; 32];

                let aggregate_share_job = AggregateShareJob {
                    task_id,
                    batch_interval,
                    aggregation_param: (),
                    helper_aggregate_share: aggregate_share.clone(),
                    report_count,
                    checksum,
                };

                tx.put_aggregate_share_job(&aggregate_share_job)
                    .await
                    .unwrap();

                let aggregate_share_job_again = tx
                    .get_aggregate_share_job_by_request::<Prio3Aes128Count, _>(&AggregateShareReq {
                        task_id,
                        batch_interval,
                        aggregation_param: ().get_encoded(),
                        report_count,
                        checksum,
                    })
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(aggregate_share_job, aggregate_share_job_again);

                assert!(tx
                    .get_aggregate_share_job_by_request::<Prio3Aes128Count, _>(&AggregateShareReq {
                        task_id,
                        batch_interval: other_batch_interval,
                        aggregation_param: ().get_encoded(),
                        report_count,
                        checksum,
                    },)
                    .await
                    .unwrap()
                    .is_none());

                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn aggregate_share_job_count_by_interval() {
        install_test_trace_subscriber();

        let (ds, _db_handle) = ephemeral_datastore().await;

        ds.run_tx(|tx| {
            Box::pin(async move {
                let first_task_id = TaskId::random();
                let mut task = new_dummy_task(first_task_id, Vdaf::Prio3Aes128Count, Role::Helper);
                task.max_batch_lifetime = 2;
                task.min_batch_duration = Duration::from_seconds(100);
                tx.put_task(&task).await?;

                let second_task_id = TaskId::random();
                let other_task =
                    new_dummy_task(second_task_id, Vdaf::Prio3Aes128Count, Role::Helper);
                tx.put_task(&other_task).await?;

                let aggregate_share = AggregateShare::from(vec![Field64::from(17)]);

                // For first_task_id:
                // [100, 200) has been collected once, by the second job.
                // [200, 300) has been collected twice, by the first and second jobs.
                // For second_task_id:
                // [100, 200) has been collected once, by the third job.
                let aggregate_share_jobs = [
                    (
                        first_task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(200),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                    ),
                    (
                        first_task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(200),
                        )
                        .unwrap(),
                    ),
                    (
                        second_task_id,
                        Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                    ),
                ];

                for (task_id, interval) in aggregate_share_jobs {
                    tx.put_aggregate_share_job::<Prio3Aes128Count, _>(&AggregateShareJob {
                        task_id,
                        batch_interval: interval,
                        aggregation_param: (),
                        helper_aggregate_share: aggregate_share.clone(),
                        report_count: 10,
                        checksum: [1; 32],
                    })
                    .await
                    .unwrap();
                }

                struct TestCase {
                    label: &'static str,
                    expected_count: u64,
                    interval: Interval,
                }

                let first_task_collected_batch_units: &[TestCase] = &[
                    TestCase {
                        label: "first task interval [0, 100)",
                        expected_count: 0,
                        interval: Interval::new(
                            Time::from_seconds_since_epoch(0),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                    },
                    TestCase {
                        label: "first task interval [100, 200)",
                        expected_count: 1,
                        interval: Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                    },
                    TestCase {
                        label: "first task interval [200, 300)",
                        expected_count: 2,
                        interval: Interval::new(
                            Time::from_seconds_since_epoch(200),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                    },
                ];

                let second_task_collected_batch_units: &[TestCase] = &[
                    TestCase {
                        label: "second task interval [0, 100)",
                        expected_count: 0,
                        interval: Interval::new(
                            Time::from_seconds_since_epoch(0),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                    },
                    TestCase {
                        label: "second task interval [100, 200)",
                        expected_count: 1,
                        interval: Interval::new(
                            Time::from_seconds_since_epoch(100),
                            Duration::from_seconds(100),
                        )
                        .unwrap(),
                    },
                ];

                for (task_id, test_case_list) in [
                    (first_task_id, first_task_collected_batch_units),
                    (second_task_id, second_task_collected_batch_units),
                ] {
                    let counts = tx
                        .get_aggregate_share_job_counts_for_intervals(
                            task_id,
                            &test_case_list
                                .iter()
                                .map(|v| v.interval)
                                .collect::<Vec<_>>(),
                        )
                        .await
                        .unwrap();
                    tracing::warn!(?counts, "first task counts");
                    for TestCase {
                        label,
                        expected_count,
                        interval,
                    } in test_case_list
                    {
                        if *expected_count == 0 {
                            assert!(!counts.contains_key(interval), "test case: {}", label);
                        } else {
                            assert_eq!(
                                counts.get(interval),
                                Some(expected_count),
                                "test case: {}",
                                label
                            );
                        }
                    }
                }

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
    fn generate_vdaf_values<A: vdaf::Aggregator + vdaf::Client>(
        vdaf: A,
        agg_param: A::AggregationParam,
        measurement: A::Measurement,
    ) -> (A::VerifyParam, A::PrepareStep, A::OutputShare)
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let (public_param, mut verify_params) = vdaf.setup().unwrap();

        let input_shares = vdaf.shard(&public_param, &measurement).unwrap();
        let prep_states: Vec<A::PrepareStep> = verify_params
            .iter()
            .zip(input_shares)
            .map(|(verify_param, input_share)| {
                vdaf.prepare_init(verify_param, &agg_param, b"nonce", &input_share)
                    .unwrap()
            })
            .collect();
        let (mut prep_states, prep_msgs): (Vec<A::PrepareStep>, Vec<A::PrepareMessage>) =
            prep_states
                .iter()
                .map(|prep_state| {
                    if let PrepareTransition::Continue(prep_state, prep_msg) =
                        vdaf.prepare_step(prep_state.clone(), None)
                    {
                        (prep_state, prep_msg)
                    } else {
                        panic!("generate_vdaf_values: VDAF returned something other than Continue")
                    }
                })
                .unzip();
        let prep_msg = vdaf.prepare_preprocess(prep_msgs).unwrap();
        let mut output_shares: Vec<A::OutputShare> = prep_states
            .iter()
            .map(|prep_state| {
                if let PrepareTransition::Finish(output_share) =
                    vdaf.prepare_step(prep_state.clone(), Some(prep_msg.clone()))
                {
                    output_share
                } else {
                    panic!("generate_vdaf_values: VDAF returned something other than Finish")
                }
            })
            .collect();

        (
            verify_params.remove(0),
            prep_states.remove(0),
            output_shares.remove(0),
        )
    }
}
