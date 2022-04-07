//! Janus datastore (durable storage) implementation.

use self::models::{
    AggregationJob, AggregatorRole, ReportAggregation, ReportAggregationState,
    ReportAggregationStateCode,
};
#[cfg(test)]
use crate::{
    hpke::{HpkePrivateKey, HpkeRecipient, Label},
    message::{Duration, HpkeConfig, Role},
    task::AggregatorAuthKey,
};
use crate::{
    message::{AggregationJobId, Extension, HpkeCiphertext, Nonce, Report, ReportShare, TaskId},
    task::TaskParameters,
};
use prio::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode},
    vdaf,
};
use std::{convert::TryFrom, fmt::Display, future::Future, io::Cursor, pin::Pin};
use tokio_postgres::{error::SqlState, row::RowIndex, IsolationLevel, Row};
#[cfg(test)]
use url::Url;

// TODO(brandon): retry network-related & other transient failures once we know what they look like

/// Datastore represents a datastore for Janus, with support for transactional reads and writes.
/// In practice, Datastore instances are currently backed by a PostgreSQL database.
pub struct Datastore {
    pool: deadpool_postgres::Pool,
}

impl Datastore {
    /// new creates a new Datastore using the given Client for backing storage. It is assumed that
    /// the Client is connected to a database with a compatible version of the Janus database schema.
    pub fn new(pool: deadpool_postgres::Pool) -> Datastore {
        Self { pool }
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
}

impl Transaction<'_> {
    // TODO(brandon): implement basic getters/putters for all types

    // This is pub to be used in integration tests
    #[doc(hidden)]
    pub async fn put_task(&self, task: &TaskParameters) -> Result<(), Error> {
        let aggregator_role = AggregatorRole::from_role(task.role)?;

        let endpoints: Vec<&str> = task
            .aggregator_endpoints
            .iter()
            .map(|url| url.as_str())
            .collect();

        let max_batch_lifetime = i64::try_from(task.max_batch_lifetime)?;
        let min_batch_size = i64::try_from(task.min_batch_size)?;
        let min_batch_duration = i64::try_from(task.min_batch_duration.0)?;
        let tolerable_clock_skew = i64::try_from(task.tolerable_clock_skew.0)?;

        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO tasks (task_id, aggregator_role, aggregator_endpoints, vdaf,
                vdaf_verify_param, max_batch_lifetime, min_batch_size, min_batch_duration,
                tolerable_clock_skew, collector_hpke_config, agg_auth_key, hpke_config,
                hpke_private_key)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    &&task.id.0[..],                             // id
                    &aggregator_role,                            // aggregator_role
                    &endpoints,                                  // aggregator_endpoints
                    &task.vdaf,                                  // vdaf
                    &task.vdaf_verify_parameter,                 // verify param
                    &max_batch_lifetime,                         // max batch lifetime
                    &min_batch_size,                             // min batch size
                    &min_batch_duration,                         // min batch duration
                    &tolerable_clock_skew,                       // tolerable clock skew
                    &task.collector_hpke_config.get_encoded(),   // collector hpke config
                    &task.agg_auth_key.as_slice(),               // agg_auth_key
                    &task.hpke_recipient.config().get_encoded(), // hpke_config
                    &task.hpke_recipient.private_key().as_ref(), // hpke_private_key
                ],
            )
            .await?;
        Ok(())
    }

    /// Construct a [`TaskParameters`] from the contents of the provided `Row`.
    /// If `task_id` is not `None`, it is used. Otherwise the task ID is read
    /// from the row.
    #[cfg(test)]
    fn task_parameters_from_row(
        task_id: Option<TaskId>,
        row: &Row,
    ) -> Result<TaskParameters, Error> {
        let task_id = task_id.map_or_else(
            || {
                let encoded_task_id: Vec<u8> = row.get("task_id");
                TaskId::get_decoded(&encoded_task_id)
            },
            Ok,
        )?;

        let aggregator_role: AggregatorRole = row.get("aggregator_role");
        let endpoints: Vec<String> = row.get("aggregator_endpoints");
        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| Ok(Url::parse(&endpoint)?))
            .collect::<Result<_, Error>>()?;
        let vdaf = row.get("vdaf");
        let vdaf_verify_parameter = row.get("vdaf_verify_param");
        let max_batch_lifetime = row.get_bigint_as_u64("max_batch_lifetime")?;
        let min_batch_size = row.get_bigint_as_u64("min_batch_size")?;
        let min_batch_duration = Duration(row.get_bigint_as_u64("min_batch_duration")?);
        let tolerable_clock_skew = Duration(row.get_bigint_as_u64("tolerable_clock_skew")?);
        let collector_hpke_config = HpkeConfig::get_decoded(row.get("collector_hpke_config"))?;
        let agg_auth_key = AggregatorAuthKey::from_bytes(row.get("agg_auth_key"))?;
        let hpke_config = HpkeConfig::get_decoded(row.get("hpke_config"))?;
        let hpke_private_key = HpkePrivateKey::new(row.get("hpke_private_key"));
        let hpke_recipient = HpkeRecipient::new(
            task_id,
            &hpke_config,
            Label::InputShare,
            Role::Client,
            aggregator_role.as_role(),
            &hpke_private_key,
        );

        Ok(TaskParameters::new(
            task_id,
            endpoints,
            vdaf,
            aggregator_role.as_role(),
            vdaf_verify_parameter,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            tolerable_clock_skew,
            &collector_hpke_config,
            agg_auth_key,
            &hpke_recipient,
        ))
    }

    /// Fetch the task parameters corresponing to the provided `task_id`.
    //
    // Only available in test configs for now, but will soon be used by
    // aggregators to discover tasks from the database.
    #[cfg(test)]
    pub(crate) async fn get_task_by_id(&self, task_id: TaskId) -> Result<TaskParameters, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT aggregator_role, aggregator_endpoints, vdaf, vdaf_verify_param,
                max_batch_lifetime, min_batch_size, min_batch_duration, tolerable_clock_skew,
                collector_hpke_config, agg_auth_key, hpke_config, hpke_private_key
                FROM tasks WHERE task_id=$1",
            )
            .await?;
        let row = single_row(self.tx.query(&stmt, &[&&task_id.0[..]]).await?)?;

        Self::task_parameters_from_row(Some(task_id), &row)
    }

    /// Fetch all the tasks in the database.
    #[cfg(test)]
    pub(crate) async fn get_tasks(&self) -> Result<Vec<TaskParameters>, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT task_id, aggregator_role, aggregator_endpoints, vdaf,
                vdaf_verify_param, max_batch_lifetime, min_batch_size, min_batch_duration,
                tolerable_clock_skew, collector_hpke_config, agg_auth_key, hpke_config,
                hpke_private_key
                FROM tasks",
            )
            .await?;
        let rows = self.tx.query(&stmt, &[]).await?;

        rows.iter()
            .map(|row| Self::task_parameters_from_row(None, row))
            .collect::<Result<_, _>>()
    }

    /// get_client_report retrieves a client report by ID.
    pub async fn get_client_report(&self, task_id: TaskId, nonce: Nonce) -> Result<Report, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.extensions, client_reports.input_shares FROM client_reports
                JOIN tasks ON tasks.id = client_reports.task_id
                WHERE tasks.task_id = $1 AND client_reports.nonce_time = $2 AND client_reports.nonce_rand = $3",
            )
            .await?;
        let row = single_row(
            self.tx
                .query(
                    &stmt,
                    &[
                        &&task_id.0[..],
                        &nonce.time.as_naive_date_time(),
                        &&nonce.rand.to_be_bytes()[..],
                    ],
                )
                .await?,
        )?;

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
    }

    /// put_client_report stores a client report.
    pub async fn put_client_report(&self, report: &Report) -> Result<(), Error> {
        let nonce_time = report.nonce.time.as_naive_date_time();
        let nonce_rand = report.nonce.rand.to_be_bytes();

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
    pub async fn put_report_share(
        &self,
        task_id: TaskId,
        report_share: &ReportShare,
    ) -> Result<(), Error> {
        let nonce_time = report_share.nonce.time.as_naive_date_time();
        let nonce_rand = report_share.nonce.rand.to_be_bytes();

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

    pub async fn get_aggregation_job<A: vdaf::Aggregator>(
        &self,
        aggregation_job_id: AggregationJobId,
    ) -> Result<AggregationJob<A>, Error>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT tasks.task_id, aggregation_jobs.aggregation_param, aggregation_jobs.state
                FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE aggregation_job_id = $1",
            )
            .await?;
        let row = single_row(self.tx.query(&stmt, &[&&aggregation_job_id.0[..]]).await?)?;

        let task_id = TaskId::get_decoded(row.get("task_id"))?;
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
                    /* aggregation_job_id */ &&aggregation_job.aggregation_job_id.0[..],
                    /* task_id */ &&aggregation_job.task_id.0[..],
                    /* aggregation_param */ &aggregation_job.aggregation_param.get_encoded(),
                    /* state */ &aggregation_job.state,
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn get_report_aggregation<A: vdaf::Aggregator>(
        &self,
        verify_param: &A::VerifyParam,
        aggregation_job_id: AggregationJobId,
        task_id: TaskId,
        nonce: Nonce,
    ) -> Result<ReportAggregation<A>, Error>
    where
        A::PrepareStep: ParameterizedDecode<A::VerifyParam>,
        A::OutputShare: for<'a> TryFrom<&'a [u8]>,
        for<'a> <A::OutputShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let nonce_time = nonce.time.as_naive_date_time();
        let nonce_rand = &nonce.rand.to_be_bytes()[..];

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT client_reports.nonce_time, client_reports.nonce_rand, report_aggregations.ord, report_aggregations.state, report_aggregations.vdaf_message, report_aggregations.error_code
                FROM report_aggregations
                JOIN aggregation_jobs ON aggregation_jobs.id = report_aggregations.aggregation_job_id
                JOIN client_reports ON client_reports.id = report_aggregations.client_report_id
                JOIN tasks ON tasks.id = aggregation_jobs.task_id
                WHERE aggregation_jobs.aggregation_job_id = $1 AND tasks.task_id = $2 AND client_reports.nonce_time = $3 AND client_reports.nonce_rand = $4",
            )
            .await?;
        let row = single_row(
            self.tx
                .query(
                    &stmt,
                    &[
                        &&aggregation_job_id.0[..],
                        &&task_id.0[..],
                        &nonce_time,
                        &nonce_rand,
                    ],
                )
                .await?,
        )?;

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
            ReportAggregationStateCode::Start => ReportAggregationState::Start(),
            ReportAggregationStateCode::Waiting => {
                ReportAggregationState::Waiting(A::PrepareStep::get_decoded_with_param(
                    verify_param,
                    &vdaf_message_bytes.ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state WAITING but vdaf_message is NULL"
                                .to_string(),
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
                .map_err(|err| {
                    Error::DecodeError(CodecError::Other(
                        format!("couldn't decode output share: {}", err).into(),
                    ))
                })?,
            ),
            ReportAggregationStateCode::Failed => {
                ReportAggregationState::Failed(error_code.ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state FAILED but error_code is NULL".to_string(),
                    )
                })?)
            }
            ReportAggregationStateCode::Invalid => ReportAggregationState::Invalid(),
        };

        Ok(ReportAggregation {
            aggregation_job_id,
            task_id,
            nonce,
            ord,
            state: agg_state,
        })
    }

    /// put_report_aggregation stores aggregation data for a single report.
    pub async fn put_report_aggregation<A: vdaf::Aggregator>(
        &self,
        report_aggregation: &ReportAggregation<A>,
    ) -> Result<(), Error>
    where
        A::PrepareStep: Encode,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let nonce_time = report_aggregation.nonce.time.as_naive_date_time();
        let nonce_rand = &report_aggregation.nonce.rand.to_be_bytes()[..];
        let state_code = report_aggregation.state.state_code();
        let (vdaf_message, error_code) = match &report_aggregation.state {
            ReportAggregationState::Start() => (None, None),
            ReportAggregationState::Waiting(prep_step) => (Some(prep_step.get_encoded()), None),
            ReportAggregationState::Finished(output_share) => (Some(output_share.into()), None),
            ReportAggregationState::Failed(trans_err) => (None, Some(*trans_err)),
            ReportAggregationState::Invalid() => (None, None),
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
                    /* aggregation_job_id */ &&report_aggregation.aggregation_job_id.0[..],
                    /* task_id */ &&report_aggregation.task_id.0[..],
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
}

fn single_row(rows: Vec<Row>) -> Result<Row, Error> {
    match rows.len() {
        0 => Err(Error::NotFound),
        1 => Ok(rows.into_iter().next().unwrap()),
        _ => Err(Error::TooManyRows),
    }
}

/// Extensions for [`tokio_postgres::row::Row`]
trait RowExt {
    /// Get a PostgreSQL `BIGINT` from the row, which is represented in Rust as
    /// i64 ([1]), then attempt to convert it to u64.
    ///
    /// [1]: https://docs.rs/postgres-types/latest/postgres_types/trait.FromSql.html
    fn get_bigint_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display;

    /// Get a PostgreSQL `BYTEA` from the row and then attempt to convert it to
    /// u64, treating it as an 8 byte big endian array.
    fn get_bytea_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display;
}

impl RowExt for Row {
    fn get_bigint_as_u64<I>(&self, idx: I) -> Result<u64, Error>
    where
        I: RowIndex + Display,
    {
        let bigint: i64 = self.try_get(idx)?;
        Ok(u64::try_from(bigint)?)
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
}

/// Error represents a datastore-level error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the underlying database library.
    #[error("DB error: {0}")]
    Db(#[from] tokio_postgres::Error),
    #[error("DB pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
    /// An entity requested from the datastore was not found.
    #[error("not found in datastore")]
    NotFound,
    /// A query that was expected to return at most one row unexpectedly returned more than one row.
    #[error("multiple rows returned where only one row expected")]
    TooManyRows,
    /// The database was in an unexpected state.
    #[error("inconsistent database state: {0}")]
    DbState(String),
    /// An error from decoding a value stored encoded in the underlying database.
    #[error("decoding error: {0}")]
    DecodeError(#[from] CodecError),
    /// An arbitrary error returned from the user callback; unrelated to DB internals. This error
    /// will never be generated by the datastore library itself.
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid task parameters: {0}")]
    TaskParameters(#[from] crate::task::Error),
    #[error("integer conversion failed: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
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

/// This module contains models used by the datastore that are not PPM messages.
pub mod models {
    use super::Error;
    use crate::message::{AggregationJobId, Nonce, Role, TaskId, TransitionError};
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
                _ => Err(Error::TaskParameters(crate::task::Error::InvalidParameter(
                    "role is not an aggregator",
                ))),
            }
        }

        /// Returns the [`Role`] corresponding to this value.
        #[cfg(test)]
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
        pub(crate) aggregation_job_id: AggregationJobId,
        pub(crate) task_id: TaskId,
        pub(crate) aggregation_param: A::AggregationParam,
        pub(crate) state: AggregationJobState,
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
    #[derive(Debug)]
    pub struct ReportAggregation<A: vdaf::Aggregator>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(crate) aggregation_job_id: AggregationJobId,
        pub(crate) task_id: TaskId,
        pub(crate) nonce: Nonce,
        pub(crate) ord: i64,
        pub(crate) state: ReportAggregationState<A>,
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
        Start(),
        Waiting(A::PrepareStep),
        Finished(A::OutputShare),
        Failed(TransitionError),
        Invalid(),
    }

    impl<A: vdaf::Aggregator> ReportAggregationState<A>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        pub(super) fn state_code(&self) -> ReportAggregationStateCode {
            match self {
                ReportAggregationState::Start() => ReportAggregationStateCode::Start,
                ReportAggregationState::Waiting(_) => ReportAggregationStateCode::Waiting,
                ReportAggregationState::Finished(_) => ReportAggregationStateCode::Finished,
                ReportAggregationState::Failed(_) => ReportAggregationStateCode::Failed,
                ReportAggregationState::Invalid() => ReportAggregationStateCode::Invalid,
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
}

// This is public to allow use in integration tests.
#[doc(hidden)]
pub mod test_util {
    use super::*;
    use deadpool_postgres::{Manager, Pool};
    use lazy_static::lazy_static;
    use std::str::{self, FromStr};
    use testcontainers::{clients::Cli, images::postgres::Postgres, Container, RunnableImage};
    use tokio_postgres::{Config, NoTls};

    const SCHEMA: &str = include_str!("../../db/schema.sql");

    // TODO(brandon): use podman instead of docker for container management once testcontainers supports it
    lazy_static! {
        static ref CONTAINER_CLIENT: Cli = Cli::default();
    }

    /// DbHandle represents a handle to a running (ephemeral) database. Dropping this value causes
    /// the database to be shut down & cleaned up.
    pub struct DbHandle(Container<'static, Postgres>);

    /// ephemeral_datastore creates a new Datastore instance backed by an ephemeral database which
    /// has the Janus schema applied but is otherwise empty.
    ///
    /// Dropping the second return value causes the database to be shut down & cleaned up.
    pub async fn ephemeral_datastore() -> (Datastore, DbHandle) {
        // Start an instance of Postgres running in a container.
        let db_container =
            CONTAINER_CLIENT.run(RunnableImage::from(Postgres::default()).with_tag("14-alpine"));

        // Create a connection pool whose clients will talk to our newly-running instance of Postgres.
        const POSTGRES_DEFAULT_PORT: u16 = 5432;
        let connection_string = format!(
            "postgres://postgres:postgres@localhost:{}/postgres",
            db_container.get_host_port(POSTGRES_DEFAULT_PORT)
        );
        let cfg = Config::from_str(&connection_string).unwrap();
        let conn_mgr = Manager::new(cfg, NoTls);
        let pool = Pool::builder(conn_mgr).build().unwrap();

        // Connect to the database & run our schema.
        let client = pool.get().await.unwrap();
        client.batch_execute(SCHEMA).await.unwrap();
        (Datastore::new(pool), DbHandle(db_container))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastore::{models::AggregationJobState, test_util::ephemeral_datastore},
        message::{ExtensionType, HpkeConfigId, Role, Time, TransitionError},
        task::Vdaf,
        trace::test_util::install_test_trace_subscriber,
    };
    use prio::{
        field::Field128,
        vdaf::{
            poplar1::{IdpfInput, Poplar1, ToyIdpf},
            prg::PrgAes128,
            prio3::Prio3Aes128Count,
            PrepareTransition,
        },
    };
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn roundtrip_task() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let values = [
            (
                TaskId([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1,
                ]),
                Vdaf::Prio3Aes128Count,
                Role::Leader,
            ),
            (
                TaskId([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 2,
                ]),
                Vdaf::Prio3Aes128Sum,
                Role::Helper,
            ),
            (
                TaskId([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 3,
                ]),
                Vdaf::Prio3Aes128Histogram,
                Role::Leader,
            ),
            (
                TaskId([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 4,
                ]),
                Vdaf::Poplar1,
                Role::Helper,
            ),
        ];

        for (task_id, vdaf, role) in values {
            let task_params = TaskParameters::new_dummy(
                task_id,
                vec![
                    "https://example.com/".parse().unwrap(),
                    "https://example.net/".parse().unwrap(),
                ],
                vdaf,
                role,
            );

            ds.run_tx(|tx| {
                let task_params = task_params.clone();
                Box::pin(async move { tx.put_task(&task_params).await })
            })
            .await
            .unwrap();

            let retrieved_task = ds
                .run_tx(|tx| Box::pin(async move { tx.get_task_by_id(task_id).await }))
                .await
                .unwrap();
            assert_eq!(task_params, retrieved_task);
        }

        let retrieved_tasks = ds
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap();
        assert_eq!(retrieved_tasks.len(), values.len());
        let mut saw_tasks = vec![false; values.len()];
        for task in retrieved_tasks {
            for (idx, value) in values.iter().enumerate() {
                if value.0 == task.id {
                    saw_tasks[idx] = true;
                }
            }
        }
        for (idx, saw_task) in saw_tasks.iter().enumerate() {
            assert!(saw_task, "never saw task {} in datastore", idx);
        }
    }

    #[tokio::test]
    async fn roundtrip_report() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let report = Report {
            task_id: TaskId::random(),
            nonce: Nonce {
                time: Time(12345),
                rand: 54321,
            },
            extensions: vec![
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::from("extension_data_0"),
                },
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::from("extension_data_1"),
                },
            ],
            encrypted_input_shares: vec![
                HpkeCiphertext {
                    config_id: HpkeConfigId(12),
                    encapsulated_context: Vec::from("encapsulated_context_0"),
                    payload: Vec::from("payload_0"),
                },
                HpkeCiphertext {
                    config_id: HpkeConfigId(13),
                    encapsulated_context: Vec::from("encapsulated_context_1"),
                    payload: Vec::from("payload_1"),
                },
            ],
        };

        ds.run_tx(|tx| {
            let report = report.clone();
            Box::pin(async move {
                tx.put_task(&TaskParameters::new_dummy(
                    report.task_id,
                    vec![],
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

        assert_eq!(report, retrieved_report);
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
                        Nonce {
                            time: Time(12345),
                            rand: 54321,
                        },
                    )
                    .await
                })
            })
            .await;

        assert_matches::assert_matches!(rslt, Err(Error::NotFound));
    }

    #[tokio::test]
    async fn roundtrip_report_share() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let task_id = TaskId::random();
        let report_share = ReportShare {
            nonce: Nonce {
                time: Time(12345),
                rand: 54321,
            },
            extensions: vec![
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::from("extension_data_0"),
                },
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::from("extension_data_1"),
                },
            ],
            encrypted_input_share: HpkeCiphertext {
                config_id: HpkeConfigId(12),
                encapsulated_context: Vec::from("encapsulated_context_0"),
                payload: Vec::from("payload_0"),
            },
        };

        ds.run_tx(|tx| {
            let report_share = report_share.clone();
            Box::pin(async move {
                tx.put_task(&TaskParameters::new_dummy(
                    task_id,
                    Vec::new(),
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
                    let nonce_time = report_share.nonce.time.as_naive_date_time();
                    let nonce_rand = report_share.nonce.rand.to_be_bytes();
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
    async fn roundtrip_aggregation_job_by_aggregation_job_id() {
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
                tx.put_task(&TaskParameters::new_dummy(
                    aggregation_job.task_id,
                    Vec::new(),
                    Vdaf::Poplar1,
                    Role::Leader,
                ))
                .await?;
                tx.put_aggregation_job(&aggregation_job).await
            })
        })
        .await
        .unwrap();

        let got_aggregation_job: AggregationJob<ToyPoplar1> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_aggregation_job(aggregation_job.aggregation_job_id)
                        .await
                })
            })
            .await
            .unwrap();

        assert_eq!(aggregation_job, got_aggregation_job);
    }

    #[tokio::test]
    async fn roundtrip_report_aggregation() {
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (verify_param, prep_step, output_share) = generate_vdaf_values(vdaf, (), 0);

        for (ord, state) in [
            ReportAggregationState::<Prio3Aes128Count>::Start(),
            ReportAggregationState::Waiting(prep_step),
            ReportAggregationState::Finished(output_share),
            ReportAggregationState::Failed(TransitionError::VdafPrepError),
            ReportAggregationState::Invalid(),
        ]
        .iter()
        .enumerate()
        {
            let task_id = TaskId::random();
            let aggregation_job_id = AggregationJobId::random();
            let nonce = Nonce {
                time: Time(12345),
                rand: 54321,
            };

            let report_aggregation = ds
                .run_tx(|tx| {
                    let state = state.clone();
                    Box::pin(async move {
                        tx.put_task(&TaskParameters::new_dummy(
                            task_id,
                            Vec::new(),
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
                                encrypted_input_share: HpkeCiphertext {
                                    config_id: HpkeConfigId(12),
                                    encapsulated_context: Vec::from("encapsulated_context_0"),
                                    payload: Vec::from("payload_0"),
                                },
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
                            aggregation_job_id,
                            task_id,
                            nonce,
                        )
                        .await
                    })
                })
                .await
                .unwrap();

            assert_eq!(report_aggregation, got_report_aggregation);
        }
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
