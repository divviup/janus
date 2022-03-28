//! Janus datastore (durable storage) implementation.

use crate::{
    message::{Extension, HpkeCiphertext, Nonce, Report, TaskId, Time},
    task::{TaskParameters, Vdaf},
};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use std::{future::Future, io::Cursor, pin::Pin};
use tokio_postgres::{error::SqlState, IsolationLevel, Row};

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
        // TODO: interpolate values from `task` into prepared statement
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO tasks (id, ord, aggregator_endpoints, vdaf, vdaf_verify_param,
                max_batch_lifetime, min_batch_size, min_batch_duration, collector_hpke_config)
                VALUES ($1, 0, '{}', $2, '', 0, 0, INTERVAL '0', '')",
            )
            .await?;
        self.tx
            .execute(
                &stmt,
                &[
                    &&task.id.0[..], // id
                    &task.vdaf,      // vdaf
                ],
            )
            .await?;
        Ok(())
    }

    /// get_client_report retrieves a client report by ID.
    pub async fn get_client_report(&self, id: i64) -> Result<Report, Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "SELECT task_id, nonce_time, nonce_rand, extensions, input_shares
                FROM client_reports WHERE id = $1",
            )
            .await?;
        let row = single_row(self.tx.query(&stmt, &[&id]).await?)?;

        let task_id = TaskId::get_decoded(row.get("task_id"))?;

        let nonce_time = Time::from_naive_date_time(row.get("nonce_time"));
        let nonce_rand: i64 = row.get("nonce_rand");

        let encoded_extensions: Vec<u8> = row.get("extensions");
        let extensions: Vec<Extension> =
            decode_u16_items(&(), &mut Cursor::new(&encoded_extensions))?;

        let encoded_input_shares: Vec<u8> = row.get("input_shares");
        let input_shares: Vec<HpkeCiphertext> =
            decode_u16_items(&(), &mut Cursor::new(&encoded_input_shares))?;

        Ok(Report {
            task_id,
            nonce: Nonce {
                time: nonce_time,
                rand: nonce_rand as u64,
            },
            extensions,
            encrypted_input_shares: input_shares,
        })
    }

    pub async fn get_client_report_by_task_id_and_nonce(
        &self,
        task_id: TaskId,
        nonce: Nonce,
    ) -> Result<Report, Error> {
        let nonce_time = nonce.time.as_naive_date_time();
        let nonce_rand = nonce.rand as i64;

        let stmt = self
            .tx
            .prepare_cached(
                "SELECT extensions, input_shares FROM client_reports
            WHERE task_id = $1 AND nonce_time = $2 AND nonce_rand = $3",
            )
            .await?;
        let row = single_row(
            self.tx
                .query(
                    &stmt,
                    &[
                        /* task_id */ &task_id.get_encoded(),
                        /* nonce_time */ &nonce_time,
                        /* nonce_rand */ &nonce_rand,
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
    pub async fn put_client_report(&self, report: &Report) -> Result<i64, Error> {
        let nonce_time = report.nonce.time.as_naive_date_time();
        let nonce_rand = report.nonce.rand as i64;

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
            VALUES ($1, $2, $3, $4, $5) RETURNING (id)"
        ).await?;
        let row = self
            .tx
            .query_one(
                &stmt,
                &[
                    /* task_id */ &&report.task_id.0[..],
                    /* nonce_time */ &nonce_time,
                    /* nonce_rand */ &nonce_rand,
                    /* extensions */ &encoded_extensions,
                    /* input_shares */ &encoded_input_shares,
                ],
            )
            .await?;
        Ok(row.get("id"))
    }

    /// This is a test-only method that is used to test round-tripping of values.
    /// TODO: remove this once the tasks table is finalized, and there's a method to retrieve an
    /// entire `TaskParameters` from the database.
    #[allow(unused)]
    async fn get_task_vdaf_by_id(&self, task_id: &TaskId) -> Result<Vdaf, Error> {
        let stmt = self
            .tx
            .prepare_cached("SELECT vdaf FROM tasks WHERE id=$1")
            .await?;
        let row = single_row(self.tx.query(&stmt, &[&&task_id.0[..]]).await?)?;
        Ok(row.get("vdaf"))
    }
}

fn single_row(rows: Vec<Row>) -> Result<Row, Error> {
    match rows.len() {
        0 => Err(Error::NotFound),
        1 => Ok(rows.into_iter().next().unwrap()),
        _ => Err(Error::TooManyRows),
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
    /// An error from decoding a value stored encoded in the underlying database.
    #[error("decoding error: {0}")]
    DecodeError(#[from] CodecError),
    /// An arbitrary error returned from the user callback; unrelated to DB internals. This error
    /// will never be generated by the datastore library itself.
    #[error(transparent)]
    User(#[from] Box<dyn std::error::Error + Send + Sync>),
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

// This is public to allow use in integration tests.
#[doc(hidden)]
pub mod test_util {
    use super::*;
    use deadpool_postgres::{Manager, Pool};
    use lazy_static::lazy_static;
    use std::str::{self, FromStr};
    use testcontainers::{clients::Cli, images::postgres::Postgres, Container, Docker};
    use tokio_postgres::{Config, NoTls};

    const SCHEMA: &str = include_str!("../../db/schema.sql");

    // TODO(brandon): use podman instead of docker for container management once testcontainers supports it
    lazy_static! {
        static ref DOCKER: Cli = Cli::default();
    }

    /// DbHandle represents a handle to a running (ephemeral) database. Dropping this value causes
    /// the database to be shut down & cleaned up.
    pub struct DbHandle(Container<'static, Cli, Postgres>);

    /// ephemeral_datastore creates a new Datastore instance backed by an ephemeral database which
    /// has the Janus schema applied but is otherwise empty.
    ///
    /// Dropping the second return value causes the database to be shut down & cleaned up.
    pub async fn ephemeral_datastore() -> (Datastore, DbHandle) {
        // Start an instance of Postgres running in a container.
        let db_container = DOCKER.run(Postgres::default().with_version(14));

        // Create a connection pool whose clients will talk to our newly-running instance of Postgres.
        const POSTGRES_DEFAULT_PORT: u16 = 5432;
        let connection_string = format!(
            "postgres://postgres:postgres@localhost:{}/postgres",
            db_container.get_host_port(POSTGRES_DEFAULT_PORT).unwrap()
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
    use crate::datastore::test_util::ephemeral_datastore;
    use crate::hpke::{HpkeRecipient, Label};
    use crate::message::{Duration, ExtensionType, HpkeConfigId, Role};
    use crate::trace::test_util::install_trace_subscriber;

    #[tokio::test]
    async fn roundtrip_report() {
        install_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let task_id = TaskId([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let report = Report {
            task_id,
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

        let report_id = ds
            .run_tx(|tx| {
                let report = report.clone();
                Box::pin(async move {
                    tx.put_task(&TaskParameters::new_dummy(task_id, vec![]))
                        .await?;
                    tx.put_client_report(&report).await
                })
            })
            .await
            .unwrap();

        let retrieved_report = ds
            .run_tx(|tx| Box::pin(async move { tx.get_client_report(report_id).await }))
            .await
            .unwrap();

        assert_eq!(report, retrieved_report);
    }

    #[tokio::test]
    async fn report_not_found() {
        install_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let rslt = ds
            .run_tx(|tx| Box::pin(async move { tx.get_client_report(12345).await }))
            .await;

        assert_matches::assert_matches!(rslt, Err(Error::NotFound));
    }

    #[tokio::test]
    async fn roundtrip_report_by_task_id_and_nonce() {
        install_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let task_id = TaskId([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let nonce = Nonce {
            time: Time(12345),
            rand: 54321,
        };
        let report = Report {
            task_id,
            nonce,
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
                tx.put_task(&TaskParameters::new_dummy(task_id, vec![]))
                    .await?;
                tx.put_client_report(&report).await
            })
        })
        .await
        .unwrap();

        let retrieved_report = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report_by_task_id_and_nonce(task_id, nonce)
                        .await
                })
            })
            .await
            .unwrap();

        assert_eq!(report, retrieved_report);
    }

    #[tokio::test]
    async fn report_not_found_by_task_id_and_nonce() {
        install_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        let task_id = TaskId([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let nonce = Nonce {
            time: Time(12345),
            rand: 54321,
        };

        let rslt = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report_by_task_id_and_nonce(task_id, nonce)
                        .await
                })
            })
            .await;

        assert_matches::assert_matches!(rslt, Err(Error::NotFound));
    }

    #[tokio::test]
    async fn roundtrip_task() {
        let (ds, _db_handle) = ephemeral_datastore().await;

        let task_ids = [
            TaskId([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ]),
            TaskId([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 2,
            ]),
            TaskId([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 3,
            ]),
            TaskId([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 4,
            ]),
        ];
        let vdafs = [
            Vdaf::Prio3Aes128Count,
            Vdaf::Prio3Aes128Sum,
            Vdaf::Prio3Aes128Histogram,
            Vdaf::Poplar1,
        ];

        for (task_id, vdaf) in task_ids.into_iter().zip(vdafs.into_iter()) {
            let task_params = TaskParameters::new(
                task_id,
                vec![
                    "https://example.com/".parse().unwrap(),
                    "https://example.net/".parse().unwrap(),
                ],
                vdaf.clone(),
                vec![],
                0,
                0,
                Duration(0),
                &HpkeRecipient::generate(
                    task_id,
                    Label::AggregateShare,
                    Role::Leader,
                    Role::Collector,
                )
                .config,
            );

            ds.run_tx(|tx| {
                let task_params = task_params.clone();
                Box::pin(async move { tx.put_task(&task_params).await })
            })
            .await
            .unwrap();

            let retrieved_vdaf = ds
                .run_tx(|tx| Box::pin(async move { tx.get_task_vdaf_by_id(&task_id).await }))
                .await
                .unwrap();
            assert_eq!(vdaf, retrieved_vdaf);
        }
    }
}
