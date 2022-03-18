//! Janus datastore (durable storage) implementation.

use crate::message::{Extension, HpkeCiphertext, Nonce, Report, TaskId, Time};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode};
use std::{future::Future, io::Cursor, pin::Pin};
use tokio_postgres::{error::SqlState, IsolationLevel, Row};

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
        for<'a> F: Fn(&'a Transaction) -> Pin<Box<dyn Future<Output = Result<T, Error>> + 'a>>,
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
        for<'a> F: Fn(&'a Transaction) -> Pin<Box<dyn Future<Output = Result<T, Error>> + 'a>>,
    {
        // Open transaction.
        let mut client = self.pool.get().await.unwrap(); // XXX: don't unwrap (need to figure out error handling)
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

    #[cfg(test)]
    async fn put_task(&self, task_id: TaskId) -> Result<(), Error> {
        let stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO tasks (id, ord, aggregator_endpoints, vdaf, vdaf_verify_param,
                max_batch_lifetime, min_batch_size, min_batch_duration, collector_hpke_config)
                VALUES ($1, 0, '{}', 'PRIO3', '', 0, 0, INTERVAL '0', '')",
            )
            .await?;
        self.tx
            .execute(&stmt, &[/* task_id */ &&task_id.0[..]])
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

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use deadpool_postgres::{Manager, Pool};
    use std::str::{self, FromStr};
    use testcontainers::{images::postgres::Postgres, Container, Docker};
    use tokio_postgres::{Config, NoTls};

    const SCHEMA: &str = include_str!("../../db/schema.sql");

    /// ephemeral_datastore creates a new Datastore instance backed by an ephemeral database which
    /// has the Janus schema applied but is otherwise empty.
    ///
    /// Dropping the second return value causes the database to be shut down & cleaned up.
    pub(crate) async fn ephemeral_datastore<D: Docker>(
        container_client: &D,
    ) -> (Datastore, Container<'_, D, Postgres>) {
        // Start an instance of Postgres running in a container.
        let db_container = container_client.run(Postgres::default().with_version(14));

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
        (Datastore::new(pool), db_container)
    }
}

#[cfg(test)]
mod tests {
    // TODO(brandon): use podman instead of docker for container management once testcontainers supports this

    use super::*;
    use crate::datastore::test_util::ephemeral_datastore;
    use crate::message::{ExtensionType, HpkeConfigId};
    use crate::trace::test_util::install_trace_subscriber;
    use testcontainers::clients;

    #[tokio::test]
    async fn roundtrip_report() {
        install_trace_subscriber();
        let docker = clients::Cli::default();
        let (ds, _db_container) = ephemeral_datastore(&docker).await;

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
                    tx.put_task(task_id).await?;
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
        let docker = clients::Cli::default();
        let (ds, _db_container) = ephemeral_datastore(&docker).await;

        let rslt = ds
            .run_tx(|tx| Box::pin(async move { tx.get_client_report(12345).await }))
            .await;

        assert_matches::assert_matches!(rslt, Err(Error::NotFound));
    }
}
