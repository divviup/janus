//! Utilities for Janus binaries.

use crate::{
    config::DbConfig,
    datastore::{Crypter, Datastore},
};
use anyhow::{anyhow, Context, Result};
use deadpool_postgres::{Manager, Pool};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use std::str::FromStr;
use tokio_postgres::NoTls;

/// Connects to a datastore, given a config for the underlying database. `db_password` is mutually
/// exclusive with the database password specified in the connection URL in `db_config`. `ds_keys`
/// are a list of AES-128-GCM keys, encoded in base64 with no padding, used to protect secret values
/// stored in the datastore; it must not be empty.
pub fn datastore(
    db_config: DbConfig,
    db_password: Option<String>,
    ds_keys: Vec<String>,
) -> Result<Datastore> {
    let mut database_config = tokio_postgres::Config::from_str(db_config.url.as_str())
        .with_context(|| {
            format!(
                "couldn't parse database connect string: {:?}",
                db_config.url
            )
        })?;
    if database_config.get_password().is_some() && db_password.is_some() {
        return Err(anyhow!(
            "Database config & password override are both specified"
        ));
    }
    if let Some(pass) = db_password {
        database_config.password(pass);
    }

    let conn_mgr = Manager::new(database_config, NoTls);
    let pool = Pool::builder(conn_mgr)
        .build()
        .context("failed to create database connection pool")?;
    let ds_keys = ds_keys
        .into_iter()
        .filter(|k| !k.is_empty())
        .map(|k| {
            base64::decode_config(k, base64::STANDARD_NO_PAD)
                .context("couldn't base64-decode datastore keys")
                .and_then(|k| {
                    Ok(LessSafeKey::new(
                        UnboundKey::new(&AES_128_GCM, &k)
                            .map_err(|_| anyhow!("couldn't parse datastore keys as keys"))?,
                    ))
                })
        })
        .collect::<Result<Vec<LessSafeKey>>>()?;
    if ds_keys.is_empty() {
        return Err(anyhow!("ds_keys is empty"));
    }
    Ok(Datastore::new(pool, Crypter::new(ds_keys)))
}
