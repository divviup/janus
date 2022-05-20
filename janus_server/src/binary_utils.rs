//! Utilities for Janus binaries.

pub mod job_driver;

use crate::{
    config::{BinaryConfig, DbConfig},
    datastore::{Crypter, Datastore},
    metrics::{install_metrics_exporter, MetricsExporterConfiguration},
    trace::{cleanup_trace_subscriber, install_trace_subscriber, OpenTelemetryTraceConfiguration},
};
use anyhow::{anyhow, Context, Result};
use deadpool_postgres::{Manager, Pool};
use janus::time::Clock;
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use std::{
    fmt::{self, Debug, Formatter},
    fs,
    future::Future,
    path::PathBuf,
    str::FromStr,
};
use structopt::StructOpt;
use tokio_postgres::NoTls;
use tracing::info;

/// Connects to a datastore, given a config for the underlying database. `db_password` is mutually
/// exclusive with the database password specified in the connection URL in `db_config`. `ds_keys`
/// are a list of AES-128-GCM keys, encoded in base64 with no padding, used to protect secret values
/// stored in the datastore; it must not be empty.
pub fn datastore<C: Clock>(
    clock: C,
    db_config: &DbConfig,
    db_password: &Option<String>,
    ds_keys: &[String],
) -> Result<Datastore<C>> {
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
        .iter()
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
    Ok(Datastore::new(pool, Crypter::new(ds_keys), clock))
}

/// Options for Janus binaries.
pub trait BinaryOptions: StructOpt + Debug {
    /// Returns the common options.
    fn common_options(&self) -> &CommonBinaryOptions;
}

#[cfg_attr(doc, doc = "Common options that are used by all Janus binaries.")]
#[derive(StructOpt)]
pub struct CommonBinaryOptions {
    /// Path to configuration YAML.
    #[structopt(
        long,
        env = "CONFIG_FILE",
        parse(from_os_str),
        takes_value = true,
        required(true),
        help = "path to configuration file"
    )]
    config_file: PathBuf,

    /// Password for the PostgreSQL database connection. If specified, must not be specified in the
    /// connection string.
    #[structopt(long, env = "PGPASSWORD", help = "PostgreSQL password")]
    database_password: Option<String>,

    /// Datastore encryption keys.
    #[structopt(
        long,
        env = "DATASTORE_KEYS",
        takes_value = true,
        use_delimiter = true,
        required(true),
        help = "datastore encryption keys, encoded in base64 then comma-separated"
    )]
    datastore_keys: Vec<String>,

    /// Additional OTLP/gRPC metadata key/value pairs. (concatenated with those in the logging
    /// configuration sections)
    #[structopt(
        long,
        env = "OTLP_TRACING_METADATA",
        parse(try_from_str = parse_metadata_entry),
        help = "additional OTLP/gRPC metadata key/value pairs for the tracing exporter",
        value_name = "KEY=value",
        use_delimiter = true,
    )]
    otlp_tracing_metadata: Vec<(String, String)>,

    /// Additional OTLP/gRPC metadata key/value pairs. (concatenated with those in the metrics
    /// configuration sections)
    #[structopt(
        long,
        env = "OTLP_METRICS_METADATA",
        parse(try_from_str = parse_metadata_entry),
        help = "additional OTLP/gRPC metadata key/value pairs for the metrics exporter",
        value_name = "KEY=value",
        use_delimiter = true,
    )]
    otlp_metrics_metadata: Vec<(String, String)>,
}

impl Debug for CommonBinaryOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("config_file", &self.config_file)
            .finish()
    }
}

fn parse_metadata_entry(input: &str) -> Result<(String, String)> {
    if let Some(equals) = input.find('=') {
        let (key, rest) = input.split_at(equals);
        let value = &rest[1..];
        Ok((key.to_string(), value.to_string()))
    } else {
        Err(anyhow!(
            "`--otlp-tracing-metadata` and `--otlp-metrics-metadata` must be provided a key and value, joined with an `=`"
        ))
    }
}

pub async fn janus_main<O, C, Config, F, Fut>(clock: C, f: F) -> anyhow::Result<()>
where
    O: BinaryOptions,
    C: Clock,
    Config: BinaryConfig,
    F: FnOnce(C, Config, Datastore<C>) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    // Read arguments, read & parse config.
    let options = O::from_args();
    let common_options = options.common_options();
    let mut config = {
        let config_content =
            fs::read_to_string(&common_options.config_file).with_context(|| {
                format!("couldn't read config file {:?}", common_options.config_file)
            })?;
        let mut config: Config = serde_yaml::from_str(&config_content).with_context(|| {
            format!(
                "couldn't parse config file {:?}",
                common_options.config_file
            )
        })?;

        if let Some(OpenTelemetryTraceConfiguration::Otlp(otlp_config)) =
            &mut config.common_config().logging_config.open_telemetry_config
        {
            otlp_config
                .metadata
                .extend(common_options.otlp_tracing_metadata.iter().cloned());
        }
        if let Some(MetricsExporterConfiguration::Otlp(otlp_config)) =
            &mut config.common_config().metrics_config.exporter
        {
            otlp_config
                .metadata
                .extend(common_options.otlp_metrics_metadata.iter().cloned());
        }

        config
    };
    install_trace_subscriber(&config.common_config().logging_config)
        .context("couldn't install tracing subscriber")?;
    let _metrics_exporter = install_metrics_exporter(&config.common_config().metrics_config)
        .context("failed to install metrics exporter")?;

    info!(?common_options, ?config, "Starting up");

    // Connect to database.
    let datastore = datastore(
        clock.clone(),
        &config.common_config().database,
        &common_options.database_password,
        &common_options.datastore_keys,
    )
    .context("couldn't connect to database")?;

    let logging_config = config.common_config().logging_config.clone();

    f(clock, config, datastore).await?;

    cleanup_trace_subscriber(&logging_config);

    Ok(())
}
