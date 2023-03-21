//! Utilities for Janus binaries.

pub mod job_driver;

use crate::{
    config::{BinaryConfig, DbConfig},
    metrics::{install_metrics_exporter, MetricsExporterConfiguration},
    trace::{cleanup_trace_subscriber, install_trace_subscriber, OpenTelemetryTraceConfiguration},
};
use anyhow::{anyhow, Context as _, Result};
use backoff::{future::retry, ExponentialBackoff};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::Parser;
use deadpool::managed::TimeoutType;
use deadpool_postgres::{Manager, Pool, PoolError, Runtime, Timeouts};
use futures::StreamExt;
use git_version::git_version;
use http::StatusCode;
use janus_aggregator_core::datastore::{Crypter, Datastore};
use janus_core::time::Clock;
use opentelemetry::{Context, KeyValue};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use std::{
    fmt::{self, Debug, Formatter},
    fs,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
use tokio_postgres::NoTls;
use tracing::{debug, info};
use warp::Filter;

/// Reads, parses, and returns the config referenced by the given options, or None if no config file
/// path was set.
pub fn read_config<Config: BinaryConfig>(options: &CommonBinaryOptions) -> Result<Config> {
    let config_content = fs::read_to_string(&options.config_file)
        .with_context(|| format!("couldn't read config file {:?}", options.config_file))?;
    let mut config: Config = serde_yaml::from_str(&config_content)
        .with_context(|| format!("couldn't parse config file {:?}", options.config_file))?;

    if let Some(OpenTelemetryTraceConfiguration::Otlp(otlp_config)) = &mut config
        .common_config_mut()
        .logging_config
        .open_telemetry_config
    {
        otlp_config
            .metadata
            .extend(options.otlp_tracing_metadata.iter().cloned());
    }
    if let Some(MetricsExporterConfiguration::Otlp(otlp_config)) =
        &mut config.common_config_mut().metrics_config.exporter
    {
        otlp_config
            .metadata
            .extend(options.otlp_metrics_metadata.iter().cloned());
    }

    Ok(config)
}

/// Connects to a database, given a config. `db_password` is mutually exclusive with the database
/// password specified in the connection URL in `db_config`.
pub async fn database_pool(db_config: &DbConfig, db_password: Option<&str>) -> Result<Pool> {
    let mut database_config = tokio_postgres::Config::from_str(db_config.url.as_str())
        .with_context(|| {
            format!(
                "couldn't parse database connect string: {:?}",
                db_config.url
            )
        })?;
    if database_config.get_password().is_some() && db_password.is_some() {
        return Err(anyhow!(
            "database config & password override are both specified"
        ));
    }
    if let Some(pass) = db_password {
        database_config.password(pass);
    }

    let connection_pool_timeout = Duration::from_secs(db_config.connection_pool_timeouts_secs);

    let conn_mgr = Manager::new(database_config, NoTls);
    let pool = Pool::builder(conn_mgr)
        .runtime(Runtime::Tokio1)
        .timeouts(Timeouts {
            wait: Some(connection_pool_timeout),
            create: Some(connection_pool_timeout),
            recycle: Some(connection_pool_timeout),
        })
        .build()
        .context("failed to create database connection pool")?;

    // Attempt to fetch a connection from the connection pool, to check that the database is
    // accessible. This will either create a new database connection or recycle an existing one, and
    // then return the connection back to the pool.
    //
    // Retrying if we encounter timeouts when creating a connection or connection refused errors
    // (which occur if the Cloud SQL Proxy hasn't started yet and manifest as `PoolError::Backend`)
    let _ = retry(
        ExponentialBackoff {
            initial_interval: Duration::from_secs(1),
            max_interval: connection_pool_timeout,
            multiplier: 2.0,
            max_elapsed_time: Some(connection_pool_timeout),
            ..Default::default()
        },
        || async {
            pool.get().await.map_err(|error| match error {
                PoolError::Timeout(TimeoutType::Create) | PoolError::Backend(_) => {
                    debug!(?error, "transient error connecting to database");
                    backoff::Error::transient(error)
                }
                _ => backoff::Error::permanent(error),
            })
        },
    )
    .await
    .context("couldn't make connection to database")?;

    Ok(pool)
}

/// Connects to a datastore, given a connection pool to the underlying database. `datastore_keys`
/// is a list of AES-128-GCM keys, encoded in base64 with no padding, used to protect secret values
/// stored in the datastore; it must not be empty.
pub fn datastore<C: Clock>(
    pool: Pool,
    clock: C,
    datastore_keys: &[String],
) -> Result<Datastore<C>> {
    let datastore_keys = datastore_keys
        .iter()
        .filter(|k| !k.is_empty())
        .map(|k| {
            STANDARD_NO_PAD
                .decode(k)
                .context("couldn't base64-decode datastore keys")
                .and_then(|k| {
                    Ok(LessSafeKey::new(
                        UnboundKey::new(&AES_128_GCM, k.as_ref())
                            .map_err(|_| anyhow!("couldn't parse datastore keys as keys"))?,
                    ))
                })
        })
        .collect::<Result<Vec<LessSafeKey>>>()?;
    if datastore_keys.is_empty() {
        return Err(anyhow!("datastore_keys is empty"));
    }

    Ok(Datastore::new(pool, Crypter::new(datastore_keys), clock))
}

/// Options for Janus binaries.
pub trait BinaryOptions: Parser + Debug {
    /// Returns the common options.
    fn common_options(&self) -> &CommonBinaryOptions;
}

#[cfg_attr(doc, doc = "Common options that are used by all Janus binaries.")]
#[derive(Default, Parser)]
pub struct CommonBinaryOptions {
    /// Path to configuration YAML.
    #[clap(
        long,
        env = "CONFIG_FILE",
        num_args = 1,
        required(true),
        help = "path to configuration file"
    )]
    config_file: PathBuf,

    /// Password for the PostgreSQL database connection. If specified, must not be specified in the
    /// connection string.
    #[clap(
        long,
        env = "PGPASSWORD",
        hide_env_values = true,
        help = "PostgreSQL password"
    )]
    pub database_password: Option<String>,

    /// Datastore encryption keys.
    #[clap(
        long,
        env = "DATASTORE_KEYS",
        hide_env_values = true,
        num_args = 1,
        use_value_delimiter = true,
        help = "datastore encryption keys, encoded in base64 then comma-separated"
    )]
    pub datastore_keys: Vec<String>,

    /// Additional OTLP/gRPC metadata key/value pairs. (concatenated with those in the logging
    /// configuration sections)
    #[clap(
        long,
        env = "OTLP_TRACING_METADATA",
        value_parser(parse_metadata_entry),
        help = "additional OTLP/gRPC metadata key/value pairs for the tracing exporter",
        value_name = "KEY=value",
        use_value_delimiter = true
    )]
    otlp_tracing_metadata: Vec<(String, String)>,

    /// Additional OTLP/gRPC metadata key/value pairs. (concatenated with those in the metrics
    /// configuration sections)
    #[clap(
        long,
        env = "OTLP_METRICS_METADATA",
        value_parser(parse_metadata_entry),
        help = "additional OTLP/gRPC metadata key/value pairs for the metrics exporter",
        value_name = "KEY=value",
        use_value_delimiter = true
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
            "`--otlp-tracing-metadata` and `--otlp-metrics-metadata` must be provided a key and \
             value, joined with an `=`"
        ))
    }
}

/// BinaryContext provides contextual objects related to a Janus binary.
pub struct BinaryContext<C: Clock, Options: BinaryOptions, Config: BinaryConfig> {
    pub clock: C,
    pub options: Options,
    pub config: Config,
    pub datastore: Datastore<C>,
}

pub async fn janus_main<C, Options, Config, F, Fut>(clock: C, f: F) -> anyhow::Result<()>
where
    C: Clock,
    Options: BinaryOptions,
    Config: BinaryConfig,
    F: FnOnce(BinaryContext<C, Options, Config>) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    // Parse arguments, then read & parse config.
    let options = Options::parse();
    let config: Config = read_config(options.common_options())?;

    // Install tracing/metrics handlers.
    install_trace_subscriber(&config.common_config().logging_config)
        .context("couldn't install tracing subscriber")?;
    let _metrics_exporter = install_metrics_exporter(&config.common_config().metrics_config)
        .context("failed to install metrics exporter")?;

    // Create build info metrics gauge.
    let meter = opentelemetry::global::meter("janus_aggregator");
    let gauge = meter
        .u64_observable_gauge("janus_build_info")
        .with_description(
            "A metric with a constant '1' value labeled with build-time version information.",
        )
        .init();
    let mut git_revision: &str = git_version!(fallback = "unknown");
    if git_revision == "unknown" {
        if let Some(value) = option_env!("GIT_REVISION") {
            git_revision = value;
        }
    }
    gauge.observe(
        &Context::current(),
        1,
        &[
            KeyValue::new("version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("revision", git_revision),
            KeyValue::new("rust_version", env!("RUSTC_SEMVER")),
        ],
    );

    info!(common_options = ?options.common_options(), ?config, "Starting up");

    // Connect to database.
    let pool = database_pool(
        &config.common_config().database,
        options.common_options().database_password.as_deref(),
    )
    .await
    .context("couldn't create database connection pool")?;
    let datastore = datastore(
        pool,
        clock.clone(),
        &options.common_options().datastore_keys,
    )
    .context("couldn't create datastore")?;

    let logging_config = config.common_config().logging_config.clone();

    let health_check_listen_address = config.common_config().health_check_listen_address;
    let healthz_task_handle =
        tokio::task::spawn(
            async move { health_endpoint_server(health_check_listen_address).await },
        );

    let result = f(BinaryContext {
        clock,
        options,
        config,
        datastore,
    })
    .await;

    healthz_task_handle.abort();

    cleanup_trace_subscriber(&logging_config);

    result
}

/// Listen for HTTP requests on a given port, and respond to requests for "/healthz" with an empty
/// body and status code 200. Each Janus component exposes this HTTP server to enable health
/// checks, and to indicate when it has successfully started up.
async fn health_endpoint_server(address: SocketAddr) {
    let filter = warp::path("healthz")
        .and(warp::get().or(warp::head()).unify())
        .map(|| warp::reply::with_status(warp::reply::reply(), StatusCode::OK));
    let server = warp::serve(filter);
    server.bind(address).await;
}

/// Register a signal handler for SIGTERM, and return a future that will become ready when a
/// SIGTERM signal is received.
pub fn setup_signal_handler() -> Result<impl Future<Output = ()>, std::io::Error> {
    let mut signal_stream = signal_hook_tokio::Signals::new([signal_hook::consts::SIGTERM])?;
    let handle = signal_stream.handle();
    let (sender, receiver) = futures::channel::oneshot::channel();
    let mut sender = Some(sender);
    tokio::spawn(async move {
        while let Some(signal) = signal_stream.next().await {
            if signal == signal_hook::consts::SIGTERM {
                if let Some(sender) = sender.take() {
                    // This may return Err(()) if the receiver has been dropped already. If
                    // that is the case, the consumer must be shut down already, so we can
                    // safely ignore the error case.
                    let _ = sender.send(());
                    handle.close();
                    break;
                }
            }
        }
    });
    Ok(async move {
        // The receiver may return Err(Canceled) if the sender has been dropped. By inspection, the
        // sender always has a message sent across it before it is dropped, and the async task it
        // is owned by will not terminate before that happens.
        receiver.await.unwrap_or_default()
    })
}

#[cfg(test)]
mod tests {
    use super::CommonBinaryOptions;
    use clap::CommandFactory;

    #[test]
    fn verify_app() {
        CommonBinaryOptions::command().debug_assert()
    }
}
