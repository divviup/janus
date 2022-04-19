use anyhow::{anyhow, Context, Result};
use deadpool_postgres::{Manager, Pool};
use futures::StreamExt;
use janus_server::{
    aggregator::aggregator_server,
    config::AggregatorConfig,
    datastore::{self, Datastore},
    time::RealClock,
    trace::install_trace_subscriber,
};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use std::{
    fmt::{self, Debug, Formatter},
    fs::File,
    future::Future,
    iter::Iterator,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use structopt::StructOpt;
use tokio_postgres::NoTls;
use tracing::info;

#[derive(StructOpt)]
#[structopt(
    name = "janus-aggregator",
    about = "PPM aggregator server",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
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

    /// Password for the PostgreSQL database connection. (if not included in the connection
    /// string)
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
}

impl Debug for Options {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("config_file", &self.config_file)
            .finish()
    }
}

/// Register a signal handler for SIGTERM, and return a future that will become ready when a
/// SIGTERM signal is received.
fn setup_signal_handler() -> Result<impl Future<Output = ()>, std::io::Error> {
    let mut signal_stream = signal_hook_tokio::Signals::new([signal_hook::consts::SIGTERM])?;
    let handle = signal_stream.handle();
    let (sender, receiver) = futures::channel::oneshot::channel();
    let mut sender = Some(sender);
    tokio::spawn(async move {
        while let Some(signal) = signal_stream.next().await {
            if signal == signal_hook::consts::SIGTERM {
                if let Some(sender) = sender.take() {
                    // This may return Err(()) if the receiver has been dropped already. If
                    // that is the case, the warp server must be shut down already, so we can
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

#[tokio::main]
async fn main() -> Result<()> {
    // The configuration file path and any secret values are provided through
    // command line options or environment variables.
    let options = Options::from_args();

    // The bulk of configuration options are in the config file.
    let config_file = File::open(&options.config_file)
        .with_context(|| format!("failed to open config file: {:?}", options.config_file))?;

    let config: AggregatorConfig = serde_yaml::from_reader(&config_file)
        .with_context(|| format!("failed to parse config file: {:?}", options.config_file))?;

    install_trace_subscriber(&config.logging_config)
        .context("failed to install tracing subscriber")?;

    info!(?options, ?config, "starting aggregator");

    // Connect to database.
    let mut database_config = tokio_postgres::Config::from_str(config.database.url.as_str())
        .with_context(|| {
            format!(
                "failed to parse database connect string: {:?}",
                config.database.url
            )
        })?;
    if database_config.get_password().is_none() {
        if let Some(password) = options.database_password {
            database_config.password(password);
        }
    }
    let conn_mgr = Manager::new(database_config, NoTls);
    let pool = Pool::builder(conn_mgr)
        .build()
        .context("failed to create database connection pool")?;
    let datastore_keys = options
        .datastore_keys
        .into_iter()
        .filter(|k| !k.is_empty())
        .map(|k| {
            base64::decode_config(k, base64::STANDARD_NO_PAD)
                .context("couldn't base64-decode datastore keys")
                .and_then(|k| {
                    Ok(LessSafeKey::new(
                        UnboundKey::new(&AES_128_GCM, &k)
                            .map_err(|_| anyhow!("coulnd't parse datastore keys as keys"))?,
                    ))
                })
        })
        .collect::<Result<Vec<LessSafeKey>>>()?;
    if datastore_keys.is_empty() {
        return Err(anyhow!("datastore keys is empty"));
    }
    let crypter = datastore::Crypter::new(datastore_keys);
    let datastore = Arc::new(Datastore::new(pool, crypter));

    let shutdown_signal =
        setup_signal_handler().context("failed to register SIGTERM signal handler")?;

    let (bound_address, server) = aggregator_server(
        datastore,
        RealClock::default(),
        config.listen_address,
        shutdown_signal,
    )
    .context("failed to create aggregator server")?;
    info!(?bound_address, "running aggregator");

    server.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_tests() {
        trycmd::TestCases::new().case("tests/cmd/*.trycmd").run();
    }
}
