use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use janus::time::RealClock;
use janus_server::{
    aggregator::aggregator_server,
    binary_utils::datastore,
    config::AggregatorConfig,
    metrics::{install_metrics_exporter, MetricsExporterConfiguration},
    trace::{cleanup_trace_subscriber, install_trace_subscriber, OpenTelemetryTraceConfiguration},
};
use std::{
    fmt::{self, Debug, Formatter},
    fs::File,
    future::Future,
    iter::Iterator,
    path::PathBuf,
    sync::Arc,
};
use structopt::StructOpt;
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

    let mut config: AggregatorConfig = serde_yaml::from_reader(&config_file)
        .with_context(|| format!("failed to parse config file: {:?}", options.config_file))?;

    if let Some(OpenTelemetryTraceConfiguration::Otlp(otlp_config)) =
        &mut config.logging_config.open_telemetry_config
    {
        otlp_config
            .metadata
            .extend(options.otlp_tracing_metadata.iter().cloned());
    }
    if let Some(MetricsExporterConfiguration::Otlp(otlp_config)) =
        &mut config.metrics_config.exporter
    {
        otlp_config
            .metadata
            .extend(options.otlp_metrics_metadata.iter().cloned());
    }

    install_trace_subscriber(&config.logging_config)
        .context("failed to install tracing subscriber")?;
    let _metrics_exporter = install_metrics_exporter(&config.metrics_config)
        .context("failed to install metrics exporter")?;

    info!(?options, ?config, "starting aggregator");

    // Connect to database.
    let datastore = Arc::new(
        datastore(
            config.database,
            options.database_password,
            options.datastore_keys,
        )
        .context("couldn't connect to database")?,
    );

    let shutdown_signal =
        setup_signal_handler().context("failed to register SIGTERM signal handler")?;

    let (bound_address, server) = aggregator_server(
        &config.api_base_url,
        datastore,
        RealClock::default(),
        config.listen_address,
        shutdown_signal,
    )
    .context("failed to create aggregator server")?;
    info!(?bound_address, "running aggregator");

    server.await;

    cleanup_trace_subscriber(&config.logging_config);

    Ok(())
}
