use anyhow::{Context, Result};
use chrono::Duration;
use deadpool_postgres::{Manager, Pool};
use janus_server::{
    aggregator::aggregator_server,
    config::AggregatorConfig,
    datastore::Datastore,
    hpke::{HpkeRecipient, Label},
    message::Role,
    message::TaskId,
    time::RealClock,
    trace::install_trace_subscriber,
};
use std::{
    fmt::{self, Debug, Formatter},
    fs::File,
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
    /// Path to configuration YAML
    #[structopt(
        long,
        env = "CONFIG_FILE",
        parse(from_os_str),
        takes_value = true,
        required(true),
        help = "path to configuration file"
    )]
    config_file: PathBuf,
    /// The PPM protocol role this aggregator should assume.
    //
    // TODO(timg): obtain the role from the task definition in the database
    // (see discussion in #37)
    #[structopt(
        long,
        takes_value = true,
        required(true),
        possible_values = &[Role::Leader.as_str(), Role::Helper.as_str()],
        help = "role for this aggregator",
    )]
    role: Role,
}

impl Debug for Options {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("config_file", &self.config_file)
            .field("role", &self.role)
            .finish()
    }
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

    let database_config = tokio_postgres::Config::from_str(config.database.url.as_str())
        .with_context(|| {
            format!(
                "failed to parse database connect string: {:?}",
                config.database.url
            )
        })?;
    let conn_mgr = Manager::new(database_config, NoTls);
    let pool = Pool::builder(conn_mgr)
        .build()
        .context("failed to create database connection pool")?;
    let datastore = Arc::new(Datastore::new(pool));

    // TODO(timg): tasks and the corresponding HPKE configuration and private
    // keys should be loaded from the database (see discussion in #37)
    let task_id = TaskId::random();
    let hpke_recipient =
        HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, options.role);

    let (bound_address, server) = aggregator_server(
        datastore,
        RealClock::default(),
        Duration::minutes(10),
        options.role,
        hpke_recipient,
        config.listen_address,
    )
    .context("failed to create aggregator server")?;
    info!(?task_id, ?bound_address, "running aggregator");

    server.await;

    Ok(())
}
