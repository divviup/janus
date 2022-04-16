use anyhow::{anyhow, Context, Result};
use chrono::Duration;
use deadpool_postgres::{Manager, Pool};
use janus_server::{
    aggregator::aggregator_server,
    config::AggregatorConfig,
    datastore::{self, Datastore},
    hpke::test_util::generate_hpke_config_and_private_key,
    message::Role,
    message::TaskId,
    task::{self, AggregatorAuthKey, Task},
    time::RealClock,
    trace::install_trace_subscriber,
};
use prio::{
    codec::Encode,
    vdaf::{prio3::Prio3Aes128Count, Vdaf},
};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
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

    // Create task.
    // TODO(timg): tasks and the corresponding HPKE configuration and private
    // keys should be loaded from the database (see discussion in #37)
    let task_id = TaskId::random();
    let vdaf = Prio3Aes128Count::new(2).unwrap();
    let verify_param = vdaf.setup().unwrap().1.first().unwrap().clone();
    let (collector_hpke_config, _) = generate_hpke_config_and_private_key();
    let agg_auth_keys = vec![AggregatorAuthKey::generate()];
    let hpke_keys = vec![generate_hpke_config_and_private_key()];

    let task = Task::new(
        task_id,
        vec![],
        task::Vdaf::Prio3Aes128Count,
        options.role,
        verify_param.get_encoded(),
        1,
        0,
        Duration::hours(10),
        Duration::minutes(10),
        collector_hpke_config,
        agg_auth_keys,
        hpke_keys,
    )?;

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

    let (bound_address, server) =
        aggregator_server(task, datastore, RealClock::default(), config.listen_address)
            .context("failed to create aggregator server")?;
    info!(?task_id, ?bound_address, "running aggregator");

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
