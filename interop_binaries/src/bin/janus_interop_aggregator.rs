use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use janus_aggregator::{
    aggregator::{self, aggregator_filter},
    binary_utils::{janus_main, BinaryOptions, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
};
use janus_aggregator_core::{
    datastore::Datastore,
    task::{self, Task},
    SecretBytes,
};
use janus_core::{task::AuthenticationToken, time::RealClock};
use janus_interop_binaries::{
    status::{ERROR, SUCCESS},
    AddTaskResponse, AggregatorAddTaskRequest, AggregatorRole, HpkeConfigRegistry,
};
use janus_messages::{Duration, HpkeConfig, Time};
use prio::codec::Decode;
use serde::{Deserialize, Serialize};
use sqlx::{migrate::Migrator, Connection, PgConnection};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use warp::{hyper::StatusCode, reply::Response, Filter, Reply};

#[derive(Debug, Serialize)]
struct EndpointResponse<'a> {
    status: &'a str,
    endpoint: &'a str,
}

async fn handle_add_task(
    datastore: &Datastore<RealClock>,
    keyring: &Mutex<HpkeConfigRegistry>,
    request: AggregatorAddTaskRequest,
) -> anyhow::Result<()> {
    let vdaf = request.vdaf.into();
    let leader_authentication_token =
        AuthenticationToken::from(request.leader_authentication_token.into_bytes());
    let vdaf_verify_key = SecretBytes::new(
        URL_SAFE_NO_PAD
            .decode(request.vdaf_verify_key)
            .context("invalid base64url content in \"vdaf_verify_key\"")?,
    );
    let time_precision = Duration::from_seconds(request.time_precision);
    let collector_hpke_config_bytes = URL_SAFE_NO_PAD
        .decode(request.collector_hpke_config)
        .context("invalid base64url content in \"collector_hpke_config\"")?;
    let collector_hpke_config = HpkeConfig::get_decoded(&collector_hpke_config_bytes)
        .context("could not parse collector HPKE configuration")?;

    let collector_authentication_tokens =
        match (request.role, request.collector_authentication_token) {
            (AggregatorRole::Leader, None) => {
                return Err(anyhow::anyhow!("collector authentication token is missing"))
            }
            (AggregatorRole::Leader, Some(collector_authentication_token)) => {
                Vec::from([AuthenticationToken::from(
                    collector_authentication_token.into_bytes(),
                )])
            }
            (AggregatorRole::Helper, _) => Vec::new(),
        };

    let hpke_keypair = keyring.lock().await.get_random_keypair();

    let query_type = match request.query_type {
        1 => task::QueryType::TimeInterval,
        2 => task::QueryType::FixedSize {
            max_batch_size: request
                .max_batch_size
                .ok_or_else(|| anyhow::anyhow!("\"max_batch_size\" is missing"))?,
        },
        _ => {
            return Err(anyhow::anyhow!(
                "invalid query type: {}",
                request.query_type
            ))
        }
    };

    let task = Task::new(
        request.task_id,
        request.leader,
        request.helper,
        query_type,
        vdaf,
        request.role.into(),
        Vec::from([vdaf_verify_key]),
        request.max_batch_query_count,
        Time::from_seconds_since_epoch(request.task_expiration),
        None,
        request.min_batch_size,
        time_precision,
        // We can be strict about clock skew since this executable is only intended for use with
        // other aggregators running on the same host.
        Duration::from_seconds(1),
        collector_hpke_config,
        Vec::from([leader_authentication_token]),
        collector_authentication_tokens,
        [hpke_keypair],
    )
    .context("error constructing task")?;

    datastore
        .run_tx(move |tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
        .context("error adding task to database")
}

fn make_filter(
    datastore: Arc<Datastore<RealClock>>,
    dap_serving_prefix: String,
) -> anyhow::Result<impl Filter<Extract = (Response,)> + Clone> {
    let keyring = Arc::new(Mutex::new(HpkeConfigRegistry::new()));
    let dap_filter = aggregator_filter(
        Arc::clone(&datastore),
        RealClock::default(),
        aggregator::Config {
            max_upload_batch_size: 100,
            max_upload_batch_write_delay: std::time::Duration::from_millis(100),
            batch_aggregation_shard_count: 32,
        },
    )?;

    // Respect dap_serving_prefix.
    let dap_filter = dap_serving_prefix
        .split('/')
        .filter_map(|s| (!s.is_empty()).then(|| warp::path(s.to_owned()).boxed()))
        .reduce(|x, y| x.and(y).boxed())
        .unwrap_or_else(|| warp::any().boxed())
        .and(dap_filter);

    let ready_filter = warp::path!("ready").map(|| {
        warp::reply::with_status(warp::reply::json(&serde_json::json!({})), StatusCode::OK)
            .into_response()
    });
    let endpoint_filter = warp::path!("endpoint_for_task").map(move || {
        warp::reply::with_status(
            warp::reply::json(&EndpointResponse {
                status: "success",
                endpoint: &dap_serving_prefix,
            }),
            StatusCode::OK,
        )
        .into_response()
    });
    let add_task_filter = warp::path!("add_task").and(warp::body::json()).then({
        let datastore = Arc::clone(&datastore);
        move |request: AggregatorAddTaskRequest| {
            let datastore = Arc::clone(&datastore);
            let keyring = Arc::clone(&keyring);
            async move {
                let response = match handle_add_task(&datastore, &keyring, request).await {
                    Ok(()) => AddTaskResponse {
                        status: SUCCESS.to_string(),
                        error: None,
                    },
                    Err(e) => AddTaskResponse {
                        status: ERROR.to_string(),
                        error: Some(format!("{e:?}")),
                    },
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                    .into_response()
            }
        }
    });

    Ok(warp::path!("internal" / "test" / ..)
        .and(warp::post())
        .and(
            ready_filter
                .or(endpoint_filter)
                .unify()
                .or(add_task_filter)
                .unify(),
        )
        .or(dap_filter.map(Reply::into_response))
        .unify())
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus_interop_aggregator",
    about = "Janus interoperation test aggregator",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION")
)]
struct Options {
    #[clap(flatten)]
    common: CommonBinaryOptions,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        {
            &self.common
        }
    }
}

fn default_dap_serving_prefix() -> String {
    "/".to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,

    /// Address on which this server should listen for connections and serve its
    /// API endpoints.
    listen_address: SocketAddr,

    /// Path prefix, e.g. `/dap/`, to serve DAP from.
    #[serde(default = "default_dap_serving_prefix")]
    dap_serving_prefix: String,

    /// Path at which `sqlx` migration files can be found. Migrations will be applied at startup.
    sql_migrations_source: PathBuf,
}

impl BinaryConfig for Config {
    fn common_config(&self) -> &CommonConfig {
        &self.common_config
    }

    fn common_config_mut(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main::<_, Options, Config, _, _>(RealClock::default(), |ctx| async move {
        let datastore = Arc::new(ctx.datastore);

        // Apply SQL migrations to database
        let mut connection =
            PgConnection::connect(ctx.config.common_config.database.url.as_str()).await?;
        let migrator = Migrator::new(ctx.config.sql_migrations_source).await?;
        migrator.run(&mut connection).await?;

        // Run an HTTP server with both the DAP aggregator endpoints and the interoperation test
        // endpoints.
        let filter = make_filter(Arc::clone(&datastore), ctx.config.dap_serving_prefix)?;
        let server = warp::serve(filter);
        server.bind(ctx.config.listen_address).await;

        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::Options;
    use clap::CommandFactory;

    #[test]
    fn verify_clap_app() {
        Options::command().debug_assert();
    }
}
