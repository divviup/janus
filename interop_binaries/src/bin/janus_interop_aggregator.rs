use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use janus_aggregator::{
    aggregator::{self, http_handlers::aggregator_handler},
    binary_utils::{janus_main, BinaryOptions, CommonBinaryOptions},
    cache::GlobalHpkeKeypairCache,
    config::{BinaryConfig, CommonConfig},
};
use janus_aggregator_core::{
    datastore::{models::HpkeKeyState, Datastore},
    task::{self, Task},
    SecretBytes,
};
use janus_core::{
    hpke::generate_hpke_config_and_private_key,
    task::AuthenticationToken,
    time::{DurationExt, RealClock},
};
use janus_interop_binaries::{
    status::{ERROR, SUCCESS},
    AddTaskResponse, AggregatorAddTaskRequest, AggregatorRole, FetchBatchIdsRequest,
    FetchBatchIdsResponse, HpkeConfigRegistry, Keyring,
};
use janus_messages::{
    BatchId, Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, TaskId, Time,
};
use opentelemetry::metrics::Meter;
use prio::codec::Decode;
use rand::random;
use serde::{Deserialize, Serialize};
use sqlx::{migrate::Migrator, Connection, PgConnection};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use tokio::sync::Mutex;
use trillium::{Conn, Handler};
use trillium_api::{api, Json};
use trillium_router::Router;

#[derive(Debug, Serialize)]
struct EndpointResponse {
    status: &'static str,
    endpoint: String,
}

async fn handle_add_task(
    datastore: &Datastore<RealClock>,
    keyring: &Mutex<HpkeConfigRegistry>,
    request: AggregatorAddTaskRequest,
) -> anyhow::Result<()> {
    let vdaf = request.vdaf.into();
    let leader_authentication_token =
        AuthenticationToken::new_dap_auth_token_from_string(request.leader_authentication_token)
            .context("invalid header value in \"leader_authentication_token\"")?;
    let vdaf_verify_key = SecretBytes::new(
        URL_SAFE_NO_PAD
            .decode(request.verify_key)
            .context("invalid base64url content in \"verify_key\"")?,
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
                Vec::from([AuthenticationToken::new_dap_auth_token_from_string(
                    collector_authentication_token,
                )
                .context("invalid header value in \"collector_authentication_token\"")?])
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
            batch_time_window_size: None,
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
        Vec::from([request.leader, request.helper]),
        query_type,
        vdaf,
        request.role.into(),
        Vec::from([vdaf_verify_key]),
        request.max_batch_query_count,
        request.task_expiration.map(Time::from_seconds_since_epoch),
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

async fn handle_fetch_batch_ids(
    datastore: &Datastore<RealClock>,
    batch_id_storage: &Mutex<HashMap<TaskId, HashSet<BatchId>>>,
    request: FetchBatchIdsRequest,
) -> anyhow::Result<Vec<BatchId>> {
    let outstanding_batches = datastore
        .run_tx(move |tx| {
            Box::pin(async move { tx.get_outstanding_batches(&request.task_id, &None).await })
        })
        .await
        .context("error fetching batches from database")?;

    Ok({
        let mut batch_id_storage = batch_id_storage.lock().await;
        let batch_ids = batch_id_storage.entry(request.task_id).or_default();
        batch_ids.extend(outstanding_batches.into_iter().map(|ob| *ob.id()));
        batch_ids.iter().copied().collect()
    })
}

async fn make_handler(
    datastore: Arc<Datastore<RealClock>>,
    meter: &Meter,
    dap_serving_prefix: String,
) -> anyhow::Result<impl Handler> {
    let keyring = Keyring::new();
    let dap_handler = aggregator_handler(
        Arc::clone(&datastore),
        RealClock::default(),
        meter,
        aggregator::Config {
            max_upload_batch_size: 100,
            max_upload_batch_write_delay: std::time::Duration::from_millis(100),
            batch_aggregation_shard_count: 32,
            global_hpke_configs_refresh_interval: GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL,

            // TODO(janus-ops#991): Give these taskprov parameters actual values to facilitiate an E2E test.
            collector_hpke_config: generate_hpke_config_and_private_key(
                HpkeConfigId::from(1),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
            )
            .config()
            .clone(),
            report_expiry_age: None,
            tolerable_clock_skew: Duration::from_minutes(60).unwrap(),
            verify_key_init: random(),
            auth_tokens: Vec::new(),
        },
    )
    .await?;

    let handler = Router::new()
        .all(format!("{dap_serving_prefix}/*"), dap_handler)
        .post("internal/test/ready", Json(serde_json::Map::new()))
        .post(
            "internal/test/endpoint_for_task",
            Json(EndpointResponse {
                status: "success",
                endpoint: dap_serving_prefix,
            }),
        )
        .post(
            "internal/test/add_task",
            api({
                let datastore = Arc::clone(&datastore);
                move |_conn: &mut Conn, Json(request): Json<AggregatorAddTaskRequest>| {
                    let datastore = Arc::clone(&datastore);
                    let keyring = keyring.clone();
                    async move {
                        match handle_add_task(&datastore, &keyring.0, request).await {
                            Ok(()) => Json(AddTaskResponse {
                                status: SUCCESS.to_string(),
                                error: None,
                            }),
                            Err(e) => Json(AddTaskResponse {
                                status: ERROR.to_string(),
                                error: Some(format!("{e:?}")),
                            }),
                        }
                    }
                }
            }),
        )
        .post(
            "/internal/test/fetch_batch_ids",
            api({
                let datastore = Arc::clone(&datastore);
                let batch_id_storage = Arc::new(Mutex::new(HashMap::new()));
                move |_conn: &mut Conn, Json(request): Json<FetchBatchIdsRequest>| {
                    let datastore = Arc::clone(&datastore);
                    let batch_id_storage = Arc::clone(&batch_id_storage);

                    async move {
                        match handle_fetch_batch_ids(&datastore, &batch_id_storage, request).await {
                            Ok(batch_ids) => Json(FetchBatchIdsResponse {
                                status: SUCCESS.to_string(),
                                error: None,
                                batch_ids: Some(batch_ids),
                            }),
                            Err(err) => Json(FetchBatchIdsResponse {
                                status: ERROR.to_string(),
                                error: Some(format!("{err:?}")),
                                batch_ids: None,
                            }),
                        }
                    }
                }
            }),
        );
    Ok(handler)
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
        // Migration scripts are mounted into the container at this path by
        // Dockerfile.interop_aggregator
        let migrator = Migrator::new(Path::new("/etc/janus/migrations")).await?;
        migrator.run(&mut connection).await?;

        // subscriber-01 only: insert a global HPKE key, since this instance of Janus only
        // advertises global keys.
        datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let keypairs = tx.get_global_hpke_keypairs().await?;
                    if keypairs.is_empty() {
                        let keypair = generate_hpke_config_and_private_key(
                            HpkeConfigId::from(1),
                            HpkeKemId::X25519HkdfSha256,
                            HpkeKdfId::HkdfSha256,
                            HpkeAeadId::Aes128Gcm,
                        );
                        tx.put_global_hpke_keypair(&keypair).await?;
                        tx.set_global_hpke_keypair_state(
                            keypair.config().id(),
                            &HpkeKeyState::Active,
                        )
                        .await?;
                    }
                    Ok(())
                })
            })
            .await?;

        // Run an HTTP server with both the DAP aggregator endpoints and the interoperation test
        // endpoints.
        let handler = make_handler(
            Arc::clone(&datastore),
            &ctx.meter,
            ctx.config.dap_serving_prefix,
        )
        .await?;
        trillium_tokio::config()
            .with_host(&ctx.config.listen_address.ip().to_string())
            .with_port(ctx.config.listen_address.port())
            .without_signals()
            .run_async(handler)
            .await;

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
