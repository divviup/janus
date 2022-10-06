use anyhow::Context;
use base64::URL_SAFE_NO_PAD;
use clap::{Arg, Command};
use interop_binaries::{
    install_tracing_subscriber,
    status::{ERROR, SUCCESS},
    AddTaskResponse, AggregatorAddTaskRequest, HpkeConfigRegistry,
};
use janus_core::{task::AuthenticationToken, time::RealClock, TokioRuntime};
use janus_messages::{Duration, HpkeConfig, Role, TaskId, Time};
use janus_server::{
    aggregator::{
        aggregate_share::CollectJobDriver, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, aggregator_filter,
    },
    binary_utils::{database_pool, job_driver::JobDriver},
    config::DbConfig,
    datastore::{Crypter, Datastore},
    task::Task,
    SecretBytes,
};
use opentelemetry::global::meter;
use prio::codec::Decode;
use rand::random;
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use serde::Serialize;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};
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
    let task_id_bytes = base64::decode_config(request.task_id, URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"taskId\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;
    let vdaf = request.vdaf.into();
    let leader_authentication_token =
        AuthenticationToken::from(request.leader_authentication_token.into_bytes());
    let verify_key = SecretBytes::new(
        base64::decode_config(request.verify_key, URL_SAFE_NO_PAD)
            .context("invalid base64url content in \"verifyKey\"")?,
    );
    let time_precision = Duration::from_seconds(request.time_precision);
    let collector_hpke_config_bytes =
        base64::decode_config(request.collector_hpke_config, URL_SAFE_NO_PAD)
            .context("invalid base64url content in \"collectorHpkeConfig\"")?;
    let collector_hpke_config = HpkeConfig::get_decoded(&collector_hpke_config_bytes)
        .context("could not parse collector HPKE configuration")?;

    let (role, collector_authentication_tokens) = match (
        request.aggregator_id,
        request.collector_authentication_token,
    ) {
        (0, None) => {
            return Err(anyhow::anyhow!("collector authentication is missing"));
        }
        (0, Some(collector_authentication_token)) => (
            Role::Leader,
            Vec::from([AuthenticationToken::from(
                collector_authentication_token.into_bytes(),
            )]),
        ),
        (1, _) => (Role::Helper, Vec::new()),
        _ => return Err(anyhow::anyhow!("invalid \"aggregator_id\" value")),
    };

    let (hpke_config, private_key) = keyring.lock().await.get_random_keypair();

    let task = Task::new(
        task_id,
        Vec::from([request.leader, request.helper]),
        request.query_type,
        vdaf,
        role,
        Vec::from([verify_key]),
        request.max_batch_query_count,
        Time::from_seconds_since_epoch(request.task_expiration),
        request.min_batch_size,
        time_precision,
        // We can be strict about clock skew since this executable is only intended for use with
        // other aggregators running on the same host.
        Duration::from_seconds(1),
        collector_hpke_config,
        Vec::from([leader_authentication_token]),
        collector_authentication_tokens,
        [(hpke_config, private_key)],
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
    let dap_filter = aggregator_filter(Arc::clone(&datastore), RealClock::default())?;

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
    let add_task_filter = warp::path!("add_task").and(warp::body::json()).then(
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
                        error: Some(format!("{:?}", e)),
                    },
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                    .into_response()
            }
        },
    );

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

fn app() -> clap::Command<'static> {
    Command::new("Janus interoperation test aggregator")
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .default_value("8080")
                .help("Port number to listen on."),
        )
        .arg(
            Arg::new("postgres-url")
                .long("postgres-url")
                .default_value("postgres://postgres@127.0.0.1:5432/postgres")
                .help("PostgreSQL database connection URL."),
        )
        .arg(
            Arg::new("dap-serving-prefix")
                .long("dap-serving-prefix")
                .default_value("/")
                .help("Path prefix, e.g. `/dap/`, to serve DAP from"),
        )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;
    let matches = app().get_matches();
    let http_port = matches.value_of_t("port")?;
    let postgres_url = matches.value_of_t("postgres-url")?;
    let dap_serving_prefix = matches
        .get_one("dap-serving-prefix")
        .map(Clone::clone)
        .unwrap_or_else(|| "/".to_string());

    // Make an ephemeral datastore key.
    let key_bytes: [u8; 16] = random();
    let datastore_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap());
    let crypter = Crypter::new(Vec::from([datastore_key]));

    // Connect to database, apply schema, and set up datastore.
    let db_config = DbConfig {
        url: postgres_url,
        connection_pool_timeouts_secs: 30,
    };
    let pool = database_pool(&db_config, None).await?;
    let clock = RealClock::default();
    let client = pool.get().await?;
    client
        .batch_execute(include_str!("../../../db/schema.sql"))
        .await?;
    // Return the database connection we used to deploy the schema back to the pool, so it can be
    // reused.
    drop(client);
    let datastore = Arc::new(Datastore::new(pool, crypter, clock));

    // Run an HTTP server with both the DAP aggregator endpoints and the interoperation test
    // endpoints.
    let filter = make_filter(Arc::clone(&datastore), dap_serving_prefix)?;
    let server = warp::serve(filter);
    let aggregator_future = server.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, http_port)));

    // Run the aggregation job creator.
    let pool = database_pool(&db_config, None).await?;
    let datastore_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap());
    let crypter = Crypter::new(Vec::from([datastore_key]));
    let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
        Datastore::new(pool, crypter, clock),
        clock,
        StdDuration::from_secs(2),
        StdDuration::from_secs(1),
        1,
        100,
    ));
    let aggregation_job_creator_future = aggregation_job_creator.run();

    // Run the aggregation job driver.
    let aggregation_job_driver_meter = meter("aggregation_job_driver");
    let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
        reqwest::Client::new(),
        &aggregation_job_driver_meter,
    ));
    let aggregation_job_driver = Arc::new(JobDriver::new(
        clock,
        TokioRuntime,
        aggregation_job_driver_meter,
        Duration::from_seconds(1),
        Duration::from_seconds(2),
        10,
        Duration::from_seconds(1),
        aggregation_job_driver.make_incomplete_job_acquirer_callback(
            Arc::clone(&datastore),
            Duration::from_seconds(10),
        ),
        aggregation_job_driver.make_job_stepper_callback(Arc::clone(&datastore), 3),
    ));
    let aggregation_job_driver_future = aggregation_job_driver.run();

    // Run the collect job driver.
    let collect_job_driver_meter = meter("collect_job_driver");
    let collect_job_driver = Arc::new(CollectJobDriver::new(
        reqwest::Client::new(),
        &collect_job_driver_meter,
    ));
    let collect_job_driver = Arc::new(JobDriver::new(
        clock,
        TokioRuntime,
        collect_job_driver_meter,
        Duration::from_seconds(1),
        Duration::from_seconds(2),
        10,
        Duration::from_seconds(1),
        collect_job_driver.make_incomplete_job_acquirer_callback(
            Arc::clone(&datastore),
            Duration::from_seconds(10),
        ),
        collect_job_driver.make_job_stepper_callback(Arc::clone(&datastore), 3),
    ));
    let collect_job_driver_future = collect_job_driver.run();

    tokio::spawn(aggregation_job_creator_future);
    tokio::spawn(aggregation_job_driver_future);
    tokio::spawn(collect_job_driver_future);

    aggregator_future.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::app;

    #[test]
    fn verify_clap_app() {
        app().debug_assert();
    }
}
