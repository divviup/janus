use anyhow::Context;
use base64::URL_SAFE_NO_PAD;
use clap::{Arg, Command};
use interop_binaries::{
    install_tracing_subscriber,
    status::{ERROR, SUCCESS},
    VdafObject,
};
use janus_core::{
    hpke::generate_hpke_config_and_private_key,
    message::{Duration, HpkeConfig, Role, TaskId},
    time::RealClock,
    TokioRuntime,
};
use janus_server::{
    aggregator::{
        aggregate_share::CollectJobDriver, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver,
    },
    binary_utils::{database_pool, job_driver::JobDriver},
    config::DbConfig,
    datastore::{Crypter, Datastore},
    task::{AuthenticationToken, Task},
};
use opentelemetry::global::meter;
use prio::codec::Decode;
use rand::{thread_rng, Rng};
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};
use url::Url;
use warp::{hyper::StatusCode, reply::Response, Filter, Reply};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndpointRequest {
    _task_id: String,
    _aggregator_id: u8,
    _hostname_and_port: String,
}

#[derive(Debug, Serialize)]
struct EndpointResponse {
    status: &'static str,
    endpoint: &'static str,
}

static ENDPOINT_RESPONSE: EndpointResponse = EndpointResponse {
    status: "success",
    endpoint: "/",
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddTaskRequest {
    task_id: String,
    leader: String,
    helper: String,
    vdaf: VdafObject,
    leader_authentication_token: String,
    #[serde(default)]
    collector_authentication_token: Option<String>,
    aggregator_id: u8,
    verify_key: String,
    max_batch_lifetime: u64,
    min_batch_size: u64,
    min_batch_duration: u64,
    collector_hpke_config: String,
}

#[derive(Debug, Serialize)]
struct AddTaskResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
}

async fn handle_add_task(
    datastore: &Datastore<RealClock>,
    request: AddTaskRequest,
) -> anyhow::Result<()> {
    let task_id_bytes = base64::decode_config(request.task_id, base64::URL_SAFE_NO_PAD)
        .context("Invalid base64url content in \"taskId\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("Invalid length of TaskId")?;
    let leader_url = Url::parse(&request.leader).context("Bad leader URL")?;
    let helper_url = Url::parse(&request.helper).context("Bad helper URL")?;
    let vdaf: janus_core::task::VdafInstance = request.vdaf.into();
    let vdaf: janus_server::task::VdafInstance = vdaf.into();
    let leader_authentication_token =
        AuthenticationToken::from(request.leader_authentication_token.into_bytes());
    let verify_key = base64::decode_config(request.verify_key, URL_SAFE_NO_PAD)
        .context("Invalid base64url content in \"verifyKey\"")?;
    let min_batch_duration = Duration::from_seconds(request.min_batch_duration);
    let collector_hpke_config_bytes =
        base64::decode_config(request.collector_hpke_config, URL_SAFE_NO_PAD)
            .context("Invalid base64url content in \"collectorHpkeConfig\"")?;
    let collector_hpke_config = HpkeConfig::get_decoded(&collector_hpke_config_bytes)
        .context("Could not parse collector HPKE configuration")?;

    let (role, collector_authentication_tokens) = match (
        request.aggregator_id,
        request.collector_authentication_token,
    ) {
        (0, None) => {
            return Err(anyhow::anyhow!("Collector authentication is missing"));
        }
        (0, Some(collector_authentication_token)) => (
            Role::Leader,
            vec![AuthenticationToken::from(
                collector_authentication_token.into_bytes(),
            )],
        ),
        (1, _) => (Role::Helper, Vec::new()),
        _ => return Err(anyhow::anyhow!("Invalid \"aggregator_id\" value")),
    };

    let (hpke_config, private_key) = generate_hpke_config_and_private_key();

    let task = Task::new(
        task_id,
        vec![leader_url, helper_url],
        vdaf,
        role,
        vec![verify_key],
        request.max_batch_lifetime,
        request.min_batch_size,
        min_batch_duration,
        // We can be strict about clock skew since this executable is only intended for use with
        // other aggregators running on the same host.
        Duration::from_seconds(1),
        collector_hpke_config,
        vec![leader_authentication_token],
        collector_authentication_tokens,
        [(hpke_config, private_key)],
    )
    .context("Error constructing task")?;

    datastore
        .run_tx(move |tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
        .context("Error adding task to database")
}

fn make_filter(
    datastore: Arc<Datastore<RealClock>>,
) -> anyhow::Result<impl Filter<Extract = (Response,)> + Clone> {
    let clock = janus_core::time::RealClock::default();
    let dap_filter = janus_server::aggregator::aggregator_filter(Arc::clone(&datastore), clock)?;

    let endpoint_filter = warp::path!("endpoint_for_task")
        .and(warp::body::json())
        .map(|_request: EndpointRequest| {
            warp::reply::with_status(warp::reply::json(&ENDPOINT_RESPONSE), StatusCode::OK)
                .into_response()
        });
    let add_task_filter =
        warp::path!("add_task")
            .and(warp::body::json())
            .then(move |request: AddTaskRequest| {
                let datastore = Arc::clone(&datastore);
                async move {
                    let response = match handle_add_task(&datastore, request).await {
                        Ok(()) => AddTaskResponse {
                            status: SUCCESS,
                            error: None,
                        },
                        Err(e) => AddTaskResponse {
                            status: ERROR,
                            error: Some(format!("{:?}", e)),
                        },
                    };
                    warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                        .into_response()
                }
            });

    Ok(warp::path!("internal" / "test" / ..)
        .and(warp::post())
        .and(endpoint_filter.or(add_task_filter).unify())
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;
    let matches = app().get_matches();
    let http_port = matches.value_of_t::<u16>("port")?;
    let postgres_url = matches.value_of_t::<Url>("postgres-url")?;

    // Make an ephemeral datastore key.
    let mut key_bytes = [0u8; 16];
    thread_rng().fill(&mut key_bytes);
    let datastore_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap());
    let crypter = Crypter::new(vec![datastore_key]);

    // Connect to database, apply schema, and set up datastore.
    let db_config = DbConfig {
        url: postgres_url,
        connection_pool_timeouts_secs: 30,
    };
    let pool = database_pool(&db_config, &None).await?;
    let clock = janus_core::time::RealClock::default();
    let client = pool.get().await?;
    client
        .batch_execute(include_str!("../../../db/schema.sql"))
        .await?;
    drop(client);
    let datastore = Arc::new(Datastore::new(pool, crypter, clock));

    // Run an HTTP server with both the DAP aggregator endpoints and the interoperation test
    // endpoints.
    let filter = make_filter(Arc::clone(&datastore))?;
    let server = warp::serve(filter);
    let aggregator_future = server.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, http_port)));

    // Run the aggregation job creator.
    let pool = database_pool(&db_config, &None).await?;
    let datastore_key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap());
    let crypter = Crypter::new(vec![datastore_key]);
    let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
        Datastore::new(pool, crypter, clock),
        clock,
        StdDuration::from_secs(5),
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
        Duration::from_seconds(5),
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
        Duration::from_seconds(5),
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
