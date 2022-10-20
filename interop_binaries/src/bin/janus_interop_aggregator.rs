use anyhow::{anyhow, Context};
use base64::URL_SAFE_NO_PAD;
use clap::{value_parser, Arg, Command};
use janus_aggregator::{
    aggregator::{
        aggregate_share::CollectJobDriver, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, aggregator_filter,
    },
    binary_utils::{database_pool, job_driver::JobDriver},
    config::DbConfig,
    datastore::{Crypter, Datastore},
    task::{self, QueryType, Task, VdafInstance},
    SecretBytes,
};
use janus_core::{hpke::HpkePrivateKey, task::AuthenticationToken, time::RealClock, TokioRuntime};
use janus_interop_binaries::{
    install_tracing_subscriber,
    status::{ERROR, SUCCESS},
    AddAuthenticationTokenRequest, AddAuthenticationTokenResponse, AddTaskResponse,
    AggregatorAddTaskRequest, HpkeConfigRegistry, TokenRole,
};
use janus_messages::{BatchId, Duration, HpkeConfig, Role, TaskId, Time};
use opentelemetry::global::meter;
use prio::codec::Decode;
use rand::random;
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};
use tokio::sync::Mutex;
use url::Url;
use warp::{hyper::StatusCode, reply::Response, Filter, Reply};

#[derive(Debug, Serialize)]
struct EndpointResponse<'a> {
    status: &'a str,
    endpoint: &'a str,
}

#[derive(Debug, Deserialize)]
struct FetchBatchIdsRequest {
    task_id: String,
}

#[derive(Debug, Serialize)]
struct FetchBatchIdsResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    batch_ids: Option<Vec<String>>,
}

struct TaskParameters {
    task_id: TaskId,
    aggregator_endpoints: Vec<Url>,
    query_type: QueryType,
    vdaf: VdafInstance,
    role: Role,
    vdaf_verify_keys: Vec<SecretBytes>,
    max_batch_query_count: u64,
    task_expiration: Time,
    min_batch_size: u64,
    time_precision: Duration,
    collector_hpke_config: HpkeConfig,
    hpke_keypair: (HpkeConfig, HpkePrivateKey),
}

struct PartialTaskState {
    task_parameters: TaskParameters,
    aggregator_auth_token: Option<AuthenticationToken>,
    collector_auth_token: Option<AuthenticationToken>,
}

impl PartialTaskState {
    pub fn new(task_parameters: TaskParameters) -> PartialTaskState {
        PartialTaskState {
            task_parameters,
            aggregator_auth_token: None,
            collector_auth_token: None,
        }
    }

    pub fn add_aggregator_authentication_token(
        &mut self,
        token: AuthenticationToken,
    ) -> anyhow::Result<Option<Task>> {
        match (
            self.task_parameters.role,
            &mut self.aggregator_auth_token,
            &self.collector_auth_token,
        ) {
            (_, Some(_), _) => Err(anyhow::anyhow!(
                "multiple aggregator authentication tokens are not supported"
            )),
            (Role::Leader, aggregator_auth_token_opt @ None, Some(_))
            | (Role::Helper, aggregator_auth_token_opt @ None, _) => {
                *aggregator_auth_token_opt = Some(token);
                Ok(Some(self.build_task()?))
            }
            (Role::Leader, aggregator_auth_token_opt @ None, None) => {
                *aggregator_auth_token_opt = Some(token);
                Ok(None)
            }
            (Role::Client, _, _) | (Role::Collector, _, _) => unreachable!(),
        }
    }

    pub fn add_collector_authentication_token(
        &mut self,
        token: AuthenticationToken,
    ) -> anyhow::Result<Option<Task>> {
        match (
            self.task_parameters.role,
            &self.aggregator_auth_token,
            &mut self.collector_auth_token,
        ) {
            (_, _, Some(_)) => Err(anyhow::anyhow!(
                "multiple collector authentication tokens are not supported"
            )),
            (Role::Helper, _, _) => Err(anyhow::anyhow!(
                "collector authentication tokens are not supported in tasks with the helper role"
            )),
            (Role::Leader, None, collector_auth_token_opt @ None) => {
                *collector_auth_token_opt = Some(token);
                Ok(None)
            }
            (Role::Leader, Some(_), collector_auth_token_opt @ None) => {
                *collector_auth_token_opt = Some(token);
                Ok(Some(self.build_task()?))
            }
            (Role::Client, _, _) | (Role::Collector, _, _) => unreachable!(),
        }
    }

    fn build_task(&self) -> Result<Task, task::Error> {
        Task::new(
            self.task_parameters.task_id,
            self.task_parameters.aggregator_endpoints.clone(),
            self.task_parameters.query_type,
            self.task_parameters.vdaf.clone(),
            self.task_parameters.role,
            self.task_parameters.vdaf_verify_keys.clone(),
            self.task_parameters.max_batch_query_count,
            self.task_parameters.task_expiration,
            self.task_parameters.min_batch_size,
            self.task_parameters.time_precision,
            // We can be strict about clock skew since this executable is only intended for use with
            // other aggregators running on the same host.
            Duration::from_seconds(1),
            self.task_parameters.collector_hpke_config.clone(),
            self.aggregator_auth_token.iter().cloned().collect(),
            self.collector_auth_token.iter().cloned().collect(),
            [self.task_parameters.hpke_keypair.clone()],
        )
    }
}

async fn handle_add_task(
    keyring: &Mutex<HpkeConfigRegistry>,
    partial_tasks: &Mutex<HashMap<TaskId, PartialTaskState>>,
    request: AggregatorAddTaskRequest,
) -> anyhow::Result<()> {
    let task_id_bytes = base64::decode_config(request.task_id, URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"task_id\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;
    let vdaf = request.vdaf.into();
    let verify_key = SecretBytes::new(
        base64::decode_config(request.verify_key, URL_SAFE_NO_PAD)
            .context("invalid base64url content in \"verify_key\"")?,
    );
    let time_precision = Duration::from_seconds(request.time_precision);
    let collector_hpke_config_bytes =
        base64::decode_config(request.collector_hpke_config, URL_SAFE_NO_PAD)
            .context("invalid base64url content in \"collector_hpke_config\"")?;
    let collector_hpke_config = HpkeConfig::get_decoded(&collector_hpke_config_bytes)
        .context("could not parse collector HPKE configuration")?;

    let (hpke_config, private_key) = keyring.lock().await.get_random_keypair();

    let query_type = match request.query_type {
        1 => janus_aggregator::task::QueryType::TimeInterval,
        2 => janus_aggregator::task::QueryType::FixedSize {
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

    let task_parameters = TaskParameters {
        task_id,
        aggregator_endpoints: Vec::from([request.leader, request.helper]),
        query_type,
        vdaf,
        role: request.role.into(),
        vdaf_verify_keys: Vec::from([verify_key]),
        max_batch_query_count: request.max_batch_query_count,
        task_expiration: Time::from_seconds_since_epoch(request.task_expiration),
        min_batch_size: request.min_batch_size,
        time_precision,
        collector_hpke_config,
        hpke_keypair: (hpke_config, private_key),
    };

    let mut partial_tasks_guard = partial_tasks.lock().await;
    match partial_tasks_guard.entry(task_id) {
        Entry::Occupied(_) => Err(anyhow::anyhow!(
            "task already exists with TaskID {}",
            task_id
        )),
        entry @ Entry::Vacant(_) => {
            entry.or_insert_with(|| PartialTaskState::new(task_parameters));
            Ok(())
        }
    }
}

async fn handle_add_authentication_token(
    datastore: &Datastore<RealClock>,
    partial_tasks: &Mutex<HashMap<TaskId, PartialTaskState>>,
    request: AddAuthenticationTokenRequest,
) -> anyhow::Result<()> {
    let task_id_bytes = base64::decode_config(request.task_id, URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"task_id\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;

    let token = AuthenticationToken::from(request.token.clone().into_bytes());

    let mut partial_tasks_guard = partial_tasks.lock().await;
    let partial_task = partial_tasks_guard
        .get_mut(&task_id)
        .ok_or_else(|| anyhow::anyhow!("unrecognized TaskID {}", task_id))?;

    let task_opt = match request.role {
        TokenRole::Leader => partial_task.add_aggregator_authentication_token(token)?,
        TokenRole::Collector => partial_task.add_collector_authentication_token(token)?,
    };

    if let Some(task) = task_opt {
        datastore
            .run_tx(move |tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .context("error adding task to database")
    } else {
        Ok(())
    }
}

async fn handle_fetch_batch_ids(
    _datastore: &Datastore<RealClock>,
    request: FetchBatchIdsRequest,
) -> anyhow::Result<Vec<BatchId>> {
    let task_id_bytes = base64::decode_config(request.task_id, URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"task_id\"")?;
    let _task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;

    Err(anyhow::anyhow!("fixed size queries are not yet supported"))
}

fn make_filter(
    datastore: Arc<Datastore<RealClock>>,
    dap_serving_prefix: String,
) -> anyhow::Result<impl Filter<Extract = (Response,)> + Clone> {
    let keyring = Arc::new(Mutex::new(HpkeConfigRegistry::new()));
    let partial_tasks = Arc::new(Mutex::new(HashMap::new()));
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
    let add_task_filter = warp::path!("add_task").and(warp::body::json()).then({
        let partial_tasks = Arc::clone(&partial_tasks);
        move |request: AggregatorAddTaskRequest| {
            let keyring = Arc::clone(&keyring);
            let partial_tasks = Arc::clone(&partial_tasks);
            async move {
                let response = match handle_add_task(&keyring, &partial_tasks, request).await {
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
        }
    });
    let add_authentication_token_filter = warp::path!("add_authentication_token")
        .and(warp::body::json())
        .then({
            let datastore = Arc::clone(&datastore);
            move |request: AddAuthenticationTokenRequest| {
                let datastore = Arc::clone(&datastore);
                let partial_tasks = Arc::clone(&partial_tasks);
                async move {
                    let response =
                        match handle_add_authentication_token(&datastore, &partial_tasks, request)
                            .await
                        {
                            Ok(()) => AddAuthenticationTokenResponse {
                                status: SUCCESS,
                                error: None,
                            },
                            Err(e) => AddAuthenticationTokenResponse {
                                status: ERROR,
                                error: Some(format!("{:?}", e)),
                            },
                        };
                    warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                        .into_response()
                }
            }
        });
    let fetch_batch_ids_filter = warp::path!("fetch_batch_ids").and(warp::body::json()).then(
        move |request: FetchBatchIdsRequest| {
            let datastore = Arc::clone(&datastore);
            async move {
                let response = match handle_fetch_batch_ids(&datastore, request).await {
                    Ok(batch_ids) => FetchBatchIdsResponse {
                        status: SUCCESS,
                        error: None,
                        batch_ids: Some(
                            batch_ids
                                .into_iter()
                                .map(|batch_id| {
                                    base64::encode_config(batch_id.as_ref(), URL_SAFE_NO_PAD)
                                })
                                .collect(),
                        ),
                    },
                    Err(e) => FetchBatchIdsResponse {
                        status: ERROR,
                        error: Some(format!("{:?}", e)),
                        batch_ids: None,
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
                .unify()
                .or(add_authentication_token_filter)
                .unify()
                .or(fetch_batch_ids_filter)
                .unify(),
        )
        .or(dap_filter.map(Reply::into_response))
        .unify())
}

fn app() -> clap::Command {
    Command::new("Janus interoperation test aggregator")
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .default_value("8080")
                .value_parser(value_parser!(u16))
                .help("Port number to listen on."),
        )
        .arg(
            Arg::new("postgres-url")
                .long("postgres-url")
                .default_value("postgres://postgres@127.0.0.1:5432/postgres")
                .value_parser(value_parser!(Url))
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
    let http_port = matches
        .try_get_one::<u16>("port")?
        .ok_or_else(|| anyhow!("port argument missing"))?;
    let postgres_url = matches
        .try_get_one::<Url>("postgres-url")?
        .ok_or_else(|| anyhow!("postgres-url argument missing"))?;
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
        url: postgres_url.clone(),
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
    let aggregator_future = server.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, *http_port)));

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
