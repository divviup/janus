use anyhow::{anyhow, Context};
use backoff::ExponentialBackoffBuilder;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{value_parser, Arg, Command};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31, U63};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32, FixedI64};
use janus_collector::{Collector, CollectorParameters};
use janus_core::{
    hpke::HpkeKeypair,
    task::{AuthenticationToken, VdafInstance},
};
use janus_interop_binaries::{
    install_tracing_subscriber,
    status::{COMPLETE, ERROR, IN_PROGRESS, SUCCESS},
    HpkeConfigRegistry, NumberAsString, VdafObject,
};
use janus_messages::{
    query_type::QueryType, BatchId, Duration, FixedSizeQuery, HpkeConfig, Interval,
    PartialBatchSelector, Query, TaskId, Time,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3Aes128FixedPointBoundedL2VecSum;
use prio::{
    codec::{Decode, Encode},
    vdaf::{self, prio3::Prio3},
};
use rand::{distributions::Standard, prelude::Distribution, random};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};
use tokio::{spawn, sync::Mutex, task::JoinHandle};
use warp::{hyper::StatusCode, reply::Response, Filter, Reply};
#[derive(Debug, Deserialize)]
struct AddTaskRequest {
    task_id: String,
    leader: Url,
    vdaf: VdafObject,
    collector_authentication_token: String,
    #[serde(rename = "query_type")]
    _query_type: u8,
}

#[derive(Debug, Serialize)]
struct AddTaskResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
    collector_hpke_config: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RequestQuery {
    #[serde(rename = "type")]
    query_type: u8,
    batch_interval_start: Option<u64>,
    batch_interval_duration: Option<u64>,
    subtype: Option<u8>,
    batch_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CollectStartRequest {
    task_id: String,
    agg_param: String,
    query: RequestQuery,
}

#[derive(Debug, Serialize)]
struct CollectStartResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    handle: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CollectPollRequest {
    handle: String,
}

#[derive(Debug, Clone)]
struct CollectResult {
    partial_batch_selector: Option<BatchId>,
    report_count: u64,
    aggregation_result: AggregationResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum AggregationResult {
    Number(NumberAsString<u128>),
    NumberVec(Vec<NumberAsString<u128>>),
    #[cfg(feature = "fpvec_bounded_l2")]
    FloatVec(Vec<NumberAsString<f64>>),
}

#[derive(Debug, Serialize)]
struct CollectPollResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    batch_id: Option<String>,
    #[serde(default)]
    report_count: Option<u64>,
    #[serde(default)]
    result: Option<AggregationResult>,
}

struct TaskState {
    keypair: HpkeKeypair,
    leader_url: Url,
    vdaf: VdafObject,
    auth_token: AuthenticationToken,
}

/// A collection job handle.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Handle(String);

impl Distribution<Handle> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Handle {
        Handle(URL_SAFE_NO_PAD.encode(rng.gen::<[u8; 32]>()))
    }
}

enum CollectionJobState {
    InProgress(Option<JoinHandle<anyhow::Result<CollectResult>>>),
    Completed(CollectResult),
    Error,
}

async fn handle_add_task(
    tasks: &Mutex<HashMap<TaskId, TaskState>>,
    keyring: &Mutex<HpkeConfigRegistry>,
    request: AddTaskRequest,
) -> anyhow::Result<HpkeConfig> {
    let task_id_bytes = URL_SAFE_NO_PAD
        .decode(request.task_id)
        .context("invalid base64url content in \"task_id\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;

    let mut tasks_guard = tasks.lock().await;
    let entry = tasks_guard.entry(task_id);
    if let Entry::Occupied(_) = &entry {
        return Err(anyhow::anyhow!("cannot add a task with a duplicate ID"));
    }

    let keypair = keyring.lock().await.get_random_keypair();
    let hpke_config = keypair.config().clone();

    entry.or_insert(TaskState {
        keypair,
        leader_url: request.leader,
        vdaf: request.vdaf,
        auth_token: AuthenticationToken::from(request.collector_authentication_token.into_bytes()),
    });

    Ok(hpke_config)
}

async fn handle_collect_generic<V, Q>(
    http_client: &reqwest::Client,
    collector_params: CollectorParameters,
    query: Query<Q>,
    vdaf: V,
    agg_param_encoded: &[u8],
    batch_convert_fn: impl Fn(&PartialBatchSelector<Q>) -> Option<BatchId> + Send + 'static,
    result_convert_fn: impl Fn(&V::AggregateResult) -> AggregationResult + Send + 'static,
) -> anyhow::Result<JoinHandle<anyhow::Result<CollectResult>>>
where
    V: vdaf::Collector + Send + Sync + 'static,
    V::AggregationParam: Send + Sync + 'static,
    for<'a> Vec<u8>: From<&'a V::AggregateShare>,
    Q: QueryType,
{
    let collector = Collector::new(collector_params, vdaf, http_client.clone());
    let agg_param = V::AggregationParam::get_decoded(agg_param_encoded)?;
    let handle = spawn(async move {
        let collect_result = collector.collect(query, &agg_param).await?;
        Ok(CollectResult {
            partial_batch_selector: batch_convert_fn(collect_result.partial_batch_selector()),
            report_count: collect_result.report_count(),
            aggregation_result: result_convert_fn(collect_result.aggregate_result()),
        })
    });
    Ok(handle)
}

enum ParsedQuery {
    TimeInterval(Interval),
    FixedSize(FixedSizeQuery),
}

async fn handle_collect_start(
    http_client: &reqwest::Client,
    tasks: &Mutex<HashMap<TaskId, TaskState>>,
    collection_jobs: &Mutex<HashMap<Handle, CollectionJobState>>,
    request: CollectStartRequest,
) -> anyhow::Result<Handle> {
    let task_id_bytes = URL_SAFE_NO_PAD
        .decode(request.task_id)
        .context("invalid base64url content in \"task_id\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;
    let agg_param = URL_SAFE_NO_PAD
        .decode(request.agg_param)
        .context("invalid base64url content in \"agg_param\"")?;

    let tasks_guard = tasks.lock().await;
    let task_state = tasks_guard
        .get(&task_id)
        .context("task was not added before being used in a collect request")?;

    let collector_params = CollectorParameters::new(
        task_id,
        task_state.leader_url.clone(),
        task_state.auth_token.clone(),
        task_state.keypair.config().clone(),
        task_state.keypair.private_key().clone(),
    )
    .with_http_request_backoff(
        ExponentialBackoffBuilder::new()
            .with_initial_interval(StdDuration::from_secs(1))
            .with_max_interval(StdDuration::from_secs(1))
            .with_max_elapsed_time(Some(StdDuration::from_secs(60)))
            .build(),
    )
    .with_collect_poll_backoff(
        ExponentialBackoffBuilder::new()
            .with_initial_interval(StdDuration::from_millis(200))
            .with_max_interval(StdDuration::from_secs(1))
            .with_multiplier(1.2)
            .with_max_elapsed_time(Some(StdDuration::from_secs(60)))
            .build(),
    );

    let query = match request.query.query_type {
        1 => {
            let start = Time::from_seconds_since_epoch(
                request
                    .query
                    .batch_interval_start
                    .context("\"batch_interval_start\" was missing")?,
            );
            let duration = Duration::from_seconds(
                request
                    .query
                    .batch_interval_duration
                    .context("\"batch_interval_duration\" was missing")?,
            );
            let interval =
                Interval::new(start, duration).context("invalid batch interval specification")?;
            ParsedQuery::TimeInterval(interval)
        }
        2 => match request.query.subtype {
            Some(0) => {
                let batch_id_bytes = URL_SAFE_NO_PAD
                    .decode(request.query.batch_id.context("\"batch_id\" was missing")?)?;
                let batch_id =
                    BatchId::get_decoded(&batch_id_bytes).context("invalid length of BatchId")?;
                ParsedQuery::FixedSize(FixedSizeQuery::ByBatchId { batch_id })
            }
            Some(1) => ParsedQuery::FixedSize(FixedSizeQuery::CurrentBatch),
            None => return Err(anyhow::anyhow!("\"subtype\" was missing")),
            _ => return Err(anyhow::anyhow!("unrecognized \"subtype\" in query")),
        },
        _ => {
            return Err(anyhow::anyhow!(
                "unsupported query type: {}",
                request.query.query_type
            ))
        }
    };

    let vdaf_instance = task_state.vdaf.clone().into();
    let task_handle = match (query, vdaf_instance) {
        (ParsedQuery::TimeInterval(batch_interval), VdafInstance::Prio3Aes128Count {}) => {
            let vdaf =
                Prio3::new_aes128_count(2).context("failed to construct Prio3Aes128Count VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| AggregationResult::Number(NumberAsString((*result).into())),
            )
            .await?
        }

        (
            ParsedQuery::TimeInterval(batch_interval),
            VdafInstance::Prio3Aes128CountVec { length },
        ) => {
            let vdaf = Prio3::new_aes128_count_vec_multithreaded(2, length)
                .context("failed to construct Prio3Aes128CountVec VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::NumberVec(converted)
                },
            )
            .await?
        }

        (ParsedQuery::TimeInterval(batch_interval), VdafInstance::Prio3Aes128Sum { bits }) => {
            let vdaf = Prio3::new_aes128_sum(2, bits)
                .context("failed to construct Prio3Aes128Sum VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| AggregationResult::Number(NumberAsString(*result)),
            )
            .await?
        }

        (
            ParsedQuery::TimeInterval(batch_interval),
            VdafInstance::Prio3Aes128Histogram { buckets },
        ) => {
            let vdaf = Prio3::new_aes128_histogram(2, &buckets)
                .context("failed to construct Prio3Aes128Histogram VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::NumberVec(converted)
                },
            )
            .await?
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        (
            ParsedQuery::TimeInterval(batch_interval),
            janus_core::task::VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { length },
        ) => {
            let vdaf: Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>> =
                Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, length).context(
                    "failed to construct Prio3Aes128FixedPoint16BitBoundedL2VecSum VDAF",
                )?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::FloatVec(converted)
                },
            )
            .await?
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        (
            ParsedQuery::TimeInterval(batch_interval),
            janus_core::task::VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { length },
        ) => {
            let vdaf: Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>> =
                Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, length).context(
                    "failed to construct Prio3Aes128FixedPoint32BitBoundedL2VecSum VDAF",
                )?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::FloatVec(converted)
                },
            )
            .await?
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        (
            ParsedQuery::TimeInterval(batch_interval),
            janus_core::task::VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { length },
        ) => {
            let vdaf: Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>> =
                Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, length).context(
                    "failed to construct Prio3Aes128FixedPoint64BitBoundedL2VecSum VDAF",
                )?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::FloatVec(converted)
                },
            )
            .await?
        }

        (ParsedQuery::FixedSize(fixed_size_query), VdafInstance::Prio3Aes128Count {}) => {
            let vdaf =
                Prio3::new_aes128_count(2).context("failed to construct Prio3Aes128Count VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_fixed_size(fixed_size_query),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| AggregationResult::Number(NumberAsString((*result).into())),
            )
            .await?
        }

        (
            ParsedQuery::FixedSize(fixed_size_query),
            VdafInstance::Prio3Aes128CountVec { length },
        ) => {
            let vdaf = Prio3::new_aes128_count_vec_multithreaded(2, length)
                .context("failed to construct Prio3Aes128CountVec VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_fixed_size(fixed_size_query),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::NumberVec(converted)
                },
            )
            .await?
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        (
            ParsedQuery::FixedSize(fixed_size_query),
            janus_core::task::VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { length },
        ) => {
            let vdaf: Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>> =
                Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, length).context(
                    "failed to construct Prio3Aes128FixedPoint16BitBoundedL2VecSum VDAF",
                )?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_fixed_size(fixed_size_query),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::FloatVec(converted)
                },
            )
            .await?
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        (
            ParsedQuery::FixedSize(fixed_size_query),
            janus_core::task::VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { length },
        ) => {
            let vdaf: Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>> =
                Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, length).context(
                    "failed to construct Prio3Aes128FixedPoint32BitBoundedL2VecSum VDAF",
                )?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_fixed_size(fixed_size_query),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::FloatVec(converted)
                },
            )
            .await?
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        (
            ParsedQuery::FixedSize(fixed_size_query),
            janus_core::task::VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { length },
        ) => {
            let vdaf: Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>> =
                Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, length).context(
                    "failed to construct Prio3Aes128FixedPoint64BitBoundedL2VecSum VDAF",
                )?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_fixed_size(fixed_size_query),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::FloatVec(converted)
                },
            )
            .await?
        }

        (ParsedQuery::FixedSize(fixed_size_query), VdafInstance::Prio3Aes128Sum { bits }) => {
            let vdaf = Prio3::new_aes128_sum(2, bits)
                .context("failed to construct Prio3Aes128Sum VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_fixed_size(fixed_size_query),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| AggregationResult::Number(NumberAsString(*result)),
            )
            .await?
        }

        (
            ParsedQuery::FixedSize(fixed_size_query),
            VdafInstance::Prio3Aes128Histogram { buckets },
        ) => {
            let vdaf = Prio3::new_aes128_histogram(2, &buckets)
                .context("failed to construct Prio3Aes128Histogram VDAF")?;
            handle_collect_generic(
                http_client,
                collector_params,
                Query::new_fixed_size(fixed_size_query),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| {
                    let converted = result.iter().cloned().map(NumberAsString).collect();
                    AggregationResult::NumberVec(converted)
                },
            )
            .await?
        }

        (_, vdaf_instance) => {
            panic!("Unsupported VDAF: {vdaf_instance:?}")
        }
    };

    let mut collection_jobs_guard = collection_jobs.lock().await;
    Ok(loop {
        match collection_jobs_guard.entry(random()) {
            Entry::Occupied(_) => continue,
            entry @ Entry::Vacant(_) => {
                let key = entry.key().clone();
                entry.or_insert(CollectionJobState::InProgress(Some(task_handle)));
                break key;
            }
        }
    })
}

async fn handle_collect_poll(
    collection_jobs: &Mutex<HashMap<Handle, CollectionJobState>>,
    request: CollectPollRequest,
) -> anyhow::Result<Option<CollectResult>> {
    let mut collection_jobs_guard = collection_jobs.lock().await;
    let collection_job_state_entry = collection_jobs_guard.entry(Handle(request.handle.clone()));
    match collection_job_state_entry {
        Entry::Occupied(mut occupied_entry) => match occupied_entry.get_mut() {
            CollectionJobState::InProgress(join_handle_opt) => {
                if join_handle_opt.as_ref().unwrap().is_finished() {
                    // Awaiting on the JoinHandle requires owning it. We take it out of the Option,
                    // and ensure that a different enum variant is stored over it before dropping
                    // the lock on the HashMap.
                    let taken_handle = join_handle_opt.take().unwrap();
                    let task_result = taken_handle.await;
                    let collect_result = match task_result {
                        Ok(collect_result) => collect_result,
                        Err(e) => {
                            occupied_entry.insert(CollectionJobState::Error);
                            return Err(e).context("panic while handling collection");
                        }
                    };
                    match collect_result {
                        Ok(collect_result) => {
                            occupied_entry
                                .insert(CollectionJobState::Completed(collect_result.clone()));
                            Ok(Some(collect_result))
                        }
                        Err(e) => {
                            occupied_entry.insert(CollectionJobState::Error);
                            Err(e)
                        }
                    }
                } else {
                    Ok(None)
                }
            }
            CollectionJobState::Completed(collect_result) => Ok(Some(collect_result.clone())),
            CollectionJobState::Error => Err(anyhow::anyhow!(
                "collection previously resulted in an error"
            )),
        },
        Entry::Vacant(_) => Err(anyhow::anyhow!(
            "did not recognize handle in collect_poll request"
        )),
    }
}

fn make_filter() -> anyhow::Result<impl Filter<Extract = (Response,)> + Clone> {
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let tasks: Arc<Mutex<HashMap<TaskId, TaskState>>> = Arc::new(Mutex::new(HashMap::new()));
    let collection_jobs: Arc<Mutex<HashMap<Handle, CollectionJobState>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let keyring = Arc::new(Mutex::new(HpkeConfigRegistry::new()));

    let ready_filter = warp::path!("ready").map(|| {
        warp::reply::with_status(warp::reply::json(&serde_json::json!({})), StatusCode::OK)
            .into_response()
    });
    let add_task_filter = warp::path!("add_task").and(warp::body::json()).then({
        let tasks = Arc::clone(&tasks);
        let keyring = Arc::clone(&keyring);
        move |request: AddTaskRequest| {
            let tasks = Arc::clone(&tasks);
            let keyring = Arc::clone(&keyring);
            async move {
                let response = match handle_add_task(&tasks, &keyring, request).await {
                    Ok(collector_hpke_config) => AddTaskResponse {
                        status: SUCCESS,
                        error: None,
                        collector_hpke_config: Some(
                            URL_SAFE_NO_PAD.encode(collector_hpke_config.get_encoded()),
                        ),
                    },
                    Err(e) => AddTaskResponse {
                        status: ERROR,
                        error: Some(format!("{e:?}")),
                        collector_hpke_config: None,
                    },
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                    .into_response()
            }
        }
    });
    let collect_start_filter = warp::path!("collect_start").and(warp::body::json()).then({
        let tasks = Arc::clone(&tasks);
        let collection_jobs = Arc::clone(&collection_jobs);
        move |request: CollectStartRequest| {
            let http_client = http_client.clone();
            let tasks = Arc::clone(&tasks);
            let collection_jobs = Arc::clone(&collection_jobs);
            async move {
                let response =
                    match handle_collect_start(&http_client, &tasks, &collection_jobs, request)
                        .await
                    {
                        Ok(handle) => CollectStartResponse {
                            status: SUCCESS,
                            error: None,
                            handle: Some(handle.0),
                        },
                        Err(e) => CollectStartResponse {
                            status: ERROR,
                            error: Some(format!("{e:?}")),
                            handle: None,
                        },
                    };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                    .into_response()
            }
        }
    });
    let collect_poll_filter = warp::path!("collect_poll").and(warp::body::json()).then({
        move |request: CollectPollRequest| {
            let collection_jobs = Arc::clone(&collection_jobs);
            async move {
                let response = match handle_collect_poll(&collection_jobs, request).await {
                    Ok(Some(collect_result)) => CollectPollResponse {
                        status: COMPLETE,
                        error: None,
                        batch_id: collect_result
                            .partial_batch_selector
                            .map(|batch_id| URL_SAFE_NO_PAD.encode(batch_id.as_ref())),
                        report_count: Some(collect_result.report_count),
                        result: Some(collect_result.aggregation_result),
                    },
                    Ok(None) => CollectPollResponse {
                        status: IN_PROGRESS,
                        error: None,
                        batch_id: None,
                        report_count: None,
                        result: None,
                    },
                    Err(e) => CollectPollResponse {
                        status: ERROR,
                        error: Some(format!("{e:?}")),
                        batch_id: None,
                        report_count: None,
                        result: None,
                    },
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                    .into_response()
            }
        }
    });

    Ok(warp::path!("internal" / "test" / ..).and(warp::post()).and(
        ready_filter
            .or(add_task_filter)
            .unify()
            .or(collect_start_filter)
            .unify()
            .or(collect_poll_filter)
            .unify(),
    ))
}

fn app() -> clap::Command {
    Command::new("Janus interoperation test collector").arg(
        Arg::new("port")
            .long("port")
            .short('p')
            .default_value("8080")
            .value_parser(value_parser!(u16))
            .help("Port number to listen on."),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;
    let matches = app().get_matches();
    let port = matches
        .try_get_one::<u16>("port")?
        .ok_or_else(|| anyhow!("port argument missing"))?;
    let filter = make_filter()?;
    let server = warp::serve(filter);
    server
        .bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port)))
        .await;
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
