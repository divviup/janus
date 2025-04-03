use crate::{
    install_tracing_subscriber,
    status::{COMPLETE, ERROR, IN_PROGRESS, SUCCESS},
    ErrorHandler, HpkeConfigRegistry, Keyring, NumberAsString, VdafObject,
};
use anyhow::Context;
use backon::ExponentialBuilder;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use educe::Educe;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32};
use janus_collector::Collector;
use janus_core::vdaf::new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128;
#[cfg(feature = "fpvec_bounded_l2")]
use janus_core::vdaf::Prio3FixedPointBoundedL2VecSumBitSize;
use janus_core::{auth_tokens::AuthenticationToken, hpke::HpkeKeypair, vdaf::VdafInstance};
use janus_messages::{
    batch_mode::BatchMode, BatchId, Duration, HpkeConfig, Interval, PartialBatchSelector, Query,
    TaskId, Time,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSum;
use prio::{
    codec::{Decode, Encode},
    flp::gadgets::ParallelSum,
    vdaf::{self, prio3::Prio3},
};
use rand::{distributions::Standard, prelude::Distribution, random};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::Ipv4Addr,
    sync::Arc,
    time::Duration as StdDuration,
};
use tokio::{sync::Mutex, task::JoinHandle};
use trillium::{Conn, Handler};
use trillium_api::{api, Json, State};
use trillium_router::Router;

#[derive(Educe, Deserialize)]
#[educe(Debug)]
struct AddTaskRequest {
    task_id: String,
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    leader: Url,
    vdaf: VdafObject,
    collector_authentication_token: String,
    #[serde(rename = "batch_mode")]
    _batch_mode: u8,
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
    batch_mode: u8,
    batch_interval_start: Option<u64>,
    batch_interval_duration: Option<u64>,
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
    interval_start: i64,
    interval_duration: i64,
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
    interval_start: Option<i64>,
    #[serde(default)]
    interval_duration: Option<i64>,
    #[serde(default)]
    result: Option<AggregationResult>,
}

struct TaskState {
    task_id: TaskId,
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

    let auth_token =
        AuthenticationToken::new_dap_auth_token_from_string(request.collector_authentication_token)
            .context("invalid header value in \"collector_authentication_token\"")?;

    entry.or_insert(TaskState {
        task_id,
        keypair,
        leader_url: request.leader,
        vdaf: request.vdaf,
        auth_token,
    });

    Ok(hpke_config)
}

async fn handle_collect_generic<V, B>(
    http_client: &reqwest::Client,
    task_state: &TaskState,
    query: Query<B>,
    vdaf: V,
    agg_param_encoded: &[u8],
    batch_convert_fn: impl Fn(&PartialBatchSelector<B>) -> Option<BatchId> + Send + 'static,
    result_convert_fn: impl Fn(&V::AggregateResult) -> AggregationResult + Send + 'static,
) -> anyhow::Result<JoinHandle<anyhow::Result<CollectResult>>>
where
    V: vdaf::Collector + Send + Sync + 'static,
    V::AggregationParam: Send + Sync + 'static,
    B: BatchMode,
{
    let collector = Collector::builder(
        task_state.task_id,
        task_state.leader_url.clone(),
        task_state.auth_token.clone(),
        task_state.keypair.clone(),
        vdaf,
    )
    .with_http_client(http_client.clone())
    .with_http_request_backoff(
        ExponentialBuilder::new()
            .with_min_delay(StdDuration::from_secs(1))
            .with_max_delay(StdDuration::from_secs(1))
            .with_max_times(60),
    )
    .with_collect_poll_backoff(
        ExponentialBuilder::new()
            .with_min_delay(StdDuration::from_millis(200))
            .with_max_delay(StdDuration::from_secs(1))
            .with_factor(1.2)
            .with_max_times(60),
    )
    .build()?;
    let agg_param = V::AggregationParam::get_decoded(agg_param_encoded)?;
    let handle = tokio::spawn(async move {
        let collect_result = collector.collect(query, &agg_param).await?;
        let (interval_start, interval_duration) = collect_result.interval();
        Ok(CollectResult {
            partial_batch_selector: batch_convert_fn(collect_result.partial_batch_selector()),
            report_count: collect_result.report_count(),
            interval_start: interval_start.timestamp(),
            interval_duration: interval_duration.num_seconds(),
            aggregation_result: result_convert_fn(collect_result.aggregate_result()),
        })
    });
    Ok(handle)
}

enum ParsedQuery {
    TimeInterval(Interval),
    LeaderSelected,
}

async fn handle_collection_start(
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

    let query = match request.query.batch_mode {
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
        2 => ParsedQuery::LeaderSelected,
        _ => {
            return Err(anyhow::anyhow!(
                "unsupported batch mode: {}",
                request.query.batch_mode
            ))
        }
    };

    let vdaf_instance = task_state.vdaf.clone().into();
    let task_handle = match (query, vdaf_instance) {
        (ParsedQuery::TimeInterval(batch_interval), VdafInstance::Prio3Count) => {
            let vdaf = Prio3::new_count(2).context("failed to construct Prio3Count VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| AggregationResult::Number(NumberAsString((*result).into())),
            )
            .await?
        }

        (ParsedQuery::TimeInterval(batch_interval), VdafInstance::Prio3Sum { max_measurement }) => {
            let vdaf =
                Prio3::new_sum(2, max_measurement).context("failed to construct Prio3Sum VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result| AggregationResult::Number(NumberAsString(u128::from(*result))),
            )
            .await?
        }

        (
            ParsedQuery::TimeInterval(batch_interval),
            VdafInstance::Prio3SumVec {
                bits,
                length,
                chunk_length,
                dp_strategy: _,
            },
        ) => {
            let vdaf = Prio3::new_sum_vec(2, bits, length, chunk_length)
                .context("failed to construct Prio3SumVec VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
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

        (
            ParsedQuery::TimeInterval(batch_interval),
            VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                proofs,
                bits,
                length,
                chunk_length,
                dp_strategy: _,
            },
        ) => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128::<ParallelSum<_, _>>(
                proofs,
                bits,
                length,
                chunk_length,
            )
            .context("failed to construct Prio3SumVecField64MultiproofHmacSha256Aes128 VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_time_interval(batch_interval),
                vdaf,
                &agg_param,
                |_| None,
                |result: &Vec<u64>| {
                    let converted = result
                        .iter()
                        .cloned()
                        .map(u128::from)
                        .map(NumberAsString)
                        .collect();
                    AggregationResult::NumberVec(converted)
                },
            )
            .await?
        }

        (
            ParsedQuery::TimeInterval(batch_interval),
            VdafInstance::Prio3Histogram {
                length,
                chunk_length,
                dp_strategy: _,
            },
        ) => {
            let vdaf = Prio3::new_histogram(2, length, chunk_length)
                .context("failed to construct Prio3Histogram VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
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
            janus_core::vdaf::VdafInstance::Prio3FixedPointBoundedL2VecSum {
                bitsize,
                dp_strategy: _,
                length,
            },
        ) => match bitsize {
            Prio3FixedPointBoundedL2VecSumBitSize::BitSize16 => {
                let vdaf: Prio3FixedPointBoundedL2VecSum<FixedI16<U15>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum(2, length)
                        .context("failed to construct Prio3FixedPoint16BitBoundedL2VecSum VDAF")?;
                handle_collect_generic(
                    http_client,
                    task_state,
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
            Prio3FixedPointBoundedL2VecSumBitSize::BitSize32 => {
                let vdaf: Prio3FixedPointBoundedL2VecSum<FixedI32<U31>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum(2, length)
                        .context("failed to construct Prio3FixedPoint32BitBoundedL2VecSum VDAF")?;
                handle_collect_generic(
                    http_client,
                    task_state,
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
        },

        (ParsedQuery::LeaderSelected, VdafInstance::Prio3Count) => {
            let vdaf = Prio3::new_count(2).context("failed to construct Prio3Count VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_leader_selected(),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| AggregationResult::Number(NumberAsString((*result).into())),
            )
            .await?
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        (
            ParsedQuery::LeaderSelected,
            janus_core::vdaf::VdafInstance::Prio3FixedPointBoundedL2VecSum {
                bitsize,
                dp_strategy: _,
                length,
            },
        ) => match bitsize {
            Prio3FixedPointBoundedL2VecSumBitSize::BitSize16 => {
                let vdaf: Prio3FixedPointBoundedL2VecSum<FixedI16<U15>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum(2, length)
                        .context("failed to construct Prio3FixedPoint16BitBoundedL2VecSum VDAF")?;
                handle_collect_generic(
                    http_client,
                    task_state,
                    Query::new_leader_selected(),
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
            Prio3FixedPointBoundedL2VecSumBitSize::BitSize32 => {
                let vdaf: Prio3FixedPointBoundedL2VecSum<FixedI32<U31>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum(2, length)
                        .context("failed to construct Prio3FixedPoint32BitBoundedL2VecSum VDAF")?;
                handle_collect_generic(
                    http_client,
                    task_state,
                    Query::new_leader_selected(),
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
        },

        (ParsedQuery::LeaderSelected, VdafInstance::Prio3Sum { max_measurement }) => {
            let vdaf =
                Prio3::new_sum(2, max_measurement).context("failed to construct Prio3Sum VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_leader_selected(),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result| AggregationResult::Number(NumberAsString(u128::from(*result))),
            )
            .await?
        }

        (
            ParsedQuery::LeaderSelected,
            VdafInstance::Prio3SumVec {
                bits,
                length,
                chunk_length,
                dp_strategy: _,
            },
        ) => {
            let vdaf = Prio3::new_sum_vec(2, bits, length, chunk_length)
                .context("failed to construct Prio3SumVec VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_leader_selected(),
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

        (
            ParsedQuery::LeaderSelected,
            VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                proofs,
                bits,
                length,
                chunk_length,
                dp_strategy: _,
            },
        ) => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128::<ParallelSum<_, _>>(
                proofs,
                bits,
                length,
                chunk_length,
            )
            .context("failed to construct Prio3SumVecField64MultiproofHmacSha256Aes128 VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_leader_selected(),
                vdaf,
                &agg_param,
                |selector| Some(*selector.batch_id()),
                |result: &Vec<u64>| {
                    let converted = result
                        .iter()
                        .cloned()
                        .map(u128::from)
                        .map(NumberAsString)
                        .collect();
                    AggregationResult::NumberVec(converted)
                },
            )
            .await?
        }

        (
            ParsedQuery::LeaderSelected,
            VdafInstance::Prio3Histogram {
                length,
                chunk_length,
                dp_strategy: _,
            },
        ) => {
            let vdaf = Prio3::new_histogram(2, length, chunk_length)
                .context("failed to construct Prio3Histogram VDAF")?;
            handle_collect_generic(
                http_client,
                task_state,
                Query::new_leader_selected(),
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

async fn handle_collection_poll(
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
            "did not recognize handle in collection_poll request"
        )),
    }
}

#[derive(Clone)]
struct TaskStateMap(Arc<Mutex<HashMap<TaskId, TaskState>>>);

impl TaskStateMap {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }
}

#[derive(Clone)]
struct CollectionJobStateMap(Arc<Mutex<HashMap<Handle, CollectionJobState>>>);

impl CollectionJobStateMap {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }
}

fn handler() -> anyhow::Result<impl Handler> {
    let http_client = janus_collector::default_http_client()?;
    let tasks = TaskStateMap::new();
    let collection_jobs = CollectionJobStateMap::new();
    let keyring = Keyring::new();

    let router = Router::new()
        .post("/internal/test/ready", Json(serde_json::json!({})))
        .post(
            "/internal/test/add_task",
            api(
                |_conn: &mut Conn,
                 (State(tasks), State(keyring), Json(request)): (
                    State<TaskStateMap>,
                    State<Keyring>,
                    Json<AddTaskRequest>,
                )| async move {
                    match handle_add_task(&tasks.0, &keyring.0, request)
                        .await
                        .and_then(|config| {
                            config.get_encoded().context("failed to encode HPKE config")
                        }) {
                        Ok(collector_hpke_config) => Json(AddTaskResponse {
                            status: SUCCESS,
                            error: None,
                            collector_hpke_config: Some(
                                URL_SAFE_NO_PAD.encode(collector_hpke_config),
                            ),
                        }),
                        Err(e) => Json(AddTaskResponse {
                            status: ERROR,
                            error: Some(format!("{e:?}")),
                            collector_hpke_config: None,
                        }),
                    }
                },
            ),
        )
        .post(
            "/internal/test/collection_start",
            api(
                |_conn: &mut Conn,
                 (State(http_client), State(tasks), State(collection_jobs), Json(request)): (
                    State<reqwest::Client>,
                    State<TaskStateMap>,
                    State<CollectionJobStateMap>,
                    Json<CollectStartRequest>,
                )| async move {
                    match handle_collection_start(
                        &http_client,
                        &tasks.0,
                        &collection_jobs.0,
                        request,
                    )
                    .await
                    {
                        Ok(handle) => Json(CollectStartResponse {
                            status: SUCCESS,
                            error: None,
                            handle: Some(handle.0),
                        }),
                        Err(e) => Json(CollectStartResponse {
                            status: ERROR,
                            error: Some(format!("{e:?}")),
                            handle: None,
                        }),
                    }
                },
            ),
        )
        .post(
            "/internal/test/collection_poll",
            api(
                |_conn: &mut Conn,
                 (State(collection_jobs), Json(request)): (
                    State<CollectionJobStateMap>,
                    Json<CollectPollRequest>,
                )| async move {
                    match handle_collection_poll(&collection_jobs.0, request).await {
                        Ok(Some(collect_result)) => Json(CollectPollResponse {
                            status: COMPLETE,
                            error: None,
                            batch_id: collect_result
                                .partial_batch_selector
                                .map(|batch_id| URL_SAFE_NO_PAD.encode(batch_id.as_ref())),
                            report_count: Some(collect_result.report_count),
                            interval_start: Some(collect_result.interval_start),
                            interval_duration: Some(collect_result.interval_duration),
                            result: Some(collect_result.aggregation_result),
                        }),
                        Ok(None) => Json(CollectPollResponse {
                            status: IN_PROGRESS,
                            error: None,
                            batch_id: None,
                            report_count: None,
                            interval_start: None,
                            interval_duration: None,
                            result: None,
                        }),
                        Err(e) => Json(CollectPollResponse {
                            status: ERROR,
                            error: Some(format!("{e:?}")),
                            batch_id: None,
                            report_count: None,
                            interval_start: None,
                            interval_duration: None,
                            result: None,
                        }),
                    }
                },
            ),
        );

    Ok((
        State(http_client),
        State(tasks),
        State(collection_jobs),
        State(keyring),
        router,
        ErrorHandler,
    ))
}

#[derive(Debug, Parser)]
/// Janus interoperation test collector
pub struct Options {
    /// Port number to listen on.
    #[clap(long, short, default_value = "8080")]
    port: u16,
}

impl Options {
    pub fn run(self) -> anyhow::Result<()> {
        install_tracing_subscriber()?;
        trillium_tokio::config()
            .with_host(&Ipv4Addr::UNSPECIFIED.to_string())
            .with_port(self.port)
            .run(handler()?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Options;

    #[test]
    fn verify_clap_app() {
        Options::command().debug_assert();
    }
}
