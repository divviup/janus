use anyhow::Context;
use base64::URL_SAFE_NO_PAD;
use clap::{Arg, Command};
use interop_binaries::{
    install_tracing_subscriber,
    status::{COMPLETE, ERROR, IN_PROGRESS, SUCCESS},
    HpkeConfigRegistry, VdafObject,
};
use janus_core::{
    hpke::{self, associated_data_for_aggregate_share, HpkeApplicationInfo, HpkePrivateKey, Label},
    message::{Duration, HpkeConfig, Interval, Role, TaskId, Time},
};
use janus_server::{
    message::{CollectReq, CollectResp},
    task::DAP_AUTH_HEADER,
};
use prio::{
    codec::{Decode, Encode},
    field::{Field128, Field64},
    vdaf::{
        prio3::{Prio3, Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        AggregateShare, Collector, Vdaf,
    },
};
use reqwest::{
    header::{CONTENT_TYPE, LOCATION},
    Url,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, HashMap},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;
use warp::{hyper::StatusCode, reply::Response, Filter, Reply};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddTaskRequest {
    task_id: String,
    leader: Url,
    vdaf: VdafObject,
    collector_authentication_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AddTaskResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
    collector_hpke_config: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectStartRequest {
    task_id: String,
    agg_param: String,
    batch_interval_start: u64,
    batch_interval_duration: u64,
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

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum AggregationResult {
    Number(u64),
    NumberArray(Vec<u64>),
}

#[derive(Debug, Serialize)]
struct CollectPollResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    result: Option<AggregationResult>,
}

struct TaskState {
    private_key: HpkePrivateKey,
    hpke_config: HpkeConfig,
    leader_url: Url,
    vdaf: VdafObject,
    auth_token: String,
}

/// A collect job handle.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Handle(String);

impl Handle {
    fn generate() -> Handle {
        let randomness = rand::random::<[u8; 32]>();
        Handle(base64::encode_config(randomness, URL_SAFE_NO_PAD))
    }
}

struct CollectJobState {
    task_id: TaskId,
    url: Url,
    batch_interval: Interval,
    agg_param: Vec<u8>,
}

async fn handle_add_task(
    tasks: &Mutex<HashMap<TaskId, TaskState>>,
    keyring: &Mutex<HpkeConfigRegistry>,
    request: AddTaskRequest,
) -> anyhow::Result<HpkeConfig> {
    let task_id_bytes = base64::decode_config(request.task_id, base64::URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"taskId\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;

    let mut tasks_guard = tasks.lock().await;
    let entry = tasks_guard.entry(task_id);
    if let Entry::Occupied(_) = &entry {
        return Err(anyhow::anyhow!("cannot add a task with a duplicate ID"));
    }

    let (hpke_config, private_key) = keyring.lock().await.get_random_keypair();

    entry.or_insert(TaskState {
        private_key,
        hpke_config: hpke_config.clone(),
        leader_url: request.leader,
        vdaf: request.vdaf,
        auth_token: request.collector_authentication_token,
    });

    Ok(hpke_config)
}

async fn handle_collect_start(
    http_client: &reqwest::Client,
    tasks: &Mutex<HashMap<TaskId, TaskState>>,
    collect_jobs: &Mutex<HashMap<Handle, CollectJobState>>,
    request: CollectStartRequest,
) -> anyhow::Result<Handle> {
    let task_id_bytes = base64::decode_config(request.task_id, URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"taskId\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;
    let agg_param = base64::decode_config(request.agg_param, URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"aggParam\"")?;
    let batch_interval = Interval::new(
        Time::from_seconds_since_epoch(request.batch_interval_start),
        Duration::from_seconds(request.batch_interval_duration),
    )
    .context("invalid batch interval specification")?;

    let dap_collect_request = CollectReq {
        task_id,
        batch_interval,
        agg_param: agg_param.clone(),
    };

    let tasks_guard = tasks.lock().await;
    let task_state = tasks_guard
        .get(&task_id)
        .context("task was not added before being used in a collect request")?;

    let response = http_client
        .post(task_state.leader_url.join("collect")?)
        .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
        .header(DAP_AUTH_HEADER, &task_state.auth_token)
        .body(dap_collect_request.get_encoded())
        .send()
        .await
        .context("error sending collect request to the leader")?;
    let status = response.status();
    if status != StatusCode::SEE_OTHER {
        return Err(anyhow::anyhow!(format!(
            "collect request got status code {}",
            status,
        )));
    }
    let collect_job_url = Url::parse(
        response
            .headers()
            .get(LOCATION)
            .context("response to collect request did not include a Location header")?
            .to_str()
            .context("collect response Location header contained invalid characters")?,
    )
    .context("collect response Location header contained an invalid URL")?;

    let mut collect_jobs_guard = collect_jobs.lock().await;
    let handle = loop {
        let handle = Handle::generate();
        match collect_jobs_guard.entry(handle.clone()) {
            Entry::Occupied(_) => continue,
            entry @ Entry::Vacant(_) => {
                entry.or_insert(CollectJobState {
                    task_id,
                    url: collect_job_url,
                    batch_interval,
                    agg_param,
                });
                break handle;
            }
        }
    };

    Ok(handle)
}

async fn handle_collect_poll(
    http_client: &reqwest::Client,
    tasks: &Mutex<HashMap<TaskId, TaskState>>,
    collect_jobs: &Mutex<HashMap<Handle, CollectJobState>>,
    request: CollectPollRequest,
) -> anyhow::Result<Option<AggregationResult>> {
    let tasks_guard = tasks.lock().await;
    let collect_jobs_guard = collect_jobs.lock().await;
    let collect_job_state = collect_jobs_guard
        .get(&Handle(request.handle))
        .context("did not recognize handle in collect_poll request")?;
    let task_id = collect_job_state.task_id;
    let task_state = tasks_guard
        .get(&task_id)
        .context("could not look up task information while polling")?;

    let response = http_client
        .get(collect_job_state.url.clone())
        .header(DAP_AUTH_HEADER, &task_state.auth_token)
        .send()
        .await
        .context("error fetching collect job from leader")?;
    let status = response.status();
    if status == StatusCode::ACCEPTED {
        return Ok(None);
    } else if status != StatusCode::OK {
        return Err(anyhow::anyhow!(format!(
            "collect job fetch got status code {}",
            status
        )));
    }

    let dap_collect_response = CollectResp::get_decoded(
        &response
            .bytes()
            .await
            .context("error reading collect response")?,
    )
    .context("could not decode collect response")?;

    if dap_collect_response.encrypted_agg_shares.len() != 2 {
        return Err(anyhow::anyhow!(
            "collect response does not have two ciphertexts"
        ));
    }
    let associated_data =
        associated_data_for_aggregate_share(task_id, collect_job_state.batch_interval);
    let leader_aggregate_share_bytes = hpke::open(
        &task_state.hpke_config,
        &task_state.private_key,
        &HpkeApplicationInfo::new(Label::AggregateShare, Role::Leader, Role::Collector),
        &dap_collect_response.encrypted_agg_shares[0],
        &associated_data,
    )
    .context("could not decrypt aggregate share from the leader")?;
    let helper_aggregate_share_bytes = hpke::open(
        &task_state.hpke_config,
        &task_state.private_key,
        &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
        &dap_collect_response.encrypted_agg_shares[1],
        &associated_data,
    )
    .context("could not decrypt aggregate share from the helper")?;

    match task_state.vdaf {
        VdafObject::Prio3Aes128Count {} => {
            let leader_aggregate_share =
                AggregateShare::<Field64>::try_from(leader_aggregate_share_bytes.as_ref())
                    .context("could not decode leader's aggregate share")?;
            let helper_aggregate_share =
                AggregateShare::<Field64>::try_from(helper_aggregate_share_bytes.as_ref())
                    .context("could not decode helper's aggregate share")?;
            <Prio3Aes128Count as Vdaf>::AggregationParam::get_decoded(&collect_job_state.agg_param)
                .context("could not decode aggregation parameter")?;
            let vdaf =
                Prio3::new_aes128_count(2).context("failed to construct Prio3Aes128Count VDAF")?;
            let aggregate_result = vdaf
                .unshard(&(), [leader_aggregate_share, helper_aggregate_share])
                .context("could not unshard aggregate result")?;
            Ok(Some(AggregationResult::Number(aggregate_result)))
        }
        VdafObject::Prio3Aes128Sum { bits } => {
            let leader_aggregate_share =
                AggregateShare::<Field128>::try_from(leader_aggregate_share_bytes.as_ref())
                    .context("could not decode leader's aggregate share")?;
            let helper_aggregate_share =
                AggregateShare::<Field128>::try_from(helper_aggregate_share_bytes.as_ref())
                    .context("could not decode helper's aggregate share")?;
            <Prio3Aes128Sum as Vdaf>::AggregationParam::get_decoded(&collect_job_state.agg_param)
                .context("could not decode aggregation parameter")?;
            let vdaf = Prio3::new_aes128_sum(2, bits)
                .context("failed to construct Prio3Aes128Sum VDAF")?;
            let aggregate_result = vdaf
                .unshard(&(), [leader_aggregate_share, helper_aggregate_share])
                .context("could not unshard aggregate result")?;
            Ok(Some(AggregationResult::Number(
                aggregate_result
                    .try_into()
                    .context("aggregate result was too large to represent natively in JSON")?,
            )))
        }
        VdafObject::Prio3Aes128Histogram { ref buckets } => {
            let leader_aggregate_share =
                AggregateShare::<Field128>::try_from(leader_aggregate_share_bytes.as_ref())
                    .context("could not decode leader's aggregate share")?;
            let helper_aggregate_share =
                AggregateShare::<Field128>::try_from(helper_aggregate_share_bytes.as_ref())
                    .context("could not decode helper's aggregate share")?;
            <Prio3Aes128Histogram as Vdaf>::AggregationParam::get_decoded(
                &collect_job_state.agg_param,
            )
            .context("could not decode aggregation parameter")?;
            let vdaf = Prio3::new_aes128_histogram(2, buckets)
                .context("failed to construct Prio3Aes128Histogram VDAF")?;
            let aggregate_result = vdaf
                .unshard(&(), [leader_aggregate_share, helper_aggregate_share])
                .context("could not unshard aggregate result")?;
            let converted = aggregate_result
                .into_iter()
                .map(|counter| {
                    u64::try_from(counter).context(
                        "entry in aggregate result was too large to represent natively in JSON",
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(AggregationResult::NumberArray(converted)))
        }
    }
}

fn make_filter() -> anyhow::Result<impl Filter<Extract = (Response,)> + Clone> {
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let tasks: Arc<Mutex<HashMap<TaskId, TaskState>>> = Arc::new(Mutex::new(HashMap::new()));
    let collect_jobs: Arc<Mutex<HashMap<Handle, CollectJobState>>> =
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
                        collector_hpke_config: Some(base64::encode_config(
                            collector_hpke_config.get_encoded(),
                            URL_SAFE_NO_PAD,
                        )),
                    },
                    Err(e) => AddTaskResponse {
                        status: ERROR,
                        error: Some(format!("{:?}", e)),
                        collector_hpke_config: None,
                    },
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                    .into_response()
            }
        }
    });
    let collect_start_filter =
        warp::path!("collect_start").and(warp::body::json()).then({
            let http_client = http_client.clone();
            let tasks = Arc::clone(&tasks);
            let collect_jobs = Arc::clone(&collect_jobs);
            move |request: CollectStartRequest| {
                let http_client = http_client.clone();
                let tasks = Arc::clone(&tasks);
                let collect_jobs = Arc::clone(&collect_jobs);
                async move {
                    let response =
                        match handle_collect_start(&http_client, &tasks, &collect_jobs, request)
                            .await
                        {
                            Ok(handle) => CollectStartResponse {
                                status: SUCCESS,
                                error: None,
                                handle: Some(handle.0),
                            },
                            Err(e) => CollectStartResponse {
                                status: ERROR,
                                error: Some(format!("{:?}", e)),
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
            let http_client = http_client.clone();
            let tasks = Arc::clone(&tasks);
            let collect_jobs = Arc::clone(&collect_jobs);
            async move {
                let response =
                    match handle_collect_poll(&http_client, &tasks, &collect_jobs, request).await {
                        Ok(Some(result)) => CollectPollResponse {
                            status: COMPLETE,
                            error: None,
                            result: Some(result),
                        },
                        Ok(None) => CollectPollResponse {
                            status: IN_PROGRESS,
                            error: None,
                            result: None,
                        },
                        Err(e) => CollectPollResponse {
                            status: ERROR,
                            error: Some(format!("{:?}", e)),
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

fn app() -> clap::Command<'static> {
    Command::new("Janus interoperation test collector").arg(
        Arg::new("port")
            .long("port")
            .short('p')
            .default_value("8080")
            .help("Port number to listen on."),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;
    let matches = app().get_matches();
    let port = matches.value_of_t::<u16>("port")?;
    let filter = make_filter()?;
    let server = warp::serve(filter);
    server
        .bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
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
