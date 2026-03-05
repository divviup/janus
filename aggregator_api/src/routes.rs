use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
};

use anyhow::Context;
use aws_lc_rs::digest::{SHA256, digest};
use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::TimeDelta;
use http::StatusCode;
use janus_aggregator_core::{
    SecretBytes,
    datastore::{
        self,
        task_counters::{TaskAggregationCounter, TaskUploadCounter},
    },
    task::{AggregatorTask, AggregatorTaskParameters},
    taskprov::PeerAggregator,
};
use janus_core::{
    auth_tokens::AuthenticationTokenHash,
    hpke::HpkeKeypair,
    time::{Clock, TimeDeltaExt},
};
use janus_messages::{
    Duration, HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId, Role, TaskId,
    batch_mode::Code as SupportedBatchMode,
};
use rand::random;
use serde::Deserialize;

use crate::{
    ApiState, Error, git_revision,
    models::{
        AggregatorApiConfig, AggregatorRole, DeleteTaskprovPeerAggregatorReq,
        GetTaskAggregationMetricsResp, GetTaskIdsResp, GetTaskUploadMetricsResp, HpkeConfigResp,
        PatchHpkeConfigReq, PatchTaskReq, PostTaskReq, PostTaskprovPeerAggregatorReq,
        PutHpkeConfigReq, SupportedVdaf, TaskResp, TaskprovPeerAggregatorResp,
    },
    parse_hpke_config_id_param, parse_task_id_param,
};

#[derive(Deserialize)]
pub(super) struct PaginationQuery {
    pagination_token: Option<String>,
}

pub(super) async fn get_config<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
) -> Json<AggregatorApiConfig> {
    static VERSION: LazyLock<String> =
        LazyLock::new(|| format!("{}-{}", env!("CARGO_PKG_VERSION"), git_revision()));

    Json(AggregatorApiConfig {
        protocol: "DAP-16",
        dap_url: state.cfg.public_dap_url.clone(),
        role: AggregatorRole::Either,
        vdafs: Vec::from([
            SupportedVdaf::Prio3Count,
            SupportedVdaf::Prio3Sum,
            SupportedVdaf::Prio3Histogram,
            SupportedVdaf::Prio3SumVec,
        ]),
        batch_modes: Vec::from([
            SupportedBatchMode::TimeInterval,
            SupportedBatchMode::LeaderSelected,
        ]),
        features: &[
            "TokenHash",
            "UploadMetrics",
            "TimeBucketedLeaderSelected",
            "PureDpDiscreteLaplace",
            "AggregationJobMetrics",
        ],
        software_name: "Janus",
        software_version: &VERSION,
    })
}

pub(super) async fn get_task_ids<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<GetTaskIdsResp>, Error> {
    let lower_bound = query
        .pagination_token
        .map(|v| TaskId::from_str(&v))
        .transpose()
        .context("Couldn't parse pagination_token")
        .map_err(|err| Error::BadRequest(err.into()))?;

    let task_ids = state
        .ds
        .run_tx("get_task_ids", |tx| {
            Box::pin(async move { tx.get_task_ids(lower_bound).await })
        })
        .await?;
    let pagination_token = task_ids.last().cloned();

    Ok(Json(GetTaskIdsResp {
        task_ids,
        pagination_token,
    }))
}

pub(super) async fn post_task<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Json(req): Json<PostTaskReq>,
) -> Result<Json<TaskResp>, Error> {
    if !matches!(req.role, Role::Leader | Role::Helper) {
        return Err(Error::BadRequest(
            format!("invalid role {}", req.role).into(),
        ));
    }

    let vdaf_verify_key_bytes = URL_SAFE_NO_PAD
        .decode(&req.vdaf_verify_key)
        .context("Invalid base64 value for vdaf_verify_key")
        .map_err(|err| Error::BadRequest(err.into()))?;
    if vdaf_verify_key_bytes.len() != req.vdaf.verify_key_length() {
        return Err(Error::BadRequest(
            format!(
                "Wrong VDAF verify key length, expected {}, got {}",
                req.vdaf.verify_key_length(),
                vdaf_verify_key_bytes.len()
            )
            .into(),
        ));
    }

    let task_id = TaskId::try_from(digest(&SHA256, &vdaf_verify_key_bytes).as_ref())
        .map_err(|err| Error::Internal(err.into()))?;

    let vdaf_verify_key = SecretBytes::new(vdaf_verify_key_bytes);

    let (aggregator_auth_token, aggregator_parameters) = match req.role {
        Role::Leader => {
            let aggregator_auth_token = req.aggregator_auth_token.ok_or_else(|| {
                Error::BadRequest(
                    "aggregator acting in leader role must be provided an aggregator auth token"
                        .into(),
                )
            })?;
            let collector_auth_token_hash = req.collector_auth_token_hash.ok_or_else(|| {
                Error::BadRequest(
                    "aggregator acting in leader role must be provided a collector auth token hash"
                        .into(),
                )
            })?;
            (
                None,
                AggregatorTaskParameters::Leader {
                    aggregator_auth_token,
                    collector_auth_token_hash,
                    collector_hpke_config: req.collector_hpke_config,
                },
            )
        }

        Role::Helper => {
            if req.aggregator_auth_token.is_some() {
                return Err(Error::BadRequest(
                    "aggregator acting in helper role cannot be given an aggregator auth token"
                        .into(),
                ));
            }

            let aggregator_auth_token = random();
            let aggregator_auth_token_hash = AuthenticationTokenHash::from(&aggregator_auth_token);
            (
                Some(aggregator_auth_token),
                AggregatorTaskParameters::Helper {
                    aggregator_auth_token_hash,
                    collector_hpke_config: req.collector_hpke_config,
                    aggregation_mode: req.aggregation_mode.ok_or_else(|| {
                        Error::BadRequest(
                            "aggregator acting in helper role must be provided an aggregation mode"
                                .into(),
                        )
                    })?,
                },
            )
        }

        _ => unreachable!(),
    };

    let task = Arc::new(
        AggregatorTask::new(
            task_id,
            req.peer_aggregator_endpoint,
            req.batch_mode,
            req.vdaf,
            vdaf_verify_key,
            req.task_start,
            req.task_end,
            Some(Duration::from_seconds(
                3600 * 24 * 7 * 2,
                &req.time_precision,
            )),
            req.min_batch_size,
            req.time_precision,
            Duration::ONE,
            aggregator_parameters,
        )
        .context("Error constructing task")
        .map_err(|err| Error::BadRequest(err.into()))?,
    );

    state
        .ds
        .run_tx("post_task", |tx| {
            let task = Arc::clone(&task);
            Box::pin(async move {
                if let Some(existing_task) = tx.get_aggregator_task(task.id()).await? {
                    if existing_task.peer_aggregator_endpoint() == task.peer_aggregator_endpoint()
                        && existing_task.batch_mode() == task.batch_mode()
                        && existing_task.vdaf() == task.vdaf()
                        && existing_task.opaque_vdaf_verify_key() == task.opaque_vdaf_verify_key()
                        && existing_task.role() == task.role()
                        && existing_task.task_start() == task.task_start()
                        && existing_task.task_end() == task.task_end()
                        && existing_task.min_batch_size() == task.min_batch_size()
                        && existing_task.time_precision() == task.time_precision()
                        && existing_task.tolerable_clock_skew() == task.tolerable_clock_skew()
                        && existing_task.collector_hpke_config() == task.collector_hpke_config()
                    {
                        return Ok(());
                    }

                    let err = Error::Conflict(
                        "task with same VDAF verify key and task ID already exists with different parameters".to_string(),
                    );
                    return Err(datastore::Error::User(err.into()));
                }

                tx.put_aggregator_task(&task).await
            })
        })
        .await?;

    let mut task_resp =
        TaskResp::try_from(task.as_ref()).map_err(|err| Error::Internal(err.into()))?;

    task_resp.aggregator_auth_token = aggregator_auth_token;

    Ok(Json(task_resp))
}

pub(super) async fn get_task<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskResp>, Error> {
    let task_id = parse_task_id_param(&task_id)?;

    let task = state
        .ds
        .run_tx("get_task", |tx| {
            Box::pin(async move { tx.get_aggregator_task(&task_id).await })
        })
        .await?
        .ok_or(Error::NotFound)?;

    Ok(Json(
        TaskResp::try_from(&task).map_err(|err| Error::Internal(err.into()))?,
    ))
}

pub(super) async fn delete_task<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(task_id): Path<String>,
) -> Result<StatusCode, Error> {
    let task_id = parse_task_id_param(&task_id)?;
    match state
        .ds
        .run_tx("delete_task", |tx| {
            Box::pin(async move { tx.delete_task(&task_id).await })
        })
        .await
    {
        Ok(_) | Err(datastore::Error::MutationTargetNotFound) => Ok(StatusCode::NO_CONTENT),
        Err(err) => Err(err.into()),
    }
}

pub(super) async fn patch_task<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(task_id): Path<String>,
    Json(req): Json<PatchTaskReq>,
) -> Result<Json<TaskResp>, Error> {
    let task_id = parse_task_id_param(&task_id)?;
    let task = state
        .ds
        .run_tx("patch_task", |tx| {
            Box::pin(async move {
                if let Some(task_end) = req.task_end {
                    tx.update_task_end(&task_id, task_end.as_ref()).await?;
                }
                tx.get_aggregator_task(&task_id).await
            })
        })
        .await?
        .ok_or(Error::NotFound)?;

    Ok(Json(
        TaskResp::try_from(&task).map_err(|err| Error::Internal(err.into()))?,
    ))
}

pub(super) async fn get_task_upload_metrics<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(task_id): Path<String>,
) -> Result<Json<GetTaskUploadMetricsResp>, Error> {
    let task_id = parse_task_id_param(&task_id)?;
    Ok(Json(GetTaskUploadMetricsResp(
        state
            .ds
            .run_tx("get_task_upload_metrics", |tx| {
                Box::pin(async move { TaskUploadCounter::load(tx, &task_id).await })
            })
            .await?
            .ok_or(Error::NotFound)?,
    )))
}

pub(super) async fn get_task_aggregation_metrics<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(task_id): Path<String>,
) -> Result<Json<GetTaskAggregationMetricsResp>, Error> {
    let task_id = parse_task_id_param(&task_id)?;
    Ok(Json(GetTaskAggregationMetricsResp(
        state
            .ds
            .run_tx("get_task_aggregation_metrics", |tx| {
                Box::pin(async move { TaskAggregationCounter::load(tx, &task_id).await })
            })
            .await?
            .ok_or(Error::NotFound)?,
    )))
}

pub(super) async fn get_hpke_configs<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
) -> Result<Json<Vec<HpkeConfigResp>>, Error> {
    Ok(Json(
        state
            .ds
            .run_tx("get_hpke_configs", |tx| {
                Box::pin(async move { tx.get_hpke_keypairs().await })
            })
            .await?
            .into_iter()
            .map(HpkeConfigResp::from)
            .collect::<Vec<_>>(),
    ))
}

pub(super) async fn get_hpke_config<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(config_id): Path<String>,
) -> Result<Json<HpkeConfigResp>, Error> {
    let config_id = parse_hpke_config_id_param(&config_id)?;
    Ok(Json(HpkeConfigResp::from(
        state
            .ds
            .run_tx("get_hpke_config", |tx| {
                Box::pin(async move { tx.get_hpke_keypair(&config_id).await })
            })
            .await?
            .ok_or(Error::NotFound)?,
    )))
}

pub(super) async fn put_hpke_config<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Json(req): Json<PutHpkeConfigReq>,
) -> Result<impl IntoResponse, Error> {
    let existing_keypairs = state
        .ds
        .run_tx("put_hpke_config_determine_id", |tx| {
            Box::pin(async move { tx.get_hpke_keypairs().await })
        })
        .await?
        .iter()
        .map(|keypair| u8::from(*keypair.hpke_keypair().config().id()))
        .collect::<Vec<_>>();

    let config_id = HpkeConfigId::from(
        (0..=u8::MAX)
            .find(|i| !existing_keypairs.contains(i))
            .ok_or_else(|| {
                Error::Conflict("All possible IDs for HPKE keys have been taken".to_string())
            })?,
    );
    let keypair = HpkeKeypair::generate(
        config_id,
        req.kem_id.unwrap_or(HpkeKemId::X25519HkdfSha256),
        req.kdf_id.unwrap_or(HpkeKdfId::HkdfSha256),
        req.aead_id.unwrap_or(HpkeAeadId::Aes128Gcm),
    )?;

    let inserted_keypair = state
        .ds
        .run_tx("put_hpke_config", |tx| {
            let keypair = keypair.clone();
            Box::pin(async move {
                tx.put_hpke_keypair(&keypair).await?;
                tx.get_hpke_keypair(&config_id).await
            })
        })
        .await?
        .ok_or_else(|| Error::Internal("Newly inserted key disappeared".into()))?;

    Ok((
        StatusCode::CREATED,
        Json(HpkeConfigResp::from(inserted_keypair)),
    ))
}

pub(super) async fn patch_hpke_config<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(config_id): Path<String>,
    Json(req): Json<PatchHpkeConfigReq>,
) -> Result<StatusCode, Error> {
    let config_id = parse_hpke_config_id_param(&config_id)?;

    state
        .ds
        .run_tx("patch_hpke_keypair", |tx| {
            Box::pin(async move { tx.set_hpke_keypair_state(&config_id, &req.state).await })
        })
        .await?;

    Ok(StatusCode::OK)
}

pub(super) async fn delete_hpke_config<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Path(config_id): Path<String>,
) -> Result<StatusCode, Error> {
    let config_id = parse_hpke_config_id_param(&config_id)?;
    match state
        .ds
        .run_tx("delete_hpke_config", |tx| {
            Box::pin(async move { tx.delete_hpke_keypair(&config_id).await })
        })
        .await
    {
        Ok(_) | Err(datastore::Error::MutationTargetNotFound) => Ok(StatusCode::NO_CONTENT),
        Err(err) => Err(err.into()),
    }
}

pub(super) async fn get_taskprov_peer_aggregators<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
) -> Result<Json<Vec<TaskprovPeerAggregatorResp>>, Error> {
    Ok(Json(
        state
            .ds
            .run_tx("get_taskprov_peer_aggregators", |tx| {
                Box::pin(async move { tx.get_taskprov_peer_aggregators().await })
            })
            .await?
            .into_iter()
            .map(TaskprovPeerAggregatorResp::from)
            .collect::<Vec<_>>(),
    ))
}

pub(super) async fn post_taskprov_peer_aggregator<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Json(req): Json<PostTaskprovPeerAggregatorReq>,
) -> Result<impl IntoResponse, Error> {
    let to_insert = PeerAggregator::new(
        req.endpoint,
        req.peer_role,
        req.aggregation_mode,
        req.verify_key_init,
        req.collector_hpke_config,
        req.report_expiry_age
            .map(|d| TimeDelta::try_seconds_unsigned(d).map_err(|e| Error::BadRequest(e.into())))
            .transpose()?,
        req.aggregator_auth_tokens,
        req.collector_auth_tokens,
    )
    .context("Invalid request")
    .map_err(|e| Error::BadRequest(e.into()))?;

    let inserted = state
        .ds
        .run_tx("post_taskprov_peer_aggregator", |tx| {
            let to_insert = to_insert.clone();
            Box::pin(async move {
                tx.put_taskprov_peer_aggregator(&to_insert).await?;
                tx.get_taskprov_peer_aggregator(to_insert.endpoint(), to_insert.peer_role())
                    .await
            })
        })
        .await?
        .map(TaskprovPeerAggregatorResp::from)
        .ok_or_else(|| Error::Internal("Newly inserted peer aggregator disappeared".into()))?;

    Ok((StatusCode::CREATED, Json(inserted)))
}

pub(super) async fn delete_taskprov_peer_aggregator<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    Json(req): Json<DeleteTaskprovPeerAggregatorReq>,
) -> Result<StatusCode, Error> {
    let res = state
        .ds
        .run_tx("delete_taskprov_peer_aggregator", |tx| {
            let req = req.clone();
            Box::pin(async move {
                tx.delete_taskprov_peer_aggregator(&req.endpoint, &req.peer_role)
                    .await
            })
        })
        .await;
    match res {
        Ok(_) | Err(datastore::Error::MutationTargetNotFound) => Ok(StatusCode::NO_CONTENT),
        Err(err) => Err(err.into()),
    }
}
