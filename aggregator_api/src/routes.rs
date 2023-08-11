use crate::{
    models::{
        AggregatorApiConfig, AggregatorRole, GetTaskIdsResp, GetTaskMetricsResp,
        GlobalHpkeConfigResp, PatchGlobalHpkeConfigReq, PostTaskReq, PutGlobalHpkeConfigReq,
        SupportedVdaf, TaskResp,
    },
    Config, ConnExt, Error,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator_core::{
    datastore::{self, Datastore},
    task::Task,
    SecretBytes,
};
use janus_core::{hpke::generate_hpke_config_and_private_key, time::Clock};
use janus_messages::HpkeConfigId;
use janus_messages::{
    query_type::Code as SupportedQueryType, Duration, HpkeAeadId, HpkeKdfId, HpkeKemId, Role,
    TaskId,
};
use querystring::querify;
use rand::random;
use ring::digest::{digest, SHA256};
use std::{str::FromStr, sync::Arc, unreachable};
use tracing::{error, warn};
use trillium::{Conn, Handler, Status};
use trillium_api::{Halt, Json, State};

use url::Url;

pub(super) async fn get_config(
    _: &mut Conn,
    State(config): State<Arc<Config>>,
) -> Json<AggregatorApiConfig> {
    Json(AggregatorApiConfig {
        dap_url: config.public_dap_url.clone(),
        role: AggregatorRole::Either,
        vdafs: vec![
            SupportedVdaf::Prio3Count,
            SupportedVdaf::Prio3Sum,
            SupportedVdaf::Prio3Histogram,
            SupportedVdaf::Prio3CountVec,
            SupportedVdaf::Prio3SumVec,
        ],
        query_types: vec![
            SupportedQueryType::TimeInterval,
            SupportedQueryType::FixedSize,
        ],
    })
}

pub(super) async fn get_task_ids<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<impl Handler, Status> {
    const PAGINATION_TOKEN_KEY: &str = "pagination_token";
    let lower_bound = querify(conn.querystring())
        .into_iter()
        .find(|&(k, _)| k == PAGINATION_TOKEN_KEY)
        .map(|(_, v)| TaskId::from_str(v))
        .transpose()
        .map_err(|err| {
            warn!(err = ?err, "Couldn't parse pagination_token");
            Status::BadRequest
        })?;

    let task_ids = ds
        .run_tx_with_name("get_task_ids", |tx| {
            Box::pin(async move { tx.get_task_ids(lower_bound).await })
        })
        .await
        .map_err(|err| {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        })?;
    let pagination_token = task_ids.last().cloned();

    Ok((
        Json(GetTaskIdsResp {
            task_ids,
            pagination_token,
        }),
        Halt,
    ))
}

pub(super) async fn post_task<C: Clock>(
    _: &mut Conn,
    (State(ds), Json(req)): (State<Arc<Datastore<C>>>, Json<PostTaskReq>),
) -> Result<impl Handler, Error> {
    // We have to resolve impedance mismatches between the aggregator API's view of a task and
    // `aggregator_core::task::Task`. For now, we deal with this in code, but someday the two
    // representations will be harmonized.
    // https://github.com/divviup/janus/issues/1524

    if !matches!(req.role, Role::Leader | Role::Helper) {
        return Err(Error::new(
            format!("invalid role {}", req.role),
            Status::BadRequest,
        ));
    }

    // struct `aggregator_core::task::Task` expects to get two aggregator endpoint URLs, but only
    // the one for the peer aggregator is in the incoming request (or for that matter, is ever used
    // by Janus), so we insert a fake URL for "self".
    // TODO(#1524): clean this up with `aggregator_core::task::Task` changes
    // unwrap safety: this fake URL is valid
    let fake_aggregator_url = Url::parse("http://never-used.example.com").unwrap();
    let aggregator_endpoints = match req.role {
        Role::Leader => Vec::from([fake_aggregator_url, req.peer_aggregator_endpoint]),
        Role::Helper => Vec::from([req.peer_aggregator_endpoint, fake_aggregator_url]),
        _ => unreachable!(),
    };

    let vdaf_verify_key_bytes = URL_SAFE_NO_PAD
        .decode(&req.vdaf_verify_key)
        .map_err(|err| {
            Error::new(
                format!("Invalid base64 value for vdaf_verify_key: {err}"),
                Status::BadRequest,
            )
        })?;
    if vdaf_verify_key_bytes.len() != req.vdaf.verify_key_length() {
        return Err(Error::new(
            format!(
                "Wrong VDAF verify key length, expected {}, got {}",
                req.vdaf.verify_key_length(),
                vdaf_verify_key_bytes.len()
            ),
            Status::BadRequest,
        ));
    }

    // DAP recommends deriving the task ID from the VDAF verify key. We deterministically obtain a
    // 32 byte task ID by taking SHA-256(VDAF verify key).
    // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-04#name-verification-key-requiremen
    let task_id = TaskId::try_from(digest(&SHA256, &vdaf_verify_key_bytes).as_ref())
        .map_err(|err| Error::new(err.to_string(), Status::InternalServerError))?;

    let vdaf_verify_keys = Vec::from([SecretBytes::new(vdaf_verify_key_bytes)]);

    let (aggregator_auth_tokens, collector_auth_tokens) = match req.role {
        Role::Leader => {
            let aggregator_auth_token = req.aggregator_auth_token.ok_or_else(|| {
                Error::new(
                    "aggregator acting in leader role must be provided an aggregator auth token"
                        .to_string(),
                    Status::BadRequest,
                )
            })?;
            (Vec::from([aggregator_auth_token]), Vec::from([random()]))
        }

        Role::Helper => {
            if req.aggregator_auth_token.is_some() {
                return Err(Error::new(
                    "aggregator acting in helper role cannot be given an aggregator auth token"
                        .to_string(),
                    Status::BadRequest,
                ));
            }

            (Vec::from([random()]), Vec::new())
        }

        _ => unreachable!(),
    };

    let hpke_keys = Vec::from([generate_hpke_config_and_private_key(
        random(),
        HpkeKemId::X25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    )]);

    let task = Arc::new(
        Task::new(
            task_id,
            aggregator_endpoints,
            /* query_type */ req.query_type,
            /* vdaf */ req.vdaf,
            /* role */ req.role,
            vdaf_verify_keys,
            /* max_batch_query_count */ req.max_batch_query_count,
            /* task_expiration */ req.task_expiration,
            /* report_expiry_age */
            Some(Duration::from_seconds(3600 * 24 * 7 * 2)), // 2 weeks
            /* min_batch_size */ req.min_batch_size,
            /* time_precision */ req.time_precision,
            /* tolerable_clock_skew */
            Duration::from_seconds(60), // 1 minute,
            /* collector_hpke_config */ req.collector_hpke_config,
            aggregator_auth_tokens,
            collector_auth_tokens,
            hpke_keys,
        )
        .map_err(|err| {
            Error::new(
                format!("Error constructing task: {err}"),
                Status::BadRequest,
            )
        })?,
    );

    ds.run_tx_with_name("post_task", |tx| {
        let task = Arc::clone(&task);
        Box::pin(async move {
            if let Some(existing_task) = tx.get_task(task.id()).await? {
            // Check whether the existing task in the DB corresponds to the incoming task, ignoring
            // those fields that are randomly generated.
            if existing_task.aggregator_endpoints() == task.aggregator_endpoints()
                && existing_task.query_type() == task.query_type()
                && existing_task.vdaf() == task.vdaf()
                && existing_task.vdaf_verify_keys() == task.vdaf_verify_keys()
                && existing_task.role() == task.role()
                && existing_task.max_batch_query_count() == task.max_batch_query_count()
                && existing_task.task_expiration() == task.task_expiration()
                && existing_task.min_batch_size() == task.min_batch_size()
                && existing_task.time_precision() == task.time_precision()
                && existing_task.collector_hpke_config() == task.collector_hpke_config() {
                    return Ok(())
                }

                let err = Error::new(
                    "task with same VDAF verify key and task ID already exists with different parameters".to_string(),
                    Status::Conflict,
                );
                return Err(datastore::Error::User(err.into()));
            }

            tx.put_task(&task).await
        })
    })
    .await
    .map_err(|err| {
        match err {
            datastore::Error::User(user_err) if user_err.is::<Error>() => {
                // unwrap safety: we checked if the downcast is valid in the guard
                *user_err.downcast::<Error>().unwrap()
            }
            _ => {
                error!(err = %err, "Database transaction error");
                Error::new(
                    "Error storing task".to_string(),
                    Status::InternalServerError,
                )
            }
        }

    })?;

    Ok(Json(TaskResp::try_from(task.as_ref()).map_err(|err| {
        Error::new(err.to_string(), Status::InternalServerError)
    })?))
}

pub(super) async fn get_task<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<impl Handler, Status> {
    let task_id = conn.task_id_param()?;

    let task = ds
        .run_tx_with_name("get_task", |tx| {
            Box::pin(async move { tx.get_task(&task_id).await })
        })
        .await
        .map_err(|err| {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        })?
        .ok_or(Status::NotFound)?;

    Ok(Json(TaskResp::try_from(&task).map_err(|err| {
        error!(err = %err, "Error converting task to TaskResp");
        Status::InternalServerError
    })?))
}

pub(super) async fn delete_task<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<impl Handler, Status> {
    let task_id = conn.task_id_param()?;

    ds.run_tx_with_name("delete_task", |tx| {
        Box::pin(async move { tx.delete_task(&task_id).await })
    })
    .await
    .map_err(|err| match err {
        datastore::Error::MutationTargetNotFound => Status::NotFound,
        _ => {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        }
    })?;

    Ok(Status::NoContent)
}

pub(super) async fn get_task_metrics<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<impl Handler, Status> {
    let task_id = conn.task_id_param()?;

    let (reports, report_aggregations) = ds
        .run_tx_with_name("get_task_metrics", |tx| {
            Box::pin(async move { tx.get_task_metrics(&task_id).await })
        })
        .await
        .map_err(|err| {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        })?
        .ok_or(Status::NotFound)?;

    Ok(Json(GetTaskMetricsResp {
        reports,
        report_aggregations,
    }))
}

pub(super) async fn get_global_hpke_configs<C: Clock>(
    _: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Json<Vec<GlobalHpkeConfigResp>>, Status> {
    Ok(Json(
        ds.run_tx_with_name("get_global_hpke_configs", |tx| {
            Box::pin(async move { tx.get_global_hpke_keypairs().await })
        })
        .await
        .map_err(|err| {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        })?
        .into_iter()
        .map(GlobalHpkeConfigResp::from)
        .collect::<Vec<_>>(),
    ))
}

pub(super) async fn get_global_hpke_config<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Json<GlobalHpkeConfigResp>, Status> {
    let config_id = conn.hpke_config_id_param()?;
    Ok(Json(GlobalHpkeConfigResp::from(
        ds.run_tx_with_name("get_global_hpke_config", |tx| {
            Box::pin(async move { tx.get_global_hpke_keypair(&config_id).await })
        })
        .await
        .map_err(|err| {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        })?
        .ok_or(Status::NotFound)?,
    )))
}

pub(super) async fn put_global_hpke_config<C: Clock>(
    _: &mut Conn,
    (State(ds), Json(req)): (State<Arc<Datastore<C>>>, Json<PutGlobalHpkeConfigReq>),
) -> Result<(Status, Json<GlobalHpkeConfigResp>), Status> {
    let existing_keypairs = ds
        .run_tx_with_name("put_global_hpke_config_determine_id", |tx| {
            Box::pin(async move { tx.get_global_hpke_keypairs().await })
        })
        .await
        .map_err(|err| {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        })?
        .iter()
        .map(|keypair| u8::from(*keypair.hpke_keypair().config().id()))
        .collect::<Vec<_>>();

    let config_id = HpkeConfigId::from(
        (0..=u8::MAX)
            .find(|i| !existing_keypairs.contains(i))
            .ok_or_else(|| {
                warn!("All possible IDs for global HPKE key have been taken");
                Status::Conflict
            })?,
    );
    let keypair = generate_hpke_config_and_private_key(
        config_id,
        req.kem_id.unwrap_or(HpkeKemId::X25519HkdfSha256),
        req.kdf_id.unwrap_or(HpkeKdfId::HkdfSha256),
        req.aead_id.unwrap_or(HpkeAeadId::Aes128Gcm),
    );

    let inserted_keypair = ds
        .run_tx_with_name("put_global_hpke_config", |tx| {
            let keypair = keypair.clone();
            Box::pin(async move {
                tx.put_global_hpke_keypair(&keypair).await?;
                tx.get_global_hpke_keypair(&config_id).await
            })
        })
        .await
        .map_err(|err| {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        })?
        .ok_or_else(|| {
            error!(config_id = %config_id, "Newly inserted key disappeared");
            Status::InternalServerError
        })?;

    Ok((
        Status::Created,
        Json(GlobalHpkeConfigResp::from(inserted_keypair)),
    ))
}

pub(super) async fn patch_global_hpke_config<C: Clock>(
    conn: &mut Conn,
    (State(ds), Json(req)): (State<Arc<Datastore<C>>>, Json<PatchGlobalHpkeConfigReq>),
) -> Result<Status, Status> {
    let config_id = conn.hpke_config_id_param()?;

    ds.run_tx_with_name("patch_hpke_global_keypair", |tx| {
        let config_id = config_id;
        Box::pin(async move {
            tx.set_global_hpke_keypair_state(&config_id, &req.state)
                .await
        })
    })
    .await
    .map_err(|err| match err {
        datastore::Error::MutationTargetNotFound => Status::NotFound,
        _ => {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        }
    })?;

    Ok(Status::Ok)
}

pub(super) async fn delete_global_hpke_config<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Status, Status> {
    let config_id = conn.hpke_config_id_param()?;
    ds.run_tx_with_name("delete_global_hpke_config", |tx| {
        Box::pin(async move { tx.delete_global_hpke_keypair(&config_id).await })
    })
    .await
    .map_err(|err| match err {
        datastore::Error::MutationTargetNotFound => Status::NotFound,
        _ => {
            error!(err = %err, "Database transaction error");
            Status::InternalServerError
        }
    })?;
    Ok(Status::NoContent)
}
