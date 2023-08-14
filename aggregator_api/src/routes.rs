use crate::{
    models::{
        AggregatorApiConfig, AggregatorRole, GetTaskIdsResp, GetTaskMetricsResp,
        GlobalHpkeConfigResp, PatchGlobalHpkeConfigReq, PostTaskReq, PostTaskprovPeerAggregatorReq,
        PutGlobalHpkeConfigReq, SupportedVdaf, TaskResp, TaskprovPeerAggregatorResp,
    },
    Config, ConnExt, Error,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator_core::{
    datastore::{self, Datastore},
    task::Task,
    taskprov::PeerAggregator,
    SecretBytes,
};
use janus_core::{hpke::generate_hpke_config_and_private_key, time::Clock};
use janus_messages::HpkeConfigId;
use janus_messages::{
    query_type::Code as SupportedQueryType, Duration, HpkeAeadId, HpkeKdfId, HpkeKemId, Role,
    TaskId,
};
use rand::random;
use ring::digest::{digest, SHA256};
use std::{str::FromStr, sync::Arc, unreachable};
use trillium::{Conn, Status};
use trillium_api::{Json, State};
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
) -> Result<Json<GetTaskIdsResp>, Error> {
    const PAGINATION_TOKEN_KEY: &str = "pagination_token";
    let lower_bound = serde_urlencoded::from_str::<Vec<(String, String)>>(conn.querystring())?
        .into_iter()
        .find(|(k, _)| k == PAGINATION_TOKEN_KEY)
        .map(|(_, v)| TaskId::from_str(&v))
        .transpose()
        .map_err(|err| Error::BadRequest(format!("Couldn't parse pagination_token: {:?}", err)))?;

    let task_ids = ds
        .run_tx_with_name("get_task_ids", |tx| {
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
    _: &mut Conn,
    (State(ds), Json(req)): (State<Arc<Datastore<C>>>, Json<PostTaskReq>),
) -> Result<Json<TaskResp>, Error> {
    // We have to resolve impedance mismatches between the aggregator API's view of a task and
    // `aggregator_core::task::Task`. For now, we deal with this in code, but someday the two
    // representations will be harmonized.
    // https://github.com/divviup/janus/issues/1524

    if !matches!(req.role, Role::Leader | Role::Helper) {
        return Err(Error::BadRequest(format!("invalid role {}", req.role)));
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
            Error::BadRequest(format!("Invalid base64 value for vdaf_verify_key: {err}"))
        })?;
    if vdaf_verify_key_bytes.len() != req.vdaf.verify_key_length() {
        return Err(Error::BadRequest(format!(
            "Wrong VDAF verify key length, expected {}, got {}",
            req.vdaf.verify_key_length(),
            vdaf_verify_key_bytes.len()
        )));
    }

    // DAP recommends deriving the task ID from the VDAF verify key. We deterministically obtain a
    // 32 byte task ID by taking SHA-256(VDAF verify key).
    // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-04#name-verification-key-requiremen
    let task_id = TaskId::try_from(digest(&SHA256, &vdaf_verify_key_bytes).as_ref())
        .map_err(|err| Error::Internal(err.to_string()))?;

    let vdaf_verify_keys = Vec::from([SecretBytes::new(vdaf_verify_key_bytes)]);

    let (aggregator_auth_tokens, collector_auth_tokens) = match req.role {
        Role::Leader => {
            let aggregator_auth_token = req.aggregator_auth_token.ok_or_else(|| {
                Error::BadRequest(format!(
                    "aggregator acting in leader role must be provided an aggregator auth token"
                ))
            })?;
            (Vec::from([aggregator_auth_token]), Vec::from([random()]))
        }

        Role::Helper => {
            if req.aggregator_auth_token.is_some() {
                return Err(Error::BadRequest(format!(
                    "aggregator acting in helper role cannot be given an aggregator auth token"
                )));
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
        .map_err(|err| Error::BadRequest(format!("Error constructing task: {err}")))?,
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

                let err = Error::Conflict(
                    "task with same VDAF verify key and task ID already exists with different parameters".to_string(),
                );
                return Err(datastore::Error::User(err.into()));
            }

            tx.put_task(&task).await
        })
    })
    .await?;

    Ok(Json(
        TaskResp::try_from(task.as_ref()).map_err(|err| Error::Internal(err.to_string()))?,
    ))
}

pub(super) async fn get_task<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Json<TaskResp>, Error> {
    let task_id = conn.task_id_param()?;

    let task = ds
        .run_tx_with_name("get_task", |tx| {
            Box::pin(async move { tx.get_task(&task_id).await })
        })
        .await?
        .ok_or(Error::NotFound)?;

    Ok(Json(
        TaskResp::try_from(&task).map_err(|err| Error::Internal(err.to_string()))?,
    ))
}

pub(super) async fn delete_task<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Status, Error> {
    let task_id = conn.task_id_param()?;
    match ds
        .run_tx_with_name("delete_task", |tx| {
            Box::pin(async move { tx.delete_task(&task_id).await })
        })
        .await
    {
        Ok(_) | Err(datastore::Error::MutationTargetNotFound) => Ok(Status::NoContent),
        Err(err) => Err(err.into()),
    }
}

pub(super) async fn get_task_metrics<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Json<GetTaskMetricsResp>, Error> {
    let task_id = conn.task_id_param()?;

    let (reports, report_aggregations) = ds
        .run_tx_with_name("get_task_metrics", |tx| {
            Box::pin(async move { tx.get_task_metrics(&task_id).await })
        })
        .await?
        .ok_or(Error::NotFound)?;

    Ok(Json(GetTaskMetricsResp {
        reports,
        report_aggregations,
    }))
}

pub(super) async fn get_global_hpke_configs<C: Clock>(
    _: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Json<Vec<GlobalHpkeConfigResp>>, Error> {
    Ok(Json(
        ds.run_tx_with_name("get_global_hpke_configs", |tx| {
            Box::pin(async move { tx.get_global_hpke_keypairs().await })
        })
        .await?
        .into_iter()
        .map(GlobalHpkeConfigResp::from)
        .collect::<Vec<_>>(),
    ))
}

pub(super) async fn get_global_hpke_config<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Json<GlobalHpkeConfigResp>, Error> {
    let config_id = conn.hpke_config_id_param()?;
    Ok(Json(GlobalHpkeConfigResp::from(
        ds.run_tx_with_name("get_global_hpke_config", |tx| {
            Box::pin(async move { tx.get_global_hpke_keypair(&config_id).await })
        })
        .await?
        .ok_or(Error::NotFound)?,
    )))
}

pub(super) async fn put_global_hpke_config<C: Clock>(
    _: &mut Conn,
    (State(ds), Json(req)): (State<Arc<Datastore<C>>>, Json<PutGlobalHpkeConfigReq>),
) -> Result<(Status, Json<GlobalHpkeConfigResp>), Error> {
    let existing_keypairs = ds
        .run_tx_with_name("put_global_hpke_config_determine_id", |tx| {
            Box::pin(async move { tx.get_global_hpke_keypairs().await })
        })
        .await?
        .iter()
        .map(|keypair| u8::from(*keypair.hpke_keypair().config().id()))
        .collect::<Vec<_>>();

    let config_id = HpkeConfigId::from(
        (0..=u8::MAX)
            .find(|i| !existing_keypairs.contains(i))
            .ok_or_else(|| {
                Error::Conflict("All possible IDs for global HPKE key have been taken".to_string())
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
        .await?
        .ok_or_else(|| Error::Internal("Newly inserted key disappeared".to_string()))?;

    Ok((
        Status::Created,
        Json(GlobalHpkeConfigResp::from(inserted_keypair)),
    ))
}

pub(super) async fn patch_global_hpke_config<C: Clock>(
    conn: &mut Conn,
    (State(ds), Json(req)): (State<Arc<Datastore<C>>>, Json<PatchGlobalHpkeConfigReq>),
) -> Result<Status, Error> {
    let config_id = conn.hpke_config_id_param()?;

    ds.run_tx_with_name("patch_hpke_global_keypair", |tx| {
        let config_id = config_id;
        Box::pin(async move {
            tx.set_global_hpke_keypair_state(&config_id, &req.state)
                .await
        })
    })
    .await?;

    Ok(Status::Ok)
}

pub(super) async fn delete_global_hpke_config<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Status, Error> {
    let config_id = conn.hpke_config_id_param()?;
    match ds
        .run_tx_with_name("delete_global_hpke_config", |tx| {
            Box::pin(async move { tx.delete_global_hpke_keypair(&config_id).await })
        })
        .await
    {
        Ok(_) | Err(datastore::Error::MutationTargetNotFound) => Ok(Status::NoContent),
        Err(err) => Err(err.into()),
    }
}

pub(super) async fn get_taskprov_peer_aggregators<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Json<Vec<TaskprovPeerAggregatorResp>>, Error> {
    Ok(match get_endpoint_and_role(conn)? {
        Some((endpoint, role)) => Json(Vec::from([ds
            .run_tx_with_name("get_taskprov_peer_aggregator", |tx| {
                let endpoint = endpoint.clone();
                let role = role;
                Box::pin(async move { tx.get_taskprov_peer_aggregator(&endpoint, &role).await })
            })
            .await?
            .map(TaskprovPeerAggregatorResp::from)
            .ok_or(Error::NotFound)?])),
        None => Json(
            ds.run_tx_with_name("get_taskprov_peer_aggregators", |tx| {
                Box::pin(async move { tx.get_taskprov_peer_aggregators().await })
            })
            .await?
            .into_iter()
            .map(TaskprovPeerAggregatorResp::from)
            .collect::<Vec<_>>(),
        ),
    })
}

/// Inserts a new peer aggregator. Insertion is only supported, attempting to modify an existing
/// peer aggregator will fail.
///
/// TODO(1685): Requiring that we delete an existing peer aggregator before we can change it makes
/// token rotation cumbersome and fragile. Since token rotation is the main use case for updating
/// an existing peer aggregator, we will resolve peer aggregator updates in that issue.
pub(super) async fn post_taskprov_peer_aggregator<C: Clock>(
    conn: &mut Conn,
    (State(ds), Json(req)): (
        State<Arc<Datastore<C>>>,
        Json<PostTaskprovPeerAggregatorReq>,
    ),
) -> Result<(Status, Json<TaskprovPeerAggregatorResp>), Error> {
    let (endpoint, role) = get_endpoint_and_role(conn)?.ok_or(Error::BadRequest(
        "Must supply endpoint and role parameters".to_string(),
    ))?;

    let to_insert = PeerAggregator::new(
        endpoint.clone(),
        role,
        req.verify_key_init,
        req.collector_hpke_config,
        req.report_expiry_age,
        req.tolerable_clock_skew,
        req.aggregator_auth_tokens,
        req.collector_auth_tokens,
    );

    let inserted = ds
        .run_tx_with_name("post_taskprov_peer_aggregator", |tx| {
            let endpoint = endpoint.clone();
            let to_insert = to_insert.clone();
            let role = role;
            Box::pin(async move {
                tx.put_taskprov_peer_aggregator(&to_insert).await?;
                tx.get_taskprov_peer_aggregator(&endpoint, &role).await
            })
        })
        .await?
        .map(TaskprovPeerAggregatorResp::from)
        .ok_or_else(|| Error::Internal("Newly inserted peer aggregator disappeared".to_string()))?;

    Ok((Status::Created, Json(inserted)))
}

pub(super) async fn delete_taskprov_peer_aggregator<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<Status, Error> {
    let (endpoint, role) = get_endpoint_and_role(conn)?.ok_or(Error::BadRequest(
        "Must supply endpoint and role parameters".to_string(),
    ))?;

    match ds
        .run_tx_with_name("delete_taskprov_peer_aggregator", |tx| {
            let endpoint = endpoint.clone();
            let role = role;
            Box::pin(async move { tx.delete_taskprov_peer_aggregator(&endpoint, &role).await })
        })
        .await
    {
        Ok(_) | Err(datastore::Error::MutationTargetNotFound) => Ok(Status::NoContent),
        Err(err) => Err(err.into()),
    }
}

fn get_endpoint_and_role(conn: &Conn) -> Result<Option<(Url, Role)>, Error> {
    let params = serde_urlencoded::from_str::<Vec<(String, String)>>(conn.querystring())?;

    let endpoint = params
        .iter()
        .find(|(k, _)| *k == "endpoint")
        .map(|endpoint| Url::parse(&endpoint.1))
        .transpose()?;

    let role = params
        .iter()
        .find(|(k, _)| *k == "role")
        .map(|role| {
            let role = Role::from_str(&role.1)?;
            if !role.is_aggregator() {
                Err(Error::BadRequest(
                    "Role must be leader or helper".to_string(),
                ))
            } else {
                Ok(role)
            }
        })
        .transpose()?;

    match (endpoint, role) {
        (Some(endpoint), Some(role)) => Ok(Some((endpoint, role))),
        (None, None) => Ok(None),
        // Partial queries are not supported.
        (_, _) => Err(Error::BadRequest(format!(
            "Must supply both 'endpoint' and 'role' parameters"
        ))),
    }
}
