//! This crate implements the Janus Aggregator API.

use crate::models::{GetTaskIdsResp, PostTaskReq};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator_core::{
    datastore::{self, Datastore},
    task::Task,
    SecretBytes,
};
use janus_core::{
    hpke::generate_hpke_config_and_private_key, http::extract_bearer_token,
    task::AuthenticationToken, time::Clock,
};
use janus_messages::{Duration, HpkeAeadId, HpkeKdfId, HpkeKemId, Role, TaskId, Time};
use models::{GetTaskMetricsResp, TaskResp};
use querystring::querify;
use rand::{distributions::Standard, random, thread_rng, Rng};
use ring::constant_time;
use std::{str::FromStr, sync::Arc};
use tracing::{error, info_span, warn, Instrument};
use trillium::{Conn, Handler, Status};
use trillium_api::{api, Halt, Json, State};
use trillium_macros::Handler;
use trillium_opentelemetry::metrics;
use trillium_router::{Router, RouterConnExt};

/// Represents the configuration for an instance of the Aggregator API.
#[derive(Clone)]
pub struct Config {
    pub auth_tokens: Vec<SecretBytes>,
}

/// Returns a new handler for an instance of the aggregator API, backed by the given datastore,
/// according to the given configuration.
pub fn aggregator_api_handler<C: Clock>(ds: Arc<Datastore<C>>, cfg: Config) -> impl Handler {
    (
        // State used by endpoint handlers.
        State(ds),
        State(Arc::new(cfg)),
        // Metrics.
        metrics("janus_aggregator_api").with_route(|conn| conn.route().map(ToString::to_string)),
        // Authorization check.
        api(auth_check),
        // Main functionality router.
        Router::new()
            .get("/task_ids", instrumented(api(get_task_ids::<C>)))
            .post("/tasks", instrumented(api(post_task::<C>)))
            .get("/tasks/:task_id", instrumented(api(get_task::<C>)))
            .delete("/tasks/:task_id", instrumented(api(delete_task::<C>)))
            .get(
                "/tasks/:task_id/metrics",
                instrumented(api(get_task_metrics::<C>)),
            ),
    )
}

async fn auth_check(conn: &mut Conn, State(cfg): State<Arc<Config>>) -> impl Handler {
    let bearer_token = match extract_bearer_token(conn) {
        Ok(Some(t)) => t,
        _ => {
            return Some((Status::Unauthorized, Halt));
        }
    };

    if cfg.auth_tokens.iter().any(|key| {
        constant_time::verify_slices_are_equal(bearer_token.as_ref(), key.as_ref()).is_ok()
    }) {
        // Authorization succeeds.
        return None;
    }

    // Authorization fails.
    Some((Status::Unauthorized, Halt))
}

async fn get_task_ids<C: Clock>(
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

/// A simple error type that holds a message and an HTTP status. This can be used as a [`Handler`].
struct Error {
    message: String,
    status: Status,
}

impl Error {
    fn new(message: String, status: Status) -> Self {
        Self { message, status }
    }
}

#[async_trait]
impl Handler for Error {
    async fn run(&self, conn: Conn) -> Conn {
        conn.with_body(self.message.clone())
            .with_status(self.status)
            .halt()
    }
}

async fn post_task<C: Clock>(
    _: &mut Conn,
    (State(ds), Json(req)): (State<Arc<Datastore<C>>>, Json<PostTaskReq>),
) -> Result<impl Handler, Error> {
    let task_id = req.task_id.unwrap_or_else(random);
    let vdaf_verify_keys = if let Some(encoded) = req.vdaf_verify_key.as_ref() {
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|err| {
            Error::new(
                format!("Invalid base64 value for vdaf_verify_key: {err}"),
                Status::BadRequest,
            )
        })?;
        if bytes.len() != req.vdaf.verify_key_length() {
            return Err(Error::new(
                format!(
                    "Wrong VDAF verify key length, expected {}, got {}",
                    req.vdaf.verify_key_length(),
                    bytes.len()
                ),
                Status::BadRequest,
            ));
        }
        Vec::from([SecretBytes::new(bytes)])
    } else {
        Vec::from([SecretBytes::new(
            thread_rng()
                .sample_iter(Standard)
                .take(req.vdaf.verify_key_length())
                .collect(),
        )])
    };
    let task_expiration = Time::from_seconds_since_epoch(req.task_expiration);
    let time_precision = Duration::from_seconds(req.time_precision);
    let aggregator_auth_tokens = if let Some(encoded) = req.aggregator_auth_token.as_ref() {
        let token_bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|err| {
            Error::new(
                format!("Invalid base64 value for aggregator_auth_token: {err}"),
                Status::BadRequest,
            )
        })?;
        Vec::from([AuthenticationToken::try_from(token_bytes).map_err(|_| {
            Error::new(
                "Invalid HTTP header value in aggregator_auth_token".to_string(),
                Status::BadRequest,
            )
        })?])
    } else {
        Vec::from([random()])
    };
    let collector_auth_tokens = match (req.role, req.collector_auth_token) {
        (Role::Leader, None) => Vec::from([random()]),
        (Role::Leader, Some(encoded)) => {
            let token_bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|err| {
                Error::new(
                    format!("Invalid base64 value for collector_auth_token: {err}"),
                    Status::BadRequest,
                )
            })?;
            Vec::from([AuthenticationToken::try_from(token_bytes).map_err(|_| {
                Error::new(
                    "Invalid HTTP header value in collector_auth_token".to_string(),
                    Status::BadRequest,
                )
            })?])
        }
        (Role::Helper, None) => Vec::new(),
        (Role::Helper, Some(_)) => {
            return Err(Error::new(
                "Cannot set collector_auth_token in a helper task".to_string(),
                Status::BadRequest,
            ))
        }
        _ => return Err(Error::new("Invalid role".to_string(), Status::BadRequest)),
    };
    let hpke_keys = Vec::from([generate_hpke_config_and_private_key(
        random(),
        HpkeKemId::X25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    )]);

    let task = Arc::new(
        Task::new(
            /* task_id */ task_id,
            /* aggregator_endpoints */ vec![req.leader_endpoint, req.helper_endpoint],
            /* query_type */ req.query_type,
            /* vdaf */ req.vdaf,
            /* role */ req.role,
            /* vdaf_verify_keys */ vdaf_verify_keys,
            /* max_batch_query_count */ req.max_batch_query_count,
            /* task_expiration */ task_expiration,
            /* report_expiry_age */
            Some(Duration::from_seconds(3600 * 24 * 7 * 2)), // 2 weeks
            /* min_batch_size */ req.min_batch_size,
            /* time_precision */ time_precision,
            /* tolerable_clock_skew */
            Duration::from_seconds(60), // 1 minute,
            /* collector_hpke_config */ req.collector_hpke_config,
            /* aggregator_auth_tokens */ aggregator_auth_tokens,
            /* collector_auth_tokens */ collector_auth_tokens,
            /* hpke_keys */ hpke_keys,
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
        Box::pin(async move { tx.put_task(&task).await })
    })
    .await
    .map_err(|err| {
        error!(err = %err, "Database transaction error");
        Error::new(
            "Error storing task".to_string(),
            Status::InternalServerError,
        )
    })?;

    Ok(Json(TaskResp::from(task.as_ref())))
}

async fn get_task<C: Clock>(
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

    Ok(Json(TaskResp::from(&task)))
}

async fn delete_task<C: Clock>(
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

async fn get_task_metrics<C: Clock>(
    conn: &mut Conn,
    State(ds): State<Arc<Datastore<C>>>,
) -> Result<impl Handler, Status> {
    let task_id = conn.task_id_param()?;

    let (reports, report_aggregations) = ds
        .run_tx_with_name("get_task_metrics", |tx| {
            Box::pin(async move { tx.get_task_metrics(task_id).await })
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

mod models {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use janus_aggregator_core::task::{QueryType, Task};
    use janus_core::task::VdafInstance;
    use janus_messages::{Duration, HpkeConfig, Role, TaskId, Time};
    use serde::{Deserialize, Serialize};
    use url::Url;

    #[derive(Serialize)]
    pub(crate) struct GetTaskIdsResp {
        pub(crate) task_ids: Vec<TaskId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) pagination_token: Option<TaskId>,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct PostTaskReq {
        pub(crate) task_id: Option<TaskId>,
        pub(crate) leader_endpoint: Url,
        pub(crate) helper_endpoint: Url,
        pub(crate) query_type: QueryType,
        pub(crate) vdaf: VdafInstance,
        pub(crate) role: Role,
        pub(crate) vdaf_verify_key: Option<String>,
        pub(crate) max_batch_query_count: u64,
        pub(crate) task_expiration: u64, // seconds since UNIX epoch
        pub(crate) min_batch_size: u64,
        pub(crate) time_precision: u64, // seconds
        pub(crate) collector_hpke_config: HpkeConfig,
        pub(crate) aggregator_auth_token: Option<String>,
        pub(crate) collector_auth_token: Option<String>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct TaskResp {
        pub(crate) task_id: TaskId,
        pub(crate) leader_endpoint: Url,
        pub(crate) helper_endpoint: Url,
        pub(crate) query_type: QueryType,
        pub(crate) vdaf: VdafInstance,
        pub(crate) role: Role,
        pub(crate) vdaf_verify_keys: Vec<String>,
        pub(crate) max_batch_query_count: u64,
        pub(crate) task_expiration: Time,
        pub(crate) report_expiry_age: Option<Duration>,
        pub(crate) min_batch_size: u64,
        pub(crate) time_precision: Duration,
        pub(crate) tolerable_clock_skew: Duration,
        pub(crate) collector_hpke_config: HpkeConfig,
        pub(crate) aggregator_auth_tokens: Vec<String>,
        pub(crate) collector_auth_tokens: Vec<String>,
        pub(crate) aggregator_hpke_configs: Vec<HpkeConfig>,
    }

    impl From<&Task> for TaskResp {
        fn from(task: &Task) -> Self {
            let encoded_verify_keys: Vec<_> = task
                .vdaf_verify_keys()
                .iter()
                .map(|key| URL_SAFE_NO_PAD.encode(key))
                .collect();
            let encoded_aggregator_auth_tokens: Vec<_> = task
                .aggregator_auth_tokens()
                .iter()
                .map(|token| URL_SAFE_NO_PAD.encode(token))
                .collect();
            let encoded_collector_auth_tokens: Vec<_> = task
                .collector_auth_tokens()
                .iter()
                .map(|token| URL_SAFE_NO_PAD.encode(token))
                .collect();
            let mut aggregator_hpke_configs: Vec<_> = task
                .hpke_keys()
                .values()
                .map(|keypair| keypair.config().clone())
                .collect();
            aggregator_hpke_configs.sort_by_key(|config| *config.id());

            Self {
                task_id: *task.id(),
                leader_endpoint: task.aggregator_endpoints()[0].clone(),
                helper_endpoint: task.aggregator_endpoints()[1].clone(),
                query_type: *task.query_type(),
                vdaf: task.vdaf().clone(),
                role: *task.role(),
                vdaf_verify_keys: encoded_verify_keys,
                max_batch_query_count: task.max_batch_query_count(),
                task_expiration: *task.task_expiration(),
                report_expiry_age: task.report_expiry_age().cloned(),
                min_batch_size: task.min_batch_size(),
                time_precision: *task.time_precision(),
                tolerable_clock_skew: *task.tolerable_clock_skew(),
                collector_hpke_config: task.collector_hpke_config().clone(),
                aggregator_auth_tokens: encoded_aggregator_auth_tokens,
                collector_auth_tokens: encoded_collector_auth_tokens,
                aggregator_hpke_configs,
            }
        }
    }

    #[derive(Serialize)]
    pub(crate) struct GetTaskMetricsResp {
        pub(crate) reports: u64,
        pub(crate) report_aggregations: u64,
    }
}

trait ConnExt {
    fn task_id_param(&self) -> Result<TaskId, Status>;
}

impl ConnExt for Conn {
    fn task_id_param(&self) -> Result<TaskId, Status> {
        TaskId::from_str(self.param("task_id").ok_or_else(|| {
            error!("No task_id parameter");
            Status::InternalServerError
        })?)
        .map_err(|err| {
            warn!(err = ?err, "Couldn't parse task_id parameter");
            Status::BadRequest
        })
    }
}

pub fn instrumented<H: Handler>(handler: H) -> impl Handler {
    InstrumentedHandler(handler)
}

#[derive(Handler)]
struct InstrumentedHandler<H>(#[handler(except = run)] H);

impl<H: Handler> InstrumentedHandler<H> {
    async fn run(&self, conn: Conn) -> Conn {
        let route = conn.route().expect("no route in conn").to_string();
        self.0
            .run(conn)
            .instrument(info_span!("endpoint", route = route))
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregator_api_handler,
        models::{GetTaskIdsResp, GetTaskMetricsResp, PostTaskReq, TaskResp},
        Config,
    };
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine,
    };
    use futures::future::try_join_all;
    use janus_aggregator_core::{
        datastore::{
            models::{
                AggregationJob, AggregationJobState, LeaderStoredReport, ReportAggregation,
                ReportAggregationState,
            },
            test_util::{ephemeral_datastore, EphemeralDatastore},
        },
        task::{test_util::TaskBuilder, QueryType, Task},
        SecretBytes,
    };
    use janus_core::{
        hpke::{generate_hpke_config_and_private_key, HpkeKeypair, HpkePrivateKey},
        task::{AuthenticationToken, VdafInstance},
        test_util::{
            dummy_vdaf::{self, AggregationParam},
            install_test_trace_subscriber,
        },
        time::MockClock,
    };
    use janus_messages::{
        query_type::TimeInterval, AggregationJobRound, Duration, HpkeAeadId, HpkeConfig,
        HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, Interval, Role, TaskId, Time,
    };
    use rand::{distributions::Standard, random, thread_rng, Rng};
    use serde_test::{assert_ser_tokens, assert_tokens, Token};
    use std::{iter, sync::Arc};
    use trillium::{Handler, Status};
    use trillium_testing::{
        assert_response, assert_status,
        prelude::{delete, get, post},
    };

    const AUTH_TOKEN: &str = "auth_token";

    async fn setup_api_test() -> (impl Handler, EphemeralDatastore) {
        install_test_trace_subscriber();
        let ephemeral_datastore = ephemeral_datastore().await;
        let handler = aggregator_api_handler(
            Arc::new(ephemeral_datastore.datastore(MockClock::default()).await),
            Config {
                auth_tokens: Vec::from([SecretBytes::new(AUTH_TOKEN.as_bytes().to_vec())]),
            },
        );

        (handler, ephemeral_datastore)
    }

    #[tokio::test]
    async fn get_task_ids() {
        // Setup: write a few tasks to the datastore.
        let (handler, ephemeral_datastore) = setup_api_test().await;
        let ds = ephemeral_datastore.datastore(MockClock::default()).await;

        let mut task_ids: Vec<_> = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let tasks: Vec<_> = iter::repeat_with(|| {
                        TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                            .build()
                    })
                    .take(10)
                    .collect();

                    try_join_all(tasks.iter().map(|task| tx.put_task(task))).await?;

                    Ok(tasks.into_iter().map(|task| *task.id()).collect())
                })
            })
            .await
            .unwrap();
        task_ids.sort();

        fn response_for(task_ids: &[TaskId]) -> String {
            serde_json::to_string(&GetTaskIdsResp {
                task_ids: task_ids.to_vec(),
                pagination_token: task_ids.last().cloned(),
            })
            .unwrap()
        }

        // Verify: we can get the task IDs we wrote back from the API.
        assert_response!(
            get("/task_ids")
                .with_request_header(
                    "Authorization",
                    format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
                )
                .run_async(&handler)
                .await,
            Status::Ok,
            response_for(&task_ids),
        );

        // Verify: the lower_bound is respected, if specified.
        assert_response!(
            get(&format!(
                "/task_ids?pagination_token={}",
                task_ids.first().unwrap()
            ))
            .with_request_header(
                "Authorization",
                format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
            )
            .run_async(&handler)
            .await,
            Status::Ok,
            response_for(&task_ids[1..]),
        );

        // Verify: if the lower bound is large enough, nothing is returned.
        // (also verifies the "last" response will not include a pagination token)
        assert_response!(
            get(&format!(
                "/task_ids?pagination_token={}",
                task_ids.last().unwrap()
            ))
            .with_request_header(
                "Authorization",
                format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
            )
            .run_async(&handler)
            .await,
            Status::Ok,
            response_for(&[]),
        );

        // Verify: unauthorized requests are denied appropriately.
        assert_response!(
            get("/task_ids").run_async(&handler).await,
            Status::Unauthorized,
            "",
        );
    }

    /// Test the POST /tasks endpoint, with none of the optional fields provided.
    #[tokio::test]
    async fn post_task_no_optional_fields() {
        // Setup: create a datastore & handler.
        let (handler, ephemeral_datastore) = setup_api_test().await;
        let ds = ephemeral_datastore.datastore(MockClock::default()).await;

        // Verify: posting a task creates a new task which matches the request.
        let req = PostTaskReq {
            task_id: None,
            leader_endpoint: "http://leader.endpoint".try_into().unwrap(),
            helper_endpoint: "http://helper.endpoint".try_into().unwrap(),
            query_type: QueryType::TimeInterval,
            vdaf: VdafInstance::Prio3Count,
            role: Role::Leader,
            vdaf_verify_key: None,
            max_batch_query_count: 12,
            task_expiration: 12345,
            min_batch_size: 223,
            time_precision: 62,
            collector_hpke_config: generate_hpke_config_and_private_key(
                random(),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
            )
            .config()
            .clone(),
            aggregator_auth_token: None,
            collector_auth_token: None,
        };
        let mut conn = post("/tasks")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header(
                "Authorization",
                format!("Bearer {}", STANDARD.encode(AUTH_TOKEN)),
            )
            .run_async(&handler)
            .await;
        assert_status!(conn, Status::Ok);
        let got_task_resp: TaskResp = serde_json::from_slice(
            &conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();

        let got_task = ds
            .run_tx(|tx| {
                let got_task_resp = got_task_resp.clone();
                Box::pin(async move { tx.get_task(&got_task_resp.task_id).await })
            })
            .await
            .unwrap()
            .expect("task was not created");

        // Verify that the task written to the datastore matches the request...
        assert_eq!(
            [req.leader_endpoint.clone(), req.helper_endpoint.clone()],
            got_task.aggregator_endpoints()
        );
        assert_eq!(&req.query_type, got_task.query_type());
        assert_eq!(&req.vdaf, got_task.vdaf());
        assert_eq!(&req.role, got_task.role());
        assert_eq!(req.max_batch_query_count, got_task.max_batch_query_count());
        assert_eq!(
            &Time::from_seconds_since_epoch(req.task_expiration),
            got_task.task_expiration()
        );
        assert_eq!(req.min_batch_size, got_task.min_batch_size());
        assert_eq!(
            &Duration::from_seconds(req.time_precision),
            got_task.time_precision()
        );
        assert_eq!(&req.collector_hpke_config, got_task.collector_hpke_config());

        // ...and the response.
        assert_eq!(got_task_resp, TaskResp::from(&got_task));

        // Verify: unauthorized requests are denied appropriately.
        assert_response!(
            post("/tasks")
                .with_request_body(serde_json::to_vec(&req).unwrap())
                .run_async(&handler)
                .await,
            Status::Unauthorized,
            "",
        );
    }

    /// Test the POST /tasks endpoint, with all of the optional fields provided.
    #[tokio::test]
    async fn post_task_all_optional_fields() {
        // Setup: create a datastore & handler.
        let (handler, ephemeral_datastore) = setup_api_test().await;
        let ds = ephemeral_datastore.datastore(MockClock::default()).await;

        let vdaf_verify_key =
            SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());
        let aggregator_auth_token = random::<AuthenticationToken>();
        let collector_auth_token = random::<AuthenticationToken>();

        // Verify: posting a task creates a new task which matches the request.
        let req = PostTaskReq {
            task_id: Some(random()),
            leader_endpoint: "http://leader.endpoint".try_into().unwrap(),
            helper_endpoint: "http://helper.endpoint".try_into().unwrap(),
            query_type: QueryType::TimeInterval,
            vdaf: VdafInstance::Prio3Count,
            role: Role::Leader,
            vdaf_verify_key: Some(URL_SAFE_NO_PAD.encode(&vdaf_verify_key)),
            max_batch_query_count: 12,
            task_expiration: 12345,
            min_batch_size: 223,
            time_precision: 62,
            collector_hpke_config: generate_hpke_config_and_private_key(
                random(),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
            )
            .config()
            .clone(),
            aggregator_auth_token: Some(URL_SAFE_NO_PAD.encode(&aggregator_auth_token)),
            collector_auth_token: Some(URL_SAFE_NO_PAD.encode(&collector_auth_token)),
        };
        let mut conn = post("/tasks")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header(
                "Authorization",
                format!("Bearer {}", STANDARD.encode(AUTH_TOKEN)),
            )
            .run_async(&handler)
            .await;
        assert_status!(conn, Status::Ok);
        let got_task_resp: TaskResp = serde_json::from_slice(
            &conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();

        let got_task = ds
            .run_tx(|tx| {
                let got_task_resp = got_task_resp.clone();
                Box::pin(async move { tx.get_task(&got_task_resp.task_id).await })
            })
            .await
            .unwrap()
            .expect("task was not created");

        // Verify that the task written to the datastore matches the request...
        assert_eq!(req.task_id.as_ref().unwrap(), got_task.id());
        assert_eq!(
            [req.leader_endpoint.clone(), req.helper_endpoint.clone()],
            got_task.aggregator_endpoints()
        );
        assert_eq!(&req.query_type, got_task.query_type());
        assert_eq!(&req.vdaf, got_task.vdaf());
        assert_eq!(&req.role, got_task.role());
        assert_eq!(1, got_task.vdaf_verify_keys().len());
        assert_eq!(
            vdaf_verify_key.as_ref(),
            got_task.vdaf_verify_keys()[0].as_ref()
        );
        assert_eq!(req.max_batch_query_count, got_task.max_batch_query_count());
        assert_eq!(
            &Time::from_seconds_since_epoch(req.task_expiration),
            got_task.task_expiration()
        );
        assert_eq!(req.min_batch_size, got_task.min_batch_size());
        assert_eq!(
            &Duration::from_seconds(req.time_precision),
            got_task.time_precision()
        );
        assert_eq!(&req.collector_hpke_config, got_task.collector_hpke_config());
        assert_eq!(1, got_task.aggregator_auth_tokens().len());
        assert_eq!(
            aggregator_auth_token.as_ref(),
            got_task.aggregator_auth_tokens()[0].as_ref()
        );
        assert_eq!(1, got_task.collector_auth_tokens().len());
        assert_eq!(
            collector_auth_token.as_ref(),
            got_task.collector_auth_tokens()[0].as_ref()
        );

        // ...and the response.
        assert_eq!(got_task_resp, TaskResp::from(&got_task));
    }

    #[tokio::test]
    async fn get_task() {
        // Setup: write a task to the datastore.
        let (handler, ephemeral_datastore) = setup_api_test().await;
        let ds = ephemeral_datastore.datastore(MockClock::default()).await;

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();

        ds.run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move {
                tx.put_task(&task).await?;
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify: getting the task returns the expected result.
        let want_task_resp = TaskResp::from(&task);
        let mut conn = get(&format!("/tasks/{}", task.id()))
            .with_request_header(
                "Authorization",
                format!("Bearer {}", STANDARD.encode(AUTH_TOKEN)),
            )
            .run_async(&handler)
            .await;
        assert_status!(conn, Status::Ok);
        let got_task_resp = serde_json::from_slice(
            &conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(want_task_resp, got_task_resp);

        // Verify: getting a nonexistent task returns NotFound.
        assert_response!(
            get(&format!("/tasks/{}", random::<TaskId>()))
                .with_request_header(
                    "Authorization",
                    format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
                )
                .run_async(&handler)
                .await,
            Status::NotFound,
            "",
        );

        // Verify: unauthorized requests are denied appropriately.
        assert_response!(
            get(&format!("/tasks/{}", task.id()))
                .run_async(&handler)
                .await,
            Status::Unauthorized,
            "",
        );
    }

    #[tokio::test]
    async fn delete_task() {
        // Setup: write a task to the datastore.
        let (handler, ephemeral_datastore) = setup_api_test().await;
        let ds = ephemeral_datastore.datastore(MockClock::default()).await;

        let task_id = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let task =
                        TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                            .build();

                    tx.put_task(&task).await?;

                    Ok(*task.id())
                })
            })
            .await
            .unwrap();

        // Verify: deleting a task succeeds (and actually deletes the task).
        assert_response!(
            delete(&format!("/tasks/{}", &task_id))
                .with_request_header(
                    "Authorization",
                    format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
                )
                .run_async(&handler)
                .await,
            Status::NoContent,
            "",
        );

        ds.run_tx(|tx| {
            Box::pin(async move {
                assert_eq!(tx.get_task(&task_id).await.unwrap(), None);
                Ok(())
            })
        })
        .await
        .unwrap();

        // Verify: deleting a task twice returns NotFound.
        assert_response!(
            delete(&format!("/tasks/{}", &task_id))
                .with_request_header(
                    "Authorization",
                    format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
                )
                .run_async(&handler)
                .await,
            Status::NotFound,
            "",
        );

        // Verify: deleting an arbitrary nonexistent task ID returns NotFound.
        assert_response!(
            delete(&format!("/tasks/{}", &random::<TaskId>()))
                .with_request_header(
                    "Authorization",
                    format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
                )
                .run_async(&handler)
                .await,
            Status::NotFound,
            "",
        );

        // Verify: unauthorized requests are denied appropriately.
        assert_response!(
            delete(&format!("/tasks/{}", &task_id))
                .run_async(&handler)
                .await,
            Status::Unauthorized,
            ""
        );
    }

    #[tokio::test]
    async fn get_task_metrics() {
        // Setup: write a task, some reports, and some report aggregations to the datastore.
        const REPORT_COUNT: usize = 10;
        const REPORT_AGGREGATION_COUNT: usize = 4;

        let (handler, ephemeral_datastore) = setup_api_test().await;
        let ds = ephemeral_datastore.datastore(MockClock::default()).await;
        let task_id = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let task =
                        TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                            .build();
                    let task_id = *task.id();
                    tx.put_task(&task).await?;

                    let reports: Vec<_> = iter::repeat_with(|| {
                        LeaderStoredReport::new_dummy(task_id, Time::from_seconds_since_epoch(0))
                    })
                    .take(REPORT_COUNT)
                    .collect();
                    try_join_all(reports.iter().map(|report| async move {
                        tx.put_client_report(&dummy_vdaf::Vdaf::new(), report).await
                    }))
                    .await?;

                    let aggregation_job_id = random();
                    tx.put_aggregation_job(
                        &AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            task_id,
                            aggregation_job_id,
                            AggregationParam(0),
                            (),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                Duration::from_seconds(1),
                            )
                            .unwrap(),
                            AggregationJobState::InProgress,
                            AggregationJobRound::from(0),
                        ),
                    )
                    .await?;

                    try_join_all(
                        reports
                            .iter()
                            .take(REPORT_AGGREGATION_COUNT)
                            .enumerate()
                            .map(|(ord, report)| async move {
                                tx.put_report_aggregation(
                                    &ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                                        task_id,
                                        aggregation_job_id,
                                        *report.metadata().id(),
                                        *report.metadata().time(),
                                        ord.try_into().unwrap(),
                                        None,
                                        ReportAggregationState::Start,
                                    ),
                                )
                                .await
                            }),
                    )
                    .await?;

                    Ok(task_id)
                })
            })
            .await
            .unwrap();

        // Verify: requesting metrics on a task returns the correct result.
        assert_response!(
            get(&format!("/tasks/{}/metrics", &task_id))
                .with_request_header(
                    "Authorization",
                    format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
                )
                .run_async(&handler)
                .await,
            Status::Ok,
            serde_json::to_string(&GetTaskMetricsResp {
                reports: REPORT_COUNT.try_into().unwrap(),
                report_aggregations: REPORT_AGGREGATION_COUNT.try_into().unwrap(),
            })
            .unwrap(),
        );

        // Verify: requesting metrics on a nonexistent task returns NotFound.
        assert_response!(
            delete(&format!("/tasks/{}", &random::<TaskId>()))
                .with_request_header(
                    "Authorization",
                    format!("Bearer {}", STANDARD.encode(AUTH_TOKEN))
                )
                .run_async(&handler)
                .await,
            Status::NotFound,
            "",
        );

        // Verify: unauthorized requests are denied appropriately.
        assert_response!(
            get(&format!("/tasks/{}/metrics", &task_id))
                .run_async(&handler)
                .await,
            Status::Unauthorized,
            "",
        );
    }

    #[test]
    fn get_task_ids_resp_serialization() {
        assert_ser_tokens(
            &GetTaskIdsResp {
                task_ids: Vec::from([TaskId::from([0u8; 32])]),
                pagination_token: None,
            },
            &[
                Token::Struct {
                    name: "GetTaskIdsResp",
                    len: 1,
                },
                Token::Str("task_ids"),
                Token::Seq { len: Some(1) },
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
        assert_ser_tokens(
            &GetTaskIdsResp {
                task_ids: Vec::from([TaskId::from([0u8; 32])]),
                pagination_token: Some(TaskId::from([0u8; 32])),
            },
            &[
                Token::Struct {
                    name: "GetTaskIdsResp",
                    len: 2,
                },
                Token::Str("task_ids"),
                Token::Seq { len: Some(1) },
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::SeqEnd,
                Token::Str("pagination_token"),
                Token::Some,
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn post_task_req_serialization() {
        // minimal request
        assert_tokens(
            &PostTaskReq {
                task_id: None,
                leader_endpoint: "https://example.com/".parse().unwrap(),
                helper_endpoint: "https://example.net/".parse().unwrap(),
                query_type: QueryType::FixedSize {
                    max_batch_size: 999,
                },
                vdaf: VdafInstance::Prio3CountVec { length: 5 },
                role: Role::Leader,
                vdaf_verify_key: None,
                max_batch_query_count: 1,
                task_expiration: u64::MAX,
                min_batch_size: 100,
                time_precision: 3600,
                collector_hpke_config: HpkeConfig::new(
                    HpkeConfigId::from(7),
                    HpkeKemId::X25519HkdfSha256,
                    HpkeKdfId::HkdfSha256,
                    HpkeAeadId::Aes128Gcm,
                    HpkePublicKey::from([0u8; 32].to_vec()),
                ),
                aggregator_auth_token: None,
                collector_auth_token: None,
            },
            &[
                Token::Struct {
                    name: "PostTaskReq",
                    len: 14,
                },
                Token::Str("task_id"),
                Token::None,
                Token::Str("leader_endpoint"),
                Token::Str("https://example.com/"),
                Token::Str("helper_endpoint"),
                Token::Str("https://example.net/"),
                Token::Str("query_type"),
                Token::StructVariant {
                    name: "QueryType",
                    variant: "FixedSize",
                    len: 1,
                },
                Token::Str("max_batch_size"),
                Token::U64(999),
                Token::StructVariantEnd,
                Token::Str("vdaf"),
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3CountVec",
                    len: 1,
                },
                Token::Str("length"),
                Token::U64(5),
                Token::StructVariantEnd,
                Token::Str("role"),
                Token::UnitVariant {
                    name: "Role",
                    variant: "Leader",
                },
                Token::Str("vdaf_verify_key"),
                Token::None,
                Token::Str("max_batch_query_count"),
                Token::U64(1),
                Token::Str("task_expiration"),
                Token::U64(u64::MAX),
                Token::Str("min_batch_size"),
                Token::U64(100),
                Token::Str("time_precision"),
                Token::U64(3600),
                Token::Str("collector_hpke_config"),
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(7),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::StructEnd,
                Token::Str("aggregator_auth_token"),
                Token::None,
                Token::Str("collector_auth_token"),
                Token::None,
                Token::StructEnd,
            ],
        );

        // maximal request
        assert_tokens(
            &PostTaskReq {
                task_id: Some(TaskId::from([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 251, 252, 253, 254, 255,
                ])),
                leader_endpoint: "https://example.com/".parse().unwrap(),
                helper_endpoint: "https://example.net/".parse().unwrap(),
                query_type: QueryType::FixedSize {
                    max_batch_size: 999,
                },
                vdaf: VdafInstance::Prio3CountVec { length: 5 },
                role: Role::Leader,
                vdaf_verify_key: Some("encoded".to_owned()),
                max_batch_query_count: 1,
                task_expiration: u64::MAX,
                min_batch_size: 100,
                time_precision: 3600,
                collector_hpke_config: HpkeConfig::new(
                    HpkeConfigId::from(7),
                    HpkeKemId::X25519HkdfSha256,
                    HpkeKdfId::HkdfSha256,
                    HpkeAeadId::Aes128Gcm,
                    HpkePublicKey::from([0u8; 32].to_vec()),
                ),
                aggregator_auth_token: Some("encoded".to_owned()),
                collector_auth_token: Some("encoded".to_owned()),
            },
            &[
                Token::Struct {
                    name: "PostTaskReq",
                    len: 14,
                },
                Token::Str("task_id"),
                Token::Some,
                Token::Str("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBka-_z9_v8"),
                Token::Str("leader_endpoint"),
                Token::Str("https://example.com/"),
                Token::Str("helper_endpoint"),
                Token::Str("https://example.net/"),
                Token::Str("query_type"),
                Token::StructVariant {
                    name: "QueryType",
                    variant: "FixedSize",
                    len: 1,
                },
                Token::Str("max_batch_size"),
                Token::U64(999),
                Token::StructVariantEnd,
                Token::Str("vdaf"),
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3CountVec",
                    len: 1,
                },
                Token::Str("length"),
                Token::U64(5),
                Token::StructVariantEnd,
                Token::Str("role"),
                Token::UnitVariant {
                    name: "Role",
                    variant: "Leader",
                },
                Token::Str("vdaf_verify_key"),
                Token::Some,
                Token::Str("encoded"),
                Token::Str("max_batch_query_count"),
                Token::U64(1),
                Token::Str("task_expiration"),
                Token::U64(u64::MAX),
                Token::Str("min_batch_size"),
                Token::U64(100),
                Token::Str("time_precision"),
                Token::U64(3600),
                Token::Str("collector_hpke_config"),
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(7),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::StructEnd,
                Token::Str("aggregator_auth_token"),
                Token::Some,
                Token::Str("encoded"),
                Token::Str("collector_auth_token"),
                Token::Some,
                Token::Str("encoded"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn task_resp_serialization() {
        let task = Task::new(
            TaskId::from([0u8; 32]),
            Vec::from([
                "https://example.com/".parse().unwrap(),
                "https://example.net/".parse().unwrap(),
            ]),
            QueryType::FixedSize {
                max_batch_size: 999,
            },
            VdafInstance::Prio3CountVec { length: 5 },
            Role::Leader,
            Vec::from([SecretBytes::new(b"vdaf verify key!".to_vec())]),
            1,
            Time::distant_future(),
            None,
            100,
            Duration::from_seconds(3600),
            Duration::from_seconds(60),
            HpkeConfig::new(
                HpkeConfigId::from(7),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
                HpkePublicKey::from([0u8; 32].to_vec()),
            ),
            Vec::from([
                AuthenticationToken::try_from("aggregator-12345678".as_bytes().to_vec()).unwrap(),
            ]),
            Vec::from([
                AuthenticationToken::try_from("collector-abcdef00".as_bytes().to_vec()).unwrap(),
            ]),
            [(HpkeKeypair::new(
                HpkeConfig::new(
                    HpkeConfigId::from(13),
                    HpkeKemId::X25519HkdfSha256,
                    HpkeKdfId::HkdfSha256,
                    HpkeAeadId::Aes128Gcm,
                    HpkePublicKey::from([0u8; 32].to_vec()),
                ),
                HpkePrivateKey::new(b"unused".to_vec()),
            ))],
        )
        .unwrap();
        assert_tokens(
            &TaskResp::from(&task),
            &[
                Token::Struct {
                    name: "TaskResp",
                    len: 17,
                },
                Token::Str("task_id"),
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::Str("leader_endpoint"),
                Token::Str("https://example.com/"),
                Token::Str("helper_endpoint"),
                Token::Str("https://example.net/"),
                Token::Str("query_type"),
                Token::StructVariant {
                    name: "QueryType",
                    variant: "FixedSize",
                    len: 1,
                },
                Token::Str("max_batch_size"),
                Token::U64(999),
                Token::StructVariantEnd,
                Token::Str("vdaf"),
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3CountVec",
                    len: 1,
                },
                Token::Str("length"),
                Token::U64(5),
                Token::StructVariantEnd,
                Token::Str("role"),
                Token::UnitVariant {
                    name: "Role",
                    variant: "Leader",
                },
                Token::Str("vdaf_verify_keys"),
                Token::Seq { len: Some(1) },
                Token::Str("dmRhZiB2ZXJpZnkga2V5IQ"),
                Token::SeqEnd,
                Token::Str("max_batch_query_count"),
                Token::U64(1),
                Token::Str("task_expiration"),
                Token::NewtypeStruct { name: "Time" },
                Token::U64(9_000_000_000),
                Token::Str("report_expiry_age"),
                Token::None,
                Token::Str("min_batch_size"),
                Token::U64(100),
                Token::Str("time_precision"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(3600),
                Token::Str("tolerable_clock_skew"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(60),
                Token::Str("collector_hpke_config"),
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(7),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::StructEnd,
                Token::Str("aggregator_auth_tokens"),
                Token::Seq { len: Some(1) },
                Token::Str("YWdncmVnYXRvci0xMjM0NTY3OA"),
                Token::SeqEnd,
                Token::Str("collector_auth_tokens"),
                Token::Seq { len: Some(1) },
                Token::Str("Y29sbGVjdG9yLWFiY2RlZjAw"),
                Token::SeqEnd,
                Token::Str("aggregator_hpke_configs"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(13),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::StructEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn get_task_metrics_resp_serialization() {
        assert_ser_tokens(
            &GetTaskMetricsResp {
                reports: 87,
                report_aggregations: 348,
            },
            &[
                Token::Struct {
                    name: "GetTaskMetricsResp",
                    len: 2,
                },
                Token::Str("reports"),
                Token::U64(87),
                Token::Str("report_aggregations"),
                Token::U64(348),
                Token::StructEnd,
            ],
        )
    }
}
