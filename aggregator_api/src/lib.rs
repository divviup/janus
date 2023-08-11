//! This crate implements the Janus Aggregator API.
mod models;
mod routes;
#[cfg(test)]
mod tests;

use async_trait::async_trait;

use janus_aggregator_core::{datastore::Datastore, instrumented};
use janus_core::{http::extract_bearer_token, task::AuthenticationToken, time::Clock};
use janus_messages::HpkeConfigId;
use janus_messages::TaskId;

use ring::constant_time;
use routes::*;
use std::{str::FromStr, sync::Arc};
use tracing::{error, warn};
use trillium::{
    Conn, Handler,
    KnownHeaderName::{Accept, ContentType},
    Status,
    Status::{NotAcceptable, UnsupportedMediaType},
};
use trillium_api::{api, Halt, State};
use trillium_opentelemetry::metrics;
use trillium_router::{Router, RouterConnExt};
use url::Url;

/// Represents the configuration for an instance of the Aggregator API.
#[derive(Clone)]
pub struct Config {
    pub auth_tokens: Vec<AuthenticationToken>,
    pub public_dap_url: Url,
}

/// Content type
const CONTENT_TYPE: &str = "application/vnd.janus.aggregator+json;version=0.1";

struct ReplaceMimeTypes;

#[trillium::async_trait]
impl Handler for ReplaceMimeTypes {
    async fn run(&self, mut conn: Conn) -> Conn {
        // Content-Type should either be the versioned API, or nothing for e.g. GET or DELETE
        // requests (no response body)
        let request_headers = conn.inner_mut().request_headers_mut();
        if let Some(CONTENT_TYPE) | None = request_headers.get_str(ContentType) {
            request_headers.insert(ContentType, "application/json");
        } else {
            return conn.with_status(UnsupportedMediaType).halt();
        }

        // Accept should always be the versioned API
        if Some(CONTENT_TYPE) == request_headers.get_str(Accept) {
            request_headers.insert(Accept, "application/json");
        } else {
            return conn.with_status(NotAcceptable).halt();
        }

        conn
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        // API responses should always have versioned API content type
        conn.with_header(ContentType, CONTENT_TYPE)
    }
}

/// Returns a new handler for an instance of the aggregator API, backed by the given datastore,
/// according to the given configuration.
pub fn aggregator_api_handler<C: Clock>(ds: Arc<Datastore<C>>, cfg: Config) -> impl Handler {
    (
        // State used by endpoint handlers.
        State(ds),
        State(Arc::new(cfg)),
        // Metrics.
        metrics("janus_aggregator").with_route(|conn| conn.route().map(ToString::to_string)),
        // Authorization check.
        api(auth_check),
        // Check content type and accept headers
        ReplaceMimeTypes,
        // Main functionality router.
        Router::new()
            .get("/", instrumented(api(get_config)))
            .get("/task_ids", instrumented(api(get_task_ids::<C>)))
            .post("/tasks", instrumented(api(post_task::<C>)))
            .get("/tasks/:task_id", instrumented(api(get_task::<C>)))
            .delete("/tasks/:task_id", instrumented(api(delete_task::<C>)))
            .get(
                "/tasks/:task_id/metrics",
                instrumented(api(get_task_metrics::<C>)),
            )
            .get(
                "/hpke_configs",
                instrumented(api(get_global_hpke_configs::<C>)),
            )
            .get(
                "/hpke_configs/:config_id",
                instrumented(api(get_global_hpke_config::<C>)),
            )
            .put(
                "/hpke_configs",
                instrumented(api(put_global_hpke_config::<C>)),
            )
            .patch(
                "/hpke_configs/:config_id",
                instrumented(api(patch_global_hpke_config::<C>)),
            )
            .delete(
                "/hpke_configs/:config_id",
                instrumented(api(delete_global_hpke_config::<C>)),
            ),
    )
}

async fn auth_check(conn: &mut Conn, (): ()) -> impl Handler {
    let (Some(cfg), Ok(Some(bearer_token))) =
        (conn.state::<Arc<Config>>(), extract_bearer_token(conn))
    else {
        return Some((Status::Unauthorized, Halt));
    };

    if cfg.auth_tokens.iter().any(|key| {
        constant_time::verify_slices_are_equal(bearer_token.as_ref(), key.as_ref()).is_ok()
    }) {
        // Authorization succeeds.
        None
    } else {
        // Authorization fails.
        Some((Status::Unauthorized, Halt))
    }
}

/// A simple error type that holds a message and an HTTP status. This can be used as a [`Handler`].
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
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

trait ConnExt {
    fn task_id_param(&self) -> Result<TaskId, Status>;
    fn hpke_config_id_param(&self) -> Result<HpkeConfigId, Status>;
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

    fn hpke_config_id_param(&self) -> Result<HpkeConfigId, Status> {
        Ok(HpkeConfigId::from(
            self.param("config_id")
                .ok_or_else(|| {
                    error!("No config_id parameter");
                    Status::InternalServerError
                })?
                .parse::<u8>()
                .map_err(|err| {
                    warn!(err = ?err, "Couldn't parse config_id parameter");
                    Status::BadRequest
                })?,
        ))
    }
}
