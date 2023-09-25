//! This crate implements the Janus Aggregator API.
mod models;
mod routes;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use janus_aggregator_core::{
    datastore::{self, Datastore},
    instrumented,
};
use janus_core::{auth_tokens::AuthenticationToken, hpke, http::extract_bearer_token, time::Clock};
use janus_messages::{HpkeConfigId, RoleParseError, TaskId};
use routes::*;
use std::{str::FromStr, sync::Arc};
use tracing::error;
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
            )
            .get(
                "/taskprov/peer_aggregators",
                instrumented(api(get_taskprov_peer_aggregators::<C>)),
            )
            .post(
                "/taskprov/peer_aggregators",
                instrumented(api(post_taskprov_peer_aggregator::<C>)),
            )
            .delete(
                "/taskprov/peer_aggregators",
                instrumented(api(delete_taskprov_peer_aggregator::<C>)),
            ),
    )
}

async fn auth_check(conn: &mut Conn, (): ()) -> impl Handler {
    let (Some(cfg), Ok(Some(bearer_token))) =
        (conn.state::<Arc<Config>>(), extract_bearer_token(conn))
    else {
        return Some((Status::Unauthorized, Halt));
    };

    if cfg.auth_tokens.iter().any(|key| bearer_token == *key) {
        // Authorization succeeds.
        None
    } else {
        // Authorization fails.
        Some((Status::Unauthorized, Halt))
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    /// Errors that should never happen under expected behavior.
    #[error("Internal error: {0}")]
    Internal(String),
    /// A datastore error. The related HTTP status code depends on the type of datastore error.
    #[error(transparent)]
    Db(#[from] datastore::Error),
    /// Errors that should return HTTP 404.
    #[error("Target resource was not found")]
    NotFound,
    /// Errors that should return HTTP 409.
    #[error("{0}")]
    Conflict(String),
    /// Errors that should return HTTP 400.
    #[error("{0}")]
    BadRequest(String),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Role(#[from] RoleParseError),
    #[error(transparent)]
    Hpke(#[from] hpke::Error),
}

#[async_trait]
impl Handler for Error {
    async fn run(&self, conn: Conn) -> Conn {
        match self {
            Self::Internal(err) => {
                error!(?err, "Internal error");
                conn.with_status(Status::InternalServerError)
            }
            Self::Db(err) => match err {
                datastore::Error::MutationTargetNotFound => conn.with_status(Status::NotFound),
                datastore::Error::MutationTargetAlreadyExists => conn.with_status(Status::Conflict),
                // Errors that are generated by us inside a database transaction. Downcast into
                // our error and run the same handler against that.
                datastore::Error::User(user_err) if user_err.is::<Error>() => {
                    // Unwrap safety: we just checked that this downcast is valid inside the match
                    // arm.
                    user_err.downcast_ref::<Error>().unwrap().run(conn).await
                }
                err => {
                    error!(?err, "Datastore error");
                    conn.with_status(Status::InternalServerError)
                }
            },
            Self::NotFound => conn.with_status(Status::NotFound),
            Self::Conflict(message) => conn
                .with_status(Status::Conflict)
                .with_body(message.clone()),
            Self::BadRequest(message) => conn
                .with_status(Status::BadRequest)
                .with_body(message.to_string()),
            Self::Url(err) => conn
                .with_status(Status::BadRequest)
                .with_body(err.to_string()),
            Self::Role(err) => conn
                .with_status(Status::BadRequest)
                .with_body(err.to_string()),
            Self::Hpke(err) => conn
                .with_status(Status::BadRequest)
                .with_body(err.to_string()),
        }
        .halt()
    }
}

trait ConnExt {
    fn task_id_param(&self) -> Result<TaskId, Error>;
    fn hpke_config_id_param(&self) -> Result<HpkeConfigId, Error>;
}

impl ConnExt for Conn {
    fn task_id_param(&self) -> Result<TaskId, Error> {
        TaskId::from_str(
            self.param("task_id")
                .ok_or_else(|| Error::Internal("Missing task_id parameter".to_string()))?,
        )
        .map_err(|err| Error::BadRequest(format!("{:?}", err)))
    }

    fn hpke_config_id_param(&self) -> Result<HpkeConfigId, Error> {
        Ok(HpkeConfigId::from(
            self.param("config_id")
                .ok_or_else(|| Error::Internal("Missing config_id parameter".to_string()))?
                .parse::<u8>()
                .map_err(|_| Error::BadRequest("Invalid config_id parameter".to_string()))?,
        ))
    }
}
