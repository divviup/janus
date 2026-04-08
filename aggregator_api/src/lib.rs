//! This crate implements the Janus Aggregator API.
mod models;
mod routes;
#[cfg(test)]
mod tests;

use std::{str::FromStr, sync::Arc};

use axum::{
    Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use git_version::git_version;
use http::{HeaderValue, StatusCode, header::CONTENT_TYPE as CONTENT_TYPE_HEADER};
use janus_aggregator_core::{
    datastore::{self, Datastore},
    http_server::{HttpMetrics, http_metrics_middleware},
};
use janus_core::{auth_tokens::AuthenticationToken, hpke, http::extract_bearer_token, time::Clock};
use janus_messages::{HpkeConfigId, RoleParseError, TaskId};
use opentelemetry::metrics::Meter;
use routes::*;
use tower::ServiceBuilder;
use tracing::error;
use url::Url;

/// Represents the configuration for an instance of the Aggregator API.
#[derive(Clone)]
pub struct Config {
    pub auth_tokens: Vec<AuthenticationToken>,
    pub public_dap_url: Url,
}

/// Content type
const CONTENT_TYPE: &str = "application/vnd.janus.aggregator+json;version=0.1";

/// Shared state for the aggregator API.
pub(crate) struct ApiState<C: Clock> {
    pub(crate) datastore: Arc<Datastore<C>>,
    pub(crate) config: Config,
}

/// Returns a new handler for an instance of the aggregator API, backed by the given datastore,
/// according to the given configuration.
pub fn aggregator_api_handler<C: Clock>(
    ds: Arc<Datastore<C>>,
    cfg: Config,
    meter: &Meter,
) -> Router {
    let http_metrics = HttpMetrics::new(meter, "janus_aggregator_api_responses");

    let state = Arc::new(ApiState {
        datastore: ds,
        config: cfg,
    });

    Router::new()
        .route("/", get(get_config::<C>))
        .route("/task_ids", get(get_task_ids::<C>))
        .route("/tasks", post(post_task::<C>))
        .route(
            "/tasks/{task_id}",
            get(get_task::<C>)
                .patch(patch_task::<C>)
                .delete(delete_task::<C>),
        )
        .route(
            "/tasks/{task_id}/metrics/uploads",
            get(get_task_upload_metrics::<C>),
        )
        .route(
            "/tasks/{task_id}/metrics/aggregations",
            get(get_task_aggregation_metrics::<C>),
        )
        .route(
            "/hpke_configs",
            get(get_hpke_configs::<C>).put(put_hpke_config::<C>),
        )
        .route(
            "/hpke_configs/{config_id}",
            get(get_hpke_config::<C>)
                .patch(patch_hpke_config::<C>)
                .delete(delete_hpke_config::<C>),
        )
        .route(
            "/taskprov/peer_aggregators",
            get(get_taskprov_peer_aggregators::<C>)
                .post(post_taskprov_peer_aggregator::<C>)
                .delete(delete_taskprov_peer_aggregator::<C>),
        )
        .layer(
            ServiceBuilder::new()
                .layer(axum::Extension(http_metrics))
                .layer(middleware::from_fn(http_metrics_middleware))
                .layer(middleware::from_fn_with_state(
                    Arc::clone(&state),
                    auth_check::<C>,
                ))
                .layer(middleware::from_fn(replace_mime_types)),
        )
        .with_state(state)
}

/// Middleware that checks auth tokens.
async fn auth_check<C: Clock>(
    State(state): State<Arc<ApiState<C>>>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let Ok(Some(bearer_token)) = extract_bearer_token(headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if state.config.auth_tokens.contains(&bearer_token) {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

/// Middleware that validates and replaces Content-Type/Accept headers.
async fn replace_mime_types(mut request: Request, next: Next) -> Response {
    let headers = request.headers();

    // Content-Type should either be the versioned API, or nothing for GET/DELETE.
    // unwrap_or("") maps non-UTF-8 headers to "", which falls through to the Some(_) rejection.
    let content_type = headers
        .get(CONTENT_TYPE_HEADER)
        .map(|v| v.to_str().unwrap_or(""));
    match content_type {
        Some(CONTENT_TYPE) => {
            // Replace the versioned API content-type with application/json so axum's
            // Json extractor can parse request bodies.
            request.headers_mut().insert(
                CONTENT_TYPE_HEADER,
                HeaderValue::from_static("application/json"),
            );
        }
        // No Content-Type is fine for GET/DELETE. For POST/PATCH/PUT without Content-Type,
        // axum's Json extractor will reject the request with 415, which is correct behavior.
        None => {}
        Some(_) => return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }

    // Accept should always be the versioned API.
    // unwrap_or("") maps non-UTF-8 headers to "", which falls through to the _ rejection.
    let accept = request
        .headers()
        .get(http::header::ACCEPT)
        .map(|v| v.to_str().unwrap_or(""));
    match accept {
        Some(CONTENT_TYPE) => {}
        _ => return StatusCode::NOT_ACCEPTABLE.into_response(),
    }

    let mut response = next.run(request).await;

    // API responses should always have versioned API content type
    response
        .headers_mut()
        .insert(CONTENT_TYPE_HEADER, HeaderValue::from_static(CONTENT_TYPE));

    response
}

#[derive(Debug, thiserror::Error)]
enum Error {
    /// Errors that should never happen under expected behavior.
    #[error("Internal error: {0}")]
    Internal(Box<dyn std::error::Error + Send + Sync>),
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
    BadRequest(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Role(#[from] RoleParseError),
    #[error(transparent)]
    Hpke(#[from] hpke::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Self::Internal(err) => {
                error!(?err, "Internal error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            Self::Db(err) => match err {
                datastore::Error::MutationTargetNotFound => StatusCode::NOT_FOUND.into_response(),
                datastore::Error::MutationTargetAlreadyExists => {
                    StatusCode::CONFLICT.into_response()
                }
                datastore::Error::TimeUnaligned { .. } => {
                    (StatusCode::BAD_REQUEST, err.to_string()).into_response()
                }
                // Errors that are generated by us inside a database transaction. Downcast into
                // our error and run the same handler against that.
                datastore::Error::User(user_err) if user_err.is::<Error>() => {
                    // Unwrap safety: we just checked that this downcast is valid inside the
                    // match arm.
                    (*user_err.downcast::<Error>().unwrap()).into_response()
                }
                err => {
                    error!(?err, "Datastore error");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            },
            Self::NotFound => StatusCode::NOT_FOUND.into_response(),
            Self::Conflict(message) => (StatusCode::CONFLICT, message).into_response(),
            Self::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, message.to_string()).into_response()
            }
            Self::Url(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
            Self::Role(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
            Self::Hpke(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        }
    }
}

fn parse_task_id_param(task_id: &str) -> Result<TaskId, Error> {
    TaskId::from_str(task_id).map_err(|err| Error::BadRequest(err.into()))
}

fn parse_hpke_config_id_param(config_id: &str) -> Result<HpkeConfigId, Error> {
    Ok(HpkeConfigId::from(config_id.parse::<u8>().map_err(
        |_| Error::BadRequest("Invalid config_id parameter".into()),
    )?))
}

/// Returns the git revision used to build this crate, using `git describe` if available, or the
/// environment variable `GIT_REVISION`. Returns `"unknown"` instead if neither is available.
pub fn git_revision() -> &'static str {
    let mut git_revision: &'static str = git_version!(fallback = "unknown");
    if git_revision == "unknown" {
        if let Some(value) = option_env!("GIT_REVISION") {
            git_revision = value;
        }
    }
    git_revision
}
