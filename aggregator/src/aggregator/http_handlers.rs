use std::{
    borrow::Cow, collections::VecDeque, io::Cursor, sync::Arc, time::Duration as StdDuration,
};

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{FromRequestParts, Path, State as AxumState},
    response::{IntoResponse, Response},
    routing::{post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures::{
    TryStreamExt,
    io::{AsyncRead, AsyncReadExt},
    stream::Stream,
};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE};
use janus_aggregator_core::{
    datastore::{Datastore, Error as datastoreError},
    http_server::{
        BYTES_HISTOGRAM_BOUNDARIES, ErrorCode as AxumErrorCode, HttpMetrics,
        TIME_HISTOGRAM_BOUNDARIES, http_metrics_middleware, instrumented, trace_layer,
    },
    taskprov::taskprov_task_id,
};
use janus_core::{
    Runtime,
    auth_tokens::{AuthenticationToken, DAP_AUTH_HEADER},
    http::{check_content_type, check_content_type_value, extract_bearer_token},
    taskprov::TASKPROV_HEADER,
    time::Clock,
};
use janus_messages::{
    AggregateShare, AggregateShareId, AggregateShareReq, AggregationJobContinueReq,
    AggregationJobId, AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep,
    CollectionJobId, CollectionJobReq, CollectionJobResp, HpkeConfigList, MediaType, Report,
    TaskId, UploadErrors, UploadRequest, batch_mode::TimeInterval, codec::Decode,
    problem_type::DapProblemType, taskprov::TaskConfig,
};
use mime::Mime;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Meter},
};
use prio::codec::{CodecError, Encode};
use querystring::querify;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::warn;
use trillium::{Conn, Handler, KnownHeaderName, Status};
use trillium_api::{State, TryFromConn, api};
use trillium_opentelemetry::Metrics;
use trillium_proxy::{Proxy, upstream::IntoUpstreamSelector};
use trillium_router::{Router, RouterConnExt};

use super::{
    Aggregator, Config, Error,
    error::ArcError,
    queue::{LIFORequestQueue, queued_lifo},
};
use crate::aggregator::{
    AggregationJobContinueResult,
    problem_details::{ProblemDetailsConnExt, ProblemDocument, RetryAfterConnExt},
};

#[cfg(test)]
mod tests;

/// Newtype holding a textual error code, to be stored in a Trillium connection's state.
#[derive(Clone, Copy)]
struct ErrorCode(&'static str);

async fn run_error_handler(error: &Error, mut conn: Conn) -> Conn {
    let error_code = error.error_code();
    conn.insert_state(ErrorCode(error_code));
    let conn = match error {
        Error::InvalidConfiguration(_) => conn.with_status(Status::InternalServerError),
        Error::MessageDecode(_) => {
            conn.with_problem_document(&ProblemDocument::new_dap(DapProblemType::InvalidMessage))
        }
        Error::MessageEncode(_) => conn.with_status(Status::InternalServerError),
        Error::ReportRejected(_) => {
            panic!("no report rejected error should make it to the error handler")
        }
        Error::InvalidMessage(task_id, detail) => {
            let mut doc = ProblemDocument::new_dap(DapProblemType::InvalidMessage);
            if let Some(task_id) = task_id {
                doc = doc.with_task_id(task_id);
            }
            if !detail.is_empty() {
                doc = doc.with_detail(detail);
            }
            conn.with_problem_document(&doc)
        }
        Error::StepMismatch { task_id, .. } => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::StepMismatch).with_task_id(task_id),
        ),
        Error::UnrecognizedTask(task_id) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::UnrecognizedTask).with_task_id(task_id),
        ),
        Error::UnrecognizedAggregationJob(task_id, _aggregation_job_id) => conn
            .with_problem_document(
                &ProblemDocument::new_dap(DapProblemType::UnrecognizedAggregationJob)
                    .with_task_id(task_id),
            ),
        Error::UnrecognizedAggregateShareId(task_id, aggregate_share_id) => conn
            .with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#aggregate-share-id-unrecognized",
                "The aggregate share ID is not recognized.",
                StatusCode::NOT_FOUND,
            )
            .with_task_id(task_id)
            .with_aggregate_share_id(aggregate_share_id),
        ),
        Error::AbandonedAggregationJob(task_id, aggregation_job_id) => conn.with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#aggregation-job-abandoned",
                "The aggregation job has been abandoned.",
                StatusCode::GONE,
            )
            .with_task_id(task_id)
            .with_aggregation_job_id(aggregation_job_id),
        ),
        Error::DeletedAggregationJob(task_id, aggregation_job_id) => conn.with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#aggregation-job-deleted",
                "The aggregation job has been deleted.",
                StatusCode::GONE,
            )
            .with_task_id(task_id)
            .with_aggregation_job_id(aggregation_job_id),
        ),
        Error::DeletedCollectionJob(_, _) => conn.with_status(Status::NoContent),
        Error::AbandonedCollectionJob(task_id, collection_job_id) => conn.with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#collection-job-abandoned",
                "The collection job has been abandoned.",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(
                "An internal problem has caused the server to stop processing this collection job. \
                The job is no longer collectable. Contact the server operators for assistance.",
            )
            .with_task_id(task_id)
            .with_collection_job_id(collection_job_id),
        ),
        Error::UnrecognizedCollectionJob(_, _) => conn.with_status(Status::NotFound),
        Error::UnauthorizedRequest(..) => conn.with_status(Status::Forbidden),
        Error::InvalidBatchSize(task_id, _) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::InvalidBatchSize).with_task_id(task_id),
        ),
        Error::BatchInvalid(task_id, _) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::BatchInvalid).with_task_id(task_id),
        ),
        Error::BatchOverlap(task_id, _) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::BatchOverlap).with_task_id(task_id),
        ),
        Error::BatchMismatch(inner) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::BatchMismatch)
                .with_task_id(&inner.task_id)
                .with_detail(&inner.to_string()),
        ),
        Error::Datastore(error @ datastoreError::TimeUnaligned { task_id, .. }) => conn
            .with_problem_document(
                &ProblemDocument::new(
                    DapProblemType::InvalidMessage.type_uri(),
                    "Time unaligned.",
                    StatusCode::BAD_REQUEST,
                )
                .with_task_id(task_id)
                .with_detail(&error.to_string()),
            ),
        Error::Datastore(_) => conn.with_status(Status::InternalServerError),
        Error::Hpke(_)
        | Error::Vdaf(_)
        | Error::Internal(_)
        | Error::Url(_)
        | Error::Message(_)
        | Error::HttpClient(_)
        | Error::Http { .. }
        | Error::TaskParameters(_) => conn.with_status(Status::InternalServerError),
        Error::AggregateShareRequestRejected(_, _) => conn.with_status(Status::BadRequest),
        Error::EmptyAggregation(task_id) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::InvalidMessage).with_task_id(task_id),
        ),
        Error::ForbiddenMutation { .. } => conn.with_status(Status::Conflict),
        Error::BadContentType(_) => conn.with_status(Status::UnsupportedMediaType),
        Error::BadRequest(detail) => conn.with_problem_document(
            &ProblemDocument::new(
                "about:blank", // No additional semantics over-and-above the HTTP status code.
                "Bad Request.",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(&detail.to_string()),
        ),
        Error::InvalidTask(task_id, opt_out_reason) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::InvalidTask)
                .with_task_id(task_id)
                .with_detail(&format!("{opt_out_reason}")),
        ),
        Error::DifferentialPrivacy(_) => conn.with_status(Status::InternalServerError),
        Error::ClientDisconnected => conn.with_status(Status::BadRequest),
        Error::TooManyRequests => conn.with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#too-many-requests",
                "The server is currently overloaded.",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail(
                "The server is currently servicing too many requests, please try the request again \
                later.",
            ),
        ).with_retry_after(StdDuration::from_secs(30)),
        Error::RequestTimeout => conn.with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#request-timeout",
                "Request timed out waiting in queue.",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail("The request spent too long waiting to be processed."),
        ).with_retry_after(StdDuration::from_secs(30)),
    };

    if matches!(conn.status(), Some(status) if status.is_server_error()) {
        warn!(error_code, ?error, "Error handling endpoint");
    }

    conn
}

#[async_trait]
impl Handler for Error {
    async fn run(&self, conn: Conn) -> Conn {
        run_error_handler(self, conn).await
    }
}

// This implementation on a newtype avoids a warning in the generic <Arc<impl Handler> as
// Handler>::init() implementation. We can suppress this, since this handler does not use init().
#[async_trait]
impl Handler for ArcError {
    async fn run(&self, conn: Conn) -> Conn {
        run_error_handler(self, conn).await
    }
}

/// Default retry-after for rate limiting responses.
const RATE_LIMIT_RETRY_AFTER: StdDuration = StdDuration::from_secs(30);

impl Error {
    fn to_response(&self) -> Response {
        let error_code = self.error_code();
        let response = match self {
            Error::InvalidConfiguration(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::MessageDecode(_) => {
                ProblemDocument::new_dap(DapProblemType::InvalidMessage).into_response()
            }
            Error::MessageEncode(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::ReportRejected(_) => {
                panic!("no report rejected error should make it to the error handler")
            }
            Error::InvalidMessage(task_id, detail) => {
                let mut doc = ProblemDocument::new_dap(DapProblemType::InvalidMessage);
                if let Some(task_id) = task_id {
                    doc = doc.with_task_id(task_id);
                }
                if !detail.is_empty() {
                    doc = doc.with_detail(detail);
                }
                doc.into_response()
            }
            Error::StepMismatch { task_id, .. } => {
                ProblemDocument::new_dap(DapProblemType::StepMismatch)
                    .with_task_id(task_id)
                    .into_response()
            }
            Error::UnrecognizedTask(task_id) => {
                ProblemDocument::new_dap(DapProblemType::UnrecognizedTask)
                    .with_task_id(task_id)
                    .into_response()
            }
            Error::UnrecognizedAggregationJob(task_id, _) => {
                ProblemDocument::new_dap(DapProblemType::UnrecognizedAggregationJob)
                    .with_task_id(task_id)
                    .into_response()
            }
            Error::UnrecognizedAggregateShareId(task_id, aggregate_share_id) => {
                ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#aggregate-share-id-unrecognized",
                    "The aggregate share ID is not recognized.",
                    StatusCode::NOT_FOUND,
                )
                .with_task_id(task_id)
                .with_aggregate_share_id(aggregate_share_id)
                .into_response()
            }
            Error::AbandonedAggregationJob(task_id, aggregation_job_id) => {
                ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#aggregation-job-abandoned",
                    "The aggregation job has been abandoned.",
                    StatusCode::GONE,
                )
                .with_task_id(task_id)
                .with_aggregation_job_id(aggregation_job_id)
                .into_response()
            }
            Error::DeletedAggregationJob(task_id, aggregation_job_id) => {
                ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#aggregation-job-deleted",
                    "The aggregation job has been deleted.",
                    StatusCode::GONE,
                )
                .with_task_id(task_id)
                .with_aggregation_job_id(aggregation_job_id)
                .into_response()
            }
            Error::DeletedCollectionJob(_, _) => StatusCode::NO_CONTENT.into_response(),
            Error::AbandonedCollectionJob(task_id, collection_job_id) => {
                ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#collection-job-abandoned",
                    "The collection job has been abandoned.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .with_detail(
                    "An internal problem has caused the server to stop processing this collection job. \
                    The job is no longer collectable. Contact the server operators for assistance.",
                )
                .with_task_id(task_id)
                .with_collection_job_id(collection_job_id)
                .into_response()
            }
            Error::UnrecognizedCollectionJob(_, _) => StatusCode::NOT_FOUND.into_response(),
            Error::UnauthorizedRequest(..) => StatusCode::FORBIDDEN.into_response(),
            Error::InvalidBatchSize(task_id, _) => {
                ProblemDocument::new_dap(DapProblemType::InvalidBatchSize)
                    .with_task_id(task_id)
                    .into_response()
            }
            Error::BatchInvalid(task_id, _) => {
                ProblemDocument::new_dap(DapProblemType::BatchInvalid)
                    .with_task_id(task_id)
                    .into_response()
            }
            Error::BatchOverlap(task_id, _) => {
                ProblemDocument::new_dap(DapProblemType::BatchOverlap)
                    .with_task_id(task_id)
                    .into_response()
            }
            Error::BatchMismatch(inner) => ProblemDocument::new_dap(DapProblemType::BatchMismatch)
                .with_task_id(&inner.task_id)
                .with_detail(&inner.to_string())
                .into_response(),
            Error::Datastore(error @ datastoreError::TimeUnaligned { task_id, .. }) => {
                ProblemDocument::new(
                    DapProblemType::InvalidMessage.type_uri(),
                    "Time unaligned.",
                    StatusCode::BAD_REQUEST,
                )
                .with_task_id(task_id)
                .with_detail(&error.to_string())
                .into_response()
            }
            Error::Datastore(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::Hpke(_)
            | Error::Vdaf(_)
            | Error::Internal(_)
            | Error::Url(_)
            | Error::Message(_)
            | Error::HttpClient(_)
            | Error::Http { .. }
            | Error::TaskParameters(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::AggregateShareRequestRejected(_, _) => StatusCode::BAD_REQUEST.into_response(),
            Error::EmptyAggregation(task_id) => {
                ProblemDocument::new_dap(DapProblemType::InvalidMessage)
                    .with_task_id(task_id)
                    .into_response()
            }
            Error::ForbiddenMutation { .. } => StatusCode::CONFLICT.into_response(),
            Error::BadContentType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
            Error::BadRequest(detail) => ProblemDocument::new(
                "about:blank",
                "Bad Request.",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(&detail.to_string())
            .into_response(),
            Error::InvalidTask(task_id, opt_out_reason) => {
                ProblemDocument::new_dap(DapProblemType::InvalidTask)
                    .with_task_id(task_id)
                    .with_detail(&format!("{opt_out_reason}"))
                    .into_response()
            }
            Error::DifferentialPrivacy(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::ClientDisconnected => StatusCode::BAD_REQUEST.into_response(),
            Error::TooManyRequests => ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#too-many-requests",
                "The server is currently overloaded.",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail(
                "The server is currently servicing too many requests, please try the request again \
                later.",
            )
            .to_response_with_retry_after(Some(RATE_LIMIT_RETRY_AFTER)),
            Error::RequestTimeout => ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#request-timeout",
                "Request timed out waiting in queue.",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail("The request spent too long waiting to be processed.")
            .to_response_with_retry_after(Some(RATE_LIMIT_RETRY_AFTER)),
        };

        if response.status().is_server_error() {
            warn!(error_code, ?self, "Error handling endpoint");
        }

        let mut response = response;
        response.extensions_mut().insert(AxumErrorCode(error_code));
        response
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.to_response()
    }
}

impl IntoResponse for ArcError {
    fn into_response(self) -> Response {
        let error: &Error = &self;
        error.to_response()
    }
}

/// The number of seconds we send in the Access-Control-Max-Age header. This determines for how
/// long clients will cache the results of CORS preflight requests. Of popular browsers, Mozilla
/// Firefox has the highest Max-Age cap, at 24 hours, so we use that. Our CORS preflight handlers
/// are tightly scoped to relevant endpoints, and our CORS settings are unlikely to change.
/// See: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age>.
const CORS_PREFLIGHT_CACHE_AGE: StdDuration = StdDuration::from_secs(24 * 60 * 60);

/// Wrapper around a type that implements [`Encode`], producing an HTTP response with the
/// encoded body, appropriate Content-Type, and status code.
struct EncodedBody<T> {
    object: T,
    media_type: &'static str,
    status: StatusCode,
}

impl<T> EncodedBody<T>
where
    T: Encode,
{
    fn new(object: T, media_type: &'static str) -> Self {
        Self {
            object,
            media_type,
            status: StatusCode::OK,
        }
    }

    fn with_status(self, status: StatusCode) -> Self {
        Self { status, ..self }
    }
}

impl<T: Encode> IntoResponse for EncodedBody<T> {
    fn into_response(self) -> Response {
        match self.object.get_encoded() {
            Ok(encoded) => (
                self.status,
                [(CONTENT_TYPE, HeaderValue::from_static(self.media_type))],
                encoded,
            )
                .into_response(),
            Err(e) => Error::MessageEncode(e).into_response(),
        }
    }
}

#[async_trait]
impl<T> Handler for EncodedBody<T>
where
    T: Encode + Sync + Send + 'static,
{
    async fn run(&self, conn: Conn) -> Conn {
        match self.object.get_encoded() {
            Ok(encoded) => conn
                .with_response_header(KnownHeaderName::ContentType, self.media_type)
                .with_status(self.status.as_u16())
                .with_body(encoded)
                .halt(),
            Err(e) => Error::MessageEncode(e).run(conn).await,
        }
    }
}

/// A Trillium handler that returns an empty body with retry-after and location headers.
#[derive(Clone)]
struct EmptyBody {
    location: String,
}

impl EmptyBody {
    /// Return an EmptyBody with the location set to the relative path to the
    /// aggregation job for the task.
    fn for_aggregation_job(
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        step: u16,
    ) -> Self {
        Self {
            location: format!("/tasks/{task_id}/aggregation_jobs/{aggregation_job_id}?step={step}"),
        }
    }
}

#[async_trait]
impl Handler for EmptyBody {
    async fn run(&self, conn: Conn) -> Conn {
        // To be fixed in issue #3921
        conn.with_response_header(KnownHeaderName::RetryAfter, "2")
            .with_response_header(KnownHeaderName::Location, self.location.clone())
            .with_status(Status::Ok)
            .halt()
    }
}

/// A Trillium handler that wraps the proxy and only forwards the request when no prior handler
/// (i.e. the Trillium router) has set a status on the conn. This prevents the proxy from
/// overriding responses from Trillium-handled routes.
// TODO(#4283): Remove when Trillium is fully removed.
struct ConditionalProxy<H>(H);

#[async_trait]
impl<H: Handler> Handler for ConditionalProxy<H> {
    async fn run(&self, conn: Conn) -> Conn {
        if conn.status().is_some() {
            return conn;
        }
        self.0.run(conn).await
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        self.0.before_send(conn).await
    }
}

/// A Trillium handler that checks for state set when sending an error response, and updates an
/// OpenTelemetry counter accordingly.
// TODO(#4283): Remove in favour of `http_metrics_middleware` when Trillium is fully removed.
struct StatusCounter(Counter<u64>);

impl StatusCounter {
    fn new(meter: &Meter) -> Self {
        Self(
            meter
                .u64_counter("janus_aggregator_responses")
                .with_description(
                    "Count of requests handled by the aggregator, by method, route, and response status.",
                )
                .with_unit("{request}")
                .build(),
        )
    }
}

#[async_trait]
impl Handler for StatusCounter {
    async fn run(&self, conn: Conn) -> Conn {
        conn
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        // Check for the error code set by the Error handler implementation.
        let error_code_opt = conn.state::<ErrorCode>().map(|error_code| error_code.0);
        let error_code = if let Some(status) = conn.status() {
            if status.is_client_error() || status.is_server_error() {
                error_code_opt.unwrap_or("unknown")
            } else {
                // Set the label to an empty string on success.
                ""
            }
        } else {
            // No status is set, it will fall back to 404.
            error_code_opt.unwrap_or("unknown")
        };
        // Fetch the method.
        let method = conn.method().as_str();
        // Check for the route set by the router.
        let route = conn
            .route()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_owned());
        self.0.add(
            1,
            &[
                KeyValue::new("method", method),
                KeyValue::new("route", route),
                KeyValue::new("error_code", error_code),
            ],
        );
        conn
    }
}

pub(crate) static AGGREGATION_JOB_ROUTE: &str =
    "tasks/:task_id/aggregation_jobs/:aggregation_job_id";
pub(crate) static COLLECTION_JOB_ROUTE: &str =
    "/tasks/{task_id}/collection_jobs/{collection_job_id}";
pub(crate) static AGGREGATE_SHARES_ROUTE: &str =
    "tasks/:task_id/aggregate_shares/:aggregate_share_id";

/// Parsed path parameters for aggregation job endpoints. Implements a custom Axum extractor that
/// parses path segments into typed IDs.
#[allow(dead_code)] // Will be used when aggregation job handlers migrate to axum.
struct AggregationJobPath {
    task_id: TaskId,
    aggregation_job_id: AggregationJobId,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct RawAggregationJobPath {
    task_id: String,
    aggregation_job_id: String,
}

impl<S: Send + Sync> FromRequestParts<S> for AggregationJobPath {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Path(raw) = Path::<RawAggregationJobPath>::from_request_parts(parts, state)
            .await
            .map_err(|e| Error::BadRequest(e.body_text().into()))?;
        let task_id = raw
            .task_id
            .parse()
            .map_err(|_| Error::BadRequest("invalid TaskId".into()))?;
        let aggregation_job_id = raw
            .aggregation_job_id
            .parse()
            .map_err(|_| Error::BadRequest("invalid AggregationJobId".into()))?;
        Ok(Self {
            task_id,
            aggregation_job_id,
        })
    }
}

/// Parsed path parameters for aggregate share endpoints. Implements a custom Axum extractor that
/// parses path segments into typed IDs.
#[allow(dead_code)] // Will be used when aggregate share handlers migrate to axum.
struct AggregateSharePath {
    task_id: TaskId,
    aggregate_share_id: AggregateShareId,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct RawAggregateSharePath {
    task_id: String,
    aggregate_share_id: String,
}

impl<S: Send + Sync> FromRequestParts<S> for AggregateSharePath {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Path(raw) = Path::<RawAggregateSharePath>::from_request_parts(parts, state)
            .await
            .map_err(|e| Error::BadRequest(e.body_text().into()))?;
        let task_id = raw
            .task_id
            .parse()
            .map_err(|_| Error::BadRequest("invalid TaskId".into()))?;
        let aggregate_share_id = raw
            .aggregate_share_id
            .parse()
            .map_err(|_| Error::BadRequest("invalid AggregateShareId".into()))?;
        Ok(Self {
            task_id,
            aggregate_share_id,
        })
    }
}

/// Parsed path parameters for collection job endpoints. Implements a custom Axum extractor that
/// parses path segments into typed IDs, de-duplicating validation across handlers.
struct CollectionJobPath {
    task_id: TaskId,
    collection_job_id: CollectionJobId,
}

#[derive(Deserialize)]
struct RawCollectionJobPath {
    task_id: String,
    collection_job_id: String,
}

impl<S: Send + Sync> FromRequestParts<S> for CollectionJobPath {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Path(raw) = Path::<RawCollectionJobPath>::from_request_parts(parts, state)
            .await
            .map_err(|e| Error::BadRequest(e.body_text().into()))?;
        let task_id = raw
            .task_id
            .parse()
            .map_err(|_| Error::BadRequest("invalid TaskId".into()))?;
        let collection_job_id = raw
            .collection_job_id
            .parse()
            .map_err(|_| Error::BadRequest("invalid CollectionJobId".into()))?;
        Ok(Self {
            task_id,
            collection_job_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperAggregationRequestQueue {
    pub depth: usize,
    pub concurrency: u32,
    /// Maximum lifespan, in milliseconds, of requests in the Request Queue.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

pub struct AggregatorHandlerBuilder<'a, C>
where
    C: Clock,
{
    aggregator: Arc<Aggregator<C>>,
    meter: &'a Meter,
    helper_aggregation_request_queue: Option<HelperAggregationRequestQueue>,
}

impl<'a, C> AggregatorHandlerBuilder<'a, C>
where
    C: Clock,
{
    pub async fn new<R>(
        datastore: Arc<Datastore<C>>,
        clock: C,
        runtime: R,
        meter: &'a Meter,
        cfg: Config,
    ) -> Result<Self, Error>
    where
        R: Runtime + Send + Sync + 'static,
    {
        let aggregator = Arc::new(Aggregator::new(datastore, clock, runtime, meter, cfg).await?);
        Ok(Self::from_aggregator(aggregator, meter))
    }

    pub fn from_aggregator(aggregator: Arc<Aggregator<C>>, meter: &'a Meter) -> Self {
        Self {
            aggregator,
            meter,
            helper_aggregation_request_queue: None,
        }
    }

    pub fn with_helper_aggregation_request_queue(
        self,
        harq: HelperAggregationRequestQueue,
    ) -> Self {
        Self {
            helper_aggregation_request_queue: Some(harq),
            ..self
        }
    }

    /// Build just the Axum router (without the Trillium wrapper and proxy). This is useful for
    /// tests that need to serve the axum router directly.
    pub fn build_axum_router(&self) -> axum::Router {
        let http_metrics = HttpMetrics::new(self.meter, "janus_aggregator_responses");

        let hpke_cors = CorsLayer::new()
            .allow_origin(AllowOrigin::mirror_request())
            .allow_methods([http::Method::GET])
            .max_age(CORS_PREFLIGHT_CACHE_AGE);

        let upload_cors = CorsLayer::new()
            .allow_origin(AllowOrigin::mirror_request())
            .allow_methods([http::Method::POST])
            .allow_headers([CONTENT_TYPE])
            .max_age(CORS_PREFLIGHT_CACHE_AGE);

        axum::Router::new()
            .route(
                "/hpke_config",
                axum::routing::get(axum_hpke_config::<C>).layer(hpke_cors),
            )
            .route(
                "/tasks/{task_id}/reports",
                post(upload_post::<C>).layer(upload_cors),
            )
            .route(
                COLLECTION_JOB_ROUTE,
                put(collection_jobs_put::<C>)
                    .get(collection_jobs_get::<C>)
                    .delete(collection_jobs_delete::<C>),
            )
            .with_state(Arc::clone(&self.aggregator))
            .layer(
                ServiceBuilder::new()
                    .layer(axum::Extension(http_metrics))
                    .layer(axum::middleware::from_fn(http_metrics_middleware))
                    .layer(trace_layer()),
            )
    }

    pub async fn build(self) -> Result<impl Handler, Error> {
        let helper_queue = self
            .helper_aggregation_request_queue
            .map(
                |HelperAggregationRequestQueue {
                     depth,
                     concurrency,
                     timeout_ms,
                 }| {
                    LIFORequestQueue::new(
                        concurrency,
                        depth,
                        self.meter,
                        "janus_helper",
                        timeout_ms.map(StdDuration::from_millis),
                    )
                },
            )
            .transpose()?
            .map(Arc::new);

        let router = Router::new()
            .without_options_handling()
            .put(
                AGGREGATION_JOB_ROUTE,
                instrumented(if let Some(ref queue) = helper_queue {
                    Box::new(queued_lifo(
                        Arc::clone(queue),
                        api(aggregation_jobs_put::<C>),
                    )) as Box<dyn Handler>
                } else {
                    Box::new(api(aggregation_jobs_put::<C>)) as Box<dyn Handler>
                }),
            )
            .post(
                AGGREGATION_JOB_ROUTE,
                instrumented(if let Some(ref queue) = helper_queue {
                    Box::new(queued_lifo(
                        Arc::clone(queue),
                        api(aggregation_jobs_post::<C>),
                    )) as Box<dyn Handler>
                } else {
                    Box::new(api(aggregation_jobs_post::<C>)) as Box<dyn Handler>
                }),
            )
            .get(
                AGGREGATION_JOB_ROUTE,
                instrumented(api(aggregation_jobs_get::<C>)),
            )
            .delete(
                AGGREGATION_JOB_ROUTE,
                instrumented(api(aggregation_jobs_delete::<C>)),
            )
            .put(
                AGGREGATE_SHARES_ROUTE,
                instrumented(api(aggregate_shares_put::<C>)),
            )
            .get(
                AGGREGATE_SHARES_ROUTE,
                instrumented(api(aggregate_shares_get::<C>)),
            )
            .delete(
                AGGREGATE_SHARES_ROUTE,
                instrumented(api(aggregate_shares_delete::<C>)),
            );

        let metrics = Metrics::new(self.meter.clone())
            .with_route(|conn| {
                conn.route()
                    .map(|route_spec| Cow::Owned(route_spec.to_string()))
            })
            .with_error_type(|conn| {
                conn.state::<ErrorCode>()
                    .map(|error_code| Cow::Borrowed(error_code.0))
            })
            .with_duration_histogram_boundaries(TIME_HISTOGRAM_BOUNDARIES.to_vec())
            .with_request_size_histogram_boundaries(BYTES_HISTOGRAM_BOUNDARIES.to_vec())
            .with_response_size_histogram_boundaries(BYTES_HISTOGRAM_BOUNDARIES.to_vec());

        let axum_router = self.build_axum_router();

        // Bind a local listener for the axum router and spawn it.
        let axum_listener = tokio::net::TcpListener::bind("localhost:0")
            .await
            .map_err(|err| Error::Internal(format!("binding axum listener: {err}").into()))?;
        let axum_address = axum_listener.local_addr().map_err(|err| {
            Error::Internal(format!("getting axum listener address: {err}").into())
        })?;
        tokio::spawn(async move {
            axum::serve(axum_listener, axum_router).await.ok();
        });

        // Proxy fallback: routes not matched by the Trillium router are forwarded to
        // the local axum server. As endpoints migrate, they are removed from the
        // Trillium router and added to the axum router; the proxy transparently
        // forwards traffic to them. We use `proxy_not_found()` so that axum's
        // intentional 404 responses (e.g. for missing collection jobs) are forwarded
        // back to the client rather than being swallowed by the proxy.
        let upstream = format!("http://{axum_address}/").into_upstream();
        let proxy = Proxy::new(
            trillium_proxy::Client::new(trillium_tokio::ClientConfig::default())
                .with_default_pool(),
            upstream,
        )
        .proxy_not_found();

        Ok((
            State(self.aggregator),
            metrics,
            router,
            StatusCounter::new(self.meter),
            ConditionalProxy(proxy),
        ))
    }
}

const HPKE_CONFIG_SIGNATURE_HEADER: &str = "x-hpke-config-signature";

/// Axum handler for the "/hpke_config" GET endpoint.
async fn axum_hpke_config<C: Clock>(
    AxumState(aggregator): AxumState<Arc<Aggregator<C>>>,
) -> Result<Response, Error> {
    let (encoded_hpke_config_list, signature) = aggregator.handle_hpke_config().await?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(HpkeConfigList::MEDIA_TYPE),
    );
    response_headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=86400"),
    );

    if let Some(signature) = signature {
        response_headers.insert(
            HeaderName::from_static(HPKE_CONFIG_SIGNATURE_HEADER),
            // Unwrap safety: base64 encoding only produces printable ASCII characters
            HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(signature)).unwrap(),
        );
    }

    Ok((StatusCode::OK, response_headers, encoded_hpke_config_list).into_response())
}

/// Streams reports decoded from an async reader. This function reads the body in chunks and
/// yields reports as soon as they're fully decoded. When a chunk boundary falls in the middle
/// of a report, the incomplete bytes are buffered until the next chunk arrives.
///
/// This method is pub(super) so that its tests can reside in tests/report.rs.
pub(super) fn decode_reports_stream<R>(mut body: R) -> impl Stream<Item = Result<Report, Error>>
where
    R: AsyncRead + Unpin,
{
    async_stream::try_stream! {
        const CHUNK_SIZE: usize = 64 * 1024;
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let mut buffer: VecDeque<u8> = VecDeque::with_capacity(CHUNK_SIZE);

        loop {
            // Read a chunk from the body (reusing the same buffer)
            let bytes_read = body.read(&mut chunk).await
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::TimedOut => Error::ClientDisconnected,
                    _ => Error::BadRequest(e.into()),
                })?;

            if bytes_read == 0 {
                if !buffer.is_empty() {
                    Err(Error::MessageDecode(CodecError::BytesLeftOver(buffer.len())))?;
                }
                break;
            }

            buffer.extend(&chunk[..bytes_read]);
            buffer.make_contiguous();
            let (contiguous_slice, _) = buffer.as_slices();
            let mut cursor = Cursor::new(contiguous_slice);
            let mut bytes_consumed = 0;

            loop {
                match Report::decode(&mut cursor) {
                    Ok(report) => {
                        bytes_consumed = cursor.position() as usize;
                        yield report;
                    }
                    Err(decode_error) => match decode_error {
                        CodecError::LengthPrefixTooBig(_) => {
                            // Incomplete report - insufficient remaining bytes in the buffer
                            break;
                        }
                        CodecError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            // Incomplete report - we didn't make it to the end
                            break;
                        }
                        _ => {
                            Err(Error::MessageDecode(decode_error))?
                        }
                    }
                }
            }

            // Remove decoded bytes from buffer, keeping incomplete report data
            buffer.drain(..bytes_consumed);
        }
    }
}

/// Axum handler for the "/tasks/{task_id}/reports" POST endpoint.
async fn upload_post<C: Clock>(
    headers: HeaderMap,
    Path(task_id): Path<String>,
    AxumState(aggregator): AxumState<Arc<Aggregator<C>>>,
    body: Body,
) -> Result<Response, Error> {
    validate_content_type_headers::<UploadRequest>(&headers)?;

    let task_id: TaskId = task_id
        .parse()
        .map_err(|_| Error::BadRequest("invalid TaskId".into()))?;

    let body_reader = body
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionReset, e))
        .into_async_read();

    let upload_errors = match aggregator
        .handle_upload(&task_id, decode_reports_stream(body_reader))
        .await
    {
        Ok(upload_errors) => upload_errors,
        Err(arc_err) => return Ok(ArcError::from(arc_err).into_response()),
    };

    let response = if upload_errors.status().is_empty() {
        // If all reports were successfully uploaded, the response has no body.
        StatusCode::OK.into_response()
    } else {
        EncodedBody::new(upload_errors, UploadErrors::MEDIA_TYPE)
            .with_status(StatusCode::OK)
            .into_response()
    };

    Ok(response)
}

/// API handler for the "/tasks/.../aggregation_jobs/..." PUT endpoint.
async fn aggregation_jobs_put<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<Result<EncodedBody<AggregationJobResp>, EmptyBody>, Error> {
    validate_content_type::<AggregationJobInitializeReq<TimeInterval>>(conn)?;

    let task_id = parse_task_id(conn)?;
    let aggregation_job_id = parse_aggregation_job_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let response = conn
        .cancel_on_disconnect(aggregator.handle_aggregate_init(
            &task_id,
            &aggregation_job_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        ))
        .await
        .ok_or(Error::ClientDisconnected)??;

    match response {
        Some(response) => Ok(Ok(EncodedBody::new(
            response,
            AggregationJobResp::MEDIA_TYPE,
        )
        .with_status(StatusCode::CREATED))),
        None => Ok(Err(EmptyBody::for_aggregation_job(
            &task_id,
            &aggregation_job_id,
            0,
        ))),
    }
}

/// API handler for the "/tasks/.../aggregation_jobs/..." POST endpoint.
async fn aggregation_jobs_post<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<Result<EncodedBody<AggregationJobResp>, EmptyBody>, Error> {
    validate_content_type::<AggregationJobContinueReq>(conn)?;

    let task_id = parse_task_id(conn)?;
    let aggregation_job_id = parse_aggregation_job_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let response = conn
        .cancel_on_disconnect(aggregator.handle_aggregate_continue(
            &task_id,
            &aggregation_job_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        ))
        .await
        .ok_or(Error::ClientDisconnected)??;

    match response {
        AggregationJobContinueResult::Sync(resp) => {
            Ok(Ok(EncodedBody::new(resp, AggregationJobResp::MEDIA_TYPE)
                .with_status(StatusCode::ACCEPTED)))
        }
        AggregationJobContinueResult::Async(step) => Ok(Err(EmptyBody::for_aggregation_job(
            &task_id,
            &aggregation_job_id,
            step.into(),
        ))),
    }
}

/// API handler for the "/tasks/.../aggregation_jobs/..." GET endpoint.
async fn aggregation_jobs_get<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<Result<EncodedBody<AggregationJobResp>, EmptyBody>, Error> {
    let task_id = parse_task_id(conn)?;
    let aggregation_job_id = parse_aggregation_job_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let step = parse_step(conn)?
        .ok_or_else(|| Error::BadRequest("missing step query parameter".into()))?;

    let response = conn
        .cancel_on_disconnect(aggregator.handle_aggregate_get(
            &task_id,
            &aggregation_job_id,
            auth_token,
            taskprov_task_config.as_ref(),
            step,
        ))
        .await
        .ok_or(Error::ClientDisconnected)??;

    match response {
        Some(response) => Ok(Ok(EncodedBody::new(
            response,
            AggregationJobResp::MEDIA_TYPE,
        )
        .with_status(StatusCode::OK))),
        None => Ok(Err(EmptyBody::for_aggregation_job(
            &task_id,
            &aggregation_job_id,
            step.into(),
        ))),
    }
}

/// API handler for the "/tasks/.../aggregation_jobs/..." DELETE endpoint.
async fn aggregation_jobs_delete<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<Status, Error> {
    let task_id = parse_task_id(conn)?;
    let aggregation_job_id = parse_aggregation_job_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;

    conn.cancel_on_disconnect(aggregator.handle_aggregate_delete(
        &task_id,
        &aggregation_job_id,
        auth_token,
        taskprov_task_config.as_ref(),
    ))
    .await
    .ok_or(Error::ClientDisconnected)??;
    Ok(Status::NoContent)
}

/// Axum handler for the "/tasks/.../collection_jobs/..." PUT endpoint.
async fn collection_jobs_put<C: Clock>(
    headers: HeaderMap,
    path: CollectionJobPath,
    AxumState(aggregator): AxumState<Arc<Aggregator<C>>>,
    body: Bytes,
) -> Result<Response, Error> {
    validate_content_type_headers::<CollectionJobReq<TimeInterval>>(&headers)?;

    let auth_token = parse_auth_token_from_headers(&path.task_id, &headers)?;
    let response_bytes = aggregator
        .handle_create_collection_job(&path.task_id, &path.collection_job_id, &body, auth_token)
        .await?;

    Ok((
        StatusCode::CREATED,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(CollectionJobResp::<TimeInterval>::MEDIA_TYPE),
        )],
        response_bytes,
    )
        .into_response())
}

/// Axum handler for the "/tasks/.../collection_jobs/..." GET endpoint.
async fn collection_jobs_get<C: Clock>(
    headers: HeaderMap,
    path: CollectionJobPath,
    AxumState(aggregator): AxumState<Arc<Aggregator<C>>>,
) -> Result<Response, Error> {
    let auth_token = parse_auth_token_from_headers(&path.task_id, &headers)?;
    let response_bytes = aggregator
        .handle_get_collection_job(&path.task_id, &path.collection_job_id, auth_token)
        .await?;

    Ok((
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(CollectionJobResp::<TimeInterval>::MEDIA_TYPE),
        )],
        response_bytes,
    )
        .into_response())
}

/// Axum handler for the "/tasks/.../collection_jobs/..." DELETE endpoint.
async fn collection_jobs_delete<C: Clock>(
    headers: HeaderMap,
    path: CollectionJobPath,
    AxumState(aggregator): AxumState<Arc<Aggregator<C>>>,
) -> Result<StatusCode, Error> {
    let auth_token = parse_auth_token_from_headers(&path.task_id, &headers)?;
    aggregator
        .handle_delete_collection_job(&path.task_id, &path.collection_job_id, auth_token)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// API handler for the "/tasks/.../aggregate_shares/:aggregate_share_id" PUT endpoint.
async fn aggregate_shares_put<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<EncodedBody<AggregateShare>, Error> {
    validate_content_type::<AggregateShareReq<TimeInterval>>(conn)?;

    let task_id = parse_task_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let aggregate_share_id = parse_aggregate_share_id(conn)?;
    let share = conn
        .cancel_on_disconnect(aggregator.handle_put_aggregate_share(
            &task_id,
            &aggregate_share_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        ))
        .await
        .ok_or(Error::ClientDisconnected)??;

    Ok(EncodedBody::new(share, AggregateShare::MEDIA_TYPE))
}

/// API handler for the "/tasks/.../aggregate_shares/:aggregate_share_id" GET endpoint.
async fn aggregate_shares_get<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<EncodedBody<AggregateShare>, Error> {
    let task_id = parse_task_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let aggregate_share_id = parse_aggregate_share_id(conn)?;
    let share = conn
        .cancel_on_disconnect(aggregator.handle_get_aggregate_share(
            &task_id,
            &aggregate_share_id,
            auth_token,
            taskprov_task_config.as_ref(),
        ))
        .await
        .ok_or(Error::ClientDisconnected)??;

    Ok(EncodedBody::new(share, AggregateShare::MEDIA_TYPE))
}

/// API handler for the "/tasks/.../aggregate_shares/:aggregate_share_id" DELETE endpoint.
async fn aggregate_shares_delete<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<(), Error> {
    let task_id = parse_task_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let aggregate_share_id = parse_aggregate_share_id(conn)?;
    conn.cancel_on_disconnect(aggregator.handle_delete_aggregate_share(
        &task_id,
        &aggregate_share_id,
        auth_token,
        taskprov_task_config.as_ref(),
    ))
    .await
    .ok_or(Error::ClientDisconnected)??;

    conn.set_status(Status::NoContent);
    Ok(())
}

/// Check the request's Content-Type header, and return an error if its MIME essence or its
/// `message` parameter do not match those expected for messages of type `M`. The header may have
/// other parameters in it; this function does not check them.
fn validate_content_type_headers<M: MediaType>(headers: &HeaderMap) -> Result<(), Error> {
    check_content_type::<M>(headers).map_err(|e| Error::BadRequest(e.into()))
}

/// Validates the Content-Type of the request against `M` (Trillium adapter).
fn validate_content_type<M: MediaType>(conn: &Conn) -> Result<(), Error> {
    let content_type = conn
        .request_headers()
        .get(KnownHeaderName::ContentType)
        .ok_or_else(|| Error::BadRequest("no Content-Type header".into()))?;

    // For whatever, reason, HeaderValue::as_str doesn't work when content types include parameters
    // so we get the value bytes and parse into a `Mime` ourselves.
    let request_mime: Mime = str::from_utf8(content_type.as_ref())
        .map_err(|_| {
            Error::BadRequest(format!("invalid Content-Type header: {content_type}").into())
        })?
        .parse()
        .context("failed to parse Content-Type header")
        .map_err(|e| Error::BadRequest(e.into()))?;

    check_content_type_value::<M>(request_mime).map_err(|e| Error::BadRequest(e.into()))
}

/// Parse a [`TaskId`] from the "task_id" parameter in a set of path parameter
fn parse_task_id(conn: &Conn) -> Result<TaskId, Error> {
    let encoded = conn
        .param("task_id")
        .ok_or_else(|| Error::Internal("task_id parameter is missing from captures".into()))?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid TaskId".into()))
}

/// Parse an [`AggregationJobId`] from the "aggregation_job_id" parameter in a set of path parameter
fn parse_aggregation_job_id(conn: &Conn) -> Result<AggregationJobId, Error> {
    let encoded = conn.param("aggregation_job_id").ok_or_else(|| {
        Error::Internal("aggregation_job_id parameter is missing from captures".into())
    })?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid AggregationJobId".into()))
}

/// Parse an [`AggregateShareId`] from the "aggregate_share_id" parameter in a set of path
/// parameters.
fn parse_aggregate_share_id(conn: &Conn) -> Result<AggregateShareId, Error> {
    let encoded = conn.param("aggregate_share_id").ok_or_else(|| {
        Error::Internal("aggregate_share_id parameter is missing from captures".into())
    })?;
    encoded
        .parse()
        .map_err(|e| Error::BadRequest(format!("invalid aggregate share ID in path: {e}").into()))
}

/// Get an [`AuthenticationToken`] from the request, using `http::HeaderMap`.
fn parse_auth_token_from_headers(
    task_id: &TaskId,
    headers: &HeaderMap,
) -> Result<Option<AuthenticationToken>, Error> {
    // Prefer a bearer token, then fall back to DAP-Auth-Token
    if let Some(bearer_token) =
        extract_bearer_token(headers).map_err(|_| Error::UnauthorizedRequest(*task_id))?
    {
        return Ok(Some(bearer_token));
    }

    headers
        .get(DAP_AUTH_HEADER)
        .map(|value| {
            AuthenticationToken::new_dap_auth_token_from_bytes(value.as_bytes())
                .context("bad DAP-Auth-Token header")
                .map_err(|e| Error::BadRequest(e.into()))
        })
        .transpose()
}

/// Get an [`AuthenticationToken`] from the request (Trillium adapter).
fn parse_auth_token(task_id: &TaskId, conn: &Conn) -> Result<Option<AuthenticationToken>, Error> {
    // Build an http::HeaderMap with just the auth-related headers from the Trillium conn.
    let mut headers = HeaderMap::new();
    if let Some(auth) = conn.request_headers().get("authorization") {
        if let Ok(value) = HeaderValue::from_bytes(auth.as_ref()) {
            headers.insert(http::header::AUTHORIZATION, value);
        }
    }
    if let Some(dap_auth) = conn.request_headers().get(DAP_AUTH_HEADER) {
        if let Ok(value) = HeaderValue::from_bytes(dap_auth.as_ref()) {
            headers.insert(DAP_AUTH_HEADER, value);
        }
    }
    parse_auth_token_from_headers(task_id, &headers)
}

/// Parse the taskprov header from an `http::HeaderMap`.
fn parse_taskprov_header_from_headers<C: Clock>(
    aggregator: &Aggregator<C>,
    task_id: &TaskId,
    headers: &HeaderMap,
) -> Result<Option<TaskConfig>, Error> {
    if !aggregator.cfg.taskprov_config.enabled {
        return Ok(None);
    }

    let taskprov_header = match headers.get(TASKPROV_HEADER) {
        Some(taskprov_header) => taskprov_header,
        None => return Ok(None),
    };

    let task_config_encoded = URL_SAFE_NO_PAD.decode(taskprov_header).map_err(|_| {
        Error::InvalidMessage(
            Some(*task_id),
            "taskprov header could not be base64-decoded",
        )
    })?;

    // Compute expected task ID & verify it matches the task ID from the request.
    let expected_task_id = taskprov_task_id(&task_config_encoded);
    if task_id != &expected_task_id {
        return Err(Error::InvalidMessage(
            Some(*task_id),
            "derived taskprov task ID does not match task config",
        ));
    }

    // TODO(#1684): Parsing the taskprov header like this before we've been able to actually
    // authenticate the client is undesireable. We should rework this such that the authorization
    // header is handled before parsing the untrusted input.
    Ok(Some(
        TaskConfig::get_decoded(&task_config_encoded).map_err(Error::MessageDecode)?,
    ))
}

/// Parse the taskprov header from a Trillium connection (delegates to
/// [`parse_taskprov_header_from_headers`]).
fn parse_taskprov_header<C: Clock>(
    aggregator: &Aggregator<C>,
    task_id: &TaskId,
    conn: &Conn,
) -> Result<Option<TaskConfig>, Error> {
    let mut headers = HeaderMap::new();
    if let Some(val) = conn.request_headers().get(TASKPROV_HEADER) {
        if let Ok(hv) = HeaderValue::from_bytes(val.as_ref()) {
            headers.insert(TASKPROV_HEADER, hv);
        }
    }
    parse_taskprov_header_from_headers(aggregator, task_id, &headers)
}

/// Gets the [`AggregationJobStep`] from a raw query string.
fn parse_step_from_query(query: Option<&str>) -> Result<Option<AggregationJobStep>, Error> {
    const STEP_KEY: &str = "step";
    let query = match query {
        Some(q) => q,
        None => return Ok(None),
    };
    querify(query)
        .into_iter()
        .find(|(key, _)| *key == STEP_KEY)
        .map(|(_, val)| val.parse::<u16>().map(AggregationJobStep::from))
        .transpose()
        .map_err(|err| Error::BadRequest(format!("couldn't parse step: {err}").into()))
}

/// Gets the [`AggregationJobStep`] from the request's query string (Trillium adapter).
fn parse_step(conn: &Conn) -> Result<Option<AggregationJobStep>, Error> {
    parse_step_from_query(Some(conn.querystring()))
}

struct BodyBytes(Vec<u8>);

#[async_trait]
impl TryFromConn for BodyBytes {
    type Error = Error;

    async fn try_from_conn(conn: &mut Conn) -> Result<Self, Self::Error> {
        conn.request_body()
            .await
            .read_bytes()
            .await
            .map(BodyBytes)
            .map_err(|error| match error {
                trillium::Error::Io(_) | trillium::Error::Closed => Error::ClientDisconnected,
                _ => Error::BadRequest(error.into()),
            })
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use std::sync::Arc;

    use janus_aggregator_core::{
        datastore::{
            Datastore,
            test_util::{EphemeralDatastore, ephemeral_datastore},
        },
        test_util::noop_meter,
    };
    use janus_core::{
        hpke::HpkeKeypair,
        initialize_rustls,
        test_util::{install_test_trace_subscriber, runtime::TestRuntime},
        time::MockClock,
    };
    use janus_messages::codec::Decode;
    use trillium::Handler;
    use trillium_testing::{TestConn, assert_headers};

    use super::AggregatorHandlerBuilder;
    use crate::aggregator::test_util::default_aggregator_config;

    pub async fn take_response_body(test_conn: &mut TestConn) -> Vec<u8> {
        test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap()
            .into_owned()
    }

    pub async fn decode_response_body<T: Decode>(test_conn: &mut TestConn) -> T {
        T::get_decoded(&take_response_body(test_conn).await).unwrap()
    }

    pub async fn take_problem_details(test_conn: &mut TestConn) -> serde_json::Value {
        assert_headers!(&test_conn, "content-type" => "application/problem+json");
        serde_json::from_slice(&take_response_body(test_conn).await).unwrap()
    }

    /// Contains structures necessary for completing an HTTP handler test. The contained
    /// [`EphemeralDatastore`] should be given a variable binding to prevent it being prematurely
    /// dropped.
    pub struct HttpHandlerTest {
        pub clock: MockClock,
        pub ephemeral_datastore: EphemeralDatastore,
        pub datastore: Arc<Datastore<MockClock>>,
        pub handler: Box<dyn Handler>,
        pub hpke_keypair: HpkeKeypair,
    }

    impl HttpHandlerTest {
        pub async fn new() -> Self {
            install_test_trace_subscriber();
            initialize_rustls();
            let clock = MockClock::default();
            let ephemeral_datastore = ephemeral_datastore().await;
            let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

            let hpke_keypair = datastore.put_hpke_key().await.unwrap();

            let handler = AggregatorHandlerBuilder::new(
                datastore.clone(),
                clock.clone(),
                TestRuntime::default(),
                &noop_meter(),
                default_aggregator_config(),
            )
            .await
            .unwrap()
            // Shake out any bugs with helper request queuing.
            .with_helper_aggregation_request_queue(super::HelperAggregationRequestQueue {
                depth: 16,
                concurrency: 2,
                timeout_ms: None,
            })
            .build()
            .await
            .unwrap();

            Self {
                clock,
                ephemeral_datastore,
                datastore,
                handler: Box::new(handler),
                hpke_keypair,
            }
        }
    }
}
