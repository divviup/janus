use std::{collections::VecDeque, io::Cursor, sync::Arc, time::Duration as StdDuration};

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures::{
    TryStreamExt,
    io::{AsyncRead, AsyncReadExt},
    stream::Stream,
};
use http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE};
use janus_aggregator_core::{
    ErrorCode, HttpMetrics,
    datastore::{Datastore, Error as datastoreError},
    http_metrics_middleware,
    taskprov::taskprov_task_id,
};
use janus_core::{
    Runtime,
    auth_tokens::{AuthenticationToken, DAP_AUTH_HEADER},
    http::{check_content_type, extract_bearer_token},
    taskprov::TASKPROV_HEADER,
    time::Clock,
};
use janus_messages::{
    AggregateShare, AggregateShareId, AggregateShareReq, AggregationJobContinueReq,
    AggregationJobId, AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep,
    CollectionJobId, CollectionJobReq, CollectionJobResp, HpkeConfigList, MediaType, Report,
    TaskId, UploadRequest, UploadResponse, batch_mode::TimeInterval, codec::Decode,
    problem_type::DapProblemType, taskprov::TaskConfig,
};
use opentelemetry::metrics::Meter;
use prio::codec::{CodecError, Encode};
use querystring::querify;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing::warn;

use super::{
    Aggregator, Config, Error,
    error::ArcError,
    queue::{self, LIFORequestQueue},
};
use crate::aggregator::{AggregationJobContinueResult, problem_details::ProblemDocument};

#[cfg(test)]
mod tests;

/// The number of seconds we send in the Access-Control-Max-Age header. This determines for how
/// long clients will cache the results of CORS preflight requests.
const CORS_PREFLIGHT_CACHE_AGE: StdDuration = StdDuration::from_secs(24 * 60 * 60);

/// Default retry-after for rate limiting responses.
const RATE_LIMIT_RETRY_AFTER: StdDuration = StdDuration::from_secs(30);

/// Implement IntoResponse for Error, converting DAP errors to problem details responses.
impl Error {
    fn to_response(&self) -> Response {
        let error_code = self.error_code();
        let response = match self {
            Error::InvalidConfiguration(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::MessageDecode(_) => {
                (&ProblemDocument::new_dap(DapProblemType::InvalidMessage)).into_response()
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
                (&doc).into_response()
            }
            Error::StepMismatch { task_id, .. } => {
                (&ProblemDocument::new_dap(DapProblemType::StepMismatch).with_task_id(task_id))
                    .into_response()
            }
            Error::UnrecognizedTask(task_id) => {
                (&ProblemDocument::new_dap(DapProblemType::UnrecognizedTask).with_task_id(task_id))
                    .into_response()
            }
            Error::UnrecognizedAggregationJob(task_id, _) => {
                (&ProblemDocument::new_dap(DapProblemType::UnrecognizedAggregationJob)
                    .with_task_id(task_id))
                    .into_response()
            }
            Error::UnrecognizedAggregateShareId(task_id, aggregate_share_id) => {
                (&ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#aggregate-share-id-unrecognized",
                    "The aggregate share ID is not recognized.",
                    StatusCode::NOT_FOUND,
                )
                .with_task_id(task_id)
                .with_aggregate_share_id(aggregate_share_id))
                    .into_response()
            }
            Error::AbandonedAggregationJob(task_id, aggregation_job_id) => {
                (&ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#aggregation-job-abandoned",
                    "The aggregation job has been abandoned.",
                    StatusCode::GONE,
                )
                .with_task_id(task_id)
                .with_aggregation_job_id(aggregation_job_id))
                    .into_response()
            }
            Error::DeletedAggregationJob(task_id, aggregation_job_id) => {
                (&ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#aggregation-job-deleted",
                    "The aggregation job has been deleted.",
                    StatusCode::GONE,
                )
                .with_task_id(task_id)
                .with_aggregation_job_id(aggregation_job_id))
                    .into_response()
            }
            Error::DeletedCollectionJob(_, _) => StatusCode::NO_CONTENT.into_response(),
            Error::AbandonedCollectionJob(task_id, collection_job_id) => {
                (&ProblemDocument::new(
                    "https://docs.divviup.org/references/janus-errors#collection-job-abandoned",
                    "The collection job has been abandoned.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .with_detail(
                    "An internal problem has caused the server to stop processing this collection job. \
                    The job is no longer collectable. Contact the server operators for assistance.",
                )
                .with_task_id(task_id)
                .with_collection_job_id(collection_job_id))
                    .into_response()
            }
            Error::UnrecognizedCollectionJob(_, _) => StatusCode::NOT_FOUND.into_response(),
            Error::UnauthorizedRequest(..) => StatusCode::FORBIDDEN.into_response(),
            Error::InvalidBatchSize(task_id, _) => {
                (&ProblemDocument::new_dap(DapProblemType::InvalidBatchSize).with_task_id(task_id))
                    .into_response()
            }
            Error::BatchInvalid(task_id, _) => {
                (&ProblemDocument::new_dap(DapProblemType::BatchInvalid).with_task_id(task_id))
                    .into_response()
            }
            Error::BatchOverlap(task_id, _) => {
                (&ProblemDocument::new_dap(DapProblemType::BatchOverlap).with_task_id(task_id))
                    .into_response()
            }
            Error::BatchMismatch(inner) => (&ProblemDocument::new_dap(DapProblemType::BatchMismatch)
                .with_task_id(&inner.task_id)
                .with_detail(&inner.to_string()))
                .into_response(),
            Error::Datastore(error @ datastoreError::TimeUnaligned { task_id, .. }) => {
                (&ProblemDocument::new(
                    DapProblemType::InvalidMessage.type_uri(),
                    "Time unaligned.",
                    StatusCode::BAD_REQUEST,
                )
                .with_task_id(task_id)
                .with_detail(&error.to_string()))
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
                (&ProblemDocument::new_dap(DapProblemType::InvalidMessage).with_task_id(task_id))
                    .into_response()
            }
            Error::ForbiddenMutation { .. } => StatusCode::CONFLICT.into_response(),
            Error::BadContentType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
            Error::BadRequest(detail) => (&ProblemDocument::new(
                "about:blank",
                "Bad Request.",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(&detail.to_string()))
                .into_response(),
            Error::InvalidTask(task_id, opt_out_reason) => {
                (&ProblemDocument::new_dap(DapProblemType::InvalidTask)
                    .with_task_id(task_id)
                    .with_detail(&format!("{opt_out_reason}")))
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
            .into_response_with_retry_after(Some(RATE_LIMIT_RETRY_AFTER)),
            Error::RequestTimeout => ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#request-timeout",
                "Request timed out waiting in queue.",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail("The request spent too long waiting to be processed.")
            .into_response_with_retry_after(Some(RATE_LIMIT_RETRY_AFTER)),
        };

        if response.status().is_server_error() {
            warn!(error_code, ?self, "Error handling endpoint");
        }

        // Store the error code in response extensions for metrics middleware.
        let mut response = response;
        response.extensions_mut().insert(ErrorCode(error_code));
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

/// Wrapper around a type that implements [`Encode`], producing an HTTP response with the
/// encoded body, appropriate Content-Type, and status code.
struct EncodedBody<T> {
    object: T,
    media_type: &'static str,
    status: StatusCode,
}

impl<T: Encode> EncodedBody<T> {
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

/// A response type that returns an empty body with retry-after and location headers.
#[derive(Clone)]
struct EmptyBody {
    location: String,
}

impl EmptyBody {
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

impl IntoResponse for EmptyBody {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            [
                (http::header::RETRY_AFTER, "2".to_string()),
                (http::header::LOCATION, self.location),
            ],
        )
            .into_response()
    }
}

pub(crate) static AGGREGATION_JOB_ROUTE: &str =
    "/tasks/{task_id}/aggregation_jobs/{aggregation_job_id}";
pub(crate) static COLLECTION_JOB_ROUTE: &str =
    "/tasks/{task_id}/collection_jobs/{collection_job_id}";
pub(crate) static AGGREGATE_SHARES_ROUTE: &str =
    "/tasks/{task_id}/aggregate_shares/{aggregate_share_id}";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperAggregationRequestQueue {
    pub depth: usize,
    pub concurrency: u32,
    /// Maximum lifespan, in milliseconds, of requests in the Request Queue.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Shared application state for the aggregator.
pub(crate) struct AggregatorState<C: Clock> {
    pub(crate) aggregator: Arc<Aggregator<C>>,
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

    pub fn build(self) -> Result<Router, Error> {
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

        let http_metrics = HttpMetrics::new(self.meter, "janus_aggregator_responses");

        let state = Arc::new(AggregatorState {
            aggregator: Arc::clone(&self.aggregator),
        });

        // CORS layers for public endpoints
        let hpke_cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([http::Method::GET])
            .max_age(CORS_PREFLIGHT_CACHE_AGE);

        let upload_cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([http::Method::POST])
            .allow_headers([CONTENT_TYPE])
            .max_age(CORS_PREFLIGHT_CACHE_AGE);

        // Build aggregation job routes, optionally with LIFO queue middleware for
        // back-pressure and load-shedding on helpers.
        let aggregation_job_routes = Router::new().route(
            AGGREGATION_JOB_ROUTE,
            put(aggregation_jobs_put::<C>)
                .post(aggregation_jobs_post::<C>)
                .get(aggregation_jobs_get::<C>)
                .delete(aggregation_jobs_delete::<C>),
        );
        let aggregation_job_routes = if let Some(queue) = helper_queue {
            aggregation_job_routes.layer(middleware::from_fn_with_state(
                queue,
                queue::lifo_queue_middleware,
            ))
        } else {
            aggregation_job_routes
        };

        let router = Router::new()
            .route("/hpke_config", get(hpke_config::<C>).layer(hpke_cors))
            .route(
                "/tasks/{task_id}/reports",
                post(upload::<C>).layer(upload_cors),
            )
            .merge(aggregation_job_routes)
            .route(
                COLLECTION_JOB_ROUTE,
                put(collection_jobs_put::<C>)
                    .get(collection_jobs_get::<C>)
                    .delete(collection_jobs_delete::<C>),
            )
            .route(
                AGGREGATE_SHARES_ROUTE,
                put(aggregate_shares_put::<C>)
                    .get(aggregate_shares_get::<C>)
                    .delete(aggregate_shares_delete::<C>),
            )
            // In axum, the last .layer() is outermost. Extension must be outermost
            // so the HttpMetrics value is available when the metrics middleware runs.
            .layer(middleware::from_fn(http_metrics_middleware))
            .layer(axum::Extension(http_metrics))
            .with_state(state);

        Ok(router)
    }
}

const HPKE_CONFIG_SIGNATURE_HEADER: &str = "x-hpke-config-signature";

/// API handler for the "/hpke_config" GET endpoint.
async fn hpke_config<C: Clock>(
    State(state): State<Arc<AggregatorState<C>>>,
) -> Result<Response, Error> {
    let (encoded_hpke_config_list, signature) = state.aggregator.handle_hpke_config().await?;

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
            http::header::HeaderName::from_static(HPKE_CONFIG_SIGNATURE_HEADER),
            HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(signature)).unwrap(),
        );
    }

    Ok((StatusCode::OK, response_headers, encoded_hpke_config_list).into_response())
}

/// Streams reports decoded from an async reader.
pub(super) fn decode_reports_stream<R>(mut body: R) -> impl Stream<Item = Result<Report, Error>>
where
    R: AsyncRead + Unpin,
{
    async_stream::try_stream! {
        const CHUNK_SIZE: usize = 64 * 1024;
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let mut buffer: VecDeque<u8> = VecDeque::with_capacity(CHUNK_SIZE);

        loop {
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
                            break;
                        }
                        CodecError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            break;
                        }
                        _ => {
                            Err(Error::MessageDecode(decode_error))?
                        }
                    }
                }
            }

            buffer.drain(..bytes_consumed);
        }
    }
}

/// API handler for the "/tasks/.../reports" POST endpoint.
async fn upload<C: Clock>(
    headers: HeaderMap,
    Path(task_id): Path<String>,
    State(state): State<Arc<AggregatorState<C>>>,
    body: Body,
) -> Result<Response, Error> {
    validate_content_type::<UploadRequest>(&headers)?;

    let task_id: TaskId = task_id
        .parse()
        .map_err(|_| Error::BadRequest("invalid TaskId".into()))?;

    let body_reader = body
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionReset, e))
        .into_async_read();

    let response = match state
        .aggregator
        .handle_upload(&task_id, decode_reports_stream(body_reader))
        .await
    {
        Ok(response) => response,
        Err(arc_err) => return Ok(ArcError::from(arc_err).into_response()),
    };

    Ok(EncodedBody::new(response, UploadResponse::MEDIA_TYPE)
        .with_status(StatusCode::OK)
        .into_response())
}

/// Path parameters for aggregation job endpoints.
#[derive(Deserialize)]
struct AggregationJobPath {
    task_id: String,
    aggregation_job_id: String,
}

/// Path parameters for collection job endpoints.
#[derive(Deserialize)]
struct CollectionJobPath {
    task_id: String,
    collection_job_id: String,
}

/// Path parameters for aggregate share endpoints.
#[derive(Deserialize)]
struct AggregateSharePath {
    task_id: String,
    aggregate_share_id: String,
}

/// API handler for the "/tasks/.../aggregation_jobs/..." PUT endpoint.
async fn aggregation_jobs_put<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<AggregationJobPath>,
    State(state): State<Arc<AggregatorState<C>>>,
    body: Bytes,
) -> Result<Response, Error> {
    validate_content_type::<AggregationJobInitializeReq<TimeInterval>>(&headers)?;

    let task_id = parse_task_id_str(&path.task_id)?;
    let aggregation_job_id = parse_aggregation_job_id_str(&path.aggregation_job_id)?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let taskprov_task_config = parse_taskprov_header(&state.aggregator, &task_id, &headers)?;
    let response = state
        .aggregator
        .handle_aggregate_init(
            &task_id,
            &aggregation_job_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;

    match response {
        Some(response) => Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE)
            .with_status(StatusCode::CREATED)
            .into_response()),
        None => {
            Ok(EmptyBody::for_aggregation_job(&task_id, &aggregation_job_id, 0).into_response())
        }
    }
}

/// API handler for the "/tasks/.../aggregation_jobs/..." POST endpoint.
async fn aggregation_jobs_post<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<AggregationJobPath>,
    State(state): State<Arc<AggregatorState<C>>>,
    body: Bytes,
) -> Result<Response, Error> {
    validate_content_type::<AggregationJobContinueReq>(&headers)?;

    let task_id = parse_task_id_str(&path.task_id)?;
    let aggregation_job_id = parse_aggregation_job_id_str(&path.aggregation_job_id)?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let taskprov_task_config = parse_taskprov_header(&state.aggregator, &task_id, &headers)?;
    let response = state
        .aggregator
        .handle_aggregate_continue(
            &task_id,
            &aggregation_job_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;

    match response {
        AggregationJobContinueResult::Sync(resp) => {
            Ok(EncodedBody::new(resp, AggregationJobResp::MEDIA_TYPE)
                .with_status(StatusCode::ACCEPTED)
                .into_response())
        }
        AggregationJobContinueResult::Async(step) => {
            Ok(
                EmptyBody::for_aggregation_job(&task_id, &aggregation_job_id, step.into())
                    .into_response(),
            )
        }
    }
}

/// API handler for the "/tasks/.../aggregation_jobs/..." GET endpoint.
async fn aggregation_jobs_get<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<AggregationJobPath>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    State(state): State<Arc<AggregatorState<C>>>,
) -> Result<Response, Error> {
    let task_id = parse_task_id_str(&path.task_id)?;
    let aggregation_job_id = parse_aggregation_job_id_str(&path.aggregation_job_id)?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let taskprov_task_config = parse_taskprov_header(&state.aggregator, &task_id, &headers)?;
    let step = parse_step_from_query(query.as_deref())?
        .ok_or_else(|| Error::BadRequest("missing step query parameter".into()))?;

    let response = state
        .aggregator
        .handle_aggregate_get(
            &task_id,
            &aggregation_job_id,
            auth_token,
            taskprov_task_config.as_ref(),
            step,
        )
        .await?;

    match response {
        Some(response) => Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE)
            .with_status(StatusCode::OK)
            .into_response()),
        None => Ok(
            EmptyBody::for_aggregation_job(&task_id, &aggregation_job_id, step.into())
                .into_response(),
        ),
    }
}

/// API handler for the "/tasks/.../aggregation_jobs/..." DELETE endpoint.
async fn aggregation_jobs_delete<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<AggregationJobPath>,
    State(state): State<Arc<AggregatorState<C>>>,
) -> Result<StatusCode, Error> {
    let task_id = parse_task_id_str(&path.task_id)?;
    let aggregation_job_id = parse_aggregation_job_id_str(&path.aggregation_job_id)?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let taskprov_task_config = parse_taskprov_header(&state.aggregator, &task_id, &headers)?;

    state
        .aggregator
        .handle_aggregate_delete(
            &task_id,
            &aggregation_job_id,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// API handler for the "/tasks/.../collection_jobs/..." PUT endpoint.
async fn collection_jobs_put<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<CollectionJobPath>,
    State(state): State<Arc<AggregatorState<C>>>,
    body: Bytes,
) -> Result<Response, Error> {
    validate_content_type::<CollectionJobReq<TimeInterval>>(&headers)?;

    let task_id = parse_task_id_str(&path.task_id)?;
    let collection_job_id: CollectionJobId = path
        .collection_job_id
        .parse()
        .map_err(|_| Error::BadRequest("invalid CollectionJobId".into()))?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let response_bytes = state
        .aggregator
        .handle_create_collection_job(&task_id, &collection_job_id, &body, auth_token)
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

/// API handler for the "/tasks/.../collection_jobs/..." GET endpoint.
async fn collection_jobs_get<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<CollectionJobPath>,
    State(state): State<Arc<AggregatorState<C>>>,
) -> Result<Response, Error> {
    let task_id = parse_task_id_str(&path.task_id)?;
    let collection_job_id: CollectionJobId = path
        .collection_job_id
        .parse()
        .map_err(|_| Error::BadRequest("invalid CollectionJobId".into()))?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let response_bytes = state
        .aggregator
        .handle_get_collection_job(&task_id, &collection_job_id, auth_token)
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

/// API handler for the "/tasks/.../collection_jobs/..." DELETE endpoint.
async fn collection_jobs_delete<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<CollectionJobPath>,
    State(state): State<Arc<AggregatorState<C>>>,
) -> Result<StatusCode, Error> {
    let task_id = parse_task_id_str(&path.task_id)?;
    let collection_job_id: CollectionJobId = path
        .collection_job_id
        .parse()
        .map_err(|_| Error::BadRequest("invalid CollectionJobId".into()))?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    state
        .aggregator
        .handle_delete_collection_job(&task_id, &collection_job_id, auth_token)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// API handler for the "/tasks/.../aggregate_shares/:aggregate_share_id" PUT endpoint.
async fn aggregate_shares_put<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<AggregateSharePath>,
    State(state): State<Arc<AggregatorState<C>>>,
    body: Bytes,
) -> Result<Response, Error> {
    validate_content_type::<AggregateShareReq<TimeInterval>>(&headers)?;

    let task_id = parse_task_id_str(&path.task_id)?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let taskprov_task_config = parse_taskprov_header(&state.aggregator, &task_id, &headers)?;
    let aggregate_share_id = parse_aggregate_share_id_str(&path.aggregate_share_id)?;
    let share = state
        .aggregator
        .handle_put_aggregate_share(
            &task_id,
            &aggregate_share_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;

    Ok(EncodedBody::new(share, AggregateShare::MEDIA_TYPE).into_response())
}

/// API handler for the "/tasks/.../aggregate_shares/:aggregate_share_id" GET endpoint.
async fn aggregate_shares_get<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<AggregateSharePath>,
    State(state): State<Arc<AggregatorState<C>>>,
) -> Result<Response, Error> {
    let task_id = parse_task_id_str(&path.task_id)?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let taskprov_task_config = parse_taskprov_header(&state.aggregator, &task_id, &headers)?;
    let aggregate_share_id = parse_aggregate_share_id_str(&path.aggregate_share_id)?;
    let share = state
        .aggregator
        .handle_get_aggregate_share(
            &task_id,
            &aggregate_share_id,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;

    Ok(EncodedBody::new(share, AggregateShare::MEDIA_TYPE).into_response())
}

/// API handler for the "/tasks/.../aggregate_shares/:aggregate_share_id" DELETE endpoint.
async fn aggregate_shares_delete<C: Clock>(
    headers: HeaderMap,
    Path(path): Path<AggregateSharePath>,
    State(state): State<Arc<AggregatorState<C>>>,
) -> Result<StatusCode, Error> {
    let task_id = parse_task_id_str(&path.task_id)?;
    let auth_token = parse_auth_token(&task_id, &headers)?;
    let taskprov_task_config = parse_taskprov_header(&state.aggregator, &task_id, &headers)?;
    let aggregate_share_id = parse_aggregate_share_id_str(&path.aggregate_share_id)?;
    state
        .aggregator
        .handle_delete_aggregate_share(
            &task_id,
            &aggregate_share_id,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

fn validate_content_type<M: MediaType>(headers: &HeaderMap) -> Result<(), Error> {
    check_content_type::<M>(headers).map_err(|e| Error::BadRequest(e.into()))
}

fn parse_task_id_str(encoded: &str) -> Result<TaskId, Error> {
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid TaskId".into()))
}

fn parse_aggregation_job_id_str(encoded: &str) -> Result<AggregationJobId, Error> {
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid AggregationJobId".into()))
}

fn parse_aggregate_share_id_str(encoded: &str) -> Result<AggregateShareId, Error> {
    encoded
        .parse()
        .map_err(|e| Error::BadRequest(format!("invalid aggregate share ID in path: {e}").into()))
}

/// Get an [`AuthenticationToken`] from the request headers.
fn parse_auth_token(
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

fn parse_taskprov_header<C: Clock>(
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

    let task_config_encoded = URL_SAFE_NO_PAD
        .decode(taskprov_header.as_bytes())
        .map_err(|_| {
            Error::InvalidMessage(
                Some(*task_id),
                "taskprov header could not be base64-decoded",
            )
        })?;

    let expected_task_id = taskprov_task_id(&task_config_encoded);
    if task_id != &expected_task_id {
        return Err(Error::InvalidMessage(
            Some(*task_id),
            "derived taskprov task ID does not match task config",
        ));
    }

    Ok(Some(
        TaskConfig::get_decoded(&task_config_encoded).map_err(Error::MessageDecode)?,
    ))
}

/// Gets the [`AggregationJobStep`] from the request's query string.
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

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use std::sync::Arc;

    use axum::{Router, body::to_bytes, response::Response};
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

    use super::AggregatorHandlerBuilder;
    use crate::aggregator::test_util::default_aggregator_config;

    pub async fn take_response_body(response: &mut Response) -> Vec<u8> {
        let body = std::mem::take(response.body_mut());
        to_bytes(body, usize::MAX).await.unwrap().to_vec()
    }

    pub async fn decode_response_body<T: Decode>(response: &mut Response) -> T {
        T::get_decoded(&take_response_body(response).await).unwrap()
    }

    pub async fn take_problem_details(response: &mut Response) -> serde_json::Value {
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/problem+json"
        );
        serde_json::from_slice(&take_response_body(response).await).unwrap()
    }

    /// Contains structures necessary for completing an HTTP handler test.
    pub struct HttpHandlerTest {
        pub clock: MockClock,
        pub ephemeral_datastore: EphemeralDatastore,
        pub datastore: Arc<Datastore<MockClock>>,
        pub handler: Router,
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
            .with_helper_aggregation_request_queue(super::HelperAggregationRequestQueue {
                depth: 16,
                concurrency: 2,
                timeout_ms: None,
            })
            .build()
            .unwrap();

            Self {
                clock,
                ephemeral_datastore,
                datastore,
                handler,
                hpke_keypair,
            }
        }
    }
}
