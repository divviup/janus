use super::{
    error::{ArcError, ReportRejectionReason},
    Aggregator, Config, Error,
};
use crate::aggregator::problem_details::{ProblemDetailsConnExt, ProblemDocument};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator_core::{datastore::Datastore, instrumented};
use janus_core::{
    auth_tokens::{AuthenticationToken, DAP_AUTH_HEADER},
    http::extract_bearer_token,
    taskprov::TASKPROV_HEADER,
    time::Clock,
    Runtime,
};
use janus_messages::{
    codec::Decode, problem_type::DapProblemType, query_type::TimeInterval, taskprov::TaskConfig,
    AggregateShare, AggregateShareReq, AggregationJobContinueReq, AggregationJobId,
    AggregationJobInitializeReq, AggregationJobResp, Collection, CollectionJobId, CollectionReq,
    HpkeConfigList, Report, TaskId,
};
use opentelemetry::{
    metrics::{Counter, Meter},
    KeyValue,
};
use prio::codec::Encode;
use ring::digest::{digest, SHA256};
use serde::Deserialize;
use std::{borrow::Cow, time::Duration as StdDuration};
use std::{io::Cursor, sync::Arc};
use tracing::warn;
use trillium::{Conn, Handler, KnownHeaderName, Status};
use trillium_api::{api, State, TryFromConn};
use trillium_caching_headers::{CacheControlDirective, CachingHeadersExt as _};
use trillium_opentelemetry::metrics;
use trillium_router::{Router, RouterConnExt};

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
        Error::ReportRejected(rejection) => match rejection.reason() {
            ReportRejectionReason::OutdatedHpkeConfig(_) => conn.with_problem_document(
                &ProblemDocument::new_dap(DapProblemType::OutdatedConfig)
                    .with_task_id(rejection.task_id()),
            ),
            ReportRejectionReason::TooEarly => conn.with_problem_document(
                &ProblemDocument::new_dap(DapProblemType::ReportTooEarly)
                    .with_task_id(rejection.task_id()),
            ),
            _ => conn.with_problem_document(
                &ProblemDocument::new_dap(DapProblemType::ReportRejected)
                    .with_task_id(rejection.task_id())
                    .with_detail(rejection.reason().detail()),
            ),
        },
        Error::InvalidMessage(task_id, _) => {
            let mut doc = ProblemDocument::new_dap(DapProblemType::InvalidMessage);
            if let Some(task_id) = task_id {
                doc = doc.with_task_id(task_id);
            }
            conn.with_problem_document(&doc)
        }
        Error::StepMismatch { task_id, .. } => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::StepMismatch).with_task_id(task_id),
        ),
        Error::UnrecognizedTask(task_id) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::UnrecognizedTask).with_task_id(task_id),
        ),
        Error::MissingTaskId => {
            conn.with_problem_document(&ProblemDocument::new_dap(DapProblemType::MissingTaskId))
        }
        Error::UnrecognizedAggregationJob(task_id, _aggregation_job_id) => conn
            .with_problem_document(
                &ProblemDocument::new_dap(DapProblemType::UnrecognizedAggregationJob)
                    .with_task_id(task_id),
            ),
        Error::DeletedAggregationJob(task_id, aggregation_job_id) => conn.with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#aggregation-job-deleted",
                "The aggregation job has been deleted.",
                Status::Gone,
            )
            .with_task_id(task_id)
            .with_aggregation_job_id(aggregation_job_id),
        ),
        Error::DeletedCollectionJob(_, _) => conn.with_status(Status::NoContent),
        Error::AbandonedCollectionJob(task_id, collection_job_id) => conn.with_problem_document(
            &ProblemDocument::new(
                "https://docs.divviup.org/references/janus-errors#collection-job-abandoned",
                "The collection job has been abandoned.",
                Status::InternalServerError,
            )
            .with_detail(concat!(
                "An internal problem has caused the server to stop processing this collection ",
                "job. The job is no longer collectable. Contact the server operators for ",
                "assistance."
            ))
            .with_task_id(task_id)
            .with_collection_job_id(collection_job_id),
        ),
        Error::UnrecognizedCollectionJob(_, _) => conn.with_status(Status::NotFound),

        Error::UnauthorizedRequest(task_id) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::UnauthorizedRequest).with_task_id(task_id),
        ),
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
        Error::BatchQueriedTooManyTimes(task_id, _) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::BatchQueriedTooManyTimes)
                .with_task_id(task_id),
        ),
        Error::Hpke(_)
        | Error::Datastore(_)
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
        Error::BadRequest(_) => conn.with_status(Status::BadRequest),
        Error::InvalidTask(task_id, _) => conn.with_problem_document(
            &ProblemDocument::new_dap(DapProblemType::InvalidTask).with_task_id(task_id),
        ),
        Error::DifferentialPrivacy(_) => conn.with_status(Status::InternalServerError),
        Error::ClientDisconnected => conn.with_status(Status::BadRequest),
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

/// The number of seconds we send in the Access-Control-Max-Age header. This determines for how
/// long clients will cache the results of CORS preflight requests. Of popular browsers, Mozilla
/// Firefox has the highest Max-Age cap, at 24 hours, so we use that. Our CORS preflight handlers
/// are tightly scoped to relevant endpoints, and our CORS settings are unlikely to change.
/// See: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age>.
const CORS_PREFLIGHT_CACHE_AGE: u32 = 24 * 60 * 60;

/// Wrapper around a type that implements [`Encode`]. It acts as a Trillium handler, encoding the
/// inner object and sending it as the response body, setting the Content-Type header to the
/// provided media type, and setting the status to 200.
struct EncodedBody<T> {
    object: T,
    media_type: &'static str,
}

impl<T> EncodedBody<T>
where
    T: Encode,
{
    fn new(object: T, media_type: &'static str) -> Self {
        Self { object, media_type }
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
                .ok(encoded),
            Err(e) => Error::MessageEncode(e).run(conn).await,
        }
    }
}

/// A Trillium handler that checks for state set when sending an error response, and updates an
/// OpenTelemetry counter accordingly.
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
                .init(),
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
pub(crate) static COLLECTION_JOB_ROUTE: &str = "tasks/:task_id/collection_jobs/:collection_job_id";
pub(crate) static AGGREGATE_SHARES_ROUTE: &str = "tasks/:task_id/aggregate_shares";

/// Constructs a Trillium handler for the aggregator.
pub async fn aggregator_handler<C, R>(
    datastore: Arc<Datastore<C>>,
    clock: C,
    runtime: R,
    meter: &Meter,
    cfg: Config,
) -> Result<impl Handler, Error>
where
    C: Clock,
    R: Runtime + Send + Sync + 'static,
{
    let aggregator = Arc::new(Aggregator::new(datastore, clock, runtime, meter, cfg).await?);
    aggregator_handler_with_aggregator(aggregator, meter).await
}

async fn aggregator_handler_with_aggregator<C: Clock>(
    aggregator: Arc<Aggregator<C>>,
    meter: &Meter,
) -> Result<impl Handler, Error> {
    Ok((
        State(aggregator),
        metrics(meter)
            .with_route(|conn| {
                conn.route()
                    .map(|route_spec| Cow::Owned(route_spec.to_string()))
            })
            .with_error_type(|conn| {
                conn.state::<ErrorCode>()
                    .map(|error_code| Cow::Borrowed(error_code.0))
            }),
        Router::new()
            .without_options_handling()
            .get("hpke_config", instrumented(api(hpke_config::<C>)))
            .with_route(
                trillium::Method::Options,
                "hpke_config",
                hpke_config_cors_preflight,
            )
            .put("tasks/:task_id/reports", instrumented(api(upload::<C>)))
            .with_route(
                trillium::Method::Options,
                "tasks/:task_id/reports",
                upload_cors_preflight,
            )
            .put(
                AGGREGATION_JOB_ROUTE,
                instrumented(api(aggregation_jobs_put::<C>)),
            )
            .post(
                AGGREGATION_JOB_ROUTE,
                instrumented(api(aggregation_jobs_post::<C>)),
            )
            .delete(
                AGGREGATION_JOB_ROUTE,
                instrumented(api(aggregation_jobs_delete::<C>)),
            )
            .put(
                COLLECTION_JOB_ROUTE,
                instrumented(api(collection_jobs_put::<C>)),
            )
            .post(
                COLLECTION_JOB_ROUTE,
                instrumented(api(collection_jobs_post::<C>)),
            )
            .delete(
                COLLECTION_JOB_ROUTE,
                instrumented(api(collection_jobs_delete::<C>)),
            )
            .post(
                AGGREGATE_SHARES_ROUTE,
                instrumented(api(aggregate_shares::<C>)),
            ),
        StatusCounter::new(meter),
    ))
}

/// Deserialization helper struct to extract a "task_id" parameter from a query string.
#[derive(Deserialize)]
struct HpkeConfigQuery {
    /// The optional "task_id" parameter, in base64url-encoded form.
    #[serde(default)]
    task_id: Option<String>,
}

const HPKE_CONFIG_SIGNATURE_HEADER: &str = "x-hpke-config-signature";

/// API handler for the "/hpke_config" GET endpoint.
async fn hpke_config<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<(), Error> {
    let query = serde_urlencoded::from_str::<HpkeConfigQuery>(conn.querystring())
        .map_err(|err| Error::BadRequest(format!("couldn't parse query string: {err}")))?;
    let (encoded_hpke_config_list, signature) = conn
        .cancel_on_disconnect(
            aggregator.handle_hpke_config(query.task_id.as_ref().map(AsRef::as_ref)),
        )
        .await
        .ok_or(Error::ClientDisconnected)??;

    // Handle CORS, if the request header is present.
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        // Unconditionally allow CORS requests from all origins.
        let origin = origin.clone();
        conn.response_headers_mut()
            .insert(KnownHeaderName::AccessControlAllowOrigin, origin);
    }

    conn.set_cache_control(CacheControlDirective::MaxAge(StdDuration::from_secs(86400)));
    let headers = conn.response_headers_mut();
    headers.insert(KnownHeaderName::ContentType, HpkeConfigList::MEDIA_TYPE);
    if let Some(signature) = signature {
        headers.insert(
            HPKE_CONFIG_SIGNATURE_HEADER,
            URL_SAFE_NO_PAD.encode(signature),
        );
    }
    conn.set_status(Status::Ok);
    conn.set_body(encoded_hpke_config_list);
    Ok(())
}

/// Handler for CORS preflight requests to "/hpke_config".
async fn hpke_config_cors_preflight(mut conn: Conn) -> Conn {
    conn.response_headers_mut()
        .insert(KnownHeaderName::Allow, "GET");
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        let origin = origin.clone();
        let request_headers = conn.response_headers_mut();
        request_headers.insert(KnownHeaderName::AccessControlAllowOrigin, origin);
        request_headers.insert(KnownHeaderName::AccessControlAllowMethods, "GET");
        request_headers.insert(
            KnownHeaderName::AccessControlMaxAge,
            format!("{CORS_PREFLIGHT_CACHE_AGE}"),
        );
    }
    conn.set_status(Status::Ok);
    conn
}

/// API handler for the "/tasks/.../reports" PUT endpoint.
async fn upload<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<Status, ArcError> {
    validate_content_type(conn, Report::MEDIA_TYPE).map_err(Arc::new)?;

    let task_id = parse_task_id(conn).map_err(Arc::new)?;
    conn.cancel_on_disconnect(aggregator.handle_upload(&task_id, &body))
        .await
        .ok_or(Arc::new(Error::ClientDisconnected))??;

    // Handle CORS, if the request header is present.
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        // Unconditionally allow CORS requests from all origins.
        let origin = origin.clone();
        conn.response_headers_mut()
            .insert(KnownHeaderName::AccessControlAllowOrigin, origin);
    }

    Ok(Status::Ok)
}

/// Handler for CORS preflight requests to "/tasks/.../reports".
async fn upload_cors_preflight(mut conn: Conn) -> Conn {
    conn.response_headers_mut()
        .insert(KnownHeaderName::Allow, "PUT");
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        let origin = origin.clone();
        let request_headers = conn.response_headers_mut();
        request_headers.insert(KnownHeaderName::AccessControlAllowOrigin, origin);
        request_headers.insert(KnownHeaderName::AccessControlAllowMethods, "PUT");
        request_headers.insert(KnownHeaderName::AccessControlAllowHeaders, "content-type");
        request_headers.insert(
            KnownHeaderName::AccessControlMaxAge,
            format!("{CORS_PREFLIGHT_CACHE_AGE}"),
        );
    }
    conn.set_status(Status::Ok);
    conn
}

/// API handler for the "/tasks/.../aggregation_jobs/..." PUT endpoint.
async fn aggregation_jobs_put<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<EncodedBody<AggregationJobResp>, Error> {
    validate_content_type(
        conn,
        AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
    )?;

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

    Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE))
}

/// API handler for the "/tasks/.../aggregation_jobs/..." POST endpoint.
async fn aggregation_jobs_post<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<EncodedBody<AggregationJobResp>, Error> {
    validate_content_type(conn, AggregationJobContinueReq::MEDIA_TYPE)?;

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

    Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE))
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

/// API handler for the "/tasks/.../collection_jobs/..." PUT endpoint.
async fn collection_jobs_put<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<Status, Error> {
    validate_content_type(conn, CollectionReq::<TimeInterval>::MEDIA_TYPE)?;

    let task_id = parse_task_id(conn)?;
    let collection_job_id = parse_collection_job_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    conn.cancel_on_disconnect(aggregator.handle_create_collection_job(
        &task_id,
        &collection_job_id,
        &body,
        auth_token,
    ))
    .await
    .ok_or(Error::ClientDisconnected)??;

    Ok(Status::Created)
}

/// API handler for the "/tasks/.../collection_jobs/..." POST endpoint.
async fn collection_jobs_post<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<(), Error> {
    let task_id = parse_task_id(conn)?;
    let collection_job_id = parse_collection_job_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let response_opt = conn
        .cancel_on_disconnect(aggregator.handle_get_collection_job(
            &task_id,
            &collection_job_id,
            auth_token,
        ))
        .await
        .ok_or(Error::ClientDisconnected)??;
    match response_opt {
        Some(response_bytes) => {
            conn.response_headers_mut().insert(
                KnownHeaderName::ContentType,
                Collection::<TimeInterval>::MEDIA_TYPE,
            );
            conn.set_status(Status::Ok);
            conn.set_body(response_bytes);
        }
        None => conn.set_status(Status::Accepted),
    }
    Ok(())
}

/// API handler for the "/tasks/.../collection_jobs/..." DELETE endpoint.
async fn collection_jobs_delete<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<Status, Error> {
    let task_id = parse_task_id(conn)?;
    let collection_job_id = parse_collection_job_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    conn.cancel_on_disconnect(aggregator.handle_delete_collection_job(
        &task_id,
        &collection_job_id,
        auth_token,
    ))
    .await
    .ok_or(Error::ClientDisconnected)??;
    Ok(Status::NoContent)
}

/// API handler for the "/tasks/.../aggregate_shares" POST endpoint.
async fn aggregate_shares<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), BodyBytes(body)): (State<Arc<Aggregator<C>>>, BodyBytes),
) -> Result<EncodedBody<AggregateShare>, Error> {
    validate_content_type(conn, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)?;

    let task_id = parse_task_id(conn)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let share = conn
        .cancel_on_disconnect(aggregator.handle_aggregate_share(
            &task_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        ))
        .await
        .ok_or(Error::ClientDisconnected)??;

    Ok(EncodedBody::new(share, AggregateShare::MEDIA_TYPE))
}

/// Check the request's Content-Type header, and return an error if it is missing or not equal to
/// the expected value.
fn validate_content_type(conn: &Conn, expected_media_type: &'static str) -> Result<(), Error> {
    if let Some(content_type) = conn.request_headers().get(KnownHeaderName::ContentType) {
        if content_type != expected_media_type {
            Err(Error::BadRequest(format!(
                "wrong Content-Type header: {content_type}"
            )))
        } else {
            Ok(())
        }
    } else {
        Err(Error::BadRequest("no Content-Type header".to_owned()))
    }
}

/// Parse a [`TaskId`] from the "task_id" parameter in a set of path parameter
fn parse_task_id(conn: &Conn) -> Result<TaskId, Error> {
    let encoded = conn
        .param("task_id")
        .ok_or_else(|| Error::Internal("task_id parameter is missing from captures".to_string()))?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid TaskId".to_owned()))
}

/// Parse an [`AggregationJobId`] from the "aggregation_job_id" parameter in a set of path parameter
fn parse_aggregation_job_id(conn: &Conn) -> Result<AggregationJobId, Error> {
    let encoded = conn.param("aggregation_job_id").ok_or_else(|| {
        Error::Internal("aggregation_job_id parameter is missing from captures".to_string())
    })?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid AggregationJobId".to_owned()))
}

/// Parse an [`CollectionJobId`] from the "collection_job_id" parameter in a set of path parameter
fn parse_collection_job_id(conn: &Conn) -> Result<CollectionJobId, Error> {
    let encoded = conn.param("collection_job_id").ok_or_else(|| {
        Error::Internal("collection_job_id parameter is missing from captures".to_string())
    })?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid CollectionJobId".to_owned()))
}

/// Get an [`AuthenticationToken`] from the request.
fn parse_auth_token(task_id: &TaskId, conn: &Conn) -> Result<Option<AuthenticationToken>, Error> {
    // Prefer a bearer token, then fall back to DAP-Auth-Token
    if let Some(bearer_token) =
        extract_bearer_token(conn).map_err(|_| Error::UnauthorizedRequest(*task_id))?
    {
        return Ok(Some(bearer_token));
    }

    conn.request_headers()
        .get(DAP_AUTH_HEADER)
        .map(|value| {
            AuthenticationToken::new_dap_auth_token_from_bytes(value.as_ref())
                .map_err(|e| Error::BadRequest(format!("bad DAP-Auth-Token header: {e}")))
        })
        .transpose()
}

fn parse_taskprov_header<C: Clock>(
    aggregator: &Aggregator<C>,
    task_id: &TaskId,
    conn: &Conn,
) -> Result<Option<TaskConfig>, Error> {
    if aggregator.cfg.taskprov_config.enabled {
        match conn.request_headers().get(TASKPROV_HEADER) {
            Some(taskprov_header) => {
                let task_config_encoded =
                    &URL_SAFE_NO_PAD.decode(taskprov_header).map_err(|_| {
                        Error::InvalidMessage(
                            Some(*task_id),
                            "taskprov header could not be decoded",
                        )
                    })?;

                if task_id.as_ref() != digest(&SHA256, task_config_encoded).as_ref() {
                    Err(Error::InvalidMessage(
                        Some(*task_id),
                        "derived taskprov task ID does not match task config",
                    ))
                } else {
                    // TODO(#1684): Parsing the taskprov header like this before we've been able
                    // to actually authenticate the client is undesireable. We should rework this
                    // such that the authorization header is handled before parsing the untrusted
                    // input.
                    Ok(Some(
                        TaskConfig::decode(&mut Cursor::new(task_config_encoded))
                            .map_err(Error::MessageDecode)?,
                    ))
                }
            }
            None => Ok(None),
        }
    } else {
        Ok(None)
    }
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
                _ => Error::BadRequest(error.to_string()),
            })
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use super::aggregator_handler;
    use crate::aggregator::test_util::default_aggregator_config;
    use janus_aggregator_core::{
        datastore::{
            models::HpkeKeyState,
            test_util::{ephemeral_datastore, EphemeralDatastore},
            Datastore,
        },
        test_util::noop_meter,
    };
    use janus_core::{
        hpke::HpkeKeypair,
        test_util::{install_test_trace_subscriber, runtime::TestRuntime},
        time::MockClock,
    };
    use janus_messages::codec::Decode;
    use std::sync::Arc;
    use trillium::Handler;
    use trillium_testing::{assert_headers, TestConn};

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
            let clock = MockClock::default();
            let ephemeral_datastore = ephemeral_datastore().await;
            let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

            let hpke_keypair = HpkeKeypair::test();
            datastore
                .run_unnamed_tx(|tx| {
                    let hpke_keypair = hpke_keypair.clone();
                    Box::pin(async move {
                        tx.put_global_hpke_keypair(&hpke_keypair).await?;
                        tx.set_global_hpke_keypair_state(
                            hpke_keypair.config().id(),
                            &HpkeKeyState::Active,
                        )
                        .await
                    })
                })
                .await
                .unwrap();

            let handler = aggregator_handler(
                datastore.clone(),
                clock.clone(),
                TestRuntime::default(),
                &noop_meter(),
                default_aggregator_config(),
            )
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
