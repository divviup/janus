use super::{Aggregator, Config, Error};
use crate::aggregator::problem_details::ProblemDetailsConnExt;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator_core::{datastore::Datastore, instrumented};
use janus_core::{
    auth_tokens::{AuthenticationToken, DAP_AUTH_HEADER},
    http::extract_bearer_token,
    taskprov::TASKPROV_HEADER,
    time::Clock,
};
use janus_messages::{
    codec::Decode, problem_type::DapProblemType, query_type::TimeInterval, taskprov::TaskConfig,
    AggregateShare, AggregateShareReq, AggregationJobContinueReq, AggregationJobId,
    AggregationJobInitializeReq, AggregationJobResp, Collection, CollectionJobId, CollectionReq,
    HpkeConfigList, Report, TaskId,
};
use opentelemetry::{
    metrics::{Counter, Meter, Unit},
    KeyValue,
};
use prio::codec::Encode;
use ring::digest::{digest, SHA256};
use routefinder::Captures;
use serde::Deserialize;
use std::time::Duration as StdDuration;
use std::{io::Cursor, sync::Arc};
use tracing::warn;
use trillium::{Conn, Handler, KnownHeaderName, Status};
use trillium_api::{api, State};
use trillium_caching_headers::CacheControlDirective;
use trillium_opentelemetry::metrics;
use trillium_router::{Router, RouterConnExt};

/// Newtype holding a textual error code, to be stored in a Trillium connection's state.
struct ErrorCode(&'static str);

#[async_trait]
impl Handler for Error {
    async fn run(&self, mut conn: Conn) -> Conn {
        let error_code = self.error_code();
        conn.set_state(ErrorCode(error_code));
        warn!(error_code, error=?self, "Error handling endpoint");
        match self {
            Error::InvalidConfiguration(_) => conn.with_status(Status::InternalServerError),
            Error::MessageDecode(_) => {
                conn.with_problem_details(DapProblemType::InvalidMessage, None)
            }
            Error::ReportRejected(task_id, _, _) => {
                conn.with_problem_details(DapProblemType::ReportRejected, Some(task_id))
            }
            Error::InvalidMessage(task_id, _) => {
                conn.with_problem_details(DapProblemType::InvalidMessage, task_id.as_ref())
            }
            Error::StepMismatch { task_id, .. } => {
                conn.with_problem_details(DapProblemType::StepMismatch, Some(task_id))
            }
            Error::UnrecognizedTask(task_id) => {
                conn.with_problem_details(DapProblemType::UnrecognizedTask, Some(task_id))
            }
            Error::MissingTaskId => conn.with_problem_details(DapProblemType::MissingTaskId, None),
            Error::UnrecognizedAggregationJob(task_id, _) => {
                conn.with_problem_details(DapProblemType::UnrecognizedAggregationJob, Some(task_id))
            }
            Error::DeletedCollectionJob(_) => conn.with_status(Status::NoContent),
            Error::UnrecognizedCollectionJob(_) => conn.with_status(Status::NotFound),
            Error::OutdatedHpkeConfig(task_id, _) => {
                conn.with_problem_details(DapProblemType::OutdatedConfig, Some(task_id))
            }
            Error::ReportTooEarly(task_id, _, _) => {
                conn.with_problem_details(DapProblemType::ReportTooEarly, Some(task_id))
            }
            Error::UnauthorizedRequest(task_id) => {
                conn.with_problem_details(DapProblemType::UnauthorizedRequest, Some(task_id))
            }
            Error::InvalidBatchSize(task_id, _) => {
                conn.with_problem_details(DapProblemType::InvalidBatchSize, Some(task_id))
            }
            Error::BatchInvalid(task_id, _) => {
                conn.with_problem_details(DapProblemType::BatchInvalid, Some(task_id))
            }
            Error::BatchOverlap(task_id, _) => {
                conn.with_problem_details(DapProblemType::BatchOverlap, Some(task_id))
            }
            Error::BatchMismatch(inner) => {
                conn.with_problem_details(DapProblemType::BatchMismatch, Some(&inner.task_id))
            }
            Error::BatchQueriedTooManyTimes(task_id, _) => {
                conn.with_problem_details(DapProblemType::BatchQueriedTooManyTimes, Some(task_id))
            }
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
            Error::EmptyAggregation(task_id) => {
                conn.with_problem_details(DapProblemType::InvalidMessage, Some(task_id))
            }
            Error::ForbiddenMutation { .. } => conn.with_status(Status::Conflict),
            Error::BadRequest(_) => conn.with_status(Status::BadRequest),
            Error::InvalidTask(task_id, _) => {
                conn.with_problem_details(DapProblemType::InvalidTask, Some(task_id))
            }
            Error::DifferentialPrivacy(_) => conn.with_status(Status::InternalServerError),
        }
    }
}

/// The number of seconds we send in the Access-Control-Max-Age header. This determines for how
/// long clients will cache the results of CORS preflight requests. Of popular browsers, Mozilla
/// Firefox has the highest Max-Age cap, at 24 hours, so we use that. Our CORS preflight handlers
/// are tightly scoped to relevant endpoints, and our CORS settings are unlikely to change.
/// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
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
        conn.with_header(KnownHeaderName::ContentType, self.media_type)
            .ok(self.object.get_encoded())
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
                .with_unit(Unit::new("{request}"))
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
pub async fn aggregator_handler<C: Clock>(
    datastore: Arc<Datastore<C>>,
    clock: C,
    meter: &Meter,
    cfg: Config,
) -> Result<impl Handler, Error> {
    let aggregator = Arc::new(Aggregator::new(datastore, clock, meter, cfg).await?);
    aggregator_handler_with_aggregator(aggregator, meter).await
}

async fn aggregator_handler_with_aggregator<C: Clock>(
    aggregator: Arc<Aggregator<C>>,
    meter: &Meter,
) -> Result<impl Handler, Error> {
    Ok((
        State(aggregator),
        metrics("janus_aggregator").with_route(|conn| conn.route().map(ToString::to_string)),
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

/// API handler for the "/hpke_config" GET endpoint.
async fn hpke_config<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<(CacheControlDirective, EncodedBody<HpkeConfigList>), Error> {
    let query = serde_urlencoded::from_str::<HpkeConfigQuery>(conn.querystring())
        .map_err(|err| Error::BadRequest(format!("couldn't parse query string: {err}")))?;
    let hpke_config_list = aggregator
        .handle_hpke_config(query.task_id.as_ref().map(AsRef::as_ref))
        .await?;

    // Handle CORS, if the request header is present.
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        // Unconditionally allow CORS requests from all origins.
        let origin = origin.clone();
        conn.headers_mut()
            .insert(KnownHeaderName::AccessControlAllowOrigin, origin);
    }

    Ok((
        CacheControlDirective::MaxAge(StdDuration::from_secs(86400)),
        EncodedBody::new(hpke_config_list, HpkeConfigList::MEDIA_TYPE),
    ))
}

/// Handler for CORS preflight requests to "/hpke_config".
async fn hpke_config_cors_preflight(mut conn: Conn) -> Conn {
    conn.headers_mut().insert(KnownHeaderName::Allow, "GET");
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        let origin = origin.clone();
        let request_headers = conn.headers_mut();
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
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<Status, Arc<Error>> {
    validate_content_type(conn, Report::MEDIA_TYPE).map_err(Arc::new)?;

    let task_id = parse_task_id(&captures).map_err(Arc::new)?;
    aggregator.handle_upload(&task_id, &body).await?;

    // Handle CORS, if the request header is present.
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        // Unconditionally allow CORS requests from all origins.
        let origin = origin.clone();
        conn.headers_mut()
            .insert(KnownHeaderName::AccessControlAllowOrigin, origin);
    }

    Ok(Status::Ok)
}

/// Handler for CORS preflight requests to "/tasks/.../reports".
async fn upload_cors_preflight(mut conn: Conn) -> Conn {
    conn.headers_mut().insert(KnownHeaderName::Allow, "PUT");
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        let origin = origin.clone();
        let request_headers = conn.headers_mut();
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
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<EncodedBody<AggregationJobResp>, Error> {
    validate_content_type(
        conn,
        AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
    )?;

    let task_id = parse_task_id(&captures)?;
    let aggregation_job_id = parse_aggregation_job_id(&captures)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let response = aggregator
        .handle_aggregate_init(
            &task_id,
            &aggregation_job_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;

    Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE))
}

/// API handler for the "/tasks/.../aggregation_jobs/..." POST endpoint.
async fn aggregation_jobs_post<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<EncodedBody<AggregationJobResp>, Error> {
    validate_content_type(conn, AggregationJobContinueReq::MEDIA_TYPE)?;

    let task_id = parse_task_id(&captures)?;
    let aggregation_job_id = parse_aggregation_job_id(&captures)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let response = aggregator
        .handle_aggregate_continue(
            &task_id,
            &aggregation_job_id,
            &body,
            auth_token,
            taskprov_task_config.as_ref(),
        )
        .await?;

    Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE))
}

/// API handler for the "/tasks/.../collection_jobs/..." PUT endpoint.
async fn collection_jobs_put<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<Status, Error> {
    validate_content_type(conn, CollectionReq::<TimeInterval>::MEDIA_TYPE)?;

    let task_id = parse_task_id(&captures)?;
    let collection_job_id = parse_collection_job_id(&captures)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    aggregator
        .handle_create_collection_job(&task_id, &collection_job_id, &body, auth_token)
        .await?;

    Ok(Status::Created)
}

/// API handler for the "/tasks/.../collection_jobs/..." POST endpoint.
async fn collection_jobs_post<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures)): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
    ),
) -> Result<(), Error> {
    let task_id = parse_task_id(&captures)?;
    let collection_job_id = parse_collection_job_id(&captures)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let response_opt = aggregator
        .handle_get_collection_job(&task_id, &collection_job_id, auth_token)
        .await?;
    match response_opt {
        Some(response_bytes) => {
            conn.headers_mut().insert(
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
    (State(aggregator), State(captures)): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
    ),
) -> Result<Status, Error> {
    let task_id = parse_task_id(&captures)?;
    let collection_job_id = parse_collection_job_id(&captures)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    aggregator
        .handle_delete_collection_job(&task_id, &collection_job_id, auth_token)
        .await?;
    Ok(Status::NoContent)
}

/// API handler for the "/tasks/.../aggregate_shares" POST endpoint.
async fn aggregate_shares<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<EncodedBody<AggregateShare>, Error> {
    validate_content_type(conn, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)?;

    let task_id = parse_task_id(&captures)?;
    let auth_token = parse_auth_token(&task_id, conn)?;
    let taskprov_task_config = parse_taskprov_header(&aggregator, &task_id, conn)?;
    let share = aggregator
        .handle_aggregate_share(&task_id, &body, auth_token, taskprov_task_config.as_ref())
        .await?;

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

/// Parse a [`TaskId`] from the "task_id" parameter in a set of path parameter [`Captures`].
fn parse_task_id(captures: &Captures) -> Result<TaskId, Error> {
    let encoded = captures
        .get("task_id")
        .ok_or_else(|| Error::Internal("task_id parameter is missing from captures".to_string()))?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid TaskId".to_owned()))
}

/// Parse an [`AggregationJobId`] from the "aggregation_job_id" parameter in a set of path parameter
/// [`Captures`].
fn parse_aggregation_job_id(captures: &Captures) -> Result<AggregationJobId, Error> {
    let encoded = captures.get("aggregation_job_id").ok_or_else(|| {
        Error::Internal("aggregation_job_id parameter is missing from captures".to_string())
    })?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid AggregationJobId".to_owned()))
}

/// Parse an [`CollectionJobId`] from the "collection_job_id" parameter in a set of path parameter
/// [`Captures`].
fn parse_collection_job_id(captures: &Captures) -> Result<CollectionJobId, Error> {
    let encoded = captures.get("collection_job_id").ok_or_else(|| {
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
                    Ok(Some(TaskConfig::decode(&mut Cursor::new(
                        task_config_encoded,
                    ))?))
                }
            }
            None => Ok(None),
        }
    } else {
        Ok(None)
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use janus_messages::codec::Decode;
    use std::borrow::Cow;
    use trillium_testing::{assert_headers, TestConn};

    async fn take_response_body(test_conn: &mut TestConn) -> Cow<'_, [u8]> {
        test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap()
    }

    pub async fn decode_response_body<T: Decode>(test_conn: &mut TestConn) -> T {
        T::get_decoded(&take_response_body(test_conn).await).unwrap()
    }

    pub async fn take_problem_details(test_conn: &mut TestConn) -> serde_json::Value {
        assert_headers!(&test_conn, "content-type" => "application/problem+json");
        serde_json::from_slice(&take_response_body(test_conn).await).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregator::{
            aggregate_init_tests::{
                put_aggregation_job, setup_aggregate_init_test, PrepareInitGenerator,
            },
            aggregation_job_continue::test_util::{
                post_aggregation_job_and_decode, post_aggregation_job_expecting_error,
            },
            collection_job_tests::setup_collection_job_test_case,
            empty_batch_aggregations,
            http_handlers::{
                aggregator_handler, aggregator_handler_with_aggregator,
                test_util::{decode_response_body, take_problem_details},
            },
            tests::{
                create_report, create_report_custom, default_aggregator_config,
                generate_helper_report_share, generate_helper_report_share_for_plaintext,
                BATCH_AGGREGATION_SHARD_COUNT,
            },
            Config,
        },
        config::TaskprovConfig,
    };
    use assert_matches::assert_matches;
    use futures::future::try_join_all;
    use janus_aggregator_core::{
        datastore::{
            models::{
                AggregateShareJob, AggregationJob, AggregationJobState, Batch, BatchAggregation,
                BatchAggregationState, BatchState, CollectionJob, CollectionJobState, HpkeKeyState,
                ReportAggregation, ReportAggregationState,
            },
            test_util::{ephemeral_datastore, EphemeralDatastore},
            Datastore,
        },
        query_type::{AccumulableQueryType, CollectableQueryType},
        task::{test_util::TaskBuilder, QueryType, VerifyKey},
        test_util::noop_meter,
    };
    use janus_core::{
        auth_tokens::AuthenticationToken,
        hpke::{
            self,
            test_util::{
                generate_test_hpke_config_and_private_key,
                generate_test_hpke_config_and_private_key_with_id,
            },
            HpkeApplicationInfo, HpkeKeypair, Label,
        },
        report_id::ReportIdChecksumExt,
        test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf},
        time::{Clock, DurationExt, IntervalExt, MockClock, TimeExt},
        vdaf::{VdafInstance, VERIFY_KEY_LENGTH},
    };
    use janus_messages::{
        query_type::TimeInterval, AggregateShare as AggregateShareMessage, AggregateShareAad,
        AggregateShareReq, AggregationJobContinueReq, AggregationJobId,
        AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep, BatchSelector,
        Collection, CollectionJobId, CollectionReq, Duration, Extension, ExtensionType,
        HpkeCiphertext, HpkeConfigId, HpkeConfigList, InputShareAad, Interval,
        PartialBatchSelector, PrepareContinue, PrepareError, PrepareInit, PrepareResp,
        PrepareStepResult, Query, Report, ReportId, ReportIdChecksum, ReportMetadata, ReportShare,
        Role, TaskId, Time,
    };
    use prio::{
        codec::{Decode, Encode},
        idpf::IdpfInput,
        topology::ping_pong::PingPongMessage,
        vdaf::{
            poplar1::{Poplar1, Poplar1AggregationParam},
            xof::XofShake128,
            Aggregator,
        },
    };
    use rand::random;
    use serde_json::json;
    use std::{collections::HashMap, sync::Arc};
    use trillium::{Handler, KnownHeaderName, Status};
    use trillium_testing::{
        assert_headers,
        prelude::{delete, get, post, put},
        TestConn,
    };

    /// Returns structures necessary for completing an HTTP handler test. The returned
    /// [`EphemeralDatastore`] should be given a variable binding to prevent it being prematurely
    /// dropped.
    async fn setup_http_handler_test() -> (
        MockClock,
        EphemeralDatastore,
        Arc<Datastore<MockClock>>,
        impl Handler,
    ) {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let handler = aggregator_handler(
            datastore.clone(),
            clock.clone(),
            &noop_meter(),
            default_aggregator_config(),
        )
        .await
        .unwrap();

        (clock, ephemeral_datastore, datastore, handler)
    }

    #[tokio::test]
    async fn hpke_config() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .build()
            .leader_view()
            .unwrap();
        datastore.put_aggregator_task(&task).await.unwrap();

        let unknown_task_id: TaskId = random();
        let want_hpke_key = task.current_hpke_key().clone();

        // No task ID provided and no global keys are configured.
        let mut test_conn = get("/hpke_config").run_async(&handler).await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:missingTaskID",
                "title": "HPKE configuration was requested without specifying a task ID.",
            })
        );

        // Unknown task ID provided
        let mut test_conn = get(&format!("/hpke_config?task_id={unknown_task_id}"))
            .run_async(&handler)
            .await;
        // Expected status and problem type should be per the protocol
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{unknown_task_id}"),
            })
        );

        // Recognized task ID provided
        let mut test_conn = get(&format!("/hpke_config?task_id={}", task.id()))
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "cache-control" => "max-age=86400",
            "content-type" => (HpkeConfigList::MEDIA_TYPE),
        );

        let hpke_config_list: HpkeConfigList = decode_response_body(&mut test_conn).await;
        assert_eq!(
            hpke_config_list.hpke_configs(),
            &[want_hpke_key.config().clone()]
        );
        check_hpke_config_is_usable(&hpke_config_list, &want_hpke_key);
    }

    #[tokio::test]
    async fn global_hpke_config() {
        let (clock, _ephemeral_datastore, datastore, _) = setup_http_handler_test().await;

        // Insert an HPKE config, i.e. start the application with a keypair already
        // in the database.
        let first_hpke_keypair = generate_test_hpke_config_and_private_key_with_id(1);
        datastore
            .run_unnamed_tx(|tx| {
                let keypair = first_hpke_keypair.clone();
                Box::pin(async move {
                    tx.put_global_hpke_keypair(&keypair).await?;
                    tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

        let aggregator = Arc::new(
            crate::aggregator::Aggregator::new(
                datastore.clone(),
                clock.clone(),
                &noop_meter(),
                Config::default(),
            )
            .await
            .unwrap(),
        );
        let handler = aggregator_handler_with_aggregator(aggregator.clone(), &noop_meter())
            .await
            .unwrap();

        // No task ID provided
        let mut test_conn = get("/hpke_config").run_async(&handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "cache-control" => "max-age=86400",
            "content-type" => (HpkeConfigList::MEDIA_TYPE),
        );
        let hpke_config_list: HpkeConfigList = decode_response_body(&mut test_conn).await;
        assert_eq!(
            hpke_config_list.hpke_configs(),
            &[first_hpke_keypair.config().clone()]
        );
        check_hpke_config_is_usable(&hpke_config_list, &first_hpke_keypair);

        // Insert an inactive HPKE config.
        let second_hpke_keypair = generate_test_hpke_config_and_private_key_with_id(2);
        datastore
            .run_unnamed_tx(|tx| {
                let keypair = second_hpke_keypair.clone();
                Box::pin(async move { tx.put_global_hpke_keypair(&keypair).await })
            })
            .await
            .unwrap();
        aggregator.refresh_caches().await.unwrap();
        let mut test_conn = get("/hpke_config").run_async(&handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        let hpke_config_list: HpkeConfigList = decode_response_body(&mut test_conn).await;
        assert_eq!(
            hpke_config_list.hpke_configs(),
            &[first_hpke_keypair.config().clone()]
        );

        // Set key active.
        datastore
            .run_unnamed_tx(|tx| {
                let keypair = second_hpke_keypair.clone();
                Box::pin(async move {
                    tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                        .await
                })
            })
            .await
            .unwrap();
        aggregator.refresh_caches().await.unwrap();
        let mut test_conn = get("/hpke_config").run_async(&handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        let hpke_config_list: HpkeConfigList = decode_response_body(&mut test_conn).await;
        // Unordered comparison.
        assert_eq!(
            HashMap::from_iter(
                hpke_config_list
                    .hpke_configs()
                    .iter()
                    .map(|config| (config.id(), config))
            ),
            HashMap::from([
                (
                    first_hpke_keypair.config().id(),
                    &first_hpke_keypair.config().clone()
                ),
                (
                    second_hpke_keypair.config().id(),
                    &second_hpke_keypair.config().clone()
                ),
            ]),
        );

        // Expire a key.
        datastore
            .run_unnamed_tx(|tx| {
                let keypair = second_hpke_keypair.clone();
                Box::pin(async move {
                    tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Expired)
                        .await
                })
            })
            .await
            .unwrap();
        aggregator.refresh_caches().await.unwrap();
        let mut test_conn = get("/hpke_config").run_async(&handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        let hpke_config_list: HpkeConfigList = decode_response_body(&mut test_conn).await;
        assert_eq!(
            hpke_config_list.hpke_configs(),
            &[first_hpke_keypair.config().clone()]
        );

        // Delete a key, no keys left.
        datastore
            .run_unnamed_tx(|tx| {
                let keypair = first_hpke_keypair.clone();
                Box::pin(async move { tx.delete_global_hpke_keypair(keypair.config().id()).await })
            })
            .await
            .unwrap();
        aggregator.refresh_caches().await.unwrap();
        let test_conn = get("/hpke_config").run_async(&handler).await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
    }

    #[tokio::test]
    async fn global_hpke_config_with_taskprov() {
        let (clock, _ephemeral_datastore, datastore, _) = setup_http_handler_test().await;

        // Insert an HPKE config, i.e. start the application with a keypair already
        // in the database.
        let first_hpke_keypair = generate_test_hpke_config_and_private_key_with_id(1);
        datastore
            .run_unnamed_tx(|tx| {
                let keypair = first_hpke_keypair.clone();
                Box::pin(async move {
                    tx.put_global_hpke_keypair(&keypair).await?;
                    tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

        // Insert a taskprov task. This task won't have its task-specific HPKE key.
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build();
        let taskprov_helper_task = task.taskprov_helper_view().unwrap();
        datastore
            .put_aggregator_task(&taskprov_helper_task)
            .await
            .unwrap();

        let cfg = Config {
            taskprov_config: TaskprovConfig { enabled: true },
            ..Default::default()
        };

        let aggregator = Arc::new(
            crate::aggregator::Aggregator::new(
                datastore.clone(),
                clock.clone(),
                &noop_meter(),
                cfg,
            )
            .await
            .unwrap(),
        );
        let handler = aggregator_handler_with_aggregator(aggregator.clone(), &noop_meter())
            .await
            .unwrap();

        let mut test_conn = get(&format!("/hpke_config?task_id={}", task.id()))
            .run_async(&handler)
            .await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        let hpke_config_list: HpkeConfigList = decode_response_body(&mut test_conn).await;
        assert_eq!(
            hpke_config_list.hpke_configs(),
            &[first_hpke_keypair.config().clone()]
        );
        check_hpke_config_is_usable(&hpke_config_list, &first_hpke_keypair);
    }

    fn check_hpke_config_is_usable(hpke_config_list: &HpkeConfigList, hpke_keypair: &HpkeKeypair) {
        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
        let message = b"this is a message";
        let associated_data = b"some associated data";

        let ciphertext = hpke::seal(
            &hpke_config_list.hpke_configs()[0],
            &application_info,
            message,
            associated_data,
        )
        .unwrap();
        let plaintext = hpke::open(
            hpke_keypair,
            &application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap();
        assert_eq!(&plaintext, message);
    }

    #[tokio::test]
    async fn hpke_config_cors_headers() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .build()
            .leader_view()
            .unwrap();
        datastore.put_aggregator_task(&task).await.unwrap();

        // Check for appropriate CORS headers in response to a preflight request.
        let test_conn = TestConn::build(
            trillium::Method::Options,
            &format!("/hpke_config?task_id={}", task.id()),
            (),
        )
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .with_request_header(KnownHeaderName::AccessControlRequestMethod, "GET")
        .run_async(&handler)
        .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/",
            "access-control-allow-methods"=> "GET",
            "access-control-max-age"=> "86400",
        );

        // Check for appropriate CORS headers with a simple GET request.
        let test_conn = get(&format!("/hpke_config?task_id={}", task.id()))
            .with_request_header(KnownHeaderName::Origin, "https://example.com/")
            .run_async(&handler)
            .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/",
        );
    }

    #[tokio::test]
    async fn upload_handler() {
        async fn check_response(
            test_conn: &mut TestConn,
            desired_status: Status,
            desired_type: &str,
            desired_title: &str,
            desired_task_id: &TaskId,
        ) {
            assert_eq!(test_conn.status(), Some(desired_status));
            assert_eq!(
                take_problem_details(test_conn).await,
                json!({
                    "status": desired_status as u16,
                    "type": format!("urn:ietf:params:ppm:dap:error:{desired_type}"),
                    "title": desired_title,
                    "taskid": format!("{desired_task_id}"),
                }),
            )
        }

        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        const REPORT_EXPIRY_AGE: u64 = 1_000_000;
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .with_report_expiry_age(Some(Duration::from_seconds(REPORT_EXPIRY_AGE)))
            .build();

        let leader_task = task.leader_view().unwrap();
        datastore.put_aggregator_task(&leader_task).await.unwrap();

        let report = create_report(&leader_task, clock.now());

        // Upload a report. Do this twice to prove that PUT is idempotent.
        for _ in 0..2 {
            let mut test_conn = put(task.report_upload_uri().unwrap().path())
                .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
                .with_request_body(report.get_encoded())
                .run_async(&handler)
                .await;

            assert_eq!(test_conn.status(), Some(Status::Ok));
            assert!(test_conn.take_response_body().is_none());
        }

        let accepted_report_id = report.metadata().id();

        // Verify that new reports using an existing report ID are rejected with reportRejected
        let duplicate_id_report = create_report_custom(
            &leader_task,
            clock.now(),
            *accepted_report_id,
            leader_task.current_hpke_key(),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(duplicate_id_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportRejected",
            "Report could not be processed.",
            task.id(),
        )
        .await;

        // Verify that reports older than the report expiry age are rejected with the reportRejected
        // error type.
        let gc_eligible_report = Report::new(
            ReportMetadata::new(
                random(),
                clock
                    .now()
                    .sub(&Duration::from_seconds(REPORT_EXPIRY_AGE + 30000))
                    .unwrap(),
            ),
            report.public_share().to_vec(),
            report.leader_encrypted_input_share().clone(),
            report.helper_encrypted_input_share().clone(),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(gc_eligible_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportRejected",
            "Report could not be processed.",
            task.id(),
        )
        .await;

        // should reject a report using the wrong HPKE config for the leader, and reply with
        // the error type outdatedConfig.
        let unused_hpke_config_id = (0..)
            .map(HpkeConfigId::from)
            .find(|id| !leader_task.hpke_keys().contains_key(id))
            .unwrap();
        let bad_report = Report::new(
            report.metadata().clone(),
            report.public_share().to_vec(),
            HpkeCiphertext::new(
                unused_hpke_config_id,
                report
                    .leader_encrypted_input_share()
                    .encapsulated_key()
                    .to_vec(),
                report.leader_encrypted_input_share().payload().to_vec(),
            ),
            report.helper_encrypted_input_share().clone(),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(bad_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "outdatedConfig",
            "The message was generated using an outdated configuration.",
            task.id(),
        )
        .await;

        // Reports from the future should be rejected.
        let bad_report_time = clock
            .now()
            .add(&Duration::from_minutes(10).unwrap())
            .unwrap()
            .add(&Duration::from_seconds(1))
            .unwrap();
        let bad_report = Report::new(
            ReportMetadata::new(*report.metadata().id(), bad_report_time),
            report.public_share().to_vec(),
            report.leader_encrypted_input_share().clone(),
            report.helper_encrypted_input_share().clone(),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(bad_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportTooEarly",
            "Report could not be processed because it arrived too early.",
            task.id(),
        )
        .await;

        // Reports with timestamps past the task's expiration should be rejected.
        let task_expire_soon = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .with_task_expiration(Some(clock.now().add(&Duration::from_seconds(60)).unwrap()))
            .build();
        let leader_task_expire_soon = task_expire_soon.leader_view().unwrap();
        datastore
            .put_aggregator_task(&leader_task_expire_soon)
            .await
            .unwrap();
        let report_2 = create_report(
            &leader_task_expire_soon,
            clock.now().add(&Duration::from_seconds(120)).unwrap(),
        );
        let mut test_conn = put(task_expire_soon.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(report_2.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportRejected",
            "Report could not be processed.",
            task_expire_soon.id(),
        )
        .await;

        // Check for appropriate CORS headers in response to a preflight request.
        let test_conn = TestConn::build(
            trillium::Method::Options,
            task.report_upload_uri().unwrap().path(),
            (),
        )
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .with_request_header(KnownHeaderName::AccessControlRequestMethod, "PUT")
        .with_request_header(KnownHeaderName::AccessControlRequestHeaders, "content-type")
        .run_async(&handler)
        .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/",
            "access-control-allow-methods"=> "PUT",
            "access-control-allow-headers" => "content-type",
            "access-control-max-age"=> "86400",
        );

        // Check for appropriate CORS headers in response to the main request.
        let test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::Origin, "https://example.com/")
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(
                Report::new(
                    ReportMetadata::new(
                        random(),
                        clock
                            .now()
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                    ),
                    report.public_share().to_vec(),
                    report.leader_encrypted_input_share().clone(),
                    report.helper_encrypted_input_share().clone(),
                )
                .get_encoded(),
            )
            .run_async(&handler)
            .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/"
        );
    }

    // Helper should not expose /upload endpoint
    #[tokio::test]
    async fn upload_handler_helper() {
        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build();
        let helper_task = task.helper_view().unwrap();
        datastore.put_aggregator_task(&helper_task).await.unwrap();
        let report = create_report(&helper_task, clock.now());

        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(report.get_encoded())
            .run_async(&handler)
            .await;

        assert!(!test_conn.status().unwrap().is_success());
        let problem_details = take_problem_details(&mut test_conn).await;
        assert_eq!(
            problem_details,
            json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(
            problem_details
                .as_object()
                .unwrap()
                .get("status")
                .unwrap()
                .as_u64()
                .unwrap(),
            test_conn.status().unwrap() as u16 as u64
        );
    }

    #[tokio::test]
    async fn aggregate_leader() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build();
        datastore
            .put_aggregator_task(&task.leader_view().unwrap())
            .await
            .unwrap();

        let request = AggregationJobInitializeReq::new(
            Vec::new(),
            PartialBatchSelector::new_time_interval(),
            Vec::new(),
        );
        let aggregation_job_id: AggregationJobId = random();

        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
        assert!(!test_conn.status().unwrap().is_success());

        let problem_details = take_problem_details(&mut test_conn).await;
        assert_eq!(
            problem_details,
            json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(
            problem_details
                .as_object()
                .unwrap()
                .get("status")
                .unwrap()
                .as_u64()
                .unwrap(),
            test_conn.status().unwrap() as u16 as u64
        );

        // Check that CORS headers don't bleed over to other routes.
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => None,
            "access-control-allow-methods" => None,
            "access-control-max-age" => None,
        );

        let test_conn = TestConn::build(
            trillium::Method::Options,
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
            (),
        )
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .with_request_header(KnownHeaderName::AccessControlRequestMethod, "PUT")
        .run_async(&handler)
        .await;
        assert_headers!(&test_conn, "access-control-allow-methods" => None);
    }

    #[tokio::test]
    async fn aggregate_wrong_agg_auth_token() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let dap_auth_token = AuthenticationToken::DapAuth(random());

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .with_aggregator_auth_token(dap_auth_token.clone())
            .build();

        datastore
            .put_aggregator_task(&task.helper_view().unwrap())
            .await
            .unwrap();

        let request = AggregationJobInitializeReq::new(
            Vec::new(),
            PartialBatchSelector::new_time_interval(),
            Vec::new(),
        );
        let aggregation_job_id: AggregationJobId = random();

        let wrong_token_value = random();

        // Send the right token, but the wrong format: convert the DAP auth token to an equivalent
        // Bearer token, which should be rejected.
        let wrong_token_format =
            AuthenticationToken::new_bearer_token_from_bytes(dap_auth_token.as_ref()).unwrap();

        for auth_token in [Some(wrong_token_value), Some(wrong_token_format), None] {
            let mut test_conn = put(task
                .aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path())
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded());

            if let Some(auth_token) = auth_token {
                let (auth_header, auth_value) = auth_token.request_authentication();
                test_conn = test_conn.with_request_header(auth_header, auth_value);
            }

            let mut test_conn = test_conn.run_async(&handler).await;

            let want_status = 400;
            assert_eq!(
                take_problem_details(&mut test_conn).await,
                json!({
                    "status": want_status,
                    "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                    "title": "The request's authorization is not valid.",
                    "taskid": format!("{}", task.id()),
                })
            );
            assert_eq!(want_status, test_conn.status().unwrap() as u16);
        }
    }

    #[tokio::test]
    // Silence the unit_arg lint so that we can work with dummy_vdaf::Vdaf::{InputShare,
    // Measurement} values (whose type is ()).
    #[allow(clippy::unit_arg, clippy::let_unit_value)]
    async fn aggregate_init() {
        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake).build();

        let helper_task = task.helper_view().unwrap();

        let vdaf = dummy_vdaf::Vdaf::new();
        let verify_key: VerifyKey<0> = task.vdaf_verify_key().unwrap();
        let hpke_key = helper_task.current_hpke_key();
        let measurement = ();
        let prep_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            vdaf.clone(),
            dummy_vdaf::AggregationParam(0),
        );

        // prepare_init_0 is a "happy path" report.
        let (prepare_init_0, transcript_0) = prep_init_generator.next(&measurement);

        // report_share_1 fails decryption.
        let (prepare_init_1, transcript_1) = prep_init_generator.next(&measurement);

        let encrypted_input_share = prepare_init_1.report_share().encrypted_input_share();
        let mut corrupted_payload = encrypted_input_share.payload().to_vec();
        corrupted_payload[0] ^= 0xFF;
        let corrupted_input_share = HpkeCiphertext::new(
            *encrypted_input_share.config_id(),
            encrypted_input_share.encapsulated_key().to_vec(),
            corrupted_payload,
        );

        let prepare_init_1 = PrepareInit::new(
            ReportShare::new(
                prepare_init_1.report_share().metadata().clone(),
                transcript_1.public_share.get_encoded(),
                corrupted_input_share,
            ),
            prepare_init_1.message().clone(),
        );

        // prepare_init_2 fails decoding due to an issue with the input share.
        let (prepare_init_2, transcript_2) = prep_init_generator.next(&measurement);

        let mut input_share_bytes = transcript_2.helper_input_share.get_encoded();
        input_share_bytes.push(0); // can no longer be decoded.
        let report_share_2 = generate_helper_report_share_for_plaintext(
            prepare_init_2.report_share().metadata().clone(),
            hpke_key.config(),
            transcript_2.public_share.get_encoded(),
            &input_share_bytes,
            &InputShareAad::new(
                *task.id(),
                prepare_init_2.report_share().metadata().clone(),
                transcript_2.public_share.get_encoded(),
            )
            .get_encoded(),
        );

        let prepare_init_2 = PrepareInit::new(report_share_2, prepare_init_2.message().clone());

        // prepare_init_3 has an unknown HPKE config ID.
        let (prepare_init_3, transcript_3) = prep_init_generator.next(&measurement);

        let wrong_hpke_config = loop {
            let hpke_config = generate_test_hpke_config_and_private_key().config().clone();
            if helper_task.hpke_keys().contains_key(hpke_config.id()) {
                continue;
            }
            break hpke_config;
        };

        let report_share_3 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            prepare_init_3.report_share().metadata().clone(),
            &wrong_hpke_config,
            &transcript_3.public_share,
            Vec::new(),
            &transcript_3.helper_input_share,
        );

        let prepare_init_3 = PrepareInit::new(report_share_3, prepare_init_3.message().clone());

        // prepare_init_4 has already been aggregated in another aggregation job, with the same
        // aggregation parameter.
        let (prepare_init_4, _) = prep_init_generator.next(&measurement);

        // prepare_init_5 falls into a batch that has already been collected.
        let past_clock = MockClock::new(Time::from_seconds_since_epoch(
            task.time_precision().as_seconds() / 2,
        ));
        let report_metadata_5 = ReportMetadata::new(
            random(),
            past_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_5 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_5.id(),
            &measurement,
        );
        let report_share_5 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_5,
            hpke_key.config(),
            &transcript_5.public_share,
            Vec::new(),
            &transcript_5.helper_input_share,
        );

        let prepare_init_5 = PrepareInit::new(
            report_share_5,
            transcript_5.leader_prepare_transitions[0].message.clone(),
        );

        // prepare_init_6 fails decoding due to an issue with the public share.
        let public_share_6 = Vec::from([0]);
        let report_metadata_6 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_6 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_6.id(),
            &measurement,
        );
        let report_share_6 = generate_helper_report_share_for_plaintext(
            report_metadata_6.clone(),
            hpke_key.config(),
            public_share_6.clone(),
            &transcript_6.helper_input_share.get_encoded(),
            &InputShareAad::new(*task.id(), report_metadata_6, public_share_6).get_encoded(),
        );

        let prepare_init_6 = PrepareInit::new(
            report_share_6,
            transcript_6.leader_prepare_transitions[0].message.clone(),
        );

        // prepare_init_7 fails due to having repeated extensions.
        let report_metadata_7 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_7 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_7.id(),
            &measurement,
        );
        let report_share_7 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_7,
            hpke_key.config(),
            &transcript_7.public_share,
            Vec::from([
                Extension::new(ExtensionType::Tbd, Vec::new()),
                Extension::new(ExtensionType::Tbd, Vec::new()),
            ]),
            &transcript_7.helper_input_share,
        );

        let prepare_init_7 = PrepareInit::new(
            report_share_7,
            transcript_7.leader_prepare_transitions[0].message.clone(),
        );

        // prepare_init_8 has already been aggregated in another aggregation job, with a different
        // aggregation parameter.
        let (prepare_init_8, transcript_8) = prep_init_generator.next(&measurement);

        let (conflicting_aggregation_job, non_conflicting_aggregation_job) = datastore
            .run_unnamed_tx(|tx| {
                let task = helper_task.clone();
                let report_share_4 = prepare_init_4.report_share().clone();
                let report_share_5 = prepare_init_5.report_share().clone();
                let report_share_8 = prepare_init_8.report_share().clone();
                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;

                    // report_share_4 and report_share_8 are already in the datastore as they were
                    // referenced by existing aggregation jobs.
                    tx.put_report_share(task.id(), &report_share_4).await?;
                    tx.put_report_share(task.id(), &report_share_8).await?;

                    // Put in an aggregation job and report aggregation for report_share_4. It uses
                    // the same aggregation parameter as the aggregation job this test will later
                    // add and so should cause report_share_4 to fail to prepare.
                    let conflicting_aggregation_job = AggregationJob::new(
                        *task.id(),
                        random(),
                        dummy_vdaf::AggregationParam(0),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    );
                    tx.put_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &conflicting_aggregation_job,
                    )
                    .await
                    .unwrap();
                    tx.put_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                        *task.id(),
                        *conflicting_aggregation_job.id(),
                        *report_share_4.metadata().id(),
                        *report_share_4.metadata().time(),
                        0,
                        None,
                        ReportAggregationState::Start,
                    ))
                    .await
                    .unwrap();

                    // Put in an aggregation job and report aggregation for report_share_8, using a
                    // a different aggregation parameter. As the aggregation parameter differs,
                    // report_share_8 should prepare successfully in the aggregation job we'll PUT
                    // later.
                    let non_conflicting_aggregation_job = AggregationJob::new(
                        *task.id(),
                        random(),
                        dummy_vdaf::AggregationParam(1),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    );
                    tx.put_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &non_conflicting_aggregation_job,
                    )
                    .await
                    .unwrap();
                    tx.put_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                        *task.id(),
                        *non_conflicting_aggregation_job.id(),
                        *report_share_8.metadata().id(),
                        *report_share_8.metadata().time(),
                        0,
                        None,
                        ReportAggregationState::Start,
                    ))
                    .await
                    .unwrap();

                    // Put in an aggregate share job for the interval that report_share_5 falls into
                    // which should cause it to later fail to prepare.
                    tx.put_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &AggregateShareJob::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            dummy_vdaf::AggregationParam(0),
                            dummy_vdaf::AggregateShare(0),
                            1,
                            ReportIdChecksum::for_report_id(report_share_5.metadata().id()),
                        ),
                    )
                    .await?;

                    Ok((conflicting_aggregation_job, non_conflicting_aggregation_job))
                })
            })
            .await
            .unwrap();

        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([
                prepare_init_0.clone(),
                prepare_init_1.clone(),
                prepare_init_2.clone(),
                prepare_init_3.clone(),
                prepare_init_4.clone(),
                prepare_init_5.clone(),
                prepare_init_6.clone(),
                prepare_init_7.clone(),
                prepare_init_8.clone(),
            ]),
        );

        // Send request, parse response. Do this twice to prove that the request is idempotent.
        let aggregation_job_id: AggregationJobId = random();
        for _ in 0..2 {
            let mut test_conn =
                put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
            assert_eq!(test_conn.status(), Some(Status::Ok));
            assert_headers!(
                &test_conn,
                "content-type" => (AggregationJobResp::MEDIA_TYPE)
            );
            let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

            // Validate response.
            assert_eq!(aggregate_resp.prepare_resps().len(), 9);

            let prepare_step_0 = aggregate_resp.prepare_resps().get(0).unwrap();
            assert_eq!(
                prepare_step_0.report_id(),
                prepare_init_0.report_share().metadata().id()
            );
            assert_matches!(prepare_step_0.result(), PrepareStepResult::Continue { message } => {
                assert_eq!(message, &transcript_0.helper_prepare_transitions[0].message);
            });

            let prepare_step_1 = aggregate_resp.prepare_resps().get(1).unwrap();
            assert_eq!(
                prepare_step_1.report_id(),
                prepare_init_1.report_share().metadata().id()
            );
            assert_matches!(
                prepare_step_1.result(),
                &PrepareStepResult::Reject(PrepareError::HpkeDecryptError)
            );

            let prepare_step_2 = aggregate_resp.prepare_resps().get(2).unwrap();
            assert_eq!(
                prepare_step_2.report_id(),
                prepare_init_2.report_share().metadata().id()
            );
            assert_matches!(
                prepare_step_2.result(),
                &PrepareStepResult::Reject(PrepareError::InvalidMessage)
            );

            let prepare_step_3 = aggregate_resp.prepare_resps().get(3).unwrap();
            assert_eq!(
                prepare_step_3.report_id(),
                prepare_init_3.report_share().metadata().id()
            );
            assert_matches!(
                prepare_step_3.result(),
                &PrepareStepResult::Reject(PrepareError::HpkeUnknownConfigId)
            );

            let prepare_step_4 = aggregate_resp.prepare_resps().get(4).unwrap();
            assert_eq!(
                prepare_step_4.report_id(),
                prepare_init_4.report_share().metadata().id()
            );
            assert_eq!(
                prepare_step_4.result(),
                &PrepareStepResult::Reject(PrepareError::ReportReplayed)
            );

            let prepare_step_5 = aggregate_resp.prepare_resps().get(5).unwrap();
            assert_eq!(
                prepare_step_5.report_id(),
                prepare_init_5.report_share().metadata().id()
            );
            assert_eq!(
                prepare_step_5.result(),
                &PrepareStepResult::Reject(PrepareError::BatchCollected)
            );

            let prepare_step_6 = aggregate_resp.prepare_resps().get(6).unwrap();
            assert_eq!(
                prepare_step_6.report_id(),
                prepare_init_6.report_share().metadata().id()
            );
            assert_eq!(
                prepare_step_6.result(),
                &PrepareStepResult::Reject(PrepareError::InvalidMessage),
            );

            let prepare_step_7 = aggregate_resp.prepare_resps().get(7).unwrap();
            assert_eq!(
                prepare_step_7.report_id(),
                prepare_init_7.report_share().metadata().id()
            );
            assert_eq!(
                prepare_step_7.result(),
                &PrepareStepResult::Reject(PrepareError::InvalidMessage),
            );

            let prepare_step_8 = aggregate_resp.prepare_resps().get(8).unwrap();
            assert_eq!(
                prepare_step_8.report_id(),
                prepare_init_8.report_share().metadata().id()
            );
            assert_matches!(prepare_step_8.result(), PrepareStepResult::Continue { message } => {
                assert_eq!(message, &transcript_8.helper_prepare_transitions[0].message);
            });

            // Check aggregation job in datastore.
            let aggregation_jobs = datastore
                .run_unnamed_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move {
                        tx.get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            task.id(),
                        )
                        .await
                    })
                })
                .await
                .unwrap();

            assert_eq!(aggregation_jobs.len(), 3);

            let mut saw_conflicting_aggregation_job = false;
            let mut saw_non_conflicting_aggregation_job = false;
            let mut saw_new_aggregation_job = false;

            for aggregation_job in aggregation_jobs {
                if aggregation_job.eq(&conflicting_aggregation_job) {
                    saw_conflicting_aggregation_job = true;
                } else if aggregation_job.eq(&non_conflicting_aggregation_job) {
                    saw_non_conflicting_aggregation_job = true;
                } else if aggregation_job.task_id().eq(task.id())
                    && aggregation_job.id().eq(&aggregation_job_id)
                    && aggregation_job.partial_batch_identifier().eq(&())
                    && aggregation_job.state().eq(&AggregationJobState::Finished)
                {
                    saw_new_aggregation_job = true;
                }
            }

            assert!(saw_conflicting_aggregation_job);
            assert!(saw_non_conflicting_aggregation_job);
            assert!(saw_new_aggregation_job);
        }
    }

    #[tokio::test]
    #[allow(clippy::unit_arg)]
    async fn aggregate_init_with_reports_encrypted_by_global_key() {
        let (clock, _ephemeral_datastore, datastore, _) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake).build();

        let helper_task = task.helper_view().unwrap();
        datastore.put_aggregator_task(&helper_task).await.unwrap();
        let vdaf = dummy_vdaf::Vdaf::new();
        let aggregation_param = dummy_vdaf::AggregationParam(0);
        let prep_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            vdaf.clone(),
            aggregation_param,
        );

        // Insert some global HPKE keys.
        // Same ID as the task to test having both keys to choose from.
        let global_hpke_keypair_same_id = generate_test_hpke_config_and_private_key_with_id(
            (*helper_task.current_hpke_key().config().id()).into(),
        );
        // Different ID to test misses on the task key.
        let global_hpke_keypair_different_id = generate_test_hpke_config_and_private_key_with_id(
            (0..)
                .map(HpkeConfigId::from)
                .find(|id| !helper_task.hpke_keys().contains_key(id))
                .unwrap()
                .into(),
        );
        datastore
            .run_unnamed_tx(|tx| {
                let global_hpke_keypair_same_id = global_hpke_keypair_same_id.clone();
                let global_hpke_keypair_different_id = global_hpke_keypair_different_id.clone();
                Box::pin(async move {
                    // Leave these in the PENDING state--they should still be decryptable.
                    tx.put_global_hpke_keypair(&global_hpke_keypair_same_id)
                        .await?;
                    tx.put_global_hpke_keypair(&global_hpke_keypair_different_id)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

        // Create new handler _after_ the keys have been inserted so that they come pre-cached.
        let handler = aggregator_handler(
            datastore.clone(),
            clock.clone(),
            &noop_meter(),
            default_aggregator_config(),
        )
        .await
        .unwrap();

        let verify_key: VerifyKey<0> = task.vdaf_verify_key().unwrap();

        // This report was encrypted with a global HPKE config that has the same config
        // ID as the task's HPKE config.
        let (prepare_init_same_id, transcript_same_id) = prep_init_generator.next(&());

        // This report was encrypted with a global HPKE config that has the same config
        // ID as the task's HPKE config, but will fail to decrypt.
        let (prepare_init_same_id_corrupted, transcript_same_id_corrupted) =
            prep_init_generator.next(&());

        let encrypted_input_share = prepare_init_same_id_corrupted
            .report_share()
            .encrypted_input_share();
        let mut corrupted_payload = encrypted_input_share.payload().to_vec();
        corrupted_payload[0] ^= 0xFF;
        let corrupted_input_share = HpkeCiphertext::new(
            *encrypted_input_share.config_id(),
            encrypted_input_share.encapsulated_key().to_vec(),
            corrupted_payload,
        );

        let prepare_init_same_id_corrupted = PrepareInit::new(
            ReportShare::new(
                prepare_init_same_id_corrupted
                    .report_share()
                    .metadata()
                    .clone(),
                transcript_same_id_corrupted.public_share.get_encoded(),
                corrupted_input_share,
            ),
            prepare_init_same_id_corrupted.message().clone(),
        );

        // This report was encrypted with a global HPKE config that doesn't collide
        // with the task HPKE config's ID.
        let report_metadata_different_id = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_different_id = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_different_id.id(),
            &(),
        );
        let report_share_different_id = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_different_id,
            global_hpke_keypair_different_id.config(),
            &transcript_different_id.public_share,
            Vec::new(),
            &transcript_different_id.helper_input_share,
        );

        let prepare_init_different_id = PrepareInit::new(
            report_share_different_id,
            transcript_different_id.leader_prepare_transitions[0]
                .message
                .clone(),
        );

        // This report was encrypted with a global HPKE config that doesn't collide
        // with the task HPKE config's ID, but will fail decryption.
        let report_metadata_different_id_corrupted = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_different_id_corrupted = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_different_id_corrupted.id(),
            &(),
        );
        let report_share_different_id_corrupted = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_different_id_corrupted.clone(),
            global_hpke_keypair_different_id.config(),
            &transcript_different_id_corrupted.public_share,
            Vec::new(),
            &transcript_different_id_corrupted.helper_input_share,
        );
        let encrypted_input_share = report_share_different_id_corrupted.encrypted_input_share();
        let mut corrupted_payload = encrypted_input_share.payload().to_vec();
        corrupted_payload[0] ^= 0xFF;
        let corrupted_input_share = HpkeCiphertext::new(
            *encrypted_input_share.config_id(),
            encrypted_input_share.encapsulated_key().to_vec(),
            corrupted_payload,
        );
        let encoded_public_share = transcript_different_id_corrupted.public_share.get_encoded();

        let prepare_init_different_id_corrupted = PrepareInit::new(
            ReportShare::new(
                report_metadata_different_id_corrupted,
                encoded_public_share.clone(),
                corrupted_input_share,
            ),
            transcript_different_id_corrupted.leader_prepare_transitions[0]
                .message
                .clone(),
        );

        let aggregation_job_id: AggregationJobId = random();
        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([
                prepare_init_same_id.clone(),
                prepare_init_different_id.clone(),
                prepare_init_same_id_corrupted.clone(),
                prepare_init_different_id_corrupted.clone(),
            ]),
        );

        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

        // Validate response.
        assert_eq!(aggregate_resp.prepare_resps().len(), 4);

        let prepare_step_same_id = aggregate_resp.prepare_resps().get(0).unwrap();
        assert_eq!(
            prepare_step_same_id.report_id(),
            prepare_init_same_id.report_share().metadata().id()
        );
        assert_matches!(prepare_step_same_id.result(), PrepareStepResult::Continue { message } => {
            assert_eq!(message, &transcript_same_id.helper_prepare_transitions[0].message);
        });

        let prepare_step_different_id = aggregate_resp.prepare_resps().get(1).unwrap();
        assert_eq!(
            prepare_step_different_id.report_id(),
            prepare_init_different_id.report_share().metadata().id()
        );
        assert_matches!(
            prepare_step_different_id.result(),
            PrepareStepResult::Continue { message } => {
                assert_eq!(message, &transcript_different_id.helper_prepare_transitions[0].message);
            }
        );

        let prepare_step_same_id_corrupted = aggregate_resp.prepare_resps().get(2).unwrap();
        assert_eq!(
            prepare_step_same_id_corrupted.report_id(),
            prepare_init_same_id_corrupted
                .report_share()
                .metadata()
                .id(),
        );
        assert_matches!(
            prepare_step_same_id_corrupted.result(),
            &PrepareStepResult::Reject(PrepareError::HpkeDecryptError)
        );

        let prepare_step_different_id_corrupted = aggregate_resp.prepare_resps().get(3).unwrap();
        assert_eq!(
            prepare_step_different_id_corrupted.report_id(),
            prepare_init_different_id_corrupted
                .report_share()
                .metadata()
                .id()
        );
        assert_matches!(
            prepare_step_different_id_corrupted.result(),
            &PrepareStepResult::Reject(PrepareError::HpkeDecryptError)
        );
    }

    #[allow(clippy::unit_arg)]
    #[tokio::test]
    async fn aggregate_init_change_report_timestamp() {
        let test_case = setup_aggregate_init_test().await;

        let other_aggregation_parameter = dummy_vdaf::AggregationParam(1);
        assert_ne!(test_case.aggregation_param, other_aggregation_parameter);

        // This report has the same ID as the previous one, but a different timestamp.
        let mutated_timestamp_report_metadata = ReportMetadata::new(
            *test_case.prepare_inits[0].report_share().metadata().id(),
            test_case
                .clock
                .now()
                .add(test_case.task.time_precision())
                .unwrap(),
        );
        let (mutated_timestamp_prepare_init, _) = test_case
            .prepare_init_generator
            .next_with_metadata(mutated_timestamp_report_metadata, &());

        // Send another aggregate job re-using the same report ID but with a different timestamp. It
        // should be flagged as a replay.
        let request = AggregationJobInitializeReq::new(
            other_aggregation_parameter.get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([mutated_timestamp_prepare_init.clone()]),
        );

        let mut test_conn =
            put_aggregation_job(&test_case.task, &random(), &request, &test_case.handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

        assert_eq!(aggregate_resp.prepare_resps().len(), 1);

        let prepare_step = aggregate_resp.prepare_resps().get(0).unwrap();
        assert_eq!(
            prepare_step.report_id(),
            mutated_timestamp_prepare_init
                .report_share()
                .metadata()
                .id(),
        );
        assert_matches!(
            prepare_step.result(),
            &PrepareStepResult::Reject(PrepareError::ReportReplayed)
        );

        // The attempt to mutate the report share timestamp should not cause any change in the
        // datastore.
        let client_reports = test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task_id = *test_case.task.id();
                Box::pin(async move {
                    let reports = tx.get_report_metadatas_for_task(&task_id).await.unwrap();

                    Ok(reports)
                })
            })
            .await
            .unwrap();
        assert_eq!(client_reports.len(), 2);
        assert_eq!(
            &client_reports[0],
            test_case.prepare_inits[0].report_share().metadata()
        );
        assert_eq!(
            &client_reports[1],
            test_case.prepare_inits[1].report_share().metadata()
        );
    }

    #[tokio::test]
    async fn aggregate_init_prep_init_failed() {
        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::FakeFailsPrepInit).build();
        let helper_task = task.helper_view().unwrap();
        let prep_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            dummy_vdaf::Vdaf::new(),
            dummy_vdaf::AggregationParam(0),
        );

        datastore.put_aggregator_task(&helper_task).await.unwrap();

        let (prepare_init, _) = prep_init_generator.next(&());
        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([prepare_init.clone()]),
        );

        // Send request, and parse response.
        let aggregation_job_id: AggregationJobId = random();
        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "content-type" => (AggregationJobResp::MEDIA_TYPE)
        );
        let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

        // Validate response.
        assert_eq!(aggregate_resp.prepare_resps().len(), 1);

        let prepare_step = aggregate_resp.prepare_resps().get(0).unwrap();
        assert_eq!(
            prepare_step.report_id(),
            prepare_init.report_share().metadata().id()
        );
        assert_matches!(
            prepare_step.result(),
            &PrepareStepResult::Reject(PrepareError::VdafPrepError)
        );
    }

    #[tokio::test]
    async fn aggregate_init_prep_step_failed() {
        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::FakeFailsPrepStep).build();
        let helper_task = task.helper_view().unwrap();
        let prep_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            dummy_vdaf::Vdaf::new(),
            dummy_vdaf::AggregationParam(0),
        );

        datastore.put_aggregator_task(&helper_task).await.unwrap();

        let (prepare_init, _) = prep_init_generator.next(&());
        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([prepare_init.clone()]),
        );

        let aggregation_job_id: AggregationJobId = random();
        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "content-type" => (AggregationJobResp::MEDIA_TYPE)
        );
        let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

        // Validate response.
        assert_eq!(aggregate_resp.prepare_resps().len(), 1);

        let prepare_step = aggregate_resp.prepare_resps().get(0).unwrap();
        assert_eq!(
            prepare_step.report_id(),
            prepare_init.report_share().metadata().id()
        );
        assert_matches!(
            prepare_step.result(),
            &PrepareStepResult::Reject(PrepareError::VdafPrepError)
        );
    }

    #[tokio::test]
    async fn aggregate_init_duplicated_report_id() {
        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake).build();

        let helper_task = task.helper_view().unwrap();
        let prep_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            dummy_vdaf::Vdaf::new(),
            dummy_vdaf::AggregationParam(0),
        );

        datastore.put_aggregator_task(&helper_task).await.unwrap();

        let (prepare_init, _) = prep_init_generator.next(&());

        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([prepare_init.clone(), prepare_init]),
        );
        let aggregation_job_id: AggregationJobId = random();

        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;

        let want_status = 400;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());
    }

    #[tokio::test]
    async fn aggregate_continue() {
        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let aggregation_job_id = random();
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Poplar1 { bits: 1 }).build();
        let helper_task = task.helper_view().unwrap();

        let vdaf = Arc::new(Poplar1::<XofShake128, 16>::new(1));
        let verify_key: VerifyKey<VERIFY_KEY_LENGTH> = task.vdaf_verify_key().unwrap();
        let hpke_key = helper_task.current_hpke_key();
        let measurement = IdpfInput::from_bools(&[true]);
        let aggregation_param =
            Poplar1AggregationParam::try_from_prefixes(vec![measurement.clone()]).unwrap();

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_0 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_0.id(),
            &measurement,
        );
        let helper_prep_state_0 = transcript_0.helper_prepare_transitions[0].prepare_state();
        let leader_prep_message_0 = &transcript_0.leader_prepare_transitions[1].message;
        let report_share_0 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_0.clone(),
            hpke_key.config(),
            &transcript_0.public_share,
            Vec::new(),
            &transcript_0.helper_input_share,
        );

        // report_share_1 is omitted by the leader's request.
        let report_metadata_1 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_1 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_1.id(),
            &measurement,
        );

        let helper_prep_state_1 = transcript_1.helper_prepare_transitions[0].prepare_state();
        let report_share_1 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_1.clone(),
            hpke_key.config(),
            &transcript_1.public_share,
            Vec::new(),
            &transcript_1.helper_input_share,
        );

        // report_share_2 falls into a batch that has already been collected.
        let past_clock = MockClock::new(Time::from_seconds_since_epoch(
            task.time_precision().as_seconds() / 2,
        ));
        let report_metadata_2 = ReportMetadata::new(
            random(),
            past_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_2 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_2.id(),
            &measurement,
        );
        let helper_prep_state_2 = transcript_2.helper_prepare_transitions[0].prepare_state();
        let leader_prep_message_2 = &transcript_2.leader_prepare_transitions[1].message;
        let report_share_2 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_2.clone(),
            hpke_key.config(),
            &transcript_2.public_share,
            Vec::new(),
            &transcript_2.helper_input_share,
        );

        datastore
            .run_unnamed_tx(|tx| {
                let task = helper_task.clone();
                let (report_share_0, report_share_1, report_share_2) = (
                    report_share_0.clone(),
                    report_share_1.clone(),
                    report_share_2.clone(),
                );
                let (helper_prep_state_0, helper_prep_state_1, helper_prep_state_2) = (
                    helper_prep_state_0.clone(),
                    helper_prep_state_1.clone(),
                    helper_prep_state_2.clone(),
                );
                let (report_metadata_0, report_metadata_1, report_metadata_2) = (
                    report_metadata_0.clone(),
                    report_metadata_1.clone(),
                    report_metadata_2.clone(),
                );
                let aggregation_param = aggregation_param.clone();
                let helper_aggregate_share = transcript_0.helper_aggregate_share.clone();

                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;

                    tx.put_report_share(task.id(), &report_share_0).await?;
                    tx.put_report_share(task.id(), &report_share_1).await?;
                    tx.put_report_share(task.id(), &report_share_2).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param.clone(),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation::<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_0.id(),
                            *report_metadata_0.time(),
                            0,
                            None,
                            ReportAggregationState::WaitingHelper(helper_prep_state_0),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation::<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_1.id(),
                            *report_metadata_1.time(),
                            1,
                            None,
                            ReportAggregationState::WaitingHelper(helper_prep_state_1),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation::<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_2.id(),
                            *report_metadata_2.time(),
                            2,
                            None,
                            ReportAggregationState::WaitingHelper(helper_prep_state_2),
                        ),
                    )
                    .await?;

                    tx.put_aggregate_share_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>(
                        &AggregateShareJob::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            aggregation_param.clone(),
                            helper_aggregate_share,
                            0,
                            ReportIdChecksum::default(),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([
                PrepareContinue::new(*report_metadata_0.id(), leader_prep_message_0.clone()),
                PrepareContinue::new(*report_metadata_2.id(), leader_prep_message_2.clone()),
            ]),
        );

        // Send request, and parse response.
        let aggregate_resp =
            post_aggregation_job_and_decode(&task, &aggregation_job_id, &request, &handler).await;

        // Validate response.
        assert_eq!(
            aggregate_resp,
            AggregationJobResp::new(Vec::from([
                PrepareResp::new(*report_metadata_0.id(), PrepareStepResult::Finished),
                PrepareResp::new(
                    *report_metadata_2.id(),
                    PrepareStepResult::Reject(PrepareError::BatchCollected),
                )
            ]))
        );

        // Validate datastore.
        let (aggregation_job, report_aggregations) = datastore
            .run_unnamed_tx(|tx| {
                let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            &Role::Helper,
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();
                    Ok((aggregation_job, report_aggregations))
                })
            })
            .await
            .unwrap();

        assert_eq!(
            aggregation_job,
            AggregationJob::new(
                *task.id(),
                aggregation_job_id,
                aggregation_param,
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
                AggregationJobStep::from(1),
            )
            .with_last_request_hash(aggregation_job.last_request_hash().unwrap())
        );
        assert_eq!(
            report_aggregations,
            Vec::from([
                ReportAggregation::new(
                    *task.id(),
                    aggregation_job_id,
                    *report_metadata_0.id(),
                    *report_metadata_0.time(),
                    0,
                    Some(PrepareResp::new(
                        *report_metadata_0.id(),
                        PrepareStepResult::Finished
                    )),
                    ReportAggregationState::Finished,
                ),
                ReportAggregation::new(
                    *task.id(),
                    aggregation_job_id,
                    *report_metadata_1.id(),
                    *report_metadata_1.time(),
                    1,
                    None,
                    ReportAggregationState::Failed(PrepareError::ReportDropped),
                ),
                ReportAggregation::new(
                    *task.id(),
                    aggregation_job_id,
                    *report_metadata_2.id(),
                    *report_metadata_2.time(),
                    2,
                    Some(PrepareResp::new(
                        *report_metadata_2.id(),
                        PrepareStepResult::Reject(PrepareError::BatchCollected)
                    )),
                    ReportAggregationState::Failed(PrepareError::BatchCollected),
                )
            ])
        );
    }

    #[tokio::test]
    async fn aggregate_continue_accumulate_batch_aggregation() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Poplar1 { bits: 1 }).build();
        let helper_task = task.helper_view().unwrap();
        let aggregation_job_id_0 = random();
        let aggregation_job_id_1 = random();
        let first_batch_interval_clock = MockClock::default();
        let second_batch_interval_clock = MockClock::new(
            first_batch_interval_clock
                .now()
                .add(task.time_precision())
                .unwrap(),
        );

        let vdaf = Poplar1::new(1);
        let verify_key: VerifyKey<VERIFY_KEY_LENGTH> = task.vdaf_verify_key().unwrap();
        let hpke_key = helper_task.current_hpke_key();
        let measurement = IdpfInput::from_bools(&[true]);
        let aggregation_param =
            Poplar1AggregationParam::try_from_prefixes(vec![measurement.clone()]).unwrap();

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            first_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_0 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_0.id(),
            &measurement,
        );
        let helper_prep_state_0 = transcript_0.helper_prepare_transitions[0].prepare_state();
        let ping_pong_leader_message_0 = &transcript_0.leader_prepare_transitions[1].message;
        let report_share_0 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_0.clone(),
            hpke_key.config(),
            &transcript_0.public_share,
            Vec::new(),
            &transcript_0.helper_input_share,
        );

        // report_share_1 is another "happy path" report to exercise in-memory accumulation of
        // output shares
        let report_metadata_1 = ReportMetadata::new(
            random(),
            first_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_1 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_1.id(),
            &measurement,
        );
        let helper_prep_state_1 = transcript_1.helper_prepare_transitions[0].prepare_state();
        let ping_pong_leader_message_1 = &transcript_1.leader_prepare_transitions[1].message;
        let report_share_1 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_1.clone(),
            hpke_key.config(),
            &transcript_1.public_share,
            Vec::new(),
            &transcript_1.helper_input_share,
        );

        // report_share_2 aggregates successfully, but into a distinct batch aggregation which has
        // already been collected.
        let report_metadata_2 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_2 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_2.id(),
            &measurement,
        );
        let helper_prep_state_2 = transcript_2.helper_prepare_transitions[0].prepare_state();
        let ping_pong_leader_message_2 = &transcript_2.leader_prepare_transitions[1].message;
        let report_share_2 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_2.clone(),
            hpke_key.config(),
            &transcript_2.public_share,
            Vec::new(),
            &transcript_2.helper_input_share,
        );

        let first_batch_identifier = Interval::new(
            report_metadata_0
                .time()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            *task.time_precision(),
        )
        .unwrap();
        let second_batch_identifier = Interval::new(
            report_metadata_2
                .time()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            *task.time_precision(),
        )
        .unwrap();
        let second_batch_want_batch_aggregations =
            empty_batch_aggregations::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>(
                &helper_task,
                BATCH_AGGREGATION_SHARD_COUNT,
                &second_batch_identifier,
                &aggregation_param,
                &[],
            );

        datastore
            .run_unnamed_tx(|tx| {
                let task = helper_task.clone();
                let (report_share_0, report_share_1, report_share_2) = (
                    report_share_0.clone(),
                    report_share_1.clone(),
                    report_share_2.clone(),
                );
                let (helper_prep_state_0, helper_prep_state_1, helper_prep_state_2) = (
                    helper_prep_state_0.clone(),
                    helper_prep_state_1.clone(),
                    helper_prep_state_2.clone(),
                );
                let (report_metadata_0, report_metadata_1, report_metadata_2) = (
                    report_metadata_0.clone(),
                    report_metadata_1.clone(),
                    report_metadata_2.clone(),
                );
                let aggregation_param = aggregation_param.clone();
                let second_batch_want_batch_aggregations =
                    second_batch_want_batch_aggregations.clone();

                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;

                    tx.put_report_share(task.id(), &report_share_0).await?;
                    tx.put_report_share(task.id(), &report_share_1).await?;
                    tx.put_report_share(task.id(), &report_share_2).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        aggregation_param.clone(),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_0.id(),
                        *report_metadata_0.time(),
                        0,
                        None,
                        ReportAggregationState::WaitingHelper(helper_prep_state_0),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_1.id(),
                        *report_metadata_1.time(),
                        1,
                        None,
                        ReportAggregationState::WaitingHelper(helper_prep_state_1),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_2.id(),
                        *report_metadata_2.time(),
                        2,
                        None,
                        ReportAggregationState::WaitingHelper(helper_prep_state_2),
                    ))
                    .await?;

                    for batch_identifier in [first_batch_identifier, second_batch_identifier] {
                        tx.put_batch(&Batch::<
                            VERIFY_KEY_LENGTH,
                            TimeInterval,
                            Poplar1<XofShake128, 16>,
                        >::new(
                            *task.id(),
                            batch_identifier,
                            aggregation_param.clone(),
                            BatchState::Closed,
                            0,
                            batch_identifier,
                        ))
                        .await
                        .unwrap()
                    }

                    try_join_all(
                        second_batch_want_batch_aggregations
                            .iter()
                            .map(|ba| tx.put_batch_aggregation(ba)),
                    )
                    .await
                    .unwrap();

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([
                PrepareContinue::new(*report_metadata_0.id(), ping_pong_leader_message_0.clone()),
                PrepareContinue::new(*report_metadata_1.id(), ping_pong_leader_message_1.clone()),
                PrepareContinue::new(*report_metadata_2.id(), ping_pong_leader_message_2.clone()),
            ]),
        );

        // Send request, and parse response.
        let _ =
            post_aggregation_job_and_decode(&task, &aggregation_job_id_0, &request, &handler).await;

        // Map the batch aggregation ordinal value to 0, as it may vary due to sharding.
        let first_batch_got_batch_aggregations: Vec<_> = datastore
            .run_unnamed_tx(|tx| {
                let (task, vdaf, report_metadata_0, aggregation_param) = (
                    helper_task.clone(),
                    vdaf.clone(),
                    report_metadata_0.clone(),
                    aggregation_param.clone(),
                );
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collection_identifier::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                        _,
                    >(
                        tx,
                        &task,
                        &vdaf,
                        &Interval::new(
                            report_metadata_0
                                .time()
                                .to_batch_interval_start(task.time_precision())
                                .unwrap(),
                            *task.time_precision(),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|agg| {
                BatchAggregation::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>::new(
                    *agg.task_id(),
                    *agg.batch_identifier(),
                    agg.aggregation_parameter().clone(),
                    0,
                    BatchAggregationState::Aggregating,
                    agg.aggregate_share().cloned(),
                    agg.report_count(),
                    *agg.client_timestamp_interval(),
                    *agg.checksum(),
                )
            })
            .collect();

        let aggregate_share = vdaf
            .aggregate(
                &aggregation_param,
                [
                    transcript_0.helper_output_share.clone(),
                    transcript_1.helper_output_share.clone(),
                ],
            )
            .unwrap();
        let checksum = ReportIdChecksum::for_report_id(report_metadata_0.id())
            .updated_with(report_metadata_1.id());

        assert_eq!(
            first_batch_got_batch_aggregations,
            Vec::from([BatchAggregation::new(
                *task.id(),
                Interval::new(
                    report_metadata_0
                        .time()
                        .to_batch_interval_start(task.time_precision())
                        .unwrap(),
                    *task.time_precision()
                )
                .unwrap(),
                aggregation_param.clone(),
                0,
                BatchAggregationState::Aggregating,
                Some(aggregate_share),
                2,
                Interval::from_time(report_metadata_0.time()).unwrap(),
                checksum,
            ),])
        );

        let second_batch_got_batch_aggregations = datastore
            .run_unnamed_tx(|tx| {
                let (task, vdaf, report_metadata_2, aggregation_param) = (
                    helper_task.clone(),
                    vdaf.clone(),
                    report_metadata_2.clone(),
                    aggregation_param.clone(),
                );
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collection_identifier::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                        _,
                    >(
                        tx,
                        &task,
                        &vdaf,
                        &Interval::new(
                            report_metadata_2
                                .time()
                                .to_batch_interval_start(task.time_precision())
                                .unwrap(),
                            Duration::from_seconds(task.time_precision().as_seconds()),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(
            second_batch_got_batch_aggregations,
            second_batch_want_batch_aggregations
        );

        // Aggregate some more reports, which should get accumulated into the
        // batch_aggregations rows created earlier.
        // report_share_3 gets aggreated into the first batch interval.
        let report_metadata_3 = ReportMetadata::new(
            random(),
            first_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_3 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_3.id(),
            &measurement,
        );
        let helper_prep_state_3 = transcript_3.helper_prepare_transitions[0].prepare_state();
        let ping_pong_leader_message_3 = &transcript_3.leader_prepare_transitions[1].message;
        let report_share_3 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_3.clone(),
            hpke_key.config(),
            &transcript_3.public_share,
            Vec::new(),
            &transcript_3.helper_input_share,
        );

        // report_share_4 gets aggregated into the second batch interval (which has already been
        // collected).
        let report_metadata_4 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_4 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_4.id(),
            &measurement,
        );
        let helper_prep_state_4 = transcript_4.helper_prepare_transitions[0].prepare_state();
        let ping_pong_leader_message_4 = &transcript_4.leader_prepare_transitions[1].message;
        let report_share_4 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_4.clone(),
            hpke_key.config(),
            &transcript_4.public_share,
            Vec::new(),
            &transcript_4.helper_input_share,
        );

        // report_share_5 also gets aggregated into the second batch interval (which has already
        // been collected).
        let report_metadata_5 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_5 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &aggregation_param,
            report_metadata_5.id(),
            &measurement,
        );
        let helper_prep_state_5 = transcript_5.helper_prepare_transitions[0].prepare_state();
        let ping_pong_leader_message_5 = &transcript_5.leader_prepare_transitions[1].message;
        let report_share_5 = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata_5.clone(),
            hpke_key.config(),
            &transcript_5.public_share,
            Vec::new(),
            &transcript_5.helper_input_share,
        );

        datastore
            .run_unnamed_tx(|tx| {
                let task = helper_task.clone();
                let (report_share_3, report_share_4, report_share_5) = (
                    report_share_3.clone(),
                    report_share_4.clone(),
                    report_share_5.clone(),
                );
                let (helper_prep_state_3, helper_prep_state_4, helper_prep_state_5) = (
                    helper_prep_state_3.clone(),
                    helper_prep_state_4.clone(),
                    helper_prep_state_5.clone(),
                );
                let (report_metadata_3, report_metadata_4, report_metadata_5) = (
                    report_metadata_3.clone(),
                    report_metadata_4.clone(),
                    report_metadata_5.clone(),
                );
                let aggregation_param = aggregation_param.clone();

                Box::pin(async move {
                    tx.put_report_share(task.id(), &report_share_3).await?;
                    tx.put_report_share(task.id(), &report_share_4).await?;
                    tx.put_report_share(task.id(), &report_share_5).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        aggregation_param,
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_3.id(),
                        *report_metadata_3.time(),
                        3,
                        None,
                        ReportAggregationState::WaitingHelper(helper_prep_state_3),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_4.id(),
                        *report_metadata_4.time(),
                        4,
                        None,
                        ReportAggregationState::WaitingHelper(helper_prep_state_4),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_5.id(),
                        *report_metadata_5.time(),
                        5,
                        None,
                        ReportAggregationState::WaitingHelper(helper_prep_state_5),
                    ))
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([
                PrepareContinue::new(*report_metadata_3.id(), ping_pong_leader_message_3.clone()),
                PrepareContinue::new(*report_metadata_4.id(), ping_pong_leader_message_4.clone()),
                PrepareContinue::new(*report_metadata_5.id(), ping_pong_leader_message_5.clone()),
            ]),
        );

        let _ =
            post_aggregation_job_and_decode(&task, &aggregation_job_id_1, &request, &handler).await;

        // Map the batch aggregation ordinal value to 0, as it may vary due to sharding, and merge
        // batch aggregations over the same interval. (the task & aggregation parameter will always
        // be the same)
        let merged_first_batch_aggregation = datastore
            .run_unnamed_tx(|tx| {
                let (task, vdaf, report_metadata_0, aggregation_param) = (
                    helper_task.clone(),
                    vdaf.clone(),
                    report_metadata_0.clone(),
                    aggregation_param.clone(),
                );
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collection_identifier::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                        _,
                    >(
                        tx,
                        &task,
                        &vdaf,
                        &Interval::new(
                            report_metadata_0
                                .time()
                                .to_batch_interval_start(task.time_precision())
                                .unwrap(),
                            Duration::from_seconds(task.time_precision().as_seconds()),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|agg| {
                BatchAggregation::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>::new(
                    *agg.task_id(),
                    *agg.batch_identifier(),
                    agg.aggregation_parameter().clone(),
                    0,
                    BatchAggregationState::Aggregating,
                    agg.aggregate_share().cloned(),
                    agg.report_count(),
                    *agg.client_timestamp_interval(),
                    *agg.checksum(),
                )
            })
            .reduce(|left, right| left.merged_with(&right).unwrap())
            .unwrap();

        let first_aggregate_share = vdaf
            .aggregate(
                &aggregation_param,
                [
                    &transcript_0.helper_output_share,
                    &transcript_1.helper_output_share,
                    &transcript_3.helper_output_share,
                ]
                .into_iter()
                .cloned(),
            )
            .unwrap();
        let first_checksum = ReportIdChecksum::for_report_id(report_metadata_0.id())
            .updated_with(report_metadata_1.id())
            .updated_with(report_metadata_3.id());

        assert_eq!(
            merged_first_batch_aggregation,
            BatchAggregation::new(
                *task.id(),
                Interval::new(
                    report_metadata_0
                        .time()
                        .to_batch_interval_start(task.time_precision())
                        .unwrap(),
                    *task.time_precision()
                )
                .unwrap(),
                aggregation_param.clone(),
                0,
                BatchAggregationState::Aggregating,
                Some(first_aggregate_share),
                3,
                Interval::from_time(report_metadata_0.time()).unwrap(),
                first_checksum,
            ),
        );

        let second_batch_got_batch_aggregations = datastore
            .run_unnamed_tx(|tx| {
                let (task, vdaf, report_metadata_2, aggregation_param) = (
                    helper_task.clone(),
                    vdaf.clone(),
                    report_metadata_2.clone(),
                    aggregation_param.clone(),
                );
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collection_identifier::<
                        VERIFY_KEY_LENGTH,
                        Poplar1<XofShake128, 16>,
                        _,
                    >(
                        tx,
                        &task,
                        &vdaf,
                        &Interval::new(
                            report_metadata_2
                                .time()
                                .to_batch_interval_start(task.time_precision())
                                .unwrap(),
                            Duration::from_seconds(task.time_precision().as_seconds()),
                        )
                        .unwrap(),
                        &aggregation_param,
                    )
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(
            second_batch_got_batch_aggregations,
            second_batch_want_batch_aggregations
        );
    }

    #[tokio::test]
    async fn aggregate_continue_leader_sends_non_continue_or_finish_transition() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Poplar1 { bits: 1 }).build();
        let helper_task = task.helper_view().unwrap();
        let report_id = random();
        let aggregation_param = Poplar1AggregationParam::try_from_prefixes(Vec::from([
            IdpfInput::from_bools(&[false]),
        ]))
        .unwrap();
        let transcript = run_vdaf(
            &Poplar1::new_shake128(1),
            task.vdaf_verify_key().unwrap().as_bytes(),
            &aggregation_param,
            &report_id,
            &IdpfInput::from_bools(&[false]),
        );
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(54321),
        );

        // Setup datastore.
        datastore
            .run_unnamed_tx(|tx| {
                let (task, aggregation_param, report_metadata, transcript) = (
                    helper_task.clone(),
                    aggregation_param.clone(),
                    report_metadata.clone(),
                    transcript.clone(),
                );
                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata.clone(),
                            Vec::from("public share"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        16,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param,
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await?;
                    tx.put_report_aggregation(
                        &ReportAggregation::<16, Poplar1<XofShake128, 16>>::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata.id(),
                            *report_metadata.time(),
                            0,
                            None,
                            ReportAggregationState::WaitingHelper(
                                transcript.helper_prepare_transitions[0]
                                    .prepare_state()
                                    .clone(),
                            ),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([PrepareContinue::new(
                *report_metadata.id(),
                // An AggregationJobContinueReq should only ever contain Continue or Finished
                PingPongMessage::Initialize {
                    prep_share: Vec::new(),
                },
            )]),
        );

        let resp =
            post_aggregation_job_and_decode(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(resp.prepare_resps().len(), 1);
        assert_eq!(
            resp.prepare_resps()[0],
            PrepareResp::new(
                *report_metadata.id(),
                PrepareStepResult::Reject(PrepareError::VdafPrepError),
            )
        );
    }

    #[tokio::test]
    async fn aggregate_continue_prep_step_fails() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Poplar1 { bits: 1 }).build();
        let helper_task = task.helper_view().unwrap();
        let vdaf = Poplar1::new_shake128(1);
        let report_id = random();
        let aggregation_param = Poplar1AggregationParam::try_from_prefixes(Vec::from([
            IdpfInput::from_bools(&[false]),
        ]))
        .unwrap();
        let transcript = run_vdaf(
            &vdaf,
            task.vdaf_verify_key().unwrap().as_bytes(),
            &aggregation_param,
            &report_id,
            &IdpfInput::from_bools(&[false]),
        );
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(report_id, Time::from_seconds_since_epoch(54321));
        let helper_report_share = generate_helper_report_share::<Poplar1<XofShake128, 16>>(
            *task.id(),
            report_metadata.clone(),
            helper_task.current_hpke_key().config(),
            &transcript.public_share,
            Vec::new(),
            &transcript.helper_input_share,
        );

        // Setup datastore.
        datastore
            .run_unnamed_tx(|tx| {
                let (task, aggregation_param, report_metadata, transcript, helper_report_share) = (
                    helper_task.clone(),
                    aggregation_param.clone(),
                    report_metadata.clone(),
                    transcript.clone(),
                    helper_report_share.clone(),
                );

                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;
                    tx.put_report_share(task.id(), &helper_report_share).await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        16,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param,
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await?;
                    tx.put_report_aggregation(
                        &ReportAggregation::<16, Poplar1<XofShake128, 16>>::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata.id(),
                            *report_metadata.time(),
                            0,
                            None,
                            ReportAggregationState::WaitingHelper(
                                transcript.helper_prepare_transitions[0]
                                    .prepare_state()
                                    .clone(),
                            ),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([PrepareContinue::new(
                *report_metadata.id(),
                PingPongMessage::Continue {
                    prep_msg: Vec::new(),
                    prep_share: Vec::new(),
                },
            )]),
        );

        let aggregate_resp =
            post_aggregation_job_and_decode(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(
            aggregate_resp,
            AggregationJobResp::new(Vec::from([PrepareResp::new(
                *report_metadata.id(),
                PrepareStepResult::Reject(PrepareError::VdafPrepError),
            )]),)
        );

        // Check datastore state.
        let (aggregation_job, report_aggregation) = datastore
            .run_unnamed_tx(|tx| {
                let (vdaf, task, report_metadata) =
                    (vdaf.clone(), task.clone(), report_metadata.clone());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<16, TimeInterval, Poplar1<XofShake128, 16>>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            &vdaf,
                            &Role::Helper,
                            task.id(),
                            &aggregation_job_id,
                            aggregation_job.aggregation_parameter(),
                            report_metadata.id(),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(
            aggregation_job,
            AggregationJob::new(
                *task.id(),
                aggregation_job_id,
                aggregation_param,
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
                AggregationJobStep::from(1),
            )
            .with_last_request_hash(aggregation_job.last_request_hash().unwrap())
        );
        assert_eq!(
            report_aggregation,
            ReportAggregation::new(
                *task.id(),
                aggregation_job_id,
                *report_metadata.id(),
                *report_metadata.time(),
                0,
                Some(PrepareResp::new(
                    *report_metadata.id(),
                    PrepareStepResult::Reject(PrepareError::VdafPrepError)
                )),
                ReportAggregationState::Failed(PrepareError::VdafPrepError),
            )
        );
    }

    #[tokio::test]
    async fn aggregate_continue_unexpected_transition() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Poplar1 { bits: 1 }).build();
        let helper_task = task.helper_view().unwrap();
        let report_id = random();
        let aggregation_param = Poplar1AggregationParam::try_from_prefixes(Vec::from([
            IdpfInput::from_bools(&[false]),
        ]))
        .unwrap();
        let transcript = run_vdaf(
            &Poplar1::new_shake128(1),
            task.vdaf_verify_key().unwrap().as_bytes(),
            &aggregation_param,
            &report_id,
            &IdpfInput::from_bools(&[false]),
        );
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(report_id, Time::from_seconds_since_epoch(54321));

        // Setup datastore.
        datastore
            .run_unnamed_tx(|tx| {
                let (task, aggregation_param, report_metadata, transcript) = (
                    helper_task.clone(),
                    aggregation_param.clone(),
                    report_metadata.clone(),
                    transcript.clone(),
                );

                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata.clone(),
                            Vec::from("PUBLIC"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        16,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param,
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await?;
                    tx.put_report_aggregation(
                        &ReportAggregation::<16, Poplar1<XofShake128, 16>>::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata.id(),
                            *report_metadata.time(),
                            0,
                            None,
                            ReportAggregationState::WaitingHelper(
                                transcript.helper_prepare_transitions[0]
                                    .prepare_state()
                                    .clone(),
                            ),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([PrepareContinue::new(
                ReportId::from(
                    [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1], // not the same as above
                ),
                PingPongMessage::Continue {
                    prep_msg: Vec::new(),
                    prep_share: Vec::new(),
                },
            )]),
        );

        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:invalidMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregate_continue_out_of_order_transition() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Poplar1 { bits: 1 }).build();
        let helper_task = task.helper_view().unwrap();
        let report_id_0 = random();
        let aggregation_param = Poplar1AggregationParam::try_from_prefixes(Vec::from([
            IdpfInput::from_bools(&[false]),
        ]))
        .unwrap();
        let transcript_0 = run_vdaf(
            &Poplar1::new_shake128(1),
            task.vdaf_verify_key().unwrap().as_bytes(),
            &aggregation_param,
            &report_id_0,
            &IdpfInput::from_bools(&[false]),
        );
        let report_metadata_0 =
            ReportMetadata::new(report_id_0, Time::from_seconds_since_epoch(54321));
        let report_id_1 = random();
        let transcript_1 = run_vdaf(
            &Poplar1::new_shake128(1),
            task.vdaf_verify_key().unwrap().as_bytes(),
            &aggregation_param,
            &report_id_1,
            &IdpfInput::from_bools(&[false]),
        );
        let report_metadata_1 =
            ReportMetadata::new(report_id_1, Time::from_seconds_since_epoch(54321));
        let aggregation_job_id = random();

        // Setup datastore.
        datastore
            .run_unnamed_tx(|tx| {
                let (
                    task,
                    aggregation_param,
                    report_metadata_0,
                    report_metadata_1,
                    transcript_0,
                    transcript_1,
                ) = (
                    helper_task.clone(),
                    aggregation_param.clone(),
                    report_metadata_0.clone(),
                    report_metadata_1.clone(),
                    transcript_0.clone(),
                    transcript_1.clone(),
                );

                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;

                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata_0.clone(),
                            Vec::from("public"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata_1.clone(),
                            Vec::from("public"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        16,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param.clone(),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation(
                        &ReportAggregation::<16, Poplar1<XofShake128, 16>>::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_0.id(),
                            *report_metadata_0.time(),
                            0,
                            None,
                            ReportAggregationState::WaitingHelper(
                                transcript_0.helper_prepare_transitions[0]
                                    .prepare_state()
                                    .clone(),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation(
                        &ReportAggregation::<16, Poplar1<XofShake128, 16>>::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_1.id(),
                            *report_metadata_1.time(),
                            1,
                            None,
                            ReportAggregationState::WaitingHelper(
                                transcript_1.helper_prepare_transitions[0]
                                    .prepare_state()
                                    .clone(),
                            ),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([
                // Report IDs are in opposite order to what was stored in the datastore.
                PrepareContinue::new(
                    *report_metadata_1.id(),
                    PingPongMessage::Continue {
                        prep_msg: Vec::new(),
                        prep_share: Vec::new(),
                    },
                ),
                PrepareContinue::new(
                    *report_metadata_0.id(),
                    PingPongMessage::Continue {
                        prep_msg: Vec::new(),
                        prep_share: Vec::new(),
                    },
                ),
            ]),
        );
        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:invalidMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregate_continue_for_non_waiting_aggregation() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake).build();
        let helper_task = task.helper_view().unwrap();
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(54321),
        );

        // Setup datastore.
        datastore
            .run_unnamed_tx(|tx| {
                let (task, report_metadata) = (helper_task.clone(), report_metadata.clone());
                Box::pin(async move {
                    tx.put_aggregator_task(&task).await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata.clone(),
                            Vec::from("public share"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_aggregation_job(
                        &AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            aggregation_job_id,
                            dummy_vdaf::AggregationParam(0),
                            (),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                Duration::from_seconds(1),
                            )
                            .unwrap(),
                            AggregationJobState::InProgress,
                            AggregationJobStep::from(0),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata.id(),
                        *report_metadata.time(),
                        0,
                        None,
                        ReportAggregationState::Failed(PrepareError::VdafPrepError),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([PrepareContinue::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                PingPongMessage::Continue {
                    prep_msg: Vec::new(),
                    prep_share: Vec::new(),
                },
            )]),
        );
        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:invalidMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn collection_job_put_request_to_helper() {
        let test_case = setup_collection_job_test_case(Role::Helper, QueryType::TimeInterval).await;

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    *test_case.task.time_precision(),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job_with_auth_token(&collection_job_id, &request, Some(&random()))
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_invalid_batch_interval() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    // Collect request will be rejected because batch interval is too small
                    Duration::from_seconds(test_case.task.time_precision().as_seconds() - 1),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch implied by the query is invalid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_invalid_aggregation_parameter() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(test_case.task.time_precision().as_seconds()),
                )
                .unwrap(),
            ),
            // dummy_vdaf::AggregationParam is a tuple struct wrapping a u8, so this is not a valid
            // encoding of an aggregation parameter.
            Vec::from([0u8, 0u8]),
        );

        let mut test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        // Collect request will be rejected because the aggregation parameter can't be decoded
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_invalid_batch_size() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake)
            .with_min_batch_size(1)
            .build();
        let leader_task = task.leader_view().unwrap();
        datastore.put_aggregator_task(&leader_task).await.unwrap();

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(task.time_precision().as_seconds()),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let (header, value) = task.collector_auth_token().request_authentication();
        let mut test_conn = put(task.collection_job_uri(&collection_job_id).unwrap().path())
            .with_request_header(header, value)
            .with_request_header(
                KnownHeaderName::ContentType,
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        // Collect request will be rejected because there are no reports in the batch interval
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_unauthenticated() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();
        let collection_job_id: CollectionJobId = random();
        let req = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        // Incorrect authentication token.
        let mut test_conn = test_case
            .put_collection_job_with_auth_token(&collection_job_id, &req, Some(&random()))
            .await;

        let want_status = Status::BadRequest;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Aggregator authentication token.
        let mut test_conn = test_case
            .put_collection_job_with_auth_token(
                &collection_job_id,
                &req,
                Some(test_case.task.aggregator_auth_token()),
            )
            .await;

        let want_status = Status::BadRequest;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Missing authentication token.
        let mut test_conn = test_case
            .put_collection_job_with_auth_token(&collection_job_id, &req, None)
            .await;

        let want_status = Status::BadRequest;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());
    }

    #[tokio::test]
    async fn collection_job_post_request_unauthenticated_collection_jobs() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        assert_eq!(test_conn.status().unwrap(), Status::Created);

        // Incorrect authentication token.
        let mut test_conn = test_case
            .post_collection_job_with_auth_token(&collection_job_id, Some(&random()))
            .await;

        let want_status = Status::BadRequest;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Aggregator authentication token.
        let mut test_conn = test_case
            .post_collection_job_with_auth_token(
                &collection_job_id,
                Some(test_case.task.aggregator_auth_token()),
            )
            .await;

        let want_status = Status::BadRequest;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Missing authentication token.
        let mut test_conn = test_case
            .post_collection_job_with_auth_token(&collection_job_id, None)
            .await;

        let want_status = Status::BadRequest;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());
    }

    #[tokio::test]
    async fn collection_job_success_time_interval() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let batch_interval = TimeInterval::to_batch_identifier(
            &test_case.task.leader_view().unwrap(),
            &(),
            &Time::from_seconds_since_epoch(0),
        )
        .unwrap();

        let aggregation_param = dummy_vdaf::AggregationParam::default();
        let leader_aggregate_share = dummy_vdaf::AggregateShare(0);
        let helper_aggregate_share = dummy_vdaf::AggregateShare(1);

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            aggregation_param.get_encoded(),
        );

        test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task_id = *test_case.task.id();

                Box::pin(async move {
                    tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        task_id,
                        batch_interval,
                        aggregation_param,
                        BatchState::Open,
                        1,
                        batch_interval,
                    ))
                    .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

        let test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        let want_collection_job = CollectionJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            *test_case.task.id(),
            collection_job_id,
            Query::new_time_interval(batch_interval),
            aggregation_param,
            batch_interval,
            CollectionJobState::Start,
        );
        let want_batches = Vec::from([Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            *test_case.task.id(),
            batch_interval,
            aggregation_param,
            BatchState::Closing,
            1,
            batch_interval,
        )]);

        let (got_collection_job, got_batches) = test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task_id = *test_case.task.id();

                Box::pin(async move {
                    let got_collection_job = tx
                        .get_collection_job(&dummy_vdaf::Vdaf::new(), &task_id, &collection_job_id)
                        .await?
                        .unwrap();
                    let got_batches = tx.get_batches_for_task(&task_id).await?;
                    Ok((got_collection_job, got_batches))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_collection_job, got_collection_job);
        assert_eq!(want_batches, got_batches);

        assert_eq!(test_conn.status(), Some(Status::Created));

        let test_conn = test_case.post_collection_job(&collection_job_id).await;
        assert_eq!(test_conn.status(), Some(Status::Accepted));

        // Update the collection job with the aggregate shares and some aggregation jobs. collection
        // job should now be complete.
        test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task = test_case.task.clone();
                let helper_aggregate_share_bytes = helper_aggregate_share.get_encoded();
                Box::pin(async move {
                    let encrypted_helper_aggregate_share = hpke::seal(
                        task.collector_hpke_keypair().config(),
                        &HpkeApplicationInfo::new(
                            &Label::AggregateShare,
                            &Role::Helper,
                            &Role::Collector,
                        ),
                        &helper_aggregate_share_bytes,
                        &AggregateShareAad::new(
                            *task.id(),
                            aggregation_param.get_encoded(),
                            BatchSelector::new_time_interval(batch_interval),
                        )
                        .get_encoded(),
                    )
                    .unwrap();

                    let collection_job = tx
                        .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &dummy_vdaf::Vdaf::new(),
                            task.id(),
                            &collection_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap()
                        .with_state(CollectionJobState::Finished {
                            report_count: 12,
                            encrypted_helper_aggregate_share,
                            leader_aggregate_share,
                        });

                    tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&collection_job)
                        .await
                        .unwrap();
                    Ok(())
                })
            })
            .await
            .unwrap();

        let mut test_conn = test_case.post_collection_job(&collection_job_id).await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "content-type" => (Collection::<TimeInterval>::MEDIA_TYPE)
        );
        let collect_resp: Collection<TimeInterval> = decode_response_body(&mut test_conn).await;

        assert_eq!(collect_resp.report_count(), 12);
        assert_eq!(collect_resp.interval(), &batch_interval);

        let decrypted_leader_aggregate_share = hpke::open(
            test_case.task.collector_hpke_keypair(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
            collect_resp.leader_encrypted_aggregate_share(),
            &AggregateShareAad::new(
                *test_case.task.id(),
                aggregation_param.get_encoded(),
                BatchSelector::new_time_interval(batch_interval),
            )
            .get_encoded(),
        )
        .unwrap();
        assert_eq!(
            leader_aggregate_share,
            dummy_vdaf::AggregateShare::get_decoded(decrypted_leader_aggregate_share.as_ref())
                .unwrap()
        );

        let decrypted_helper_aggregate_share = hpke::open(
            test_case.task.collector_hpke_keypair(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            collect_resp.helper_encrypted_aggregate_share(),
            &AggregateShareAad::new(
                *test_case.task.id(),
                aggregation_param.get_encoded(),
                BatchSelector::new_time_interval(batch_interval),
            )
            .get_encoded(),
        )
        .unwrap();
        assert_eq!(
            helper_aggregate_share,
            dummy_vdaf::AggregateShare::get_decoded(decrypted_helper_aggregate_share.as_ref())
                .unwrap()
        );
    }

    #[tokio::test]
    async fn collection_job_post_request_no_such_collection_job() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let no_such_collection_job_id: CollectionJobId = random();

        let (header, value) = test_case
            .task
            .collector_auth_token()
            .request_authentication();
        let test_conn = post(&format!(
            "/tasks/{}/collection_jobs/{no_such_collection_job_id}",
            test_case.task.id()
        ))
        .with_request_header(header, value)
        .run_async(&test_case.handler)
        .await;
        assert_eq!(test_conn.status(), Some(Status::NotFound));
    }

    #[tokio::test]
    async fn collection_job_put_request_batch_queried_too_many_times() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;
        let interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task = test_case.task.clone();
                Box::pin(async move {
                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            dummy_vdaf::AggregationParam(0),
                            0,
                            BatchAggregationState::Aggregating,
                            Some(dummy_vdaf::AggregateShare(0)),
                            10,
                            interval,
                            ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        // Sending this request will consume a query for [0, time_precision).
        let request = CollectionReq::new(
            Query::new_time_interval(interval),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let test_conn = test_case.put_collection_job(&random(), &request).await;

        assert_eq!(test_conn.status(), Some(Status::Created));

        // This request will not be allowed due to the query count already being consumed.
        let invalid_request = CollectionReq::new(
            Query::new_time_interval(interval),
            dummy_vdaf::AggregationParam(1).get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job(&random(), &invalid_request)
            .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes",
                "title": "The batch described by the query has been queried too many times.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_batch_overlap() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;
        let interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task = test_case.task.clone();
                Box::pin(async move {
                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            interval,
                            dummy_vdaf::AggregationParam(0),
                            0,
                            BatchAggregationState::Aggregating,
                            Some(dummy_vdaf::AggregateShare(0)),
                            10,
                            interval,
                            ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        // Sending this request will consume a query for [0, 2 * time_precision).
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_microseconds(
                        2 * test_case.task.time_precision().as_microseconds().unwrap(),
                    ),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let test_conn = test_case.put_collection_job(&random(), &request).await;

        assert_eq!(test_conn.status(), Some(Status::Created));

        // This request will not be allowed due to overlapping with the previous request.
        let invalid_request = CollectionReq::new(
            Query::new_time_interval(interval),
            dummy_vdaf::AggregationParam(1).get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job(&random(), &invalid_request)
            .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
                "title": "The queried batch overlaps with a previously queried batch.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn delete_collection_job() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        let collection_job_id: CollectionJobId = random();

        let (header, value) = test_case
            .task
            .collector_auth_token()
            .request_authentication();

        // Try to delete a collection job that doesn't exist
        let test_conn = delete(
            test_case
                .task
                .collection_job_uri(&collection_job_id)
                .unwrap()
                .path(),
        )
        .with_request_header(header, value.clone())
        .run_async(&test_case.handler)
        .await;
        assert_eq!(test_conn.status(), Some(Status::NotFound));

        // Create a collection job
        let request = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        assert_eq!(test_conn.status(), Some(Status::Created));

        // Cancel the job
        let test_conn = delete(
            test_case
                .task
                .collection_job_uri(&collection_job_id)
                .unwrap()
                .path(),
        )
        .with_request_header(header, value)
        .run_async(&test_case.handler)
        .await;
        assert_eq!(test_conn.status(), Some(Status::NoContent));

        // Get the job again
        let test_conn = test_case.post_collection_job(&collection_job_id).await;
        assert_eq!(test_conn.status(), Some(Status::NoContent));
    }

    #[tokio::test]
    async fn aggregate_share_request_to_leader() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake).build();
        let leader_task = task.leader_view().unwrap();
        datastore.put_aggregator_task(&leader_task).await.unwrap();

        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            Vec::new(),
            0,
            ReportIdChecksum::default(),
        );

        let (header, value) = task.aggregator_auth_token().request_authentication();

        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(header, value)
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_share_request_invalid_batch_interval() {
        let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        // Prepare parameters.
        const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(3600);
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake)
            .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
            .build();
        let helper_task = task.helper_view().unwrap();
        datastore.put_aggregator_task(&helper_task).await.unwrap();

        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    clock.now(),
                    // Collect request will be rejected because batch interval is too small
                    Duration::from_seconds(task.time_precision().as_seconds() - 1),
                )
                .unwrap(),
            ),
            Vec::new(),
            0,
            ReportIdChecksum::default(),
        );

        let (header, value) = task.aggregator_auth_token().request_authentication();

        // Test that a request for an invalid batch fails. (Specifically, the batch interval is too
        // small.)
        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(header, value.clone())
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch implied by the query is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );

        // Test that a request for a too-old batch fails.
        let test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(header, value)
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(
                AggregateShareReq::new(
                    BatchSelector::new_time_interval(
                        Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision())
                            .unwrap(),
                    ),
                    Vec::new(),
                    0,
                    ReportIdChecksum::default(),
                )
                .get_encoded(),
            )
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
    }

    #[tokio::test]
    async fn aggregate_share_request() {
        let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake)
            .with_max_batch_query_count(1)
            .with_time_precision(Duration::from_seconds(500))
            .with_min_batch_size(10)
            .build();
        let helper_task = task.helper_view().unwrap();
        datastore.put_aggregator_task(&helper_task).await.unwrap();

        // There are no batch aggregations in the datastore yet
        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            0,
            ReportIdChecksum::default(),
        );

        let (header, value) = task.aggregator_auth_token().request_authentication();

        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(header, value)
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );

        // Put some batch aggregations in the DB.
        datastore
            .run_unnamed_tx(|tx| {
                let task = helper_task.clone();
                Box::pin(async move {
                    for aggregation_param in [
                        dummy_vdaf::AggregationParam(0),
                        dummy_vdaf::AggregationParam(1),
                    ] {
                        let interval_1 = Interval::new(
                            Time::from_seconds_since_epoch(500),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            interval_1,
                            aggregation_param,
                            BatchState::Closed,
                            0,
                            interval_1,
                        ))
                        .await
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            0,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_1,
                            aggregation_param,
                            0,
                            BatchAggregationState::Aggregating,
                            Some(dummy_vdaf::AggregateShare(64)),
                            5,
                            interval_1,
                            ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                        ))
                        .await
                        .unwrap();

                        let interval_2 = Interval::new(
                            Time::from_seconds_since_epoch(1500),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            interval_2,
                            aggregation_param,
                            BatchState::Closed,
                            0,
                            interval_2,
                        ))
                        .await
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            0,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_2,
                            aggregation_param,
                            0,
                            BatchAggregationState::Aggregating,
                            Some(dummy_vdaf::AggregateShare(128)),
                            5,
                            interval_2,
                            ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                        ))
                        .await
                        .unwrap();

                        let interval_3 = Interval::new(
                            Time::from_seconds_since_epoch(2000),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            interval_3,
                            aggregation_param,
                            BatchState::Closed,
                            0,
                            interval_3,
                        ))
                        .await
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            0,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_3,
                            aggregation_param,
                            0,
                            BatchAggregationState::Aggregating,
                            Some(dummy_vdaf::AggregateShare(256)),
                            5,
                            interval_3,
                            ReportIdChecksum::get_decoded(&[4; 32]).unwrap(),
                        ))
                        .await
                        .unwrap();

                        let interval_4 = Interval::new(
                            Time::from_seconds_since_epoch(2500),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch(&Batch::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            interval_4,
                            aggregation_param,
                            BatchState::Closed,
                            0,
                            interval_4,
                        ))
                        .await
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            0,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_4,
                            aggregation_param,
                            0,
                            BatchAggregationState::Aggregating,
                            Some(dummy_vdaf::AggregateShare(512)),
                            5,
                            interval_4,
                            ReportIdChecksum::get_decoded(&[8; 32]).unwrap(),
                        ))
                        .await
                        .unwrap();
                    }

                    Ok(())
                })
            })
            .await
            .unwrap();

        // Specified interval includes too few reports.
        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(1000),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            5,
            ReportIdChecksum::default(),
        );
        let (header, value) = task.aggregator_auth_token().request_authentication();
        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(header, value)
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );

        // Make requests that will fail because the checksum or report counts don't match.
        for misaligned_request in [
            // Interval is big enough, but checksum doesn't match.
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(0).get_encoded(),
                10,
                ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
            ),
            // Interval is big enough, but report count doesn't match.
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(0).get_encoded(),
                20,
                ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
            ),
        ] {
            let (header, value) = task.aggregator_auth_token().request_authentication();
            let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
                .with_request_header(header, value)
                .with_request_header(
                    KnownHeaderName::ContentType,
                    AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
                )
                .with_request_body(misaligned_request.get_encoded())
                .run_async(&handler)
                .await;

            assert_eq!(test_conn.status(), Some(Status::BadRequest));
            assert_eq!(
                take_problem_details(&mut test_conn).await,
                json!({
                    "status": Status::BadRequest as u16,
                    "type": "urn:ietf:params:ppm:dap:error:batchMismatch",
                    "title": "Leader and helper disagree on reports aggregated in a batch.",
                    "taskid": format!("{}", task.id()),
                })
            );
        }

        // Valid requests: intervals are big enough, do not overlap, checksum and report count are
        // good.
        for (label, request, expected_result) in [
            (
                "first and second batchess",
                AggregateShareReq::new(
                    BatchSelector::new_time_interval(
                        Interval::new(
                            Time::from_seconds_since_epoch(0),
                            Duration::from_seconds(2000),
                        )
                        .unwrap(),
                    ),
                    dummy_vdaf::AggregationParam(0).get_encoded(),
                    10,
                    ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
                ),
                dummy_vdaf::AggregateShare(64 + 128),
            ),
            (
                "third and fourth batches",
                AggregateShareReq::new(
                    BatchSelector::new_time_interval(
                        Interval::new(
                            Time::from_seconds_since_epoch(2000),
                            Duration::from_seconds(2000),
                        )
                        .unwrap(),
                    ),
                    dummy_vdaf::AggregationParam(0).get_encoded(),
                    10,
                    ReportIdChecksum::get_decoded(&[8 ^ 4; 32]).unwrap(),
                ),
                // Should get sum over the third and fourth batches
                dummy_vdaf::AggregateShare(256 + 512),
            ),
        ] {
            // Request the aggregate share multiple times. If the request parameters don't change,
            // then there is no query count violation and all requests should succeed.
            for iteration in 0..3 {
                let (header, value) = task.aggregator_auth_token().request_authentication();
                let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
                    .with_request_header(header, value)
                    .with_request_header(
                        KnownHeaderName::ContentType,
                        AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
                    )
                    .with_request_body(request.get_encoded())
                    .run_async(&handler)
                    .await;

                assert_eq!(
                    test_conn.status(),
                    Some(Status::Ok),
                    "test case: {label:?}, iteration: {iteration}"
                );
                assert_headers!(
                    &test_conn,
                    "content-type" => (AggregateShareMessage::MEDIA_TYPE)
                );
                let aggregate_share_resp: AggregateShareMessage =
                    decode_response_body(&mut test_conn).await;

                let aggregate_share = hpke::open(
                    task.collector_hpke_keypair(),
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    aggregate_share_resp.encrypted_aggregate_share(),
                    &AggregateShareAad::new(
                        *task.id(),
                        dummy_vdaf::AggregationParam(0).get_encoded(),
                        request.batch_selector().clone(),
                    )
                    .get_encoded(),
                )
                .unwrap();

                // Should get the sum over the first and second aggregate shares
                let decoded_aggregate_share =
                    dummy_vdaf::AggregateShare::get_decoded(aggregate_share.as_ref()).unwrap();
                assert_eq!(
                    decoded_aggregate_share, expected_result,
                    "test case: {label:?}, iteration: {iteration}"
                );
            }
        }

        // Requests for collection intervals that overlap with but are not identical to previous
        // collection intervals fail.
        let all_batch_request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(4000),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            20,
            ReportIdChecksum::get_decoded(&[8 ^ 4 ^ 3 ^ 2; 32]).unwrap(),
        );
        let (header, value) = task.aggregator_auth_token().request_authentication();
        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(header, value)
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(all_batch_request.get_encoded())
            .run_async(&handler)
            .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
                "title": "The queried batch overlaps with a previously queried batch.",
                "taskid": format!("{}", task.id()),
            }),
        );

        // Previous sequence of aggregate share requests should have consumed the available queries
        // for all the batches. Further requests for any batches will cause query count violations.
        for query_count_violation_request in [
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(1).get_encoded(),
                10,
                ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
            ),
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(1).get_encoded(),
                10,
                ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
            ),
        ] {
            let (header, value) = task.aggregator_auth_token().request_authentication();
            let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
                .with_request_header(header, value)
                .with_request_header(
                    KnownHeaderName::ContentType,
                    AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
                )
                .with_request_body(query_count_violation_request.get_encoded())
                .run_async(&handler)
                .await;
            assert_eq!(test_conn.status(), Some(Status::BadRequest));
            assert_eq!(
                take_problem_details(&mut test_conn).await,
                json!({
                    "status": Status::BadRequest as u16,
                    "type": "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes",
                    "title": "The batch described by the query has been queried too many times.",
                    "taskid": format!("{}", task.id()),
                })
            );
        }
    }
}
