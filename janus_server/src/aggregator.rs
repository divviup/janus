//! Common functionality for PPM aggregators
use crate::{
    datastore::{self, Datastore},
    hpke::HpkeRecipient,
    message::{HpkeConfigId, Nonce, Report, Role, TaskId},
    time::Clock,
};
use bytes::Bytes;
use chrono::Duration;
use http::{header::CACHE_CONTROL, StatusCode};
use prio::codec::{Decode, Encode};
use std::{convert::Infallible, future::Future, net::SocketAddr, ops::Sub, sync::Arc};
use tracing::warn;
use url::Url;
use warp::{
    filters::BoxedFilter,
    reply::{self, Response},
    trace, Filter, Rejection, Reply,
};

/// Errors returned by functions and methods in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An invalid configuration was passed.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Error decoding an incoming message.
    #[error("message decoding failed: {0}")]
    MessageDecode(#[from] prio::codec::CodecError),
    /// Corresponds to `staleReport`, §3.1
    #[error("stale report: {0}")]
    StaleReport(Nonce, TaskId),
    /// Corresponds to `unrecognizedMessage`, §3.1
    #[error("unrecognized message: {0}")]
    UnrecognizedMessage(&'static str, TaskId),
    /// Corresponds to `unrecognizedTask`, §3.1
    #[error("unrecognized task")]
    UnrecognizedTask(TaskId),
    /// Corresponds to `outdatedHpkeConfig`, §3.1
    #[error("outdated HPKE config: {0}")]
    OutdatedHpkeConfig(HpkeConfigId, TaskId),
    /// A report was rejected becuase the timestamp is too far in the future,
    /// §4.3.4.
    // TODO(timg): define an error type in §3.1 and clarify language on
    // rejecting future reports
    #[error("report from the future: {0}")]
    ReportFromTheFuture(Nonce, TaskId),
    /// Corresponds to `invalidHmac`, §3.1
    #[error("invalid HMAC tag")]
    InvalidHmac(TaskId),
    /// An error from the datastore.
    #[error("datastore error: {0}")]
    Datastore(datastore::Error),
}

// This From implementation ensures that we don't end up with e.g.
// Error::Datastore(datastore::Error::User(Error::...)) by automatically unwrapping to the internal
// aggregator error if converting a datastore::Error::User that contains an Error. Other
// datastore::Error values are wrapped in Error::Datastore unchanged.
impl From<datastore::Error> for Error {
    fn from(err: datastore::Error) -> Self {
        match err {
            datastore::Error::User(err) => match err.downcast::<Error>() {
                Ok(err) => *err,
                Err(err) => Error::Datastore(datastore::Error::User(err)),
            },
            _ => Error::Datastore(err),
        }
    }
}

/// A PPM aggregator
#[derive(Clone, derivative::Derivative)]
#[derivative(Debug)]
pub struct Aggregator<C> {
    /// The datastore used for durable storage.
    #[derivative(Debug = "ignore")]
    datastore: Arc<Datastore>,
    /// The clock to use to sample time.
    clock: C,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    tolerable_clock_skew: Duration,
    /// Role of this aggregator.
    role: Role,
    /// Used to decrypt reports received by this aggregator.
    // TODO: Aggregators should have multiple generations of HPKE config
    // available to decrypt tardy reports
    report_recipient: HpkeRecipient,
}

impl<C: Clock> Aggregator<C> {
    /// Create a new aggregator. `report_recipient` is used to decrypt reports
    /// received by this aggregator.
    fn new(
        datastore: Arc<Datastore>,
        clock: C,
        tolerable_clock_skew: Duration,
        role: Role,
        report_recipient: HpkeRecipient,
    ) -> Result<Self, Error> {
        if tolerable_clock_skew < Duration::zero() {
            return Err(Error::InvalidConfiguration(
                "tolerable clock skew must be positive",
            ));
        }

        Ok(Self {
            datastore,
            clock,
            tolerable_clock_skew,
            role,
            report_recipient,
        })
    }

    /// Implements the `/upload` endpoint for the leader, described in §4.2 of
    /// draft-gpew-priv-ppm.
    async fn handle_upload(&self, report: &Report) -> Result<(), Error> {
        // §4.2.2 The leader's report is the first one
        if report.encrypted_input_shares.len() != 2 {
            warn!(
                share_count = report.encrypted_input_shares.len(),
                "unexpected number of encrypted shares in report"
            );
            return Err(Error::UnrecognizedMessage(
                "unexpected number of encrypted shares in report",
                report.task_id,
            ));
        }
        let leader_report = &report.encrypted_input_shares[0];

        // §4.2.2: verify that the report's HPKE config ID is known
        if leader_report.config_id != self.report_recipient.config.id {
            warn!(
                config_id = ?leader_report.config_id,
                "unknown HPKE config ID"
            );
            return Err(Error::OutdatedHpkeConfig(
                leader_report.config_id,
                report.task_id,
            ));
        }

        let now = self.clock.now();

        // §4.2.4: reject reports from too far in the future
        if report.nonce.time.as_naive_date_time().sub(now) > self.tolerable_clock_skew {
            warn!(?report.task_id, ?report.nonce, "report timestamp exceeds tolerable clock skew");
            return Err(Error::ReportFromTheFuture(report.nonce, report.task_id));
        }

        // Check that we can decrypt the report. This isn't required by the spec
        // but this exercises HPKE decryption and saves us the trouble of
        // storing reports we can't use. We don't inform the client if this
        // fails.
        if let Err(error) = self.report_recipient.open(
            leader_report,
            &Report::associated_data(report.nonce, &report.extensions),
        ) {
            warn!(?report.task_id, ?report.nonce, ?error, "report decryption failed");
            return Ok(());
        }

        self.datastore
            .run_tx(|tx| {
                let report = report.clone();
                Box::pin(async move {
                    // §4.2.2 and 4.3.2.2: reject reports whose nonce has been seen before
                    match tx
                        .get_client_report_by_task_id_and_nonce(report.task_id, report.nonce)
                        .await
                    {
                        Ok(_) => {
                            warn!(?report.task_id, ?report.nonce, "report replayed");
                            // TODO (issue #34): change this error type.
                            return Err(datastore::Error::User(
                                Error::StaleReport(report.nonce, report.task_id).into(),
                            ));
                        }

                        Err(datastore::Error::NotFound) => (), // happy path

                        Err(err) => return Err(err),
                    };

                    // TODO: reject with `staleReport` reports whose timestamps fall in a
                    // batch interval that has already been collected (§4.3.2). We don't
                    // support collection so we can't implement this requirement yet.

                    // Store the report.
                    tx.put_client_report(&report).await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }
}

impl<C> Aggregator<C> {
    /// Returns the HTTPS URL of this aggregator's own endpoint.
    fn own_endpoint(&self) -> Url {
        // TODO (issue #20): determine this URL endpoint from configuration
        // TODO (issue abetterinternet/ppm-specification#209): This may no longer be needed if the
        // requirements for the "instance" problem details member change.
        Url::parse("https://example.com/ppm_aggregator").unwrap()
    }
}

/// Injects a clone of the provided value into the warp filter, making it
/// available to the filter's map() or and_then() handler.
fn with_cloned_value<T: Clone + Sync + Send>(
    value: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || value.clone())
}

fn with_decoded_message<T: Decode + Send + Sync>(
) -> impl Filter<Extract = (Result<T, Error>,), Error = Rejection> + Clone {
    warp::body::bytes().map(|body: Bytes| T::get_decoded(&body).map_err(Error::from))
}

/// Representation of the different problem types defined in Table 1 in §3.1.
enum PpmProblemType {
    UnrecognizedMessage,
    UnrecognizedTask,
    OutdatedConfig,
    StaleReport,
    InvalidHmac,
}

impl PpmProblemType {
    /// Returns the problem type URI for a particular kind of error.
    fn type_uri(&self) -> &'static str {
        match self {
            PpmProblemType::UnrecognizedMessage => "urn:ietf:params:ppm:error:unrecognizedMessage",
            PpmProblemType::UnrecognizedTask => "urn:ietf:params:ppm:error:unrecognizedTask",
            PpmProblemType::OutdatedConfig => "urn:ietf:params:ppm:error:outdatedConfig",
            PpmProblemType::StaleReport => "urn:ietf:params:ppm:error:staleReport",
            PpmProblemType::InvalidHmac => "urn:ietf:params:ppm:error:invalidHmac",
        }
    }

    /// Returns a human-readable summary of a problem type.
    fn description(&self) -> &'static str {
        match self {
            PpmProblemType::UnrecognizedMessage => {
                "The message type for a response was incorrect or the payload was malformed."
            }
            PpmProblemType::UnrecognizedTask => {
                "An endpoint received a message with an unknown task ID."
            }
            PpmProblemType::OutdatedConfig => {
                "The message was generated using an outdated configuration."
            }
            PpmProblemType::StaleReport => {
                "Report could not be processed because it arrived too late."
            }
            PpmProblemType::InvalidHmac => "The aggregate message's HMAC was not valid.",
        }
    }
}

/// The media type for problem details formatted as a JSON document, per RFC 7807.
static PROBLEM_DETAILS_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Construct an error response in accordance with §3.1.
/// TODO (PR abetterinternet/ppm-specification#208): base64-encoding the TaskID has not yet been
/// adopted in the specification, and may change.
/// TODO (issue abetterinternet/ppm-specification#209): The handling of the instance, title,
/// detail, and taskid fields are subject to change.
fn build_problem_details_response(
    error_type: PpmProblemType,
    task_id: TaskId,
    endpoint: &Url,
) -> Response {
    // So far, 400 Bad Request seems to be the appropriate choice for each defined problem type.
    let status = StatusCode::BAD_REQUEST;
    warp::reply::with_status(
        warp::reply::with_header(
            warp::reply::json(&serde_json::json!({
                "type": error_type.type_uri(),
                "title": error_type.description(),
                "status": status.as_u16(),
                "detail": error_type.description(),
                "instance": endpoint.as_str(),
                "taskid": base64::encode(task_id.as_bytes()),
            })),
            http::header::CONTENT_TYPE,
            PROBLEM_DETAILS_JSON_MEDIA_TYPE,
        ),
        status,
    )
    .into_response()
}

/// Produces a closure that will transform applicable errors into a problem details JSON object.
/// (See RFC 7807) The returned closure is meant to be used in a warp `map` filter.
fn error_handler<R>(
    aggregator_endpoint: Url,
) -> impl Fn(Result<R, Error>) -> warp::reply::Response + Clone
where
    R: Reply,
{
    move |result| match result {
        Ok(reply) => reply.into_response(),
        Err(Error::InvalidConfiguration(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Err(Error::MessageDecode(_)) => StatusCode::BAD_REQUEST.into_response(),
        Err(Error::StaleReport(_, task_id)) => build_problem_details_response(
            PpmProblemType::StaleReport,
            task_id,
            &aggregator_endpoint,
        ),
        Err(Error::UnrecognizedMessage(_, task_id)) => build_problem_details_response(
            PpmProblemType::UnrecognizedMessage,
            task_id,
            &aggregator_endpoint,
        ),
        Err(Error::UnrecognizedTask(task_id)) => build_problem_details_response(
            PpmProblemType::UnrecognizedTask,
            task_id,
            &aggregator_endpoint,
        ),
        Err(Error::OutdatedHpkeConfig(_, task_id)) => build_problem_details_response(
            PpmProblemType::OutdatedConfig,
            task_id,
            &aggregator_endpoint,
        ),
        Err(Error::ReportFromTheFuture(_, _)) => {
            // TODO: build a problem details document once an error type is defined for reports
            // with timestamps too far in the future.
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(Error::InvalidHmac(task_id)) => build_problem_details_response(
            PpmProblemType::InvalidHmac,
            task_id,
            &aggregator_endpoint,
        ),
        Err(Error::Datastore(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Constructs a Warp filter with endpoints common to all aggregators.
fn aggregator_filter<C: 'static + Clock>(
    datastore: Arc<Datastore>,
    clock: C,
    tolerable_clock_skew: Duration,
    role: Role,
    hpke_recipient: HpkeRecipient,
) -> Result<BoxedFilter<(impl Reply,)>, Error> {
    if !role.is_aggregator() {
        return Err(Error::InvalidConfiguration("role is not an aggregator"));
    }

    let hpke_config_encoded = hpke_recipient.config.get_encoded();

    let aggregator = Aggregator::new(datastore, clock, tolerable_clock_skew, role, hpke_recipient)?;

    let error_handler_fn = error_handler(aggregator.own_endpoint());

    let hpke_config_endpoint = warp::path("hpke_config")
        .and(warp::get())
        .map(move || {
            reply::with_header(
                reply::with_status(hpke_config_encoded.clone(), StatusCode::OK),
                CACHE_CONTROL,
                "max-age=86400",
            )
        })
        .with(trace::named("hpke_config"));

    let upload_endpoint = warp::path("upload")
        .and(warp::post())
        .and(with_cloned_value(aggregator))
        .and_then(|aggregator: Aggregator<C>| async {
            // Only the leader supports upload
            if aggregator.role != Role::Leader {
                return Err(warp::reject::not_found());
            }
            Ok(aggregator)
        })
        .and(with_decoded_message())
        .then(
            |aggregator: Aggregator<C>, report_res: Result<Report, Error>| async move {
                aggregator.handle_upload(&report_res?).await?;

                Ok(StatusCode::OK) as Result<_, Error>
            },
        )
        .map(error_handler_fn)
        .with(trace::named("upload"));

    Ok(hpke_config_endpoint.or(upload_endpoint).boxed())
}

/// Construct a PPM aggregator server, listening on the provided [`SocketAddr`].
/// If the `SocketAddr`'s `port` is 0, an ephemeral port is used. Returns a
/// `SocketAddr` representing the address and port the server are listening on
/// and a future that can be `await`ed to begin serving requests.
pub fn aggregator_server<C: 'static + Clock>(
    datastore: Arc<Datastore>,
    clock: C,
    tolerable_clock_skew: Duration,
    role: Role,
    hpke_recipient: HpkeRecipient,
    listen_address: SocketAddr,
) -> Result<(SocketAddr, impl Future<Output = ()> + 'static), Error> {
    let routes = aggregator_filter(datastore, clock, tolerable_clock_skew, role, hpke_recipient)?;

    Ok(warp::serve(routes).bind_ephemeral(listen_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastore::test_util::{ephemeral_datastore, DbHandle},
        hpke::{HpkeSender, Label},
        message::{HpkeConfig, TaskId, Time},
        task::TaskParameters,
        time::tests::MockClock,
        trace::test_util::install_trace_subscriber,
    };
    use assert_matches::assert_matches;
    use http::Method;
    use hyper::body::to_bytes;
    use prio::codec::Decode;
    use std::io::Cursor;
    use url::Url;
    use warp::reply::Reply;

    #[tokio::test]
    async fn invalid_role() {
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let hpke_recipient = HpkeRecipient::generate(
            TaskId::random(),
            Label::InputShare,
            Role::Client,
            Role::Leader,
        );

        for invalid_role in [Role::Collector, Role::Client] {
            assert_matches!(
                aggregator_filter(
                    datastore.clone(),
                    MockClock::default(),
                    Duration::minutes(10),
                    invalid_role,
                    hpke_recipient.clone(),
                ),
                Err(Error::InvalidConfiguration(_))
            );
        }
    }

    #[tokio::test]
    async fn invalid_clock_skew() {
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let hpke_recipient = HpkeRecipient::generate(
            TaskId::random(),
            Label::InputShare,
            Role::Client,
            Role::Leader,
        );

        assert_matches!(
            Aggregator::new(
                Arc::new(datastore),
                MockClock::default(),
                Duration::minutes(-10),
                Role::Leader,
                hpke_recipient
            ),
            Err(Error::InvalidConfiguration(_))
        );
    }

    #[tokio::test]
    async fn hpke_config() {
        install_trace_subscriber();

        let task_id = TaskId::random();
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let hpke_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let response = warp::test::request()
            .path("/hpke_config")
            .method("GET")
            .filter(
                &aggregator_filter(
                    Arc::new(datastore),
                    MockClock::default(),
                    Duration::minutes(10),
                    Role::Leader,
                    hpke_recipient.clone(),
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "max-age=86400"
        );

        let bytes = to_bytes(response.into_body()).await.unwrap();
        let hpke_config = HpkeConfig::decode(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(hpke_config, hpke_recipient.config);
        let sender = HpkeSender::from_recipient(&hpke_recipient);

        let message = b"this is a message";
        let associated_data = b"some associated data";

        let ciphertext = sender.seal(message, associated_data).unwrap();

        let plaintext = hpke_recipient.open(&ciphertext, associated_data).unwrap();
        assert_eq!(&plaintext, message);
    }

    async fn setup_report(
        datastore: &Datastore,
        clock: &MockClock,
        skew: Duration,
    ) -> (HpkeRecipient, Report) {
        let task_id = TaskId::random();

        datastore
            .run_tx(|tx| {
                let fake_url = Url::parse("localhost:8080").unwrap();

                let task_parameters =
                    TaskParameters::new_dummy(task_id, vec![fake_url.clone(), fake_url]);
                Box::pin(async move { tx.put_task(&task_parameters).await })
            })
            .await
            .unwrap();

        let hpke_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let report_time = clock.now() - skew;

        let nonce = Nonce {
            time: Time(report_time.timestamp() as u64),
            rand: 0,
        };
        let extensions = vec![];
        let associated_data = Report::associated_data(nonce, &extensions);
        let message = b"this is a message";

        let leader_sender = HpkeSender::from_recipient(&hpke_recipient);
        let leader_ciphertext = leader_sender.seal(message, &associated_data).unwrap();

        let helper_sender = HpkeSender::from_recipient(&hpke_recipient);
        let helper_ciphertext = helper_sender.seal(message, &associated_data).unwrap();

        let report = Report {
            task_id,
            nonce,
            extensions,
            encrypted_input_shares: vec![leader_ciphertext, helper_ciphertext],
        };

        (hpke_recipient, report)
    }

    /// Convenience method to handle interaction with `warp::test` for typical PPM requests.
    async fn drive_filter(
        method: Method,
        path: &str,
        body: &[u8],
        filter: &BoxedFilter<(impl Reply + 'static,)>,
    ) -> Result<Response, Rejection> {
        warp::test::request()
            .method(method.as_str())
            .path(path)
            .body(body)
            .filter(filter)
            .await
            .map(|reply| reply.into_response())
    }

    #[tokio::test]
    async fn upload_filter() {
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();
        let skew = Duration::minutes(10);

        let (report_recipient, report) = setup_report(&datastore, &clock, skew).await;
        let filter = aggregator_filter(
            Arc::new(datastore),
            clock,
            skew,
            Role::Leader,
            report_recipient,
        )
        .unwrap();

        let response = drive_filter(Method::POST, "/upload", &report.get_encoded(), &filter)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(to_bytes(response.into_body()).await.unwrap().is_empty());

        // should reject duplicate reports with the staleReport type.
        // TODO (issue #34): change this error type.
        let response = drive_filter(Method::POST, "/upload", &report.get_encoded(), &filter)
            .await
            .unwrap();
        let (part, body) = response.into_parts();
        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:error:staleReport",
                "title": "Report could not be processed because it arrived too late.",
                "detail": "Report could not be processed because it arrived too late.",
                "instance": "https://example.com/ppm_aggregator",
                "taskid": base64::encode(report.task_id.as_bytes()),
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
            part.status.as_u16() as u64
        );

        // should reject a report with only one share with the unrecognizedMessage type.
        let mut bad_report = report.clone();
        bad_report.encrypted_input_shares.truncate(1);
        let response = drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
            .await
            .unwrap();
        let (part, body) = response.into_parts();
        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "https://example.com/ppm_aggregator",
                "taskid": base64::encode(report.task_id.as_bytes()),
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
            part.status.as_u16() as u64
        );

        // should reject a report using the wrong HPKE config for the leader, and reply with
        // the error type outdatedConfig.
        let mut bad_report = report.clone();
        bad_report.encrypted_input_shares[0].config_id = HpkeConfigId(101);
        let response = drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
            .await
            .unwrap();
        let (part, body) = response.into_parts();
        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:error:outdatedConfig",
                "title": "The message was generated using an outdated configuration.",
                "detail": "The message was generated using an outdated configuration.",
                "instance": "https://example.com/ppm_aggregator",
                "taskid": base64::encode(report.task_id.as_bytes()),
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
            part.status.as_u16() as u64
        );

        // reports from the future should be rejected.
        let mut bad_report = report.clone();
        bad_report.nonce.time = Time::from_naive_date_time(
            MockClock::default().now() + Duration::minutes(10) + Duration::seconds(1),
        );
        let response = drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
            .await
            .unwrap();
        assert!(!response.status().is_success());
        // TODO: update this test once an error type has been defined, and validate the problem
        // details.
        assert_eq!(response.status().as_u16(), 400);
    }

    // Helper should not expose /upload endpoint
    #[tokio::test]
    async fn upload_filter_helper() {
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();
        let skew = Duration::minutes(10);

        let (report_recipient, report) = setup_report(&datastore, &clock, skew).await;

        let filter = aggregator_filter(
            Arc::new(datastore),
            clock,
            skew,
            Role::Helper,
            report_recipient,
        )
        .unwrap();

        let result = warp::test::request()
            .method("POST")
            .path("/upload")
            .body(report.get_encoded())
            .filter(&filter)
            .await;

        // We can't use `Result::unwrap_err` or `assert_matches!` here because
        //  `impl Reply` is not `Debug`
        if let Err(rejection) = result {
            assert!(rejection.is_not_found());
        } else {
            panic!("should get rejection");
        }
    }

    async fn setup_upload_test(
        skew: Duration,
    ) -> (Aggregator<MockClock>, Report, Arc<Datastore>, DbHandle) {
        let (datastore, db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let clock = MockClock::default();
        let (report_recipient, report) = setup_report(&datastore, &clock, skew).await;

        let aggregator = Aggregator::new(
            datastore.clone(),
            clock,
            skew,
            Role::Leader,
            report_recipient,
        )
        .unwrap();

        (aggregator, report, datastore, db_handle)
    }

    #[tokio::test]
    async fn upload() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, report, datastore, _db_handle) = setup_upload_test(skew).await;

        aggregator.handle_upload(&report).await.unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report_by_task_id_and_nonce(report.task_id, report.nonce)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report, got_report);

        // should reject duplicate reports.
        // TODO (issue #34): change this error type.
        assert_matches!(aggregator.handle_upload(&report).await, Err(Error::StaleReport(stale_nonce, task_id)) => {
            assert_eq!(task_id, report.task_id);
            assert_eq!(report.nonce, stale_nonce);
        });
    }

    #[tokio::test]
    async fn upload_wrong_number_of_encrypted_shares() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, mut report, _, _db_handle) = setup_upload_test(skew).await;

        report.encrypted_input_shares = vec![report.encrypted_input_shares[0].clone()];

        assert_matches!(
            aggregator.handle_upload(&report).await,
            Err(Error::UnrecognizedMessage(_, _))
        );
    }

    #[tokio::test]
    async fn upload_wrong_hpke_config_id() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, mut report, _, _db_handle) = setup_upload_test(skew).await;

        report.encrypted_input_shares[0].config_id = HpkeConfigId(101);

        assert_matches!(aggregator.handle_upload(&report).await, Err(Error::OutdatedHpkeConfig(config_id, task_id)) => {
            assert_eq!(task_id, report.task_id);
            assert_eq!(config_id, HpkeConfigId(101));
        });
    }

    fn reencrypt_report(report: Report, hpke_recipient: &HpkeRecipient) -> Report {
        let associated_data = Report::associated_data(report.nonce, &report.extensions);
        let message = b"this is a message";

        let leader_sender = HpkeSender::from_recipient(hpke_recipient);
        let leader_ciphertext = leader_sender.seal(message, &associated_data).unwrap();

        let helper_sender = HpkeSender::from_recipient(hpke_recipient);
        let helper_ciphertext = helper_sender.seal(message, &associated_data).unwrap();

        Report {
            task_id: report.task_id,
            nonce: report.nonce,
            extensions: report.extensions,
            encrypted_input_shares: vec![leader_ciphertext, helper_ciphertext],
        }
    }

    #[tokio::test]
    async fn report_in_the_future() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, mut report, datastore, _db_handle) = setup_upload_test(skew).await;

        // Boundary condition
        report.nonce.time = Time::from_naive_date_time(aggregator.clock.now() + skew);
        let mut report = reencrypt_report(report, &aggregator.report_recipient);
        aggregator.handle_upload(&report).await.unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report_by_task_id_and_nonce(report.task_id, report.nonce)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report, got_report);

        // Just past the clock skew
        report.nonce.time =
            Time::from_naive_date_time(aggregator.clock.now() + skew + Duration::seconds(1));
        let report = reencrypt_report(report, &aggregator.report_recipient);
        assert_matches!(aggregator.handle_upload(&report).await, Err(Error::ReportFromTheFuture(nonce, task_id)) => {
            assert_eq!(task_id, report.task_id);
            assert_eq!(report.nonce, nonce);
        });
    }
}
