use janus_messages::{problem_type::DapProblemType, AggregationJobId, CollectionJobId, TaskId};
use serde::Serialize;
use std::time::Duration;
use trillium::{Conn, KnownHeaderName, Status};
use trillium_api::ApiConnExt;

trait DapProblemTypeExt {
    /// Returns the HTTP status code that should be used in responses whose body is a problem
    /// document of this type.
    fn http_status(&self) -> Status;
}

impl DapProblemTypeExt for DapProblemType {
    /// Returns the HTTP status code that should be used in responses whose body is a problem
    /// document of this type.
    fn http_status(&self) -> Status {
        match self {
            // The HTTPS request authentication section does not specify that an authorization
            // failure is an "abort" of the protocol, and thus we can use a non-400 error code.
            // Therefore, we choose to use 403 Forbidden.
            //
            // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-09.html#section-3.1
            DapProblemType::UnauthorizedRequest => Status::Forbidden,

            // Per the Errors section of the protocol, error responses corresponding to an "abort"
            // in the protocol should use HTTP status code 400 Bad Request unless explicitly
            // specified otherwise.
            //
            // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-09.html#section-3.2
            _ => Status::BadRequest,
        }
    }
}

/// The media type for problem details formatted as a JSON document, per RFC 7807.
static PROBLEM_DETAILS_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Serialization helper struct for [DAP JSON problem details error responses][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-07#section-3.2.
#[derive(Debug, Serialize)]
pub struct ProblemDocument<'a> {
    #[serde(rename = "type")]
    type_: &'static str,
    title: &'static str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    taskid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregation_job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection_job_id: Option<String>,
    #[serde(skip)]
    retry_after: Option<Duration>,
}

impl<'a> ProblemDocument<'a> {
    /// Creates a general problem document for errors that aren't defined in DAP. Follow
    /// [RFC 9457][1] for guidance on a good problem document.
    ///
    /// If the error is defined in DAP, use [`Self::new_dap`] instead.
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc9457
    pub fn new(type_: &'static str, title: &'static str, status: Status) -> Self {
        Self {
            type_,
            title,
            status: status.into(),
            taskid: None,
            detail: None,
            aggregation_job_id: None,
            collection_job_id: None,
            retry_after: None,
        }
    }

    /// Creates a problem document corresponding to a [`DapProblemType`].
    pub fn new_dap(error_type: DapProblemType) -> Self {
        Self::new(
            error_type.type_uri(),
            error_type.description(),
            error_type.http_status(),
        )
    }

    pub fn with_task_id(self, taskid: &TaskId) -> Self {
        Self {
            taskid: Some(taskid.to_string()),
            ..self
        }
    }

    pub fn with_detail(self, detail: &'a str) -> Self {
        Self {
            detail: Some(detail),
            ..self
        }
    }

    pub fn with_aggregation_job_id(self, aggregation_job_id: &AggregationJobId) -> Self {
        Self {
            aggregation_job_id: Some(aggregation_job_id.to_string()),
            ..self
        }
    }

    pub fn with_collection_job_id(self, collection_job_id: &CollectionJobId) -> Self {
        Self {
            collection_job_id: Some(collection_job_id.to_string()),
            ..self
        }
    }

    pub fn with_retry_after(self, retry_after: Duration) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..self
        }
    }
}

pub trait ProblemDetailsConnExt {
    /// Send a response containing a JSON-encoded problem details document for the given
    /// DAP-specific problem document, and set the appropriate HTTP status code.
    fn with_problem_document(self, problem_document: &ProblemDocument) -> Self;
}

impl ProblemDetailsConnExt for Conn {
    fn with_problem_document(self, problem_document: &ProblemDocument) -> Self {
        let mut conn = self
            .with_status(problem_document.status)
            .with_response_header(
                KnownHeaderName::ContentType,
                PROBLEM_DETAILS_JSON_MEDIA_TYPE,
            );

        // Add Retry-After header if specified
        if let Some(retry_after) = problem_document.retry_after {
            conn = conn.with_response_header(
                KnownHeaderName::RetryAfter,
                retry_after.as_secs().to_string(),
            );
        }

        conn.with_json(problem_document)
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::{
        error::{BatchMismatch, ReportRejection, ReportRejectionReason},
        send_request_to_helper, Error, RequestBody,
    };
    use assert_matches::assert_matches;
    use bytes::Bytes;
    use futures::future::join_all;
    use http::Method;
    use janus_aggregator_core::test_util::noop_meter;
    use janus_core::{
        retries::test_util::LimitedRetryer,
        time::{Clock, RealClock},
    };
    use janus_messages::{
        problem_type::{DapProblemType, DapProblemTypeParseError},
        Duration, Interval, ReportIdChecksum,
    };
    use rand::random;
    use reqwest::Client;
    use std::{borrow::Cow, sync::Arc};
    use trillium::{KnownHeaderName, Status};
    use trillium_testing::prelude::post;

    #[test]
    fn dap_problem_type_round_trip() {
        for problem_type in [
            DapProblemType::InvalidMessage,
            DapProblemType::UnrecognizedTask,
            DapProblemType::MissingTaskId,
            DapProblemType::UnrecognizedAggregationJob,
            DapProblemType::OutdatedConfig,
            DapProblemType::ReportRejected,
            DapProblemType::ReportTooEarly,
            DapProblemType::BatchInvalid,
            DapProblemType::InvalidBatchSize,
            DapProblemType::BatchQueriedTooManyTimes,
            DapProblemType::BatchMismatch,
            DapProblemType::UnauthorizedRequest,
            DapProblemType::BatchOverlap,
        ] {
            let uri = problem_type.type_uri();
            assert_eq!(uri.parse::<DapProblemType>().unwrap(), problem_type);
        }
        assert_matches!("".parse::<DapProblemType>(), Err(DapProblemTypeParseError));
    }

    #[tokio::test]
    async fn problem_details_round_trip() {
        let request_histogram = noop_meter()
            .f64_histogram("janus_http_request_duration")
            .with_unit("s")
            .init();

        struct TestCase {
            error_factory: Box<dyn Fn() -> Error + Send + Sync>,
            expected_problem_type: Option<DapProblemType>,
        }

        impl TestCase {
            fn new(
                error_factory: Box<dyn Fn() -> Error + Send + Sync>,
                expected_problem_type: Option<DapProblemType>,
            ) -> TestCase {
                TestCase {
                    error_factory,
                    expected_problem_type,
                }
            }
        }

        join_all(
            [
                TestCase::new(Box::new(|| Error::InvalidConfiguration("test")), None),
                TestCase::new(
                    Box::new(|| {
                        Error::ReportRejected(ReportRejection::new(
                            random(),
                            random(),
                            RealClock::default().now(),
                            ReportRejectionReason::TaskExpired
                        ))
                    }),
                    Some(DapProblemType::ReportRejected),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::ReportRejected(ReportRejection::new(
                            random(),
                            random(),
                            RealClock::default().now(),
                            ReportRejectionReason::TooEarly
                        ))
                    }),
                    Some(DapProblemType::ReportTooEarly),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::ReportRejected(ReportRejection::new(
                            random(),
                            random(),
                            RealClock::default().now(),
                            ReportRejectionReason::OutdatedHpkeConfig(random()),
                        ))
                    }),
                    Some(DapProblemType::OutdatedConfig),
                ),
                TestCase::new(
                    Box::new(|| Error::InvalidMessage(Some(random()), "test")),
                    Some(DapProblemType::InvalidMessage),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedTask(random())),
                    Some(DapProblemType::UnrecognizedTask),
                ),
                TestCase::new(
                    Box::new(|| Error::MissingTaskId),
                    Some(DapProblemType::MissingTaskId),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedAggregationJob(random(), random())),
                    Some(DapProblemType::UnrecognizedAggregationJob),
                ),
                TestCase::new(
                    Box::new(|| Error::UnauthorizedRequest(random())),
                    Some(DapProblemType::UnauthorizedRequest),
                ),
                TestCase::new(
                    Box::new(|| Error::InvalidBatchSize(random(), 8)),
                    Some(DapProblemType::InvalidBatchSize),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::BatchInvalid(
                            random(),
                            format!(
                                "{}",
                                Interval::new(
                                    RealClock::default().now(),
                                    Duration::from_seconds(3600)
                                )
                                .unwrap()
                            ),
                        )
                    }),
                    Some(DapProblemType::BatchInvalid),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::BatchOverlap(
                            random(),
                            Interval::new(RealClock::default().now(), Duration::from_seconds(3600))
                                .unwrap(),
                        )
                    }),
                    Some(DapProblemType::BatchOverlap),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::BatchMismatch(Box::new(BatchMismatch {
                            task_id: random(),
                            own_checksum: ReportIdChecksum::from([0; 32]),
                            own_report_count: 100,
                            peer_checksum: ReportIdChecksum::from([1; 32]),
                            peer_report_count: 99,
                        }))
                    }),
                    Some(DapProblemType::BatchMismatch),
                ),
                TestCase::new(
                    Box::new(|| Error::BatchQueriedTooManyTimes(random(), 99)),
                    Some(DapProblemType::BatchQueriedTooManyTimes),
                ),
                TestCase::new(
                    Box::new(|| Error::TooManyRequests),
                    None,
                ),
                TestCase::new(
                    Box::new(|| Error::RequestTimeout),
                    None,
                ),
            ]
            .into_iter()
            .map(|test_case| {
                let request_histogram = request_histogram.clone();
                async move {
                    // Run the handler implementation of the given error, and capture its response.
                    let error_factory = Arc::new(test_case.error_factory);
                    let error = error_factory();
                    let mut test_conn = post("/").run_async(&error).await;
                    let body = if let Some(body) = test_conn.take_response_body() {
                        body.into_bytes().await.unwrap()
                    } else {
                        Cow::from([].as_slice())
                    };

                    // Serve the response via mockito, and run it through post_to_helper's error handling.
                    let mut server = mockito::Server::new_async().await;
                    let error_mock = server
                        .mock("POST", "/")
                        .with_status(test_conn.status().unwrap() as u16 as usize)
                        .with_header("Content-Type", "application/problem+json")
                        .with_body(body)
                        .create_async()
                        .await;
                    let actual_error = send_request_to_helper(
                        &Client::new(),
                        LimitedRetryer::new(0),
                        Method::POST,
                        server.url().parse().unwrap(),
                        "test",
                        Some(RequestBody {
                            content_type: "text/plain",
                            body: Bytes::new(),
                        }),
                        &random(),
                        &request_histogram,
                    )
                    .await
                    .unwrap_err();
                    error_mock.assert_async().await;

                    // Confirm that post_to_helper() correctly parsed the error type from error_handler().
                    assert_matches!(
                        actual_error,
                        Error::Http(error_response) => {
                            assert_eq!(error_response.dap_problem_type(), test_case.expected_problem_type.as_ref());
                        }
                    );
                }
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_retry_after_header() {
        // Test that TooManyRequests and RequestTimeout errors include Retry-After headers
        let too_many_requests_error = Error::TooManyRequests;
        let test_conn = post("/").run_async(&too_many_requests_error).await;

        // Check status code
        assert_eq!(test_conn.status().unwrap(), Status::TooManyRequests);

        // Check that Retry-After header is present and has correct value
        let headers = test_conn.response_headers();
        let retry_after = headers.get(KnownHeaderName::RetryAfter);
        assert!(
            retry_after.is_some(),
            "TooManyRequests should include Retry-After header"
        );

        // Check that the retry-after value is "30" (30 seconds as configured in the handler)
        assert_eq!(retry_after.unwrap(), "30");

        // Test RequestTimeout error
        let request_timeout_error = Error::RequestTimeout;
        let test_conn = post("/").run_async(&request_timeout_error).await;

        // Check status code
        assert_eq!(test_conn.status().unwrap(), Status::RequestTimeout);

        // Check that Retry-After header is present and has correct value
        let headers = test_conn.response_headers();
        let retry_after = headers.get(KnownHeaderName::RetryAfter);
        assert!(
            retry_after.is_some(),
            "RequestTimeout should include Retry-After header"
        );

        // Check that the retry-after value is "30" (30 seconds as configured in the handler)
        assert_eq!(retry_after.unwrap(), "30");
    }
}
