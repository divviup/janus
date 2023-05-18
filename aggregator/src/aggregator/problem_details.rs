use janus_messages::{problem_type::DapProblemType, TaskId};
use serde::Serialize;
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
        // Per the errors section of the protocol, error responses should use "HTTP status code 400
        // Bad Request unless explicitly specified otherwise."
        // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-03#name-errors
        Status::BadRequest
    }
}

/// The media type for problem details formatted as a JSON document, per RFC 7807.
static PROBLEM_DETAILS_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Serialization helper struct for JSON problem details error responses. See
/// https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-03#section-3.2.
#[derive(Serialize)]
struct ProblemDocument<'a> {
    #[serde(rename = "type")]
    type_: &'static str,
    title: &'static str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    taskid: &'a Option<String>,
}

pub trait ProblemDetailsConnExt {
    /// Send a response containing a JSON-encoded problem details document for the given
    /// DAP-specific problem type, (optionally including the DAP task ID) and set the appropriate
    /// HTTP status code.
    fn with_problem_details(self, error_type: DapProblemType, task_id: Option<&TaskId>) -> Self;
}

impl ProblemDetailsConnExt for Conn {
    fn with_problem_details(self, error_type: DapProblemType, task_id: Option<&TaskId>) -> Self {
        let status = error_type.http_status();

        self.with_status(status as u16)
            .with_header(
                KnownHeaderName::ContentType,
                PROBLEM_DETAILS_JSON_MEDIA_TYPE,
            )
            .with_json(&ProblemDocument {
                type_: error_type.type_uri(),
                title: error_type.description(),
                status: status as u16,
                taskid: &task_id.as_ref().map(ToString::to_string),
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::{error::BatchMismatch, send_request_to_helper, Error};
    use assert_matches::assert_matches;
    use futures::future::join_all;
    use http::Method;
    use janus_core::time::{Clock, RealClock};
    use janus_messages::{
        problem_type::{DapProblemType, DapProblemTypeParseError},
        Duration, HpkeConfigId, Interval, ReportIdChecksum,
    };
    use rand::random;
    use reqwest::Client;
    use std::{borrow::Cow, sync::Arc};
    use trillium_testing::prelude::post;

    #[test]
    fn dap_problem_type_round_trip() {
        for problem_type in [
            DapProblemType::UnrecognizedMessage,
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
        let meter = opentelemetry::global::meter("");
        let request_histogram = meter
            .f64_histogram("janus_http_request_duration_seconds")
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
                        Error::ReportRejected(random(), random(), RealClock::default().now())
                    }),
                    Some(DapProblemType::ReportRejected),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedMessage(Some(random()), "test")),
                    Some(DapProblemType::UnrecognizedMessage),
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
                    Box::new(|| Error::OutdatedHpkeConfig(random(), HpkeConfigId::from(0))),
                    Some(DapProblemType::OutdatedConfig),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::ReportTooEarly(random(), random(), RealClock::default().now())
                    }),
                    Some(DapProblemType::ReportTooEarly),
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
                        Method::POST,
                        server.url().parse().unwrap(),
                        "test",
                        "text/plain",
                        (),
                        &random(),
                        &request_histogram,
                    )
                    .await
                    .unwrap_err();
                    error_mock.assert_async().await;

                    // Confirm that post_to_helper() correctly parsed the error type from error_handler().
                    assert_matches!(
                        actual_error,
                        Error::Http { dap_problem_type: problem_type, .. } => {
                            assert_eq!(problem_type, test_case.expected_problem_type);
                        }
                    );
                }
            }),
        )
        .await;
    }
}
