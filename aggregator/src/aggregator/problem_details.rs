use janus_messages::{
    AggregateShareId, AggregationJobId, CollectionJobId, TaskId, problem_type::DapProblemType,
};
use serde::Serialize;
use std::time::Duration;
use trillium::{Conn, KnownHeaderName, Status};
use trillium_api::ApiConnExt;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregate_share_id: Option<String>,
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
            aggregate_share_id: None,
        }
    }

    /// Creates a problem document corresponding to a [`DapProblemType`].
    pub fn new_dap(error_type: DapProblemType) -> Self {
        Self::new(
            error_type.type_uri(),
            error_type.description(),
            // Per the Errors section of the protocol, error responses corresponding to an "abort"
            // in the protocol should use HTTP status code 400 Bad Request unless explicitly
            // specified otherwise.
            //
            // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-09.html#section-3.2
            Status::BadRequest,
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

    pub fn with_aggregate_share_id(self, aggregate_share_id: &AggregateShareId) -> Self {
        Self {
            aggregate_share_id: Some(aggregate_share_id.to_string()),
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
        self.with_status(problem_document.status)
            .with_response_header(
                KnownHeaderName::ContentType,
                PROBLEM_DETAILS_JSON_MEDIA_TYPE,
            )
            .with_json(problem_document)
    }
}

pub trait RetryAfterConnExt {
    fn with_retry_after(self, retry_after: Duration) -> Self;
}

impl RetryAfterConnExt for Conn {
    fn with_retry_after(self, retry_after: Duration) -> Self {
        self.with_response_header(
            KnownHeaderName::RetryAfter,
            retry_after.as_secs().to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::{Error, RequestBody, error::BatchMismatch, send_request_to_helper};
    use assert_matches::assert_matches;
    use bytes::Bytes;
    use futures::future::join_all;
    use http::Method;
    use janus_aggregator_core::{TIME_HISTOGRAM_BOUNDARIES, test_util::noop_meter};
    use janus_core::{
        initialize_rustls,
        retries::test_util::LimitedRetryer,
        test_util::install_test_trace_subscriber,
        time::{Clock, RealClock},
    };
    use janus_messages::{
        Duration, Interval, ReportIdChecksum,
        problem_type::{DapProblemType, DapProblemTypeParseError},
    };
    use rand::random;
    use reqwest::Client;
    use std::{borrow::Cow, sync::Arc};
    use trillium::Status;
    use trillium_testing::{assert_headers, assert_status, prelude::post};

    #[test]
    fn dap_problem_type_round_trip() {
        for problem_type in [
            DapProblemType::InvalidMessage,
            DapProblemType::UnrecognizedTask,
            DapProblemType::UnrecognizedAggregationJob,
            DapProblemType::BatchInvalid,
            DapProblemType::InvalidBatchSize,
            DapProblemType::BatchMismatch,
            DapProblemType::BatchOverlap,
        ] {
            let uri = problem_type.type_uri();
            assert_eq!(uri.parse::<DapProblemType>().unwrap(), problem_type);
        }
        assert_matches!("".parse::<DapProblemType>(), Err(DapProblemTypeParseError));
    }

    #[tokio::test]
    async fn problem_details_round_trip() {
        install_test_trace_subscriber();
        initialize_rustls();
        let request_histogram = noop_meter()
            .f64_histogram("janus_http_request_duration")
            .with_unit("s")
            .with_boundaries(TIME_HISTOGRAM_BOUNDARIES.to_vec())
            .build();

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
                    Box::new(|| Error::InvalidMessage(Some(random()), "test")),
                    Some(DapProblemType::InvalidMessage),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedTask(random())),
                    Some(DapProblemType::UnrecognizedTask),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedAggregationJob(random(), random())),
                    Some(DapProblemType::UnrecognizedAggregationJob),
                ),
                TestCase::new(
                    Box::new(|| Error::UnauthorizedRequest(random())),
                    None,
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
                                Interval::new_with_duration(
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
                            Interval::new_with_duration(RealClock::default().now(), Duration::from_seconds(3600))
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
        for error in [Error::TooManyRequests, Error::RequestTimeout] {
            let test_conn = post("/").run_async(&error).await;
            assert_status!(test_conn, Status::TooManyRequests);
            assert_headers!(test_conn, "Retry-After" => "30");
        }
    }
}
