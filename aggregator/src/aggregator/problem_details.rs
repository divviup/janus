use std::time::Duration;

use axum::response::{IntoResponse, Response};
use http::{
    HeaderValue, StatusCode,
    header::{CONTENT_TYPE, RETRY_AFTER},
};
use janus_messages::{
    AggregateShareId, AggregationJobId, CollectionJobId, TaskId, problem_type::DapProblemType,
};
use serde::Serialize;

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
    pub fn new(type_: &'static str, title: &'static str, status: StatusCode) -> Self {
        Self {
            type_,
            title,
            status: status.as_u16(),
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
            StatusCode::BAD_REQUEST,
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

    /// Returns the HTTP status code for this problem document.
    pub fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Converts this problem document into an axum [`Response`].
    pub fn into_response_with_retry_after(&self, retry_after: Option<Duration>) -> Response {
        let body = serde_json::to_vec(self).unwrap_or_default();
        let mut response = (
            self.status_code(),
            [(
                CONTENT_TYPE,
                HeaderValue::from_static(PROBLEM_DETAILS_JSON_MEDIA_TYPE),
            )],
            body,
        )
            .into_response();
        if let Some(retry_after) = retry_after {
            response.headers_mut().insert(
                RETRY_AFTER,
                HeaderValue::from_str(&retry_after.as_secs().to_string()).unwrap(),
            );
        }
        response
    }
}

impl IntoResponse for &ProblemDocument<'_> {
    fn into_response(self) -> Response {
        self.into_response_with_retry_after(None)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use axum::{Router, body::to_bytes, routing::post};
    use bytes::Bytes;
    use futures::future::join_all;
    use http::{Method, StatusCode};
    use janus_aggregator_core::{TIME_HISTOGRAM_BOUNDARIES, test_util::noop_meter};
    use janus_core::{
        initialize_rustls,
        retries::test_util::LimitedRetryer,
        test_util::install_test_trace_subscriber,
        time::{Clock, DateTimeExt, RealClock},
    };
    use janus_messages::{
        Duration, Interval, ReportIdChecksum,
        problem_type::{DapProblemType, DapProblemTypeParseError},
        taskprov::TimePrecision,
    };
    use rand::random;
    use reqwest::Client;
    use tower::ServiceExt;

    use crate::aggregator::{Error, RequestBody, error::BatchMismatch, send_request_to_helper};

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
                                Interval::new(
                                    RealClock::default().now().to_time(&TimePrecision::from_seconds(1)),
                                    Duration::from_seconds(3600, &TimePrecision::from_seconds(1))
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
                            Interval::new(RealClock::default().now().to_time(&TimePrecision::from_seconds(1)), Duration::from_seconds(3600, &TimePrecision::from_seconds(1)))
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
                    use axum::response::IntoResponse;
                    // Convert the error to an axum response and capture status/body.
                    let error_factory = Arc::new(test_case.error_factory);
                    let error = error_factory();
                    let response = error.into_response();
                    let status = response.status();
                    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

                    // Serve the response via mockito, and run it through post_to_helper's
                    // error handling.
                    let mut server = mockito::Server::new_async().await;
                    let error_mock = server
                        .mock("POST", "/")
                        .with_status(status.as_u16() as usize)
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

                    // Confirm that post_to_helper() correctly parsed the error type from
                    // error_handler().
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
        use axum::response::IntoResponse;
        // Test that TooManyRequests and RequestTimeout errors include Retry-After headers
        for error in [Error::TooManyRequests, Error::RequestTimeout] {
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response
                    .headers()
                    .get("Retry-After")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "30"
            );
        }
    }
}
