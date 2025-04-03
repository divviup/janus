//! Provides a simple interface for retrying fallible HTTP requests.

use crate::http::HttpErrorResponse;
use backon::{Backoff, BackoffBuilder, ExponentialBackoff, ExponentialBuilder, Retryable};
use bytes::Bytes;
use futures::future::Future;
use http::HeaderMap;
use reqwest::StatusCode;
use std::{error::Error as StdError, time::Duration};
use tracing::{debug, warn};

/// Traverse chain of source errors looking for an `std::io::Error`.
fn find_io_error(original_error: &reqwest::Error) -> Option<&std::io::Error> {
    let mut cause = original_error.source();
    while let Some(err) = cause {
        if let Some(typed) = err.downcast_ref() {
            return Some(typed);
        }
        cause = err.source();
    }

    None
}

/// An [`ExponentialBackoff`] with parameters suitable for most HTTP requests. The parameters are
/// copied from the parameters used in the GCP Go SDK[1].
///
/// AWS doesn't give us specific guidance on what intervals to use, but the GCP implementation cites
/// AWS blog posts so the same parameters are probably fine for both, and most HTTP APIs for that
/// matter.
///
/// [1]: https://github.com/googleapis/gax-go/blob/fbaf9882acf3297573f3a7cb832e54c7d8f40635/v2/call_option.go#L120
pub fn http_request_exponential_backoff() -> ExponentialBackoff {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(30))
        .with_factor(2.0)
        .with_jitter()
        .with_max_times(10)
        .build()
}

/// HttpResponse represents an HTTP response. It will typically be returned from
/// [`retry_http_request`].
#[derive(Clone, Debug)]
pub struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl HttpResponse {
    /// Returns the HTTP status code associated with this HTTP response.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the headers associated with this HTTP response.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the body of the HTTP response.
    pub fn body(&self) -> &Bytes {
        &self.body
    }
}

/// HttpRetryError represents both an HTTP error and whether that error is
/// retryable. The result field can be either a problem doc
/// (`HttpErrorResponse`) or a direct error from `reqwest`. Since there are
/// error conditions from both which are retryable, a separate boolean tracks
/// that.
#[derive(Debug)]
struct HttpRetryError {
    result: Result<HttpErrorResponse, reqwest::Error>,
    retryable: bool,
}

impl HttpRetryError {
    fn retryable_error(err: reqwest::Error) -> HttpRetryError {
        HttpRetryError {
            result: Err(err),
            retryable: true,
        }
    }
    fn fatal_error(err: reqwest::Error) -> HttpRetryError {
        HttpRetryError {
            result: Err(err),
            retryable: false,
        }
    }

    async fn retryable_response(resp: reqwest::Response) -> HttpRetryError {
        HttpRetryError {
            result: Ok(HttpErrorResponse::from_response(resp).await),
            retryable: true,
        }
    }

    async fn fatal_response(resp: reqwest::Response) -> HttpRetryError {
        HttpRetryError {
            result: Ok(HttpErrorResponse::from_response(resp).await),
            retryable: false,
        }
    }
}

/// Executes the provided HTTP request function, retrying using the parameters in the provided
/// `ExponentialBackoff` if the [`reqwest::Error`] returned by `request_fn` is:
///
///   - a timeout
///   - a problem establishing a connection
///   - an HTTP status code indicating a server error
///   - HTTP status code 429 Too Many Requests
///
/// If the request eventually succeeds, an [`HttpResponse`] corresponding to the request returned by
/// `request_fn` is returned.
///
/// If an unretryable failure occurs or enough transient failures occur, then `Err(ret)` is
/// returned, where `ret` is the `Result<HttpErrorResponse, reqwest::Error>` corresponding to the
/// last call to `request_fn`. `HttpErrorResponse` is populated when the result was a successful
/// HTTP transaction indicating a failure, while `reqwest::Error` is populated when there is an
/// HTTP-level error such as a connection failure, timeout, or I/O error. Retryable failures are
/// logged.
///
/// # TODOs:
///
/// This function could take a list of HTTP status codes that should be considered retryable, so
/// that a caller could opt to retry when it sees 408 Request Timeout, but since none of the servers
/// this is currently used to communicate with ever return those statuses, we don't yet need that
/// feature.
#[allow(clippy::result_large_err)]
pub async fn retry_http_request<ResultFuture>(
    backoff: impl Backoff,
    request_fn: impl Fn() -> ResultFuture,
) -> Result<HttpResponse, Result<HttpErrorResponse, reqwest::Error>>
where
    ResultFuture: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    retry_http_request_notify(backoff, |_, _| {}, request_fn).await
}

/// Executes the provided HTTP request function, retrying using the parameters in the provided
/// `ExponentialBackoff` if the [`reqwest::Error`] returned by `request_fn` is:
///
///   - a timeout
///   - a problem establishing a connection
///   - an HTTP status code indicating a server error
///   - HTTP status code 429 Too Many Requests
///
/// If the request eventually succeeds, an [`HttpResponse`] corresponding to the request returned by
/// `request_fn` is returned.
///
/// If an unretryable failure occurs or enough transient failures occur, then `Err(ret)` is
/// returned, where `ret` is the `Result<HttpErrorResponse, reqwest::Error>` corresponding to the
/// last call to `request_fn`. `HttpErrorResponse` is populated when the result was a successful
/// HTTP transaction indicating a failure, while `reqwest::Error` is populated when there is an
/// HTTP-level error such as a connection failure, timeout, or I/O error. Retryable failures are
/// logged.
///
/// Each retried failure notifies the provided [`Notify`] instance. Note that a permanent failure
/// (either explicit, or due to too many transient failures) will _not_ notify the provided
/// notifier.
///
/// # TODOs:
///
/// This function could take a list of HTTP status codes that should be considered retryable, so
/// that a caller could opt to retry when it sees 408 Request Timeout, but since none of the servers
/// this is currently used to communicate with ever return those statuses, we don't yet need that
/// feature.
#[allow(clippy::result_large_err)]
pub async fn retry_http_request_notify<ResultFuture>(
    backoff: impl Backoff,
    notify: impl Fn(&Result<HttpErrorResponse, reqwest::Error>, Duration),
    request_fn: impl Fn() -> ResultFuture,
) -> Result<HttpResponse, Result<HttpErrorResponse, reqwest::Error>>
where
    ResultFuture: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    fn check_reqwest_result<T>(rslt: Result<T, reqwest::Error>) -> Result<T, HttpRetryError> {
        rslt.map_err(|err| {
            if err.is_timeout() || err.is_connect() {
                warn!(?err, "Encountered retryable network error");
                return HttpRetryError::retryable_error(err);
            }

            if let Some(io_error) = find_io_error(&err) {
                if let std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted = io_error.kind()
                {
                    warn!(?err, "Encountered retryable network error");
                    return HttpRetryError::retryable_error(err);
                }
            }

            debug!("Encountered non-retryable network error");
            HttpRetryError::fatal_error(err)
        })
    }

    (|| async {
        let response = check_reqwest_result(request_fn().await)?;
        let status = response.status();
        if status.is_server_error() || status.is_client_error() {
            if is_retryable_http_status(status) {
                warn!(?response, "Encountered retryable HTTP error");
                return Err(HttpRetryError::retryable_response(response).await);
            } else {
                warn!(?response, "Encountered non-retryable HTTP error");
                return Err(HttpRetryError::fatal_response(response).await);
            }
        }
        let headers = response.headers().clone();
        let body = check_reqwest_result(response.bytes().await)?;

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    })
    .retry(backoff)
    .when(|e| e.retryable)
    .notify(|e, d| notify(&e.result, d))
    .await
    .map_err(|e| e.result)
}

pub fn is_retryable_http_status(status: StatusCode) -> bool {
    (status.is_server_error() && status != StatusCode::NOT_IMPLEMENTED)
        || status == StatusCode::TOO_MANY_REQUESTS
}

pub fn is_retryable_http_client_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request() || error.is_body()
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use backon::{Backoff, BackoffBuilder, ExponentialBackoff, ExponentialBuilder};
    use std::time::Duration;

    /// An [`ExponentialBackoff`] with parameters tuned for tests where we don't want to be retrying
    /// for 10 minutes.
    pub fn test_http_request_exponential_backoff() -> ExponentialBackoff {
        ExponentialBuilder::default()
            .with_jitter()
            .with_min_delay(Duration::from_nanos(1))
            .with_max_delay(Duration::from_nanos(30))
            .with_factor(2.0)
            .with_max_times(5)
            .build()
    }

    /// A [`Backoff`] that immediately retries a given number of times, and then gives up.
    #[derive(Clone)]
    pub struct LimitedRetryer {}

    impl LimitedRetryer {
        pub fn build(max_retries: u64) -> impl Backoff {
            let mut retryer_vec = Vec::new();
            for _ in 0..max_retries {
                retryer_vec.push(Duration::ZERO)
            }
            retryer_vec.into_iter().build()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        retries::{retry_http_request, retry_http_request_notify, test_util::LimitedRetryer},
        test_util::install_test_trace_subscriber,
    };
    use http_api_problem::PROBLEM_JSON_MEDIA_TYPE;
    use reqwest::StatusCode;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use url::Url;

    #[tokio::test]
    async fn http_retry_client_error() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;

        let mock_404 = server
            .mock("GET", "/")
            .with_status(StatusCode::NOT_FOUND.as_u16().into())
            .with_header("some-header", "some-value")
            .with_body("some-body") // once told me
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        // HTTP 404 should cause the client to give up after a single attempt, and the caller should
        // get `Err(Ok(HttpErrorResponse))`.
        let mut notify_count = 0;
        let response = retry_http_request_notify(
            LimitedRetryer::build(10),
            |_, _| {
                notify_count += 1;
            },
            || async { http_client.get(server.url()).send().await },
        )
        .await
        .unwrap_err()
        .unwrap();

        assert_eq!(notify_count, 0);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        mock_404.assert_async().await;
    }

    #[tokio::test]
    async fn http_retry_server_error() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;

        let mock_500 = server
            .mock("GET", "/")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR.as_u16().into())
            .with_header("some-header", "some-value")
            .with_body("some-body")
            .expect_at_least(2)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        // We expect to eventually give up in the face of repeated HTTP 500, but the caller expects
        // an `HttpErrorResponse` so they can examine the error, which you can't get from a
        // `reqwest::Error`.
        let mut notify = NotifyCounter::default();
        let response =
            retry_http_request_notify(LimitedRetryer::build(10), &mut notify, || async {
                http_client.get(server.url()).send().await
            })
            .await
            .unwrap_err()
            .unwrap();

        // We check only that retries occurred, not the specific number of retries, because the
        // number of retries is nondeterministic.
        assert_eq!(notify.count, 10);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        mock_500.assert_async().await;
    }

    #[tokio::test]
    async fn http_retry_server_error_unimplemented() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;

        let mock_501 = server
            .mock("GET", "/")
            .with_status(StatusCode::NOT_IMPLEMENTED.as_u16().into())
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        let mut notify = NotifyCounter::default();
        let response =
            retry_http_request_notify(LimitedRetryer::build(10), &mut notify, || async {
                http_client.get(server.url()).send().await
            })
            .await
            .unwrap_err()
            .unwrap();

        assert_eq!(notify.count, 0);
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        mock_501.assert_async().await;
    }

    #[tokio::test]
    async fn http_retry_server_error_eventually_succeeds() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;

        let mock_500 = server
            .mock("GET", "/")
            .with_status(500)
            .expect_at_least(2)
            .create_async()
            .await;
        let mock_200 = server
            .mock("GET", "/")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        let mut notify = NotifyCounter::default();
        retry_http_request_notify(LimitedRetryer::build(10), &mut notify, || async {
            http_client.get(server.url()).send().await
        })
        .await
        .unwrap();

        assert_eq!(notify.count, 2);
        mock_200.assert_async().await;
        mock_500.assert_async().await;
    }

    #[tokio::test]
    async fn http_retry_timeout() {
        install_test_trace_subscriber();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_port = tcp_listener.local_addr().unwrap().port();

        let listener_task = tokio::spawn(async move {
            loop {
                let (_socket, _) = tcp_listener.accept().await.unwrap();
                // Deliberately do nothing with the socket to force a timeout in the client
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let url = Url::parse(&format!("http://127.0.0.1:{bound_port}")).unwrap();

        let http_client = reqwest::Client::builder()
            // Aggressively short timeout to force a timeout error
            .timeout(Duration::from_nanos(1))
            .build()
            .unwrap();

        let err = retry_http_request(LimitedRetryer::build(0), || async {
            http_client.get(url.clone()).send().await
        })
        .await
        .unwrap_err()
        .unwrap_err();
        assert!(err.is_timeout(), "error = {err}");

        listener_task.abort();
        assert!(listener_task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn http_retry_connection_reset() {
        install_test_trace_subscriber();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_port = tcp_listener.local_addr().unwrap().port();

        let listener_task = tokio::spawn(async move {
            // Accept connections on the TCP listener, then wait until we can read one byte from
            // them (indicating that the client has sent something). If we read successfully, drop
            // the socket so that the client will see a connection reset error.
            loop {
                let (socket, _) = tcp_listener.accept().await.unwrap();
                loop {
                    socket.readable().await.unwrap();

                    let mut buf = [0u8; 1];
                    match socket.try_read(&mut buf) {
                        Ok(1) => break,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        val => panic!("unexpected result from try_read {val:?}"),
                    }
                }
                drop(socket);
            }
        });

        let url = Url::parse(&format!("http://127.0.0.1:{bound_port}")).unwrap();

        let http_client = reqwest::Client::builder().build().unwrap();

        retry_http_request(LimitedRetryer::build(0), || async {
            http_client.get(url.clone()).send().await
        })
        .await
        .unwrap_err()
        .unwrap_err();

        listener_task.abort();
        assert!(listener_task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn http_retry_server_json_problem() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;

        let mock_problem = server
            .mock("GET", "/")
            .with_status(400)
            .with_header("Content-Type", PROBLEM_JSON_MEDIA_TYPE)
            .with_body("{\"type\":\"evil://league_of_evil/bad.horse?hes.bad\"}")
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        let response = retry_http_request(LimitedRetryer::build(0), || async {
            http_client.get(server.url()).send().await
        })
        .await
        .unwrap_err()
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.type_uri(),
            Some("evil://league_of_evil/bad.horse?hes.bad")
        );
        mock_problem.assert_async().await;
    }

    #[tokio::test]
    async fn http_retry_server_json_problem_versioned_doc() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;

        // Ensure that even with a complex media type, we parse a problem
        // document.
        let mock_problem = server
            .mock("GET", "/")
            .with_status(418)
            .with_header(
                "Content-Type",
                "application/problem+json; charset=\"utf-8\"; version=4",
            )
            .with_body("{\"title\":\"too many eels\"}")
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        let response = retry_http_request(LimitedRetryer::build(0), || async {
            http_client.get(server.url()).send().await
        })
        .await
        .unwrap_err()
        .unwrap();

        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(response.title(), Some("too many eels"));
        mock_problem.assert_async().await;
    }
}
