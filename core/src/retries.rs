//! Provides a simple interface for retrying fallible HTTP requests.

use backoff::{future::retry, ExponentialBackoff};
use futures::Future;
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
    ExponentialBackoff {
        initial_interval: Duration::from_secs(1),
        max_interval: Duration::from_secs(30),
        multiplier: 2.0,
        max_elapsed_time: Some(Duration::from_secs(600)),
        ..Default::default()
    }
}
/// An [`ExponentialBackoff`] with parameters tuned for tests where we don't want to be retrying
/// for 10 minutes.
#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub fn test_http_request_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        initial_interval: Duration::from_nanos(1),
        max_interval: Duration::from_nanos(30),
        multiplier: 2.0,
        max_elapsed_time: Some(Duration::from_millis(100)),
        ..Default::default()
    }
}

/// Executes the provided request function and awaits the returned future, retrying using the
/// parameters in the provided `ExponentialBackoff` if the [`reqwest::Error`] returned by
/// `request_fn` is:
///
///   - a timeout
///   - a problem establishing a connection
///   - an HTTP status code indicating a server error
///
/// If the request eventually succeeds, the value returned by `request_fn` is returned. If an
/// unretryable failure occurs or enough transient failures occur, then `Err(ret)` is returned,
/// where `ret` is the `Result<reqwest::Response, reqwest::Error>` returned by the last call to
/// `request_fn`. Retryable failures are logged.
///
/// # TODOs:
///
/// This function could take a list of HTTP status codes that should be considered retryable, so
/// that a caller could opt to retry when it sees 408 Request Timeout or 429 Too Many Requests, but
/// since none of the servers this is currently used to communicate with ever return those statuses,
/// we don't yet need that feature.
pub async fn retry_http_request<RequestFn, ResultFuture>(
    backoff: ExponentialBackoff,
    request_fn: RequestFn,
) -> Result<reqwest::Response, Result<reqwest::Response, reqwest::Error>>
where
    RequestFn: Fn() -> ResultFuture,
    ResultFuture: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    retry(backoff, || async {
        // In all branches in this match, we wrap the reqwest::Response or reqwest::Error up in a
        // Result<reqwest::Response, backoff::Error<Result<reqwest::Response, reqwest::Error>>>>,
        // which allows us to retry on certain HTTP status codes without discarding the
        // reqwest::Response, which the caller may need in order to examine its body or headers.
        match request_fn().await {
            Ok(response) => {
                if response.status().is_server_error()
                    && response.status() != StatusCode::NOT_IMPLEMENTED
                {
                    warn!(?response, "encountered retryable server error");
                    return Err(backoff::Error::transient(Ok(response)));
                }

                Ok(response)
            }
            Err(error) => {
                if error.is_timeout() || error.is_connect() {
                    warn!(?error, "encountered retryable error");
                    return Err(backoff::Error::transient(Err(error)));
                }

                if let Some(io_error) = find_io_error(&error) {
                    if let std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted = io_error.kind()
                    {
                        warn!(?error, "encountered retryable error");
                        return Err(backoff::Error::transient(Err(error)));
                    }
                }

                debug!("encountered non-retryable error");
                Err(backoff::Error::permanent(Err(error)))
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use crate::{
        retries::{retry_http_request, test_http_request_exponential_backoff},
        test_util::install_test_trace_subscriber,
    };
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
            .with_body("some-body")
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        // HTTP 404 should cause the client to give up after a single attempt, and the caller should
        // get `Ok(reqwest::Response)`.
        let response = retry_http_request(test_http_request_exponential_backoff(), || async {
            http_client.get(server.url()).send().await
        })
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("some-header").unwrap(),
            &"some-value"
        );
        assert_eq!(response.text().await.unwrap(), "some-body".to_string());

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
        // a `reqwest::Response` so they can examine the status code, headers and response body,
        // which you can't get from a `reqwest::Error`.
        let response = retry_http_request(test_http_request_exponential_backoff(), || async {
            http_client.get(server.url()).send().await
        })
        .await
        .unwrap_err()
        .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get("some-header").unwrap(),
            &"some-value"
        );
        assert_eq!(response.text().await.unwrap(), "some-body".to_string());
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

        let response = retry_http_request(test_http_request_exponential_backoff(), || async {
            http_client.get(server.url()).send().await
        })
        .await
        .unwrap();

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
            .expect_at_least(1)
            .create_async()
            .await;
        let mock_200 = server
            .mock("GET", "/")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let http_client = reqwest::Client::builder().build().unwrap();

        retry_http_request(test_http_request_exponential_backoff(), || async {
            http_client.get(server.url()).send().await
        })
        .await
        .unwrap();

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

        let err = retry_http_request(test_http_request_exponential_backoff(), || async {
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

        retry_http_request(test_http_request_exponential_backoff(), || async {
            http_client.get(url.clone()).send().await
        })
        .await
        .unwrap_err()
        .unwrap_err();

        listener_task.abort();
        assert!(listener_task.await.unwrap_err().is_cancelled());
    }
}
