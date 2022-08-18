//! This crate contains functionality useful for Janus integration tests.

#[cfg(feature = "daphne")]
pub mod daphne;
#[cfg(feature = "janus")]
pub mod janus;

#[cfg(feature = "janus")]
lazy_static::lazy_static! {
    static ref CONTAINER_CLIENT: testcontainers::clients::Cli =
        testcontainers::clients::Cli::default();
}

/// Waits a while for the given port to start responding to HTTP requests, panicking if this
/// doesn't happen soon enough.
#[cfg(any(feature = "daphne", feature = "janus"))]
async fn await_http_server(port: u16) {
    use backoff::{future::retry, ExponentialBackoff};
    use futures::TryFutureExt;
    use std::time::Duration;
    use url::Url;

    let http_client = reqwest::Client::default();
    let url = Url::parse(&format!("http://localhost:{port}/")).unwrap();
    retry(
        // (We use ExponentialBackoff as a constant-time backoff as the built-in Constant
        // backoff will never time out.)
        ExponentialBackoff {
            initial_interval: Duration::from_millis(250),
            max_interval: Duration::from_millis(250),
            multiplier: 1.0,
            max_elapsed_time: Some(Duration::from_secs(10)),
            ..Default::default()
        },
        || {
            http_client
                .get(url.clone())
                .send()
                .map_err(backoff::Error::transient)
        },
    )
    .await
    .unwrap();
}
