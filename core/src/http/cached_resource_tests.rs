use crate::{
    http::cached_resource::{expires_at, CachedResource},
    retries::test_util::test_http_request_exponential_backoff,
    test_util::install_test_trace_subscriber,
};
use http::{
    header::{CACHE_CONTROL, CONTENT_TYPE},
    HeaderValue,
};
use janus_messages::Time;
use prio::codec::Encode;
use std::time::Duration;
use tokio::time::Instant;
use url::Url;

#[tokio::test]
async fn no_cache_control() {
    install_test_trace_subscriber();
    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();

    let time = Time::from_seconds_since_epoch(0);
    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_body(time.get_encoded().unwrap())
        .with_header(CONTENT_TYPE.as_str(), "time")
        .expect(1)
        .create_async()
        .await;

    // new() will fetch the resource from server. Because no cache-control is provided, resource()
    // should not refetch.
    let mut resource = CachedResource::<Time>::new(
        server_url.join("resource").unwrap(),
        "time",
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap();
    assert_eq!(resource.resource().await.unwrap(), &time);

    mock.assert_async().await;
}

#[tokio::test]
async fn with_cache_control() {
    install_test_trace_subscriber();
    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();
    let time = Time::from_seconds_since_epoch(0);
    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_header(CACHE_CONTROL.as_str(), "max-age=86400")
        .with_header(CONTENT_TYPE.as_str(), "time")
        .with_body(time.get_encoded().unwrap())
        .expect(2)
        .create_async()
        .await;

    // new() will fetch the resource from the server. Because the cache is not expired, resource()
    // should not refetch.
    let mut resource = CachedResource::<Time>::new(
        server_url.join("resource").unwrap(),
        "time",
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap();
    assert_eq!(resource.resource().await.unwrap(), &time);

    // Should not have two matches yet
    assert!(!mock.matched());

    // Advance time far enough to invalidate cache. resource() should refetch.
    tokio::time::advance(Duration::from_secs(86401)).await;

    assert_eq!(resource.resource().await.unwrap(), &time);

    // Now we should have matched twice
    mock.assert_async().await;
}

#[tokio::test]
async fn malformed_cache_control() {
    install_test_trace_subscriber();
    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();
    let time = Time::from_seconds_since_epoch(0);
    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_header(CACHE_CONTROL.as_str(), "malformed")
        .with_header(CONTENT_TYPE.as_str(), "time")
        .with_body(time.get_encoded().unwrap())
        .expect(1)
        .create_async()
        .await;

    // The cache control header should be ignored because it's malformed, meaning the resource will
    // be fetched only once.
    let mut resource = CachedResource::<Time>::new(
        server_url.join("resource").unwrap(),
        "time",
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap();
    assert_eq!(resource.resource().await.unwrap(), &time);

    mock.assert_async().await;
}

#[tokio::test]
async fn wrong_content_type() {
    install_test_trace_subscriber();
    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();
    let time = Time::from_seconds_since_epoch(0);
    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_header(CACHE_CONTROL.as_str(), "malformed")
        .with_header(CONTENT_TYPE.as_str(), "time")
        .with_body(time.get_encoded().unwrap())
        .expect(1)
        .create_async()
        .await;

    let _resource = CachedResource::<Time>::new(
        server_url.join("resource").unwrap(),
        "nottime",
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap_err();

    mock.assert_async().await;
}

#[tokio::test]
async fn static_resource() {
    install_test_trace_subscriber();
    tokio::time::pause();

    // When a static resource is provided, the refresher shouldn't make any network requests
    let time = Time::from_seconds_since_epoch(0);

    let mut resource = CachedResource::<Time>::Static(time);
    assert_eq!(resource.resource().await.unwrap(), &time);
}

#[rstest::rstest]
#[case::no_cache(&["no-cache"], None)]
#[case::max_age(&["max-age=1000"], Some(1000))]
#[case::max_age_and_no_cache(&["max-age=1000", "no-cache"], None)]
#[case::no_directive(&[], None)]
#[case::unknown_directive(&["unknown"], None)]
#[case::malformed_max_age(&["max-age=notanumber"], None)]
#[case::multiple_max_age(&["max-age=1000", "max-age=999"], None)]
// max_age = u64::MAX - 1000 + 1. Should overflow when added to the mock clock.
#[case::max_age_overflow(&["max-age=18446744073709550616"], None)]
#[tokio::test]
async fn cache_control_expiry(#[case] headers: &[&str], #[case] output: Option<u64>) {
    tokio::time::pause();

    let now = Instant::now();

    let header_values: Vec<_> = headers
        .iter()
        .map(|h| HeaderValue::from_str(h).unwrap())
        .collect();

    assert_eq!(
        expires_at(&header_values),
        output.map(|increment| now.checked_add(Duration::from_secs(increment)).unwrap())
    );
}
