use crate::{
    http::cached_resource::{CachedResource, expires_at},
    initialize_rustls,
    retries::test_util::test_http_request_exponential_backoff,
    test_util::install_test_trace_subscriber,
};
use http::{
    HeaderValue,
    header::{CACHE_CONTROL, CONTENT_TYPE},
};
use janus_messages::MediaType;
use prio::codec::{Decode, Encode};
use std::time::Duration;
use tokio::time::Instant;
use url::Url;

#[derive(Debug, Eq)]
struct TestResource {}

impl Encode for TestResource {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), prio::codec::CodecError> {
        ().encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        ().encoded_len()
    }
}

impl Decode for TestResource {
    fn decode(_: &mut std::io::Cursor<&[u8]>) -> Result<Self, prio::codec::CodecError> {
        Ok(TestResource {})
    }
}

impl PartialEq for TestResource {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl MediaType for TestResource {
    const MEDIA_TYPE: &'static str = "application/test-resource";
}

#[tokio::test]
async fn no_cache_control() {
    install_test_trace_subscriber();
    initialize_rustls();

    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();

    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_body(TestResource {}.get_encoded().unwrap())
        .with_header(CONTENT_TYPE.as_str(), TestResource::MEDIA_TYPE)
        .expect(1)
        .create_async()
        .await;

    // new() will fetch the resource from server. Because no cache-control is provided, resource()
    // should refetch.
    let mut resource = CachedResource::<TestResource>::new(
        server_url.join("resource").unwrap(),
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap();
    assert_eq!(
        resource.resource(&http_client).await.unwrap(),
        &TestResource {}
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn with_no_cache_directive() {
    install_test_trace_subscriber();
    initialize_rustls();

    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();

    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_header(CACHE_CONTROL.as_str(), "no-cache")
        .with_header(CONTENT_TYPE.as_str(), TestResource::MEDIA_TYPE)
        .with_body(TestResource {}.get_encoded().unwrap())
        .expect(2)
        .create_async()
        .await;

    // new() will fetch the resource from the server. Because there is a no-cache directive,
    // resource() should refetch, but only after time advances at all.
    let mut resource = CachedResource::<TestResource>::new(
        server_url.join("resource").unwrap(),
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap();
    assert_eq!(
        resource.resource(&http_client).await.unwrap(),
        &TestResource {}
    );

    // Should not have two matches yet.
    assert!(!mock.matched());

    // Advance time by the smallest increment to invalidate cached resource.
    tokio::time::advance(Duration::from_nanos(1)).await;
    assert_eq!(
        resource.resource(&http_client).await.unwrap(),
        &TestResource {}
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn with_max_age_directive() {
    install_test_trace_subscriber();
    initialize_rustls();

    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();

    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_header(CACHE_CONTROL.as_str(), "max-age=86400")
        .with_header(CONTENT_TYPE.as_str(), TestResource::MEDIA_TYPE)
        .with_body(TestResource {}.get_encoded().unwrap())
        .expect(2)
        .create_async()
        .await;

    // new() will fetch the resource from the server. Because the cache is not expired, resource()
    // should not refetch.
    let mut resource = CachedResource::<TestResource>::new(
        server_url.join("resource").unwrap(),
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap();
    assert_eq!(
        resource.resource(&http_client).await.unwrap(),
        &TestResource {}
    );

    // Should not have two matches yet
    assert!(!mock.matched());

    // Advance time far enough to invalidate cache. resource() should refetch.
    tokio::time::advance(Duration::from_secs(86401)).await;

    assert_eq!(
        resource.resource(&http_client).await.unwrap(),
        &TestResource {}
    );

    // Now we should have matched twice
    mock.assert_async().await;
}

#[tokio::test]
async fn malformed_cache_control() {
    install_test_trace_subscriber();
    initialize_rustls();

    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();

    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_header(CACHE_CONTROL.as_str(), "malformed")
        .with_header(CONTENT_TYPE.as_str(), TestResource::MEDIA_TYPE)
        .with_body(TestResource {}.get_encoded().unwrap())
        .expect(1)
        .create_async()
        .await;

    // The cache control header should be ignored because it's malformed, meaning the resource will
    // be fetched only once.
    let mut resource = CachedResource::<TestResource>::new(
        server_url.join("resource").unwrap(),
        &http_client,
        test_http_request_exponential_backoff(),
    )
    .await
    .unwrap();
    assert_eq!(
        resource.resource(&http_client).await.unwrap(),
        &TestResource {}
    );

    mock.assert_async().await;
}

#[tokio::test]
async fn wrong_content_type() {
    install_test_trace_subscriber();
    initialize_rustls();

    tokio::time::pause();

    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = reqwest::Client::builder().build().unwrap();

    let mock = server
        .mock("GET", "/resource")
        .with_status(200)
        .with_header(CACHE_CONTROL.as_str(), "malformed")
        .with_header(CONTENT_TYPE.as_str(), "wrong-media-type")
        .with_body(TestResource {}.get_encoded().unwrap())
        .expect(1)
        .create_async()
        .await;

    CachedResource::<TestResource>::new(
        server_url.join("resource").unwrap(),
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
    let mut resource = CachedResource::Static(TestResource {});
    assert_eq!(
        resource
            .resource(&reqwest::Client::builder().build().unwrap())
            .await
            .unwrap(),
        &TestResource {}
    );
}

#[rstest::rstest]
#[case::no_cache(&["no-cache"], Some(0))]
#[case::max_age(&["max-age=1000"], Some(1000))]
#[case::max_age_and_no_cache(&["max-age=1000", "no-cache"], Some(0))]
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
