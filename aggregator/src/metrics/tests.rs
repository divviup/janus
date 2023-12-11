use std::net::Ipv4Addr;

use http::StatusCode;
use janus_core::retries::{retry_http_request, test_http_request_exponential_backoff};
use opentelemetry::metrics::MeterProvider as _;
use prometheus::Registry;

use crate::metrics::{build_opentelemetry_prometheus_meter_provider, prometheus_metrics_server};

#[tokio::test]
async fn prometheus_metrics_pull() {
    let registry = Registry::new();
    let meter_provider = build_opentelemetry_prometheus_meter_provider(registry.clone()).unwrap();
    let (join_handle, port) = prometheus_metrics_server(registry, Ipv4Addr::LOCALHOST.into(), 0)
        .await
        .unwrap();

    let meter = meter_provider.meter("tests");
    meter
        .u64_observable_gauge("test_metric")
        .with_description("Gauge for test purposes")
        .init()
        .observe(1, &[]);

    let url = format!("http://127.0.0.1:{port}/metrics");
    let response = retry_http_request(test_http_request_exponential_backoff(), || {
        reqwest::get(&url)
    })
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "text/plain; version=0.0.4"
    );
    let text = response.text().await.unwrap();
    assert!(
        text.contains("HELP") && text.contains("TYPE"),
        "Exported metrics: {:?}",
        text
    );

    join_handle.abort();
}
