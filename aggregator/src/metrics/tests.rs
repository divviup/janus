use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use http::StatusCode;
use janus_aggregator_core::datastore::test_util::ephemeral_datastore;
use janus_core::{
    retries::{retry_http_request, test_http_request_exponential_backoff},
    test_util::{install_test_trace_subscriber, runtime::TestRuntime},
    time::MockClock,
};
use opentelemetry::metrics::MeterProvider as _;
use prometheus::{
    proto::{Metric, MetricType},
    Registry,
};
use trillium_testing::prelude::get;

use crate::{
    aggregator::{http_handlers::aggregator_handler, test_util::default_aggregator_config},
    metrics::{build_opentelemetry_prometheus_meter_provider, prometheus_metrics_server},
};

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

fn labels_to_map(metric: &Metric) -> HashMap<String, String> {
    metric
        .get_label()
        .iter()
        .map(|label_pair| {
            (
                label_pair.get_name().to_owned(),
                label_pair.get_value().to_owned(),
            )
        })
        .collect::<HashMap<_, _>>()
}

#[tokio::test]
async fn http_metrics() {
    // Perform reference tests against the Prometheus metrics generated by the aggregator's HTTP
    // server. This will help identify changes, either in Janus or its dependencies, that will
    // impact downstream dashboards and alerts.

    install_test_trace_subscriber();

    let registry = Registry::new();
    let meter_provider = build_opentelemetry_prometheus_meter_provider(registry.clone()).unwrap();
    let meter = meter_provider.meter("tests");

    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
    let handler = aggregator_handler(
        datastore.clone(),
        clock.clone(),
        TestRuntime::default(),
        &meter,
        default_aggregator_config(),
    )
    .await
    .unwrap();

    get("/hpke_config").run_async(&handler).await;

    let metric_families = registry
        .gather()
        .into_iter()
        .map(|mf| (mf.get_name().to_owned(), mf))
        .collect::<HashMap<_, _>>();

    // Info metric, with a singleton time series, generated by opentelemetry-prometheus. Its labels
    // are derived from resource attributes.
    assert_eq!(
        metric_families["target_info"].get_field_type(),
        MetricType::GAUGE
    );
    assert!(metric_families["target_info"].has_help());
    assert_eq!(metric_families["target_info"].get_metric().len(), 1);
    let target_info_metric_labels = labels_to_map(&metric_families["target_info"].get_metric()[0]);
    assert!(target_info_metric_labels.contains_key("service_name"));
    assert!(target_info_metric_labels.contains_key("service_version"));
    assert!(target_info_metric_labels.contains_key("process_runtime_name"));
    assert!(target_info_metric_labels.contains_key("process_runtime_version"));

    // Info metric, with one time series per instrumentation scope (i.e. unique instance of
    // `Meter`), generated by opentelemetry-prometheus. It has a name label, and an optional version
    // label.
    assert_eq!(
        metric_families["otel_scope_info"].get_field_type(),
        MetricType::GAUGE
    );
    assert!(metric_families["otel_scope_info"].has_help());
    assert_eq!(metric_families["otel_scope_info"].get_metric().len(), 1);
    let otel_scope_info_metric_labels =
        labels_to_map(&metric_families["otel_scope_info"].get_metric()[0]);
    assert_eq!(otel_scope_info_metric_labels["otel_scope_name"], "tests");

    // Custom sum metric for HTTP responses.
    assert_eq!(
        metric_families["janus_aggregator_responses_total"].get_field_type(),
        MetricType::COUNTER
    );
    assert!(metric_families["janus_aggregator_responses_total"].has_help());
    assert_eq!(
        metric_families["janus_aggregator_responses_total"]
            .get_metric()
            .len(),
        1
    );
    let janus_aggregator_responses_total_metric_labels =
        labels_to_map(&metric_families["janus_aggregator_responses_total"].get_metric()[0]);
    assert_eq!(
        janus_aggregator_responses_total_metric_labels["method"],
        "GET"
    );
    assert_eq!(
        janus_aggregator_responses_total_metric_labels["route"],
        "/hpke_config"
    );
    assert_eq!(
        janus_aggregator_responses_total_metric_labels["error_code"],
        "missing_task_id"
    );
    assert_eq!(
        janus_aggregator_responses_total_metric_labels["otel_scope_name"],
        "tests"
    );

    // http.server.request.duration from OpenTelemetry Semantic Conventions.
    assert_eq!(
        metric_families["http_server_request_duration_seconds"].get_field_type(),
        MetricType::HISTOGRAM
    );
    assert!(metric_families["http_server_request_duration_seconds"].has_help());
    assert_eq!(
        metric_families["http_server_request_duration_seconds"]
            .get_metric()
            .len(),
        1
    );
    let http_server_request_duration_seconds_metric_labels =
        labels_to_map(&metric_families["http_server_request_duration_seconds"].get_metric()[0]);
    assert_eq!(
        http_server_request_duration_seconds_metric_labels["error_type"],
        "missing_task_id"
    );
    assert_eq!(
        http_server_request_duration_seconds_metric_labels["http_route"],
        "/hpke_config"
    );
    assert_eq!(
        http_server_request_duration_seconds_metric_labels["http_request_method"],
        "GET"
    );
    assert_eq!(
        http_server_request_duration_seconds_metric_labels["http_response_status_code"],
        "400"
    );

    // http.server.request.body_size from OpenTelemetry Semantic Conventions.
    assert_eq!(
        metric_families["http_server_request_body_size_bytes"].get_field_type(),
        MetricType::HISTOGRAM
    );
    assert!(metric_families["http_server_request_body_size_bytes"].has_help());

    // http.server.response.body_size from OpenTelemetry Semantic Conventions.
    assert_eq!(
        metric_families["http_server_response_body_size_bytes"].get_field_type(),
        MetricType::HISTOGRAM
    );
    assert!(metric_families["http_server_response_body_size_bytes"].has_help());
}