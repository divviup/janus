use super::{
    install_metrics_exporter, MetricsConfiguration, MetricsExporterConfiguration,
    MetricsExporterHandle,
};
use http::StatusCode;
use janus_core::retries::{retry_http_request, test_http_request_exponential_backoff};

#[tokio::test]
async fn prometheus_metrics_pull() {
    let handle = install_metrics_exporter(&MetricsConfiguration {
        exporter: Some(MetricsExporterConfiguration::Prometheus {
            host: Some("127.0.0.1".to_owned()),
            port: Some(0),
        }),
    })
    .await
    .unwrap();
    let port = match handle {
        MetricsExporterHandle::Prometheus { port, .. } => port,
        _ => unreachable!(),
    };

    opentelemetry::global::meter("tests")
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

    match handle {
        MetricsExporterHandle::Prometheus { handle, .. } => handle.abort(),
        _ => unreachable!(),
    }
}
