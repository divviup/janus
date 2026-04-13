use std::{sync::Arc, time::Instant};

use axum::{body::Body, extract::MatchedPath, middleware::Next, response::Response};
use http::Request;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram, Meter},
};
use tower_http::trace::TraceLayer;
use tracing::{Span, debug, info_span};
/// These boundaries are intended to be able to capture the length of short-lived operations
/// (e.g. HTTP requests) as well as longer-running operations.
pub const TIME_HISTOGRAM_BOUNDARIES: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 90.0, 300.0,
];

/// These boundaries are intended to be used with measurements having the unit of "bytes".
pub const BYTES_HISTOGRAM_BOUNDARIES: &[f64] = &[
    1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0, 131072.0, 262144.0, 524288.0,
    1048576.0, 2097152.0, 4194304.0, 8388608.0, 16777216.0, 33554432.0,
];

/// Newtype holding a textual error code, stored in response extensions for metrics.
#[derive(Clone, Copy)]
pub struct ErrorCode(pub &'static str);

/// HTTP server metrics, layered as an `Extension` on all axum routes.
#[derive(Clone)]
pub struct HttpMetrics {
    response_counter: Counter<u64>,
    request_duration: Histogram<f64>,
    request_body_size: Histogram<f64>,
    response_body_size: Histogram<f64>,
}

impl HttpMetrics {
    pub fn new(meter: &Meter, counter_name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            response_counter: meter
                .u64_counter(counter_name)
                .with_description(
                    "Count of requests handled by the aggregator, by method, route, and response status.",
                )
                .with_unit("{request}")
                .build(),
            request_duration: meter
                .f64_histogram("http.server.request.duration")
                .with_description("Duration of HTTP server requests.")
                .with_unit("s")
                .with_boundaries(TIME_HISTOGRAM_BOUNDARIES.to_vec())
                .build(),
            request_body_size: meter
                .f64_histogram("http.server.request.body_size")
                .with_description("Size of HTTP server request bodies.")
                .with_unit("By")
                .with_boundaries(BYTES_HISTOGRAM_BOUNDARIES.to_vec())
                .build(),
            response_body_size: meter
                .f64_histogram("http.server.response.body_size")
                .with_description("Size of HTTP server response bodies.")
                .with_unit("By")
                .with_boundaries(BYTES_HISTOGRAM_BOUNDARIES.to_vec())
                .build(),
        })
    }
}

/// Extracts the matched route from an axum request and rewrites `{param}` to `:param`
/// for metric label continuity.
fn normalize_axum_route(request: &Request<Body>) -> String {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| {
            p.as_str()
                .trim_start_matches('/')
                .replace('{', ":")
                .replace('}', "")
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Axum middleware that records HTTP server metrics (response counter, request duration,
/// body sizes).
// TODO: Replace with `opentelemetry-instrumentation-tower` once OpenTelemetry is upgraded
// to 0.31 or later.
pub async fn http_metrics_middleware(
    axum::Extension(metrics): axum::Extension<Arc<HttpMetrics>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let route = normalize_axum_route(&request);
    let request_body_size = request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);

    let start = Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed().as_secs_f64();
    let status_code = response.status().as_u16().to_string();

    let error_code = response
        .extensions()
        .get::<ErrorCode>()
        .map(|ec| ec.0)
        .unwrap_or_else(|| {
            if response.status().is_client_error() || response.status().is_server_error() {
                "unknown"
            } else {
                ""
            }
        });

    let response_body_size = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);

    metrics.response_counter.add(
        1,
        &[
            KeyValue::new("method", method.clone()),
            KeyValue::new("route", route.clone()),
            KeyValue::new("error_code", error_code),
        ],
    );

    let mut duration_attrs = vec![
        KeyValue::new("http.route", route.clone()),
        KeyValue::new("http.request.method", method),
        KeyValue::new("http.response.status_code", status_code),
    ];
    if !error_code.is_empty() {
        duration_attrs.push(KeyValue::new("error.type", error_code));
    }
    metrics.request_duration.record(duration, &duration_attrs);

    metrics.request_body_size.record(
        request_body_size,
        &[KeyValue::new("http.route", route.clone())],
    );

    metrics
        .response_body_size
        .record(response_body_size, &[KeyValue::new("http.route", route)]);

    response
}

/// Returns a [`TraceLayer`] that instruments axum request handlers with tracing spans.
#[allow(clippy::type_complexity)]
pub fn trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    impl Fn(&Request<Body>) -> Span + Clone,
    (),
    impl Fn(&Response<Body>, std::time::Duration, &Span) + Clone,
> {
    TraceLayer::new_for_http()
        .make_span_with(|request: &Request<Body>| {
            let route = normalize_axum_route(request);
            let method = request.method();
            info_span!("endpoint", route, %method)
        })
        .on_request(())
        .on_response(
            |response: &Response<Body>, _latency: std::time::Duration, _span: &Span| {
                let status = response.status().canonical_reason().unwrap_or("unknown");
                debug!(status, "Finished handling request");
            },
        )
}
