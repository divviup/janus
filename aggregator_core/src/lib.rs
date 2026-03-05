//! This crate contains core functionality for Janus aggregator crates.

// Workaround lint suppression but in older clippy by allowing this lint at module-level.
// https://github.com/rust-lang/rust-clippy/issues/8768
// https://github.com/rust-lang/rust-clippy/pull/9879
#![allow(clippy::single_component_path_imports)]

use std::{hash::Hash, sync::Arc, time::Instant};

use axum::{body::Body, extract::MatchedPath, middleware::Next, response::Response};
use educe::Educe;
use http::Request;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram, Meter},
};
use prio::{
    codec::{Encode, ParameterizedDecode},
    dp::DifferentialPrivacyStrategy,
    vdaf::{Aggregator, AggregatorWithNoise},
};
use tracing::{Instrument, Span, debug, info_span};
use trillium::{Conn, Handler, Status};
use trillium_macros::Handler;
use trillium_router::RouterConnExt;

pub mod batch_mode;
pub mod datastore;
pub mod task;
pub mod taskprov;

/// A secret byte array. Its implementation of [`std::fmt::Debug`] does not log the contents to
/// avoid accidental inclusion in logs.
#[derive(Clone, Educe, PartialEq, Eq)]
#[educe(Debug)]
pub struct SecretBytes(#[educe(Debug(ignore))] Vec<u8>);

impl SecretBytes {
    pub fn new(buf: Vec<u8>) -> Self {
        Self(buf)
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A trait extending [`prio::vdaf::Aggregator`] with bounds on its associated types that make it
/// usable in Janus, saving us lots of trait bound boilerplate in many places.
pub trait AsyncAggregator<const VERIFY_KEY_SIZE: usize>:
    Aggregator<
        VERIFY_KEY_SIZE,
        16,
        AggregationParam: Send + Sync + PartialEq + Eq + Hash + Ord,
        AggregateShare: Send + Sync + PartialEq,
        InputShare: Send + Sync + PartialEq,
        PrepareMessage: Send + Sync + PartialEq,
        PrepareShare: Send + Sync + PartialEq,
        PublicShare: Send + Sync + PartialEq,
        OutputShare: Send + Sync + PartialEq + Eq,
        PrepareState: Send
                          + Sync
                          + Encode
                          + PartialEq
                          + for<'a> ParameterizedDecode<(&'a Self, usize)>,
    >
    + 'static
    + Send
    + Sync
{
}

/// Blanket implementation for conforming VDAFs.
impl<
    const VERIFY_KEY_SIZE: usize,
    A: Aggregator<
            VERIFY_KEY_SIZE,
            16,
            AggregationParam: Send + Sync + PartialEq + Eq + Hash + Ord,
            AggregateShare: Send + Sync + PartialEq,
            InputShare: Send + Sync + PartialEq,
            PrepareMessage: Send + Sync + PartialEq,
            PrepareShare: Send + Sync + PartialEq,
            PublicShare: Send + Sync + PartialEq,
            OutputShare: Send + Sync + PartialEq + Eq,
            PrepareState: Send
                              + Sync
                              + Encode
                              + PartialEq
                              + for<'a> ParameterizedDecode<(&'a Self, usize)>,
        >
        + 'static
        + Send
        + Sync,
> AsyncAggregator<VERIFY_KEY_SIZE> for A
{
}

pub trait AsyncAggregatorWithNoise<const VERIFY_KEY_SIZE: usize, S: DifferentialPrivacyStrategy>:
    AsyncAggregator<VERIFY_KEY_SIZE> + AggregatorWithNoise<VERIFY_KEY_SIZE, 16, S>
{
}

impl<
    const VERIFY_KEY_SIZE: usize,
    S: DifferentialPrivacyStrategy,
    A: AsyncAggregator<VERIFY_KEY_SIZE> + AggregatorWithNoise<VERIFY_KEY_SIZE, 16, S>,
> AsyncAggregatorWithNoise<VERIFY_KEY_SIZE, S> for A
{
}

/// A marker trait for VDAFs that have an aggregation parameter other than the unit type.
pub trait VdafHasAggregationParameter {}

#[cfg(feature = "test-util")]
impl VdafHasAggregationParameter for prio::vdaf::dummy::Vdaf {}

pub fn instrumented<H: Handler>(handler: H) -> impl Handler {
    InstrumentedHandler(handler)
}

struct InstrumentedHandlerSpan(Span);

#[derive(Handler)]
struct InstrumentedHandler<H>(#[handler(except = [run, before_send])] H);

impl<H: Handler> InstrumentedHandler<H> {
    async fn run(&self, mut conn: Conn) -> Conn {
        let route = conn.route().expect("no route in conn").to_string();
        let method = conn.method();
        let span = info_span!("endpoint", route, %method);
        conn.insert_state(InstrumentedHandlerSpan(span.clone()));
        self.0.run(conn).instrument(span).await
    }

    async fn before_send(&self, mut conn: Conn) -> Conn {
        if let Some(span) = conn.take_state::<InstrumentedHandlerSpan>() {
            let conn = self.0.before_send(conn).instrument(span.0.clone()).await;
            span.0.in_scope(|| {
                let status = conn
                    .status()
                    .as_ref()
                    .map_or("unknown", Status::canonical_reason);
                debug!(status, "Finished handling request");
            });
            conn
        } else {
            self.0.before_send(conn).await
        }
    }
}

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
                    "Count of requests handled, by method, route, and response status.",
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

/// Axum middleware that records HTTP server metrics (response counter, request duration,
/// body sizes).
pub async fn http_metrics_middleware(
    axum::Extension(metrics): axum::Extension<Arc<HttpMetrics>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().trim_start_matches('/').to_string())
        .unwrap_or_else(|| "unknown".to_string());
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

/// Axum middleware that instruments request handlers with tracing spans.
pub async fn axum_instrumented(request: Request<Body>, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let method = request.method().clone();
    let span = info_span!("endpoint", route, %method);
    let response = next.run(request).instrument(span.clone()).await;
    span.in_scope(|| {
        let status = response.status().canonical_reason().unwrap_or("unknown");
        debug!(status, "Finished handling request");
    });
    response
}

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

#[cfg(feature = "test-util")]
pub mod test_util {
    use std::sync::Arc;

    use opentelemetry::{
        InstrumentationScope,
        metrics::{InstrumentProvider, Meter, MeterProvider},
    };

    pub fn noop_meter() -> Meter {
        NoopMeterProvider::new().meter("janus_aggregator")
    }

    // TODO(https://github.com/open-telemetry/opentelemetry-rust/issues/2444): Version 0.27 of
    // `opentelemetry` removed `NoopMeterProvider` from the public API. The implementation is copied
    // below until it is added back to a future version.

    #[derive(Debug, Default)]
    pub struct NoopMeterProvider {
        _private: (),
    }

    impl NoopMeterProvider {
        /// Create a new no-op meter provider.
        pub fn new() -> Self {
            Self { _private: () }
        }
    }

    impl MeterProvider for NoopMeterProvider {
        fn meter_with_scope(&self, _scope: InstrumentationScope) -> Meter {
            Meter::new(Arc::new(NoopMeter::new()))
        }
    }

    #[derive(Debug, Default)]
    pub struct NoopMeter {
        _private: (),
    }

    impl NoopMeter {
        /// Create a new no-op meter core.
        pub fn new() -> Self {
            Self { _private: () }
        }
    }

    impl InstrumentProvider for NoopMeter {}
}
