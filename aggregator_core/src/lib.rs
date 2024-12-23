//! This crate contains core functionality for Janus aggregator crates.

// Workaround lint suppression but in older clippy by allowing this lint at module-level.
// https://github.com/rust-lang/rust-clippy/issues/8768
// https://github.com/rust-lang/rust-clippy/pull/9879
#![allow(clippy::single_component_path_imports)]

use educe::Educe;
use tracing::{debug, info_span, Instrument, Span};
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

#[cfg(feature = "test-util")]
pub mod test_util {
    use opentelemetry::metrics::{noop::NoopMeterProvider, Meter, MeterProvider};

    pub fn noop_meter() -> Meter {
        NoopMeterProvider::new().meter("janus_aggregator")
    }
}
