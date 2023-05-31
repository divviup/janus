//! This crate contains core functionality for Janus aggregator crates.

// Workaround lint suppression but in older clippy by allowing this lint at module-level.
// https://github.com/rust-lang/rust-clippy/issues/8768
// https://github.com/rust-lang/rust-clippy/pull/9879
#![allow(clippy::single_component_path_imports)]

use tracing::{info, info_span, Instrument, Span};
use trillium::{Conn, Handler, Status};
use trillium_macros::Handler;
use trillium_router::RouterConnExt;

// We must import `rstest_reuse` at the top of the crate
// https://docs.rs/rstest_reuse/0.5.0/rstest_reuse/#use-rstest_reuse-at-the-top-of-your-crate
#[cfg(test)]
use rstest_reuse;

#[cfg(feature = "test-util")]
use janus_core::test_util::dummy_vdaf;

pub mod datastore;
pub mod query_type;
pub mod task;

/// A secret byte array. This does not implement `Debug` or `Display`, to avoid accidental
/// inclusion in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

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

impl<P, const SEED_SIZE: usize> VdafHasAggregationParameter
    for prio::vdaf::poplar1::Poplar1<P, SEED_SIZE>
{
}

#[cfg(feature = "test-util")]
impl VdafHasAggregationParameter for dummy_vdaf::Vdaf {}

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
        conn.set_state(InstrumentedHandlerSpan(span.clone()));
        self.0.run(conn).instrument(span).await
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        if let Some(span) = conn.state::<InstrumentedHandlerSpan>() {
            let _entered = span.0.enter();
            let status = conn
                .status()
                .as_ref()
                .map_or("unknown", Status::canonical_reason);
            info!(status, "Finished handling request");
        }
        conn
    }
}
