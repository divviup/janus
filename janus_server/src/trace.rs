//! Configures a tracing subscriber for Janus.

use atty::{self, Stream};
use serde::{Deserialize, Serialize};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt::Layer, layer::SubscriberExt, EnvFilter, Registry};

/// Errors from initializing trace subscriber.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tracing error: {0}")]
    SetGlobalTracingSubscriber(#[from] tracing::subscriber::SetGlobalDefaultError),
    #[error("logging error: {0}")]
    SetGlobalLogger(#[from] tracing_log::log_tracer::SetLoggerError),
}

/// Configuration for the tracing subscriber.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceConfiguration {
    /// If true, uses a [`tracing_subscriber::fmt::TestWriter`] to capture trace
    /// events when running tests
    #[serde(default)]
    pub use_test_writer: bool,
    /// If true OR if stdout is not a tty, trace events are output in JSON
    /// format by [`tracing_subscriber::fmt::format::Json`]. Otherwise, trace
    /// events are output in pretty format by
    /// [`tracing_subscriber::fmt::format::Pretty`].
    #[serde(default)]
    pub force_json_output: bool,
}

/// Create a base tracing layer with configuration used in all subscribers
fn base_layer<S>() -> Layer<S> {
    tracing_subscriber::fmt::layer()
        .with_thread_ids(true)
        .with_level(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
}

/// Configures and installs a tracing subscriber, to capture events logged with
/// [`tracing::info`] and the like. Captured events are written to stdout, with
/// formatting affected by the provided [`TraceConfiguration`].
pub fn install_trace_subscriber(config: &TraceConfiguration) -> Result<(), Error> {
    // If stdout is not a tty or if forced by config, output logs as JSON
    // structures
    let output_json = atty::isnt(Stream::Stdout) || config.force_json_output;

    let (pretty_layer, json_layer, test_layer) = match (output_json, config.use_test_writer) {
        (true, false) => (None, Some(base_layer().json()), None),
        (false, false) => (Some(base_layer().pretty()), None, None),
        (_, true) => (None, None, Some(base_layer().pretty().with_test_writer())),
    };

    let subscriber = Registry::default()
        .with(pretty_layer)
        .with(test_layer)
        .with(json_layer)
        // Configure filters with RUST_LOG env var. Format discussed at
        // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/struct.EnvFilter.html
        .with(EnvFilter::from_default_env());

    tracing::subscriber::set_global_default(subscriber)?;

    // Install a logger that converts logs into tracing events
    LogTracer::init()?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use std::sync::Once;

    /// install_test_trace_subscriber installs a tracing subscriber suitable for
    /// tests. It should be called at the beginning of any test that requires a
    /// tracing subscriber.
    pub(crate) fn install_test_trace_subscriber() {
        static INSTALL_TRACE_SUBSCRIBER: Once = Once::new();
        INSTALL_TRACE_SUBSCRIBER.call_once(|| {
            install_trace_subscriber(&TraceConfiguration {
                use_test_writer: true,
                ..Default::default()
            })
            .unwrap()
        });
    }
}
