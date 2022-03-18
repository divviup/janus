use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tracing error: {0}")]
    HttpClient(#[from] tracing::subscriber::SetGlobalDefaultError),
}

/// Configures and installs a tracing subscriber
pub fn install_subscriber() -> Result<(), Error> {
    // Configure a tracing subscriber. The crate emits events using `info!`,
    // `err!`, etc. macros from crate `tracing`.
    let fmt_layer = fmt::layer()
        .with_thread_ids(true)
        // TODO(#16): take an argument for pretty vs. full vs. compact vs. JSON
        // output
        .pretty()
        .with_level(true)
        .with_target(true);

    let subscriber = Registry::default()
        .with(fmt_layer)
        // Configure filters with RUST_LOG env var. Format discussed at
        // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/struct.EnvFilter.html
        .with(EnvFilter::from_default_env());

    Ok(tracing::subscriber::set_global_default(subscriber)?)
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::sync::Once;

    static INSTALL_SUBSCRIBER_ONCE: Once = Once::new();

    pub(crate) fn install_trace_subscriber() {
        INSTALL_SUBSCRIBER_ONCE.call_once(|| super::install_subscriber().unwrap());
    }
}
