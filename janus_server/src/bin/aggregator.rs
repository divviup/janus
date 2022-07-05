use anyhow::{Context, Result};
use futures::StreamExt;
use janus::time::RealClock;
use janus_server::{
    aggregator::aggregator_server,
    binary_utils::{janus_main, BinaryOptions, CommonBinaryOptions},
    config::AggregatorConfig,
};
use std::{future::Future, iter::Iterator, sync::Arc};
use structopt::StructOpt;
use tracing::info;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-aggregator",
    about = "PPM aggregator server",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    #[structopt(flatten)]
    common: CommonBinaryOptions,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        &self.common
    }
}

/// Register a signal handler for SIGTERM, and return a future that will become ready when a
/// SIGTERM signal is received.
fn setup_signal_handler() -> Result<impl Future<Output = ()>, std::io::Error> {
    let mut signal_stream = signal_hook_tokio::Signals::new([signal_hook::consts::SIGTERM])?;
    let handle = signal_stream.handle();
    let (sender, receiver) = futures::channel::oneshot::channel();
    let mut sender = Some(sender);
    tokio::spawn(async move {
        while let Some(signal) = signal_stream.next().await {
            if signal == signal_hook::consts::SIGTERM {
                if let Some(sender) = sender.take() {
                    // This may return Err(()) if the receiver has been dropped already. If
                    // that is the case, the warp server must be shut down already, so we can
                    // safely ignore the error case.
                    let _ = sender.send(());
                    handle.close();
                    break;
                }
            }
        }
    });
    Ok(async move {
        // The receiver may return Err(Canceled) if the sender has been dropped. By inspection, the
        // sender always has a message sent across it before it is dropped, and the async task it
        // is owned by will not terminate before that happens.
        receiver.await.unwrap_or_default()
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    janus_main::<Options, _, AggregatorConfig, _, _>(RealClock::default(), |ctx| async move {
        let shutdown_signal =
            setup_signal_handler().context("failed to register SIGTERM signal handler")?;

        let (bound_address, server) = aggregator_server(
            Arc::new(ctx.datastore),
            ctx.clock,
            ctx.config.listen_address,
            shutdown_signal,
        )
        .context("failed to create aggregator server")?;
        info!(?bound_address, "running aggregator");

        server.await;
        Ok(())
    })
    .await
}
