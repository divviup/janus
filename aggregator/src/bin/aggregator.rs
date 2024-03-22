use clap::Parser;
use janus_aggregator::{
    binaries::aggregator::{main_callback, Options},
    binary_utils::janus_main,
};
use janus_core::time::RealClock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main(Options::parse(), RealClock::default(), main_callback).await
}
