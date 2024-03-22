use clap::{Parser, Subcommand};
use janus_interop_binaries::commands::{
    janus_interop_aggregator, janus_interop_client, janus_interop_collector,
};

#[derive(Debug, Parser)]
#[clap(multicall = true)]
enum Options {
    #[clap(name = "janus_interop_client")]
    Client(janus_interop_client::Options),
    #[clap(name = "janus_interop_aggregator")]
    Aggregator(janus_interop_aggregator::Options),
    #[clap(name = "janus_interop_collector")]
    Collector(janus_interop_collector::Options),
    #[clap(name = "janus_interop", subcommand)]
    Default(Nested),
}

#[derive(Debug, Subcommand)]
#[clap(
    about = "Janus interoperation test binaries",
    version = env!("CARGO_PKG_VERSION"),
)]
enum Nested {
    #[clap(name = "janus_interop_client")]
    Client(janus_interop_client::Options),
    #[clap(name = "janus_interop_aggregator")]
    Aggregator(janus_interop_aggregator::Options),
    #[clap(name = "janus_interop_collector")]
    Collector(janus_interop_collector::Options),
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    match Options::parse() {
        Options::Client(options) | Options::Default(Nested::Client(options)) => options.run().await,
        Options::Aggregator(options) | Options::Default(Nested::Aggregator(options)) => {
            options.run().await
        }
        Options::Collector(options) | Options::Default(Nested::Collector(options)) => {
            options.run().await
        }
    }
}
