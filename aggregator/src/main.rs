use clap::{Parser, Subcommand};
use janus_aggregator::{
    binaries::{
        aggregation_job_creator, aggregation_job_driver, aggregator, collection_job_driver,
        janus_cli,
    },
    binary_utils::janus_main,
};
use janus_core::time::RealClock;

#[derive(Debug, Parser)]
#[clap(multicall = true)]
enum Options {
    #[clap(name = "aggregator")]
    Aggregator(aggregator::Options),
    #[clap(name = "aggregation_job_creator")]
    AggregationJobCreator(aggregation_job_creator::Options),
    #[clap(name = "aggregation_job_driver")]
    AggregationJobDriver(aggregation_job_driver::Options),
    #[clap(name = "collection_job_driver")]
    CollectionJobDriver(collection_job_driver::Options),
    #[clap(name = "janus_cli")]
    JanusCli(janus_cli::CommandLineOptions),
    #[clap(name = "janus_aggregator", subcommand)]
    Default(Nested),
}

#[derive(Debug, Subcommand)]
#[clap(
    about = "Janus aggregator",
    version = env!("CARGO_PKG_VERSION"),
)]
enum Nested {
    #[clap(name = "aggregator")]
    Aggregator(aggregator::Options),
    #[clap(name = "aggregation_job_creator")]
    AggregationJobCreator(aggregation_job_creator::Options),
    #[clap(name = "aggregation_job_driver")]
    AggregationJobDriver(aggregation_job_driver::Options),
    #[clap(name = "collection_job_driver")]
    CollectionJobDriver(collection_job_driver::Options),
    #[clap(name = "janus_cli")]
    JanusCli(janus_cli::CommandLineOptions),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Options::parse() {
        Options::Aggregator(options) | Options::Default(Nested::Aggregator(options)) => {
            janus_main(options, RealClock::default(), aggregator::main_callback).await
        }
        Options::AggregationJobCreator(options)
        | Options::Default(Nested::AggregationJobCreator(options)) => {
            janus_main(
                options,
                RealClock::default(),
                aggregation_job_creator::main_callback,
            )
            .await
        }
        Options::AggregationJobDriver(options)
        | Options::Default(Nested::AggregationJobDriver(options)) => {
            janus_main(
                options,
                RealClock::default(),
                aggregation_job_driver::main_callback,
            )
            .await
        }
        Options::CollectionJobDriver(options)
        | Options::Default(Nested::CollectionJobDriver(options)) => {
            janus_main(
                options,
                RealClock::default(),
                collection_job_driver::main_callback,
            )
            .await
        }
        Options::JanusCli(options) | Options::Default(Nested::JanusCli(options)) => {
            janus_cli::run(options).await
        }
    }
}
