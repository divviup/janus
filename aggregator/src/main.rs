use clap::{Parser, Subcommand};
use janus_aggregator::{
    binaries::{
        aggregation_job_creator, aggregation_job_driver, aggregator, collection_job_driver,
        garbage_collector, janus_cli, key_rotator,
    },
    binary_utils::janus_main,
};
use janus_core::time::RealClock;

#[derive(Debug, Parser)]
#[clap(multicall = true)]
enum Options {
    #[clap(name = "aggregator")]
    Aggregator(aggregator::Options),
    #[clap(name = "garbage_collector")]
    GarbageCollector(garbage_collector::Options),
    #[clap(name = "aggregation_job_creator")]
    AggregationJobCreator(aggregation_job_creator::Options),
    #[clap(name = "aggregation_job_driver")]
    AggregationJobDriver(aggregation_job_driver::Options),
    #[clap(name = "collection_job_driver")]
    CollectionJobDriver(collection_job_driver::Options),
    #[clap(name = "janus_cli")]
    JanusCli(janus_cli::CommandLineOptions),
    #[clap(name = "key_rotator")]
    KeyRotator(key_rotator::Options),
    #[clap(name = "janus_aggregator", subcommand)]
    Default(Nested),
}

#[derive(Debug, Subcommand)]
#[clap(
    about = "Janus aggregator",
    version = env!("CARGO_PKG_VERSION"),
)]
#[allow(clippy::large_enum_variant)]
enum Nested {
    #[clap(name = "aggregator")]
    Aggregator(aggregator::Options),
    #[clap(name = "garbage_collector")]
    GarbageCollector(garbage_collector::Options),
    #[clap(name = "aggregation_job_creator")]
    AggregationJobCreator(aggregation_job_creator::Options),
    #[clap(name = "aggregation_job_driver")]
    AggregationJobDriver(aggregation_job_driver::Options),
    #[clap(name = "collection_job_driver")]
    CollectionJobDriver(collection_job_driver::Options),
    #[clap(name = "janus_cli")]
    JanusCli(janus_cli::CommandLineOptions),
    #[clap(name = "key_rotator")]
    KeyRotator(key_rotator::Options),
}

fn main() -> anyhow::Result<()> {
    let clock = RealClock::default();
    match Options::parse() {
        Options::Aggregator(options) | Options::Default(Nested::Aggregator(options)) => janus_main(
            "aggregator",
            options,
            clock,
            true,
            aggregator::main_callback,
        ),
        Options::GarbageCollector(options)
        | Options::Default(Nested::GarbageCollector(options)) => janus_main(
            "garbage_collector",
            options,
            clock,
            false,
            garbage_collector::main_callback,
        ),
        Options::AggregationJobCreator(options)
        | Options::Default(Nested::AggregationJobCreator(options)) => janus_main(
            "aggregation_job_creator",
            options,
            clock,
            false,
            aggregation_job_creator::main_callback,
        ),
        Options::AggregationJobDriver(options)
        | Options::Default(Nested::AggregationJobDriver(options)) => janus_main(
            "aggregation_job_driver",
            options,
            clock,
            true,
            aggregation_job_driver::main_callback,
        ),
        Options::CollectionJobDriver(options)
        | Options::Default(Nested::CollectionJobDriver(options)) => janus_main(
            "collection_job_driver",
            options,
            clock,
            false,
            collection_job_driver::main_callback,
        ),
        Options::JanusCli(options) | Options::Default(Nested::JanusCli(options)) => {
            janus_cli::run(options)
        }
        Options::KeyRotator(options) | Options::Default(Nested::KeyRotator(options)) => janus_main(
            "key_rotator",
            options,
            clock,
            false,
            key_rotator::main_callback,
        ),
    }
}
