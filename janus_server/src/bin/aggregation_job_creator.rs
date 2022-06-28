use janus::time::RealClock;
use janus_server::aggregator::aggregation_job_creator::AggregationJobCreator;
use janus_server::binary_utils::{janus_main, BinaryOptions, CommonBinaryOptions};
use janus_server::config::AggregationJobCreatorConfig;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-aggregation-job-creator",
    about = "Janus aggregation job creator",
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main::<Options, _, _, _, _>(
        RealClock::default(),
        |clock, config: AggregationJobCreatorConfig, datastore| async move {
            // Start creating aggregation jobs.
            Arc::new(AggregationJobCreator::new(
                datastore,
                clock,
                Duration::from_secs(config.tasks_update_frequency_secs),
                Duration::from_secs(config.aggregation_job_creation_interval_secs),
                config.min_aggregation_job_size,
                config.max_aggregation_job_size,
            ))
            .run()
            .await;

            Ok(())
        },
    )
    .await
}
