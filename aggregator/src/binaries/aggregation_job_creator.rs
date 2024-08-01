use crate::{
    aggregator::aggregation_job_creator::AggregationJobCreator,
    binary_utils::{BinaryContext, BinaryOptions, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
};
use anyhow::Result;
use clap::Parser;
use janus_core::time::RealClock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub async fn main_callback(ctx: BinaryContext<RealClock, Options, Config>) -> Result<()> {
    // Start creating aggregation jobs.
    let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
        Arc::new(ctx.datastore),
        ctx.meter,
        ctx.config.batch_aggregation_shard_count,
        Duration::from_secs(ctx.config.tasks_update_frequency_s),
        Duration::from_secs(ctx.config.aggregation_job_creation_interval_s),
        ctx.config.min_aggregation_job_size,
        ctx.config.max_aggregation_job_size,
        ctx.config.aggregation_job_creation_report_window,
    ));
    info!("Running aggregation job creator");
    aggregation_job_creator.run(ctx.stopper).await;

    Ok(())
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus-aggregation-job-creator",
    about = "Janus aggregation job creator",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
pub struct Options {
    #[clap(flatten)]
    pub common: CommonBinaryOptions,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        &self.common
    }
}

/// Non-secret configuration options for the Janus Aggregation Job Creator job.
///
/// # Examples
///
/// ```
/// # use janus_aggregator::binaries::aggregation_job_creator::Config;
/// let yaml_config = r#"
/// ---
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// batch_aggregation_shard_count: 32
/// tasks_update_frequency_s: 3600
/// aggregation_job_creation_interval_s: 60
/// min_aggregation_job_size: 100
/// max_aggregation_job_size: 500
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
// TODO(#3293): remove aliases during next breaking changes window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(flatten)]
    pub common_config: CommonConfig,

    /// Defines the number of shards to break each batch aggregation into. Increasing this value
    /// will reduce the amount of database contention during leader aggregation, while increasing
    /// the cost of collection.
    pub batch_aggregation_shard_count: u64,
    /// How frequently we look for new tasks to start creating aggregation jobs for, in seconds.
    #[serde(alias = "tasks_update_frequency_secs")]
    pub tasks_update_frequency_s: u64,
    /// How frequently we attempt to create new aggregation jobs for each task, in seconds.
    #[serde(alias = "aggregation_job_creation_interval_secs")]
    pub aggregation_job_creation_interval_s: u64,
    /// The minimum number of client reports to include in an aggregation job. Applies to the
    /// "current" batch only; historical batches will create aggregation jobs of any size, on the
    /// theory that almost all reports will have be received for these batches already.
    pub min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    pub max_aggregation_job_size: usize,
    /// Maximum number of reports to load at a time when creating aggregation jobs.
    #[serde(default = "default_aggregation_job_creation_report_window")]
    pub aggregation_job_creation_report_window: usize,
}

fn default_aggregation_job_creation_report_window() -> usize {
    5000
}

impl BinaryConfig for Config {
    fn common_config(&self) -> &CommonConfig {
        &self.common_config
    }

    fn common_config_mut(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Options};
    use crate::config::{
        default_max_transaction_retries,
        test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
        CommonConfig,
    };
    use clap::CommandFactory;
    use janus_core::test_util::roundtrip_encoding;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn verify_app() {
        Options::command().debug_assert()
    }

    #[test]
    fn roundtrip_config() {
        roundtrip_encoding(Config {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: generate_trace_config(),
                metrics_config: generate_metrics_config(),
                health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
                max_transaction_retries: default_max_transaction_retries(),
            },
            batch_aggregation_shard_count: 32,
            tasks_update_frequency_s: 3600,
            aggregation_job_creation_interval_s: 60,
            min_aggregation_job_size: 100,
            max_aggregation_job_size: 500,
            aggregation_job_creation_report_window: 5000,
        })
    }

    #[test]
    fn documentation_config_examples() {
        serde_yaml::from_str::<Config>(include_str!(
            "../../../docs/samples/basic_config/aggregation_job_creator.yaml"
        ))
        .unwrap();
        serde_yaml::from_str::<Config>(include_str!(
            "../../../docs/samples/advanced_config/aggregation_job_creator.yaml"
        ))
        .unwrap();
    }
}
