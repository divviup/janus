use anyhow::Context;
use clap::Parser;
use janus_core::time::RealClock;
use janus_server::aggregator::aggregation_job_creator::AggregationJobCreator;
use janus_server::binary_utils::{
    janus_main, setup_signal_handler, BinaryOptions, CommonBinaryOptions,
};
use janus_server::config::{BinaryConfig, CommonConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::select;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main::<_, Options, Config, _, _>(RealClock::default(), |ctx| async move {
        let shutdown_signal =
            setup_signal_handler().context("failed to register SIGTERM signal handler")?;

        // Start creating aggregation jobs.
        let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
            ctx.datastore,
            ctx.clock,
            Duration::from_secs(ctx.config.tasks_update_frequency_secs),
            Duration::from_secs(ctx.config.aggregation_job_creation_interval_secs),
            ctx.config.min_aggregation_job_size,
            ctx.config.max_aggregation_job_size,
        ));
        select! {
            _ = aggregation_job_creator.run() => {}
            _ = shutdown_signal => {}
        };

        Ok(())
    })
    .await
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus-aggregation-job-creator",
    about = "Janus aggregation job creator",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    #[clap(flatten)]
    common: CommonBinaryOptions,
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
/// let yaml_config = r#"
/// ---
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// tasks_update_frequency_secs: 3600
/// aggregation_job_creation_interval_secs: 60
/// min_aggregation_job_size: 100
/// max_aggregation_job_size: 500
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,

    /// How frequently we look for new tasks to start creating aggregation jobs for, in seconds.
    tasks_update_frequency_secs: u64,
    /// How frequently we attempt to create new aggregation jobs for each task, in seconds.
    aggregation_job_creation_interval_secs: u64,
    /// The minimum number of client reports to include in an aggregation job. Applies to the
    /// "current" batch unit only; historical batch units will create aggregation jobs of any size,
    /// on the theory that almost all reports will have be received for these batch units already.
    min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    max_aggregation_job_size: usize,
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
    use clap::IntoApp;
    use janus_server::config::{
        test_util::{
            generate_db_config, generate_metrics_config, generate_trace_config, roundtrip_encoding,
        },
        CommonConfig,
    };
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn verify_app() {
        Options::into_app().debug_assert()
    }

    #[test]
    fn roundtrip_config() {
        roundtrip_encoding(Config {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: generate_trace_config(),
                metrics_config: generate_metrics_config(),
                health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
            },
            tasks_update_frequency_secs: 3600,
            aggregation_job_creation_interval_secs: 60,
            min_aggregation_job_size: 100,
            max_aggregation_job_size: 500,
        })
    }
}
