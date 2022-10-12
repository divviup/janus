use anyhow::Context;
use clap::Parser;
use janus_aggregator::{
    aggregator::aggregation_job_driver::AggregationJobDriver,
    binary_utils::{
        janus_main, job_driver::JobDriver, setup_signal_handler, BinaryOptions, CommonBinaryOptions,
    },
    config::{BinaryConfig, CommonConfig, JobDriverConfig},
};
use janus_core::{time::RealClock, TokioRuntime};
use janus_messages::Duration;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, sync::Arc};
use tokio::select;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    const CLIENT_USER_AGENT: &str = concat!(
        env!("CARGO_PKG_NAME"),
        "/",
        env!("CARGO_PKG_VERSION"),
        "/aggregation_job_driver",
    );

    janus_main::<_, Options, Config, _, _>(RealClock::default(), |ctx| async move {
        let meter = opentelemetry::global::meter("aggregation_job_driver");
        let datastore = Arc::new(ctx.datastore);
        let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
            reqwest::Client::builder()
                .user_agent(CLIENT_USER_AGENT)
                .build()
                .context("couldn't create HTTP client")?,
            &meter,
        ));
        let lease_duration =
            Duration::from_seconds(ctx.config.job_driver_config.worker_lease_duration_secs);
        let shutdown_signal =
            setup_signal_handler().context("failed to register SIGTERM signal handler")?;

        // Start running.
        let job_driver = Arc::new(JobDriver::new(
            ctx.clock,
            TokioRuntime,
            meter,
            Duration::from_seconds(ctx.config.job_driver_config.min_job_discovery_delay_secs),
            Duration::from_seconds(ctx.config.job_driver_config.max_job_discovery_delay_secs),
            ctx.config.job_driver_config.max_concurrent_job_workers,
            Duration::from_seconds(
                ctx.config
                    .job_driver_config
                    .worker_lease_clock_skew_allowance_secs,
            ),
            aggregation_job_driver
                .make_incomplete_job_acquirer_callback(Arc::clone(&datastore), lease_duration),
            aggregation_job_driver.make_job_stepper_callback(
                Arc::clone(&datastore),
                ctx.config.job_driver_config.maximum_attempts_before_failure,
            ),
        ));
        select! {
            _ = job_driver.run() => {}
            _ = shutdown_signal => {}
        };

        Ok(())
    })
    .await
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus-aggregation-job-driver",
    about = "Janus aggregation job driver",
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

/// Non-secret configuration options for Janus Aggregation Job Driver jobs.
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
/// min_job_discovery_delay_secs: 10
/// max_job_discovery_delay_secs: 60
/// max_concurrent_job_workers: 10
/// worker_lease_duration_secs: 600
/// worker_lease_clock_skew_allowance_secs: 60
/// maximum_attempts_before_failure: 5
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,
    #[serde(flatten)]
    job_driver_config: JobDriverConfig,
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
    use clap::CommandFactory;
    use janus_aggregator::config::{
        test_util::{
            generate_db_config, generate_metrics_config, generate_trace_config, roundtrip_encoding,
        },
        CommonConfig, JobDriverConfig,
    };
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
            },
            job_driver_config: JobDriverConfig {
                min_job_discovery_delay_secs: 10,
                max_job_discovery_delay_secs: 60,
                max_concurrent_job_workers: 10,
                worker_lease_duration_secs: 600,
                worker_lease_clock_skew_allowance_secs: 60,
                maximum_attempts_before_failure: 5,
            },
        })
    }
}
