use anyhow::Context;
use janus_core::{message::Duration, time::RealClock, TokioRuntime};
use janus_server::{
    aggregator::aggregate_share::CollectJobDriver,
    binary_utils::{janus_main, job_driver::JobDriver, BinaryOptions, CommonBinaryOptions},
    config::CollectJobDriverConfig,
};
use std::{fmt::Debug, sync::Arc};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-collect-job-driver",
    about = "Janus collect job driver",
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

const CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/collect_job_driver",
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main::<Options, _, CollectJobDriverConfig, _, _>(RealClock::default(), |ctx| async move {
        let datastore = Arc::new(ctx.datastore);
        let collect_job_driver = Arc::new(CollectJobDriver::new(
            reqwest::Client::builder()
                .user_agent(CLIENT_USER_AGENT)
                .build()
                .context("couldn't create HTTP client")?,
        ));
        let lease_duration =
            Duration::from_seconds(ctx.config.job_driver_config.worker_lease_duration_secs);

        // Start running.
        Arc::new(JobDriver::new(
            ctx.clock,
            TokioRuntime,
            Duration::from_seconds(ctx.config.job_driver_config.min_job_discovery_delay_secs),
            Duration::from_seconds(ctx.config.job_driver_config.max_job_discovery_delay_secs),
            ctx.config.job_driver_config.max_concurrent_job_workers,
            Duration::from_seconds(
                ctx.config
                    .job_driver_config
                    .worker_lease_clock_skew_allowance_secs,
            ),
            collect_job_driver.make_incomplete_job_acquirer_callback(&datastore, lease_duration),
            collect_job_driver.make_job_stepper_callback(
                &datastore,
                ctx.config.job_driver_config.maximum_attempts_before_failure,
            ),
        ))
        .run()
        .await;

        Ok(())
    })
    .await
}
