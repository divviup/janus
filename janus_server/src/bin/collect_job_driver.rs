use anyhow::Result;
use janus::{
    message::{Duration, Time},
    time::RealClock,
};
use janus_server::{
    binary_utils::{janus_main, job_driver::JobDriver, BinaryOptions, CommonBinaryOptions},
    config::CollectJobDriverConfig,
    datastore,
};
use std::{fmt::Debug, sync::Arc};
use structopt::StructOpt;
use uuid::Uuid;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main::<Options, _, _, _, _>(
        RealClock::default(),
        |clock, config: CollectJobDriverConfig, datastore| async move {
            // Start running.
            Arc::new(JobDriver::new(
                Arc::new(datastore),
                clock,
                Duration::from_seconds(config.job_driver_config.min_job_discovery_delay_secs),
                Duration::from_seconds(config.job_driver_config.max_job_discovery_delay_secs),
                config.job_driver_config.max_concurrent_job_workers,
                Duration::from_seconds(config.job_driver_config.worker_lease_duration_secs),
                Duration::from_seconds(
                    config
                        .job_driver_config
                        .worker_lease_clock_skew_allowance_secs,
                ),
                |datastore, _lease_duration, _max_acquire_count| async move {
                    datastore
                        .run_tx(|_tx| {
                            Box::pin(async move {
                                // TODO(timg) discover incomplete collect jobs in datastore
                                Ok(vec![]) as Result<Vec<(Uuid, Time)>, datastore::Error>
                            })
                        })
                        .await
                },
                |_datastore, _acquired_job: Arc<Uuid>, _| async move {
                    // TODO(timg): step collect job
                    Ok(()) as Result<_, datastore::Error>
                },
                (), // TOOD: provide shared resources as job stepper context
            ))
            .run()
            .await;

            Ok(())
        },
    )
    .await
}
