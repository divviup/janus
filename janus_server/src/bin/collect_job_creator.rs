use janus::time::RealClock;
use janus_server::{
    binary_utils::{janus_main, BinaryOptions, CommonBinaryOptions},
    config::CollectJobCreatorConfig,
    job_creator::PerTaskJobCreator,
    task::{Task, VdafInstance},
};
use prio::{
    codec::Encode,
    vdaf::{
        self,
        prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
    },
};
use std::sync::Arc;
use structopt::StructOpt;
use tracing::error;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-collect-job-creator",
    about = "Janus collect job creator",
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
        |clock, config: CollectJobCreatorConfig, datastore| async move {
            Arc::new(PerTaskJobCreator::new(
                Arc::new(datastore),
                clock,
                config.job_creator_config,
                |_clock, _datastore, task| async move {
                    CollectJobCreator {}
                        .create_collect_jobs_for_task(&task)
                        .await
                },
            ))
            .run()
            .await;

            Ok(())
        },
    )
    .await
}

struct CollectJobCreator {}

impl CollectJobCreator {
    async fn create_collect_jobs_for_task(&self, task: &Task) -> anyhow::Result<()> {
        match task.vdaf {
            VdafInstance::Prio3Aes128Count => {
                self.create_collect_jobs_for_task_no_param::<Prio3Aes128Count>(task)
                    .await
            }

            VdafInstance::Prio3Aes128Sum { .. } => {
                self.create_collect_jobs_for_task_no_param::<Prio3Aes128Sum>(task)
                    .await
            }

            VdafInstance::Prio3Aes128Histogram { .. } => {
                self.create_collect_jobs_for_task_no_param::<Prio3Aes128Histogram>(task)
                    .await
            }

            _ => {
                error!(vdaf = ?task.vdaf, "VDAF is not yet supported");
                panic!("VDAF {:?} is not yet supported", task.vdaf);
            }
        }
    }

    async fn create_collect_jobs_for_task_no_param<A: vdaf::Aggregator<AggregationParam = ()>>(
        &self,
        _task: &Task,
    ) -> anyhow::Result<()>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareStep: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        todo!("create collect jobs")
    }
}
