use std::sync::Arc;

use anyhow::Result;
use janus::time::{Clock, RealClock};
use janus_server::{
    binary_utils::{janus_main, BinaryContext, BinaryOptions, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
    task::Task,
};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tracing::info;

static SCHEMA: &str = include_str!("../../../db/schema.sql");

#[tokio::main]
async fn main() -> Result<()> {
    janus_main::<Options, _, Config, _, _>(RealClock::default(), run).await
}

async fn run<C: Clock>(ctx: BinaryContext<C, Config>) -> Result<()> {
    // Try to write the DB schema, if requested.
    if ctx.config.write_schema {
        info!("Writing database schema");
        let db_client = ctx.pool.get().await?;
        db_client.batch_execute(SCHEMA).await?;
    }

    // Write all tasks requested.
    if !ctx.config.tasks.is_empty() {
        let tasks = Arc::new(ctx.config.tasks);
        info!(task_count = tasks.len(), "Writing tasks");
        ctx.datastore
            .run_tx(|tx| {
                let tasks = Arc::clone(&tasks);
                Box::pin(async move {
                    for task in tasks.iter() {
                        tx.delete_task(task.id).await?;
                        tx.put_task(task).await?;
                    }
                    Ok(())
                })
            })
            .await?;
    }

    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-provision-task",
    about = "Janus `provision task` command",
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,

    /// If set to true, always attempt to write the schema. If set to false, never attempt to write
    /// the schema.
    #[serde(default)]
    write_schema: bool,

    /// A list of tasks to be written. Existing tasks (matching by task ID) will be overwritten.
    tasks: Vec<Task>,
}

impl BinaryConfig for Config {
    fn common_config(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

#[cfg(test)]
mod tests {
    use super::{run, Config};
    use janus::{
        message::{Role, TaskId},
        task::VdafInstance,
        time::RealClock,
    };
    use janus_server::{
        binary_utils::BinaryContext,
        config::CommonConfig,
        config::{
            test_util::{
                generate_db_config, generate_metrics_config, generate_trace_config,
                roundtrip_encoding,
            },
            DbConfig,
        },
        datastore::test_util::ephemeral_db_handle,
        metrics::MetricsConfiguration,
        task::test_util::new_dummy_task,
        trace::TraceConfiguration,
    };
    use reqwest::Url;

    #[tokio::test]
    async fn provision_task() {
        for (write_schema, tasks) in [
            (
                false,
                Vec::from([
                    new_dummy_task(
                        TaskId::random(),
                        VdafInstance::Prio3Aes128Count.into(),
                        Role::Leader,
                    ),
                    new_dummy_task(
                        TaskId::random(),
                        VdafInstance::Prio3Aes128Sum { bits: 64 }.into(),
                        Role::Helper,
                    ),
                ]),
            ),
            (
                true,
                Vec::from([
                    new_dummy_task(
                        TaskId::random(),
                        VdafInstance::Prio3Aes128Count.into(),
                        Role::Leader,
                    ),
                    new_dummy_task(
                        TaskId::random(),
                        VdafInstance::Prio3Aes128Sum { bits: 64 }.into(),
                        Role::Helper,
                    ),
                ]),
            ),
        ] {
            let db_handle = ephemeral_db_handle();
            if !write_schema {
                // If we aren't going to ask the program logic to write the schema, we write it
                // ourselves to simulate it being already written.
                db_handle.write_schema().await;
            }

            // Run the program logic with the specified parameters.
            run(BinaryContext {
                clock: RealClock::default(),
                config: Config {
                    common_config: CommonConfig {
                        database: DbConfig {
                            url: Url::parse("http://db_endpoint").unwrap(),
                        },
                        logging_config: TraceConfiguration::default(),
                        metrics_config: MetricsConfiguration::default(),
                    },
                    write_schema,
                    tasks: tasks.clone(),
                },
                datastore: db_handle.datastore(RealClock::default()),
                pool: db_handle.pool(),
            })
            .await
            .unwrap();

            // Check that the expected tasks were written.
            let ds = db_handle.datastore(RealClock::default());
            for task in tasks {
                let task_id = task.id;
                let got_task = ds
                    .run_tx(|tx| Box::pin(async move { tx.get_task(task_id).await }))
                    .await
                    .unwrap();
                assert_eq!(Some(task), got_task);
            }
        }
    }

    #[test]
    fn roundtrip_config() {
        roundtrip_encoding(Config {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: generate_trace_config(),
                metrics_config: generate_metrics_config(),
            },
            write_schema: true,
            tasks: Vec::from([new_dummy_task(
                TaskId::random(),
                VdafInstance::Prio3Aes128Count.into(),
                Role::Leader,
            )]),
        })
    }
}
