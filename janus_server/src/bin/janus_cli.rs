use anyhow::{Context, Result};
use base64::STANDARD_NO_PAD;
use deadpool_postgres::Pool;
use janus_core::time::{Clock, RealClock};
use janus_server::{
    binary_utils::{database_pool, datastore, read_config, BinaryOptions, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
    datastore::{self, Datastore},
    metrics::install_metrics_exporter,
    task::Task,
    trace::install_trace_subscriber,
};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{ObjectMeta, PostParams};
use rand::{thread_rng, Rng};
use ring::aead::AES_128_GCM;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use structopt::StructOpt;
use tokio::fs;
use tracing::info;

static SCHEMA: &str = include_str!("../../../db/schema.sql");

#[tokio::main]
async fn main() -> Result<()> {
    // Parse options, then read & parse config.
    let options = Options::from_args();
    let config: Config = read_config(&options)?;

    // Install tracing/metrics handlers.
    install_trace_subscriber(&config.common_config.logging_config)
        .context("couldn't install tracing subscriber")?;
    let _metrics_exporter = install_metrics_exporter(&config.common_config.metrics_config)
        .context("failed to install metrics exporter")?;

    info!(common_options = ?options.common_options(), ?config, "Starting up");

    options.cmd.execute(&options, &config).await
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Write the Janus database schema to the database.
    WriteSchema,

    /// Write a set of tasks identified in a file to the datastore.
    ProvisionTasks {
        /// A YAML file containing a list of tasks to be written. Existing tasks (matching by task
        /// ID) will be overwritten.
        tasks_file: PathBuf,
    },

    /// Create a datastore key and write it to a Kubernetes secret.
    CreateDatastoreKey {
        /// The Kubernetes namespace to create the datastore key secret in.
        k8s_namespace: String,

        /// The name of the Kubernetes secret to place the datastore key in.
        k8s_secret_name: String,
    },
}

impl Command {
    async fn execute(&self, options: &Options, config: &Config) -> Result<()> {
        // Note: to keep this function reasonably-readable, individual command handlers should
        // generally create the command's dependencies based on options/config, then call another
        // function with the main command logic.
        match self {
            Command::WriteSchema => {
                let pool = database_pool(
                    &config.common_config.database,
                    &options.common.database_password,
                )
                .await?;
                write_schema(&pool).await
            }

            Command::ProvisionTasks { tasks_file } => {
                let pool = database_pool(
                    &config.common_config.database,
                    &options.common.database_password,
                )
                .await?;
                let datastore =
                    datastore(pool, RealClock::default(), &options.common.datastore_keys)?;
                provision_tasks(&datastore, tasks_file).await
            }

            Command::CreateDatastoreKey {
                k8s_namespace,
                k8s_secret_name,
            } => {
                create_datastore_key(
                    kube::Client::try_default()
                        .await
                        .context("couldn't connect to Kubernetes environment")?,
                    k8s_namespace,
                    k8s_secret_name,
                )
                .await
            }
        }
    }
}

async fn write_schema(pool: &Pool) -> Result<()> {
    info!("Writing database schema");
    let db_client = pool.get().await.context("couldn't get database client")?;
    db_client
        .batch_execute(SCHEMA)
        .await
        .context("couldn't write database schema")?;
    Ok(())
}

async fn provision_tasks<C: Clock>(datastore: &Datastore<C>, tasks_file: &Path) -> Result<()> {
    // Read tasks file.
    info!("Reading tasks file");
    let tasks: Vec<Task> = {
        let task_file_contents = fs::read_to_string(tasks_file)
            .await
            .with_context(|| format!("couldn't read tasks file {:?}", tasks_file))?;
        serde_yaml::from_str(&task_file_contents)
            .with_context(|| format!("couldn't parse tasks file {:?}", tasks_file))?
    };

    // Write all tasks requested.
    let tasks = Arc::new(tasks);
    info!(task_count = tasks.len(), "Writing tasks");
    datastore
        .run_tx(|tx| {
            let tasks = Arc::clone(&tasks);
            Box::pin(async move {
                for task in tasks.iter() {
                    // We attempt to delete the task, but ignore "task not found" errors since
                    // the task not existing is an OK outcome too.
                    match tx.delete_task(task.id).await {
                        Ok(_) | Err(datastore::Error::MutationTargetNotFound) => (),
                        err => err?,
                    }

                    tx.put_task(task).await?;
                }
                Ok(())
            })
        })
        .await
        .context("couldn't write tasks")
}

async fn create_datastore_key(
    kube_client: kube::Client,
    k8s_namespace: &str,
    k8s_secret_name: &str,
) -> Result<()> {
    info!("Creating datastore key");
    let secrets_api: kube::Api<Secret> = kube::Api::namespaced(kube_client, k8s_namespace);

    // Generate a random datastore key & encode it into unpadded base64 as will be expected by
    // consumers of the secret we are about to write.
    let mut key_bytes = vec![0u8; AES_128_GCM.key_len()];
    thread_rng().fill(&mut key_bytes[..]);
    let secret_content = base64::encode_config(&key_bytes, STANDARD_NO_PAD);

    // Write the secret.
    secrets_api
        .create(
            &PostParams::default(),
            &Secret {
                metadata: ObjectMeta {
                    namespace: Some(k8s_namespace.to_string()),
                    name: Some(k8s_secret_name.to_string()),
                    ..ObjectMeta::default()
                },
                string_data: Some(BTreeMap::from([(
                    "datastore_key".to_string(),
                    secret_content,
                )])),
                ..Secret::default()
            },
        )
        .await
        .context("couldn't write datastore key secret")?;
    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus_cli",
    about = "Janus CLI tool",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    #[structopt(flatten)]
    common: CommonBinaryOptions,

    #[structopt(subcommand)]
    cmd: Command,
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
    use super::Config;
    use base64::STANDARD_NO_PAD;
    use janus_core::{
        message::{Role, TaskId},
        task::VdafInstance,
        test_util::kubernetes,
        time::RealClock,
    };
    use janus_server::{
        config::test_util::{
            generate_db_config, generate_metrics_config, generate_trace_config, roundtrip_encoding,
        },
        config::CommonConfig,
        datastore::test_util::{ephemeral_datastore, ephemeral_db_handle},
        task::test_util::new_dummy_task,
    };
    use k8s_openapi::api::core::v1::Secret;
    use ring::aead::{UnboundKey, AES_128_GCM};
    use std::{
        collections::HashMap,
        io::Write,
        net::{Ipv4Addr, SocketAddr},
    };
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn write_schema() {
        let db_handle = ephemeral_db_handle();
        let ds = db_handle.datastore(RealClock::default());

        // Verify that the query we will run later returns an error if there is no database schema written.
        ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap_err();

        // Run the program logic.
        super::write_schema(&db_handle.pool()).await.unwrap();

        // Verify that the schema was written (by running a query that would fail if it weren't).
        ds.run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn provision_tasks() {
        let tasks = Vec::from([
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
        ]);

        let (ds, _db_handle) = ephemeral_datastore(RealClock::default()).await;

        // Write tasks to a temporary file.
        let mut tasks_file = NamedTempFile::new().unwrap();
        tasks_file
            .write_all(serde_yaml::to_string(&tasks).unwrap().as_ref())
            .unwrap();
        let tasks_path = tasks_file.into_temp_path();

        // Run the program logic.
        super::provision_tasks(&ds, &tasks_path).await.unwrap();

        // Verify that the expected tasks were written.
        let want_tasks: HashMap<_, _> = tasks.into_iter().map(|task| (task.id, task)).collect();
        let got_tasks = ds
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .unwrap()
            .into_iter()
            .map(|task| (task.id, task))
            .collect();
        assert_eq!(want_tasks, got_tasks);
    }

    #[tokio::test]
    async fn create_datastore_key() {
        let k8s_cluster = kubernetes::EphemeralCluster::create();
        let kube_client = k8s_cluster.client().await;

        // Create a datastore key.
        const NAMESPACE: &str = "default";
        const SECRET_NAME: &str = "secret-name";
        super::create_datastore_key(kube_client.clone(), NAMESPACE, SECRET_NAME)
            .await
            .unwrap();

        // Verify that the secret was created.
        let secrets_api: kube::Api<Secret> = kube::Api::namespaced(kube_client, NAMESPACE);
        let secret = secrets_api.get(SECRET_NAME).await.unwrap();
        let secret_data = secret.data.unwrap().get("datastore_key").unwrap().clone();

        // Verify that the written secret data can be parsed as a datastore key.
        let datastore_key_bytes = base64::decode_config(&secret_data.0, STANDARD_NO_PAD).unwrap();
        UnboundKey::new(&AES_128_GCM, &datastore_key_bytes).unwrap();
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
        })
    }
}
