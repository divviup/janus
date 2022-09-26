use anyhow::{anyhow, Context, Result};
use base64::STANDARD_NO_PAD;
use clap::Parser;
use deadpool_postgres::Pool;
use janus_core::time::{Clock, RealClock};
use janus_server::{
    binary_utils::{database_pool, datastore, read_config, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
    datastore::{self, Datastore},
    metrics::install_metrics_exporter,
    task::Task,
    trace::install_trace_subscriber,
};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{ObjectMeta, PostParams};
use rand::{distributions::Standard, thread_rng, Rng};
use ring::aead::AES_128_GCM;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::fs;
use tracing::{debug, info};

static SCHEMA: &str = include_str!("../../../db/schema.sql");

#[tokio::main]
async fn main() -> Result<()> {
    // Parse options, then read & parse config.
    let options = Options::from_args();

    debug!(?options, "Starting up");

    options.cmd.execute().await
}

#[derive(Debug, Parser)]
enum Command {
    /// Write the Janus database schema to the database.
    WriteSchema {
        #[clap(flatten)]
        common_options: CommonBinaryOptions,
    },

    /// Write a set of tasks identified in a file to the datastore.
    ProvisionTasks {
        #[clap(flatten)]
        common_options: CommonBinaryOptions,

        #[clap(flatten)]
        kubernetes_secret_options: KubernetesSecretOptions,

        /// A YAML file containing a list of tasks to be written. Existing tasks (matching by task
        /// ID) will be overwritten.
        tasks_file: PathBuf,
    },

    /// Create a datastore key and write it to a Kubernetes secret.
    CreateDatastoreKey {
        #[clap(flatten)]
        common_options: CommonBinaryOptions,

        #[clap(flatten)]
        kubernetes_secret_options: KubernetesSecretOptions,
    },
}

impl Command {
    async fn execute(&self) -> Result<()> {
        // Note: to keep this function reasonably-readable, individual command handlers should
        // generally create the command's dependencies based on options/config, then call another
        // function with the main command logic.
        match self {
            Command::WriteSchema { common_options } => {
                let config: Config = read_config(common_options)?;
                install_tracing_and_metrics_handlers(config.common_config())?;
                let pool = database_pool(
                    &config.common_config.database,
                    common_options.database_password.as_deref(),
                )
                .await?;
                write_schema(&pool).await
            }

            Command::ProvisionTasks {
                common_options,
                kubernetes_secret_options,
                tasks_file,
            } => {
                let kube_client = kube::Client::try_default()
                    .await
                    .context("couldn't connect to Kubernetes environment")?;
                let config: Config = read_config(common_options)?;
                install_tracing_and_metrics_handlers(config.common_config())?;
                let pool = database_pool(
                    &config.common_config.database,
                    common_options.database_password.as_deref(),
                )
                .await?;

                let datastore = datastore(
                    pool,
                    RealClock::default(),
                    &kubernetes_secret_options
                        .datastore_keys(common_options, kube_client)
                        .await?,
                )?;

                provision_tasks(&datastore, tasks_file).await
            }

            Command::CreateDatastoreKey {
                common_options,
                kubernetes_secret_options,
            } => {
                let kube_client = kube::Client::try_default()
                    .await
                    .context("couldn't connect to Kubernetes environment")?;
                let config: Config = read_config(common_options)?;
                install_tracing_and_metrics_handlers(config.common_config())?;
                let k8s_namespace = kubernetes_secret_options
                    .secrets_k8s_namespace
                    .as_deref()
                    .context("--secrets-k8s-namespace is required")?;
                create_datastore_key(
                    kube_client,
                    k8s_namespace,
                    &kubernetes_secret_options.datastore_keys_secret_name,
                )
                .await
            }
        }
    }
}

fn install_tracing_and_metrics_handlers(config: &CommonConfig) -> Result<()> {
    install_trace_subscriber(&config.logging_config)
        .context("couldn't install tracing subscriber")?;
    let _metrics_exporter = install_metrics_exporter(&config.metrics_config)
        .context("failed to install metrics exporter")?;

    Ok(())
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

async fn fetch_datastore_keys(
    kube_client: &kube::Client,
    namespace: &str,
    secret_name: &str,
    secret_data_key: &str,
) -> Result<Vec<String>> {
    debug!(
        "Fetching value {} from secret {}/{}",
        secret_data_key, namespace, secret_name,
    );

    let secrets_api: kube::Api<Secret> = kube::Api::namespaced(kube_client.clone(), namespace);

    let secret = secrets_api
        .get(secret_name)
        .await?
        .data
        .context(format!("no data on secret {secret_name}"))?;
    let secret_value = secret.get(secret_data_key).context(format!(
        "no data key {secret_data_key} on secret {secret_name}"
    ))?;

    Ok(String::from_utf8(secret_value.0.clone())?
        .split(',')
        .map(&str::to_string)
        .collect())
}

async fn create_datastore_key(
    kube_client: kube::Client,
    k8s_namespace: &str,
    k8s_secret_name: &str,
) -> Result<()> {
    info!("Creating datastore key");
    let secrets_api: kube::Api<Secret> = kube::Api::namespaced(kube_client.clone(), k8s_namespace);

    // Generate a random datastore key & encode it into unpadded base64 as will be expected by
    // consumers of the secret we are about to write.
    let key_bytes: Vec<_> = thread_rng()
        .sample_iter(Standard)
        .take(AES_128_GCM.key_len())
        .collect();
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

#[derive(Debug, Parser)]
struct KubernetesSecretOptions {
    /// The Kubernetes namespace where secrets are stored.
    #[clap(
        long,
        env = "SECRETS_K8S_NAMESPACE",
        takes_value = true,
        long_help = "Kubernetes namespace where the datastore key is stored. Required if \
        --datastore-keys is not set or if command is create-datastore-key."
    )]
    secrets_k8s_namespace: Option<String>,

    /// Kubernetes secret containing the datastore key(s).
    #[clap(
        long,
        env = "DATASTORE_KEYS_SECRET_NAME",
        takes_value = true,
        default_value = "datastore-key"
    )]
    datastore_keys_secret_name: String,

    /// Key into data of datastore key Kubernetes secret
    #[clap(
        long,
        env = "DATASTORE_KEYS_SECRET_KEY",
        takes_value = true,
        help = "Key into data of datastore key Kubernetes secret",
        default_value = "datastore_key"
    )]
    datastore_keys_secret_data_key: String,
}

impl KubernetesSecretOptions {
    /// Fetch the datastore keys from the options. If --secrets-k8s-namespace is set, keys are fetched
    /// from a secret therein. Otherwise, returns the keys provided to --datastore-keys. If neither was
    /// set, returns an error.
    async fn datastore_keys(
        &self,
        options: &CommonBinaryOptions,
        kube_client: kube::Client,
    ) -> Result<Vec<String>> {
        if let Some(ref secrets_namespace) = self.secrets_k8s_namespace {
            fetch_datastore_keys(
                &kube_client,
                secrets_namespace,
                &self.datastore_keys_secret_name,
                &self.datastore_keys_secret_data_key,
            )
            .await
            .context("failed to fetch datastore key(s) from Kubernetes secret")
        } else if !options.datastore_keys.is_empty() {
            Ok(options.datastore_keys.clone())
        } else {
            Err(anyhow!(
                "Either --datastore-keys or --secrets-k8s-namespace must be set"
            ))
        }
    }
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus_cli",
    about = "Janus CLI tool",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    #[clap(subcommand)]
    cmd: Command,
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
    use super::{fetch_datastore_keys, Config, KubernetesSecretOptions, Options};
    use base64::STANDARD_NO_PAD;
    use clap::IntoApp;
    use janus_core::{task::VdafInstance, test_util::kubernetes, time::RealClock};
    use janus_messages::Role;
    use janus_server::{
        binary_utils::CommonBinaryOptions,
        config::test_util::{
            generate_db_config, generate_metrics_config, generate_trace_config, roundtrip_encoding,
        },
        config::CommonConfig,
        datastore::test_util::{ephemeral_datastore, ephemeral_db_handle},
        task::Task,
    };
    use rand::random;
    use ring::aead::{UnboundKey, AES_128_GCM};
    use std::{
        collections::HashMap,
        io::Write,
        net::{Ipv4Addr, SocketAddr},
    };
    use tempfile::NamedTempFile;

    #[test]
    fn verify_app() {
        Options::into_app().debug_assert()
    }

    #[tokio::test]
    async fn options_datastore_keys() {
        // Prep: create a Kubernetes cluster and put a secret in it
        let k8s_cluster = kubernetes::EphemeralCluster::create();
        let kube_client = k8s_cluster.cluster().client().await;
        super::create_datastore_key(kube_client.clone(), "default", "secret-name")
            .await
            .unwrap();

        let expected_datastore_keys =
            vec!["datastore-key-1".to_string(), "datastore-key-2".to_string()];

        // Keys provided at command line, not present in k8s
        let mut binary_options = CommonBinaryOptions::default();
        binary_options.datastore_keys = expected_datastore_keys.clone();

        let k8s_secret_options = KubernetesSecretOptions {
            datastore_keys_secret_name: "secret-name".to_string(),
            datastore_keys_secret_data_key: "secret-data-key".to_string(),
            secrets_k8s_namespace: None,
        };

        assert_eq!(
            k8s_secret_options
                .datastore_keys(&binary_options, kube_client.clone())
                .await
                .unwrap(),
            expected_datastore_keys
        );

        // Keys not provided at command line, present in k8s
        let k8s_secret_options = KubernetesSecretOptions {
            datastore_keys_secret_name: "secret-name".to_string(),
            datastore_keys_secret_data_key: "datastore_key".to_string(),
            secrets_k8s_namespace: Some("default".to_string()),
        };

        assert_eq!(
            k8s_secret_options
                .datastore_keys(&CommonBinaryOptions::default(), kube_client.clone())
                .await
                .unwrap()
                .len(),
            1
        );

        // Neither flag provided
        let k8s_secret_options = KubernetesSecretOptions {
            datastore_keys_secret_name: "secret-name".to_string(),
            datastore_keys_secret_data_key: "datastore_key".to_string(),
            secrets_k8s_namespace: None,
        };

        k8s_secret_options
            .datastore_keys(&CommonBinaryOptions::default(), kube_client.clone())
            .await
            .unwrap_err();
    }

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
            Task::new_dummy(
                random(),
                VdafInstance::Prio3Aes128Count.into(),
                Role::Leader,
            ),
            Task::new_dummy(
                random(),
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
        let kube_client = k8s_cluster.cluster().client().await;

        // Create a datastore key.
        const NAMESPACE: &str = "default";
        const SECRET_NAME: &str = "secret-name";
        super::create_datastore_key(kube_client.clone(), NAMESPACE, SECRET_NAME)
            .await
            .unwrap();

        // Verify that the secret was created.
        let secret_data =
            fetch_datastore_keys(&kube_client, NAMESPACE, SECRET_NAME, "datastore_key")
                .await
                .unwrap();

        // Verify that the written secret data can be parsed as a comma-separated list of datastore
        // keys.
        let datastore_key_bytes = base64::decode_config(&secret_data[0], STANDARD_NO_PAD).unwrap();
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
