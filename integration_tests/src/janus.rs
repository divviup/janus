//! Functionality for tests interacting with Janus (<https://github.com/divviup/janus>).

#[cfg(feature = "testcontainer")]
use crate::interop_api;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator::{
    binaries::{
        aggregation_job_creator::{
            self, Config as AggregationJobCreatorConfig, Options as AggregationJobCreatorOptions,
        },
        aggregation_job_driver::{
            self, Config as AggregationJobDriverConfig, Options as AggregationJobDriverOptions,
        },
        aggregator::{self, Config as AggregatorConfig, Options as AggregatorOptions},
        collection_job_driver::{
            self, Config as CollectionJobDriverConfig, Options as CollectionJobDriverOptions,
        },
    },
    binary_utils::{BinaryContext, CommonBinaryOptions},
    config::{
        default_max_transaction_retries, CommonConfig, DbConfig, JobDriverConfig, TaskprovConfig,
    },
    metrics::MetricsConfiguration,
    trace::{TokioConsoleConfiguration, TraceConfiguration},
};
use janus_aggregator_core::{
    datastore::test_util::{ephemeral_datastore, EphemeralDatastore},
    task::test_util::Task,
    test_util::noop_meter,
};
use janus_core::time::RealClock;
#[cfg(feature = "testcontainer")]
use janus_interop_binaries::{
    get_rust_log_level, test_util::await_http_server, testcontainer::Aggregator,
    ContainerLogsDropGuard,
};
use janus_messages::Role;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(feature = "testcontainer")]
use testcontainers::{runners::AsyncRunner, RunnableImage};
use trillium_tokio::Stopper;

/// Represents a running Janus test instance in a container.
#[cfg(feature = "testcontainer")]
pub struct JanusContainer {
    _container: ContainerLogsDropGuard<Aggregator>,
    port: u16,
}

#[cfg(feature = "testcontainer")]
impl JanusContainer {
    /// Create and start a new hermetic Janus test instance in the given Docker network, configured
    /// to service the given task. The aggregator port is also exposed to the host.
    pub async fn new(test_name: &str, network: &str, task: &Task, role: Role) -> JanusContainer {
        // Start the Janus interop aggregator container running.
        let endpoint = match role {
            Role::Leader => task.leader_aggregator_endpoint(),
            Role::Helper => task.helper_aggregator_endpoint(),
            _ => panic!("unexpected task role"),
        };
        let container = ContainerLogsDropGuard::new_janus(
            test_name,
            RunnableImage::from(Aggregator::default())
                .with_network(network)
                .with_env_var(get_rust_log_level())
                .with_container_name(endpoint.host_str().unwrap())
                .start()
                .await,
        );
        let port = container
            .get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT)
            .await;

        // Wait for the container to start listening on its port.
        await_http_server(port).await;

        // Write the given task to the Janus instance we started.
        interop_api::aggregator_add_task(port, task.clone(), role).await;

        Self {
            _container: container,
            port,
        }
    }

    /// Returns the port of the aggregator on the host.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Represents a running Janus test instance in this process.
pub struct JanusInProcess {
    socket_address: SocketAddr,
    stopper: Stopper,
    _ephemeral_datastore: EphemeralDatastore,
}

impl JanusInProcess {
    /// Start a new Janus instance in the current process, using a separate ephemeral database,
    /// configured to service the given task.
    pub async fn new(task: &Task, role: Role) -> Self {
        // Set up common utilities.
        let stopper = Stopper::new();
        let clock = RealClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock).await;
        let encoded_datastore_key =
            URL_SAFE_NO_PAD.encode(ephemeral_datastore.datastore_key_bytes());
        let datastore_keys = Vec::from([encoded_datastore_key]);
        let database_url = ephemeral_datastore
            .connection_string()
            .parse()
            .expect("error parsing database URL");

        // Provision the task.
        datastore
            .put_aggregator_task(&task.view_for_role(role).expect("invalid role"))
            .await
            .expect("task provisioning failed");

        // Construct configuration and options for each component.
        let common_binary_options = CommonBinaryOptions {
            datastore_keys,
            ..Default::default()
        };
        let logging_config = TraceConfiguration {
            use_test_writer: false,
            force_json_output: true,
            stackdriver_json_output: false,
            tokio_console_config: TokioConsoleConfiguration {
                enabled: false,
                listen_address: None,
            },
            open_telemetry_config: None,
            chrome: false,
        };
        let common_config = CommonConfig {
            database: DbConfig {
                url: database_url,
                connection_pool_timeouts_secs: 60,
                connection_pool_max_size: None,
                check_schema_version: false,
                tls_trust_store_path: None,
            },
            logging_config,
            metrics_config: MetricsConfiguration {
                exporter: None,
                tokio: None,
            },
            health_check_listen_address: (Ipv4Addr::LOCALHOST, 0).into(),
            max_transaction_retries: default_max_transaction_retries(),
        };
        let aggregator_options = AggregatorOptions {
            common: common_binary_options.clone(),
            aggregator_api_auth_tokens: Vec::new(),
            hpke_config_signing_key: None,
        };
        let aggregator_config = AggregatorConfig {
            common_config: common_config.clone(),
            taskprov_config: TaskprovConfig::default(),
            garbage_collection: None,
            listen_address: (Ipv4Addr::LOCALHOST, 0).into(),
            aggregator_api: None,
            max_upload_batch_size: 100,
            max_upload_batch_write_delay_ms: 100,
            batch_aggregation_shard_count: 32,
            task_counter_shard_count: 64,
            global_hpke_configs_refresh_interval: None,
            task_cache_ttl_seconds: None,
            task_cache_capacity: None,
            log_forbidden_mutations: false,
        };
        let aggregation_job_creator_options = AggregationJobCreatorOptions {
            common: common_binary_options.clone(),
        };
        let aggregation_job_creator_config = AggregationJobCreatorConfig {
            common_config: common_config.clone(),
            batch_aggregation_shard_count: 32,
            tasks_update_frequency_secs: 2,
            aggregation_job_creation_interval_secs: 1,
            min_aggregation_job_size: 1,
            max_aggregation_job_size: 100,
            aggregation_job_creation_report_window: 5000,
        };
        let aggregation_job_driver_options = AggregationJobDriverOptions {
            common: common_binary_options.clone(),
        };
        let aggregation_job_driver_config = AggregationJobDriverConfig {
            common_config: common_config.clone(),
            job_driver_config: JobDriverConfig {
                job_discovery_interval_secs: 1,
                max_concurrent_job_workers: 10,
                worker_lease_duration_secs: 10,
                worker_lease_clock_skew_allowance_secs: 1,
                maximum_attempts_before_failure: 3,
                http_request_timeout_secs: 30,
                http_request_connection_timeout_secs: 10,
                retry_initial_interval_millis: 1000,
                retry_max_interval_millis: 30_000,
                retry_max_elapsed_time_millis: 300_000,
            },
            taskprov_config: TaskprovConfig::default(),
            batch_aggregation_shard_count: 32,
        };
        let collection_job_driver_options = CollectionJobDriverOptions {
            common: common_binary_options.clone(),
        };
        let collection_job_driver_config = CollectionJobDriverConfig {
            common_config,
            job_driver_config: JobDriverConfig {
                job_discovery_interval_secs: 1,
                max_concurrent_job_workers: 10,
                worker_lease_duration_secs: 10,
                worker_lease_clock_skew_allowance_secs: 1,
                maximum_attempts_before_failure: 3,
                http_request_timeout_secs: 30,
                http_request_connection_timeout_secs: 10,
                retry_initial_interval_millis: 1000,
                retry_max_interval_millis: 30_000,
                retry_max_elapsed_time_millis: 300_000,
            },
            batch_aggregation_shard_count: 32,
            min_collection_job_retry_delay_secs: 1,
            max_collection_job_retry_delay_secs: 1,
            collection_job_retry_delay_exponential_factor: 1.0,
        };

        // Spawn each component.
        let (aggregator_future, mut socket_address_receiver) =
            aggregator::make_callback_ephemeral_address(BinaryContext {
                clock,
                options: aggregator_options,
                config: aggregator_config,
                datastore: ephemeral_datastore.datastore(clock).await,
                meter: noop_meter(),
                stopper: stopper.clone(),
            });
        tokio::spawn(async {
            aggregator_future.await.unwrap();
        });
        tokio::spawn({
            let future = aggregation_job_creator::main_callback(BinaryContext {
                clock,
                options: aggregation_job_creator_options,
                config: aggregation_job_creator_config,
                datastore: ephemeral_datastore.datastore(clock).await,
                meter: noop_meter(),
                stopper: stopper.clone(),
            });
            async {
                future.await.unwrap();
            }
        });
        tokio::spawn({
            let future = aggregation_job_driver::main_callback(BinaryContext {
                clock,
                options: aggregation_job_driver_options,
                config: aggregation_job_driver_config,
                datastore: ephemeral_datastore.datastore(clock).await,
                meter: noop_meter(),
                stopper: stopper.clone(),
            });
            async {
                future.await.unwrap();
            }
        });
        tokio::spawn({
            let future = collection_job_driver::main_callback(BinaryContext {
                clock,
                options: collection_job_driver_options,
                config: collection_job_driver_config,
                datastore: ephemeral_datastore.datastore(clock).await,
                meter: noop_meter(),
                stopper: stopper.clone(),
            });
            async {
                future.await.unwrap();
            }
        });

        // Wait for the aggregator's socket address.
        let socket_address = loop {
            if let Some(socket_address) = *socket_address_receiver.borrow_and_update() {
                break socket_address;
            }
            socket_address_receiver
                .changed()
                .await
                .expect("aggregator task shut down before sending socket address");
        };

        Self {
            socket_address,
            stopper,
            _ephemeral_datastore: ephemeral_datastore,
        }
    }

    /// Returns the aggregator's port.
    pub fn port(&self) -> u16 {
        self.socket_address.port()
    }
}

impl Drop for JanusInProcess {
    fn drop(&mut self) {
        // Request that all components shut down.
        //
        // Note that the EphemeralDatastore will be terminated when it is dropped, right after the
        // Stopper's flag is set. This means there may be some log noise about broken connections,
        // due to in-flight work on tasks that haven't read the Stopper yet.
        self.stopper.stop();
    }
}
