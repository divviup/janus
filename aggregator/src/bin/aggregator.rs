use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use janus_aggregator::{
    aggregator::{self, garbage_collector::GarbageCollector, http_handlers::aggregator_handler},
    binary_utils::{
        janus_main, setup_server, setup_signal_handler, BinaryOptions, CommonBinaryOptions,
    },
    cache::GlobalHpkeKeypairCache,
    config::{BinaryConfig, CommonConfig, TaskprovConfig},
};
use janus_aggregator_api::{self, aggregator_api_handler};
use janus_aggregator_core::SecretBytes;
use janus_core::time::RealClock;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use std::{iter::Iterator, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{join, time::interval};
use tracing::{error, info};
use trillium::Headers;
use trillium_router::router;
use trillium_tokio::Stopper;

#[tokio::main]
async fn main() -> Result<()> {
    janus_main::<_, Options, Config, _, _>(RealClock::default(), |ctx| async move {
        let datastore = Arc::new(ctx.datastore);
        let stopper = Stopper::new();
        setup_signal_handler(stopper.clone())
            .context("failed to register SIGTERM signal handler")?;
        let response_headers = ctx
            .config
            .response_headers()
            .context("failed to parse response headers")?;

        let mut handlers = (
            aggregator_handler(
                Arc::clone(&datastore),
                ctx.clock,
                &ctx.meter,
                ctx.config.aggregator_config(),
            )
            .await?,
            None,
        );

        let aggregator_api_auth_tokens = ctx
            .options
            .aggregator_api_auth_tokens
            .iter()
            .filter(|token| !token.is_empty())
            .map(|token| {
                let token_bytes = STANDARD
                    .decode(token)
                    .context("couldn't base64-decode aggregator API auth token")?;

                Ok(SecretBytes::new(token_bytes))
            })
            .collect::<Result<Vec<_>>>()?;

        let inner_aggregator_api_handler = aggregator_api_handler(
            Arc::clone(&datastore),
            janus_aggregator_api::Config {
                auth_tokens: aggregator_api_auth_tokens,
            },
        );

        let garbage_collector_future = {
            let datastore = Arc::clone(&datastore);
            async move {
                if let Some(gc_config) = ctx.config.garbage_collection {
                    let gc = GarbageCollector::new(
                        datastore,
                        gc_config.report_limit,
                        gc_config.aggregation_limit,
                        gc_config.collection_limit,
                    );
                    let mut interval = interval(Duration::from_secs(gc_config.gc_frequency_s));
                    loop {
                        interval.tick().await;
                        if let Err(err) = gc.run().await {
                            error!(?err, "GC error");
                        }
                    }
                }
            }
        };

        // No-op closure to unconditionally pass to tokio::join!
        let mut aggregator_api_future = Box::pin(async {}) as Pin<Box<dyn Future<Output = ()>>>;

        match ctx.config.aggregator_api {
            Some(AggregatorApi::ListenAddress { listen_address }) => {
                // Bind the requested address and spawn a future that serves the aggregator API on
                // it, which we'll `tokio::join!` on below
                let (aggregator_api_bound_address, aggregator_api_server) = setup_server(
                    listen_address,
                    response_headers.clone(),
                    stopper.clone(),
                    inner_aggregator_api_handler,
                )
                .await
                .context("failed to create aggregator API server")?;

                info!(?aggregator_api_bound_address, "Running aggregator API");

                aggregator_api_future =
                    Box::pin(aggregator_api_server) as Pin<Box<dyn Future<Output = ()>>>
            }
            Some(AggregatorApi::PathPrefix { path_prefix }) => {
                // Create a Trillium handler under the requested path prefix, which we'll add to the
                // DAP API handler in the setup_server call below
                info!(
                    aggregator_bound_address = ?ctx.config.listen_address,
                    path_prefix,
                    "Serving aggregator API relative to DAP API"
                );
                // Append wildcard so that this handler will match anything under the prefix
                let path_prefix = format!("{path_prefix}/*");
                handlers.1 = Some(router().all(path_prefix, inner_aggregator_api_handler));
            }
            None => { /* Do nothing */ }
        }

        let (aggregator_bound_address, aggregator_server) = setup_server(
            ctx.config.listen_address,
            response_headers,
            stopper.clone(),
            handlers,
        )
        .await
        .context("failed to create aggregator server")?;

        info!(?aggregator_bound_address, "Running aggregator");

        join!(
            aggregator_server,
            garbage_collector_future,
            aggregator_api_future
        );
        Ok(())
    })
    .await
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus-aggregator",
    about = "DAP aggregator server",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    #[clap(flatten)]
    common: CommonBinaryOptions,

    /// Aggregator API authentication tokens.
    #[clap(
        long,
        env = "AGGREGATOR_API_AUTH_TOKENS",
        hide_env_values = true,
        num_args = 0..=1,
        use_value_delimiter = true,
        help = "aggregator API auth tokens, encoded in base64 then comma-separated"
    )]
    aggregator_api_auth_tokens: Vec<String>,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        &self.common
    }
}

/// A name-value HTTP header pair, that appears in configuration objects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEntry {
    name: String,
    value: String,
}

/// Options for serving the aggregator API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AggregatorApi {
    /// Address on which this server should listen for connections to the Janus aggregator API and
    /// serve its API endpoints, independently from the address on which the DAP API is served.
    ListenAddress { listen_address: SocketAddr },
    /// The Janus aggregator API will be served on the same address as the DAP API, but relative to
    /// the provided prefix. e.g., if `path_prefix` is `aggregator-api`, then the DAP API's uploads
    /// endpoint would be `{listen-address}/tasks/{task-id}/reports`, while task IDs could be
    /// obtained from the aggregator API at `{listen-address}/aggregator-api/task_ids`.
    PathPrefix { path_prefix: String },
}

/// Non-secret configuration options for a Janus aggregator, deserialized from YAML.
///
/// # Examples
///
/// Configuration serving the aggregator API on its own port, distinct from the DAP API:
///
/// ```
/// let yaml_config = r#"
/// ---
/// listen_address: "0.0.0.0:8080"
/// aggregator_api:
///   listen_address: "0.0.0.0:8081"
/// response_headers:
/// - name: "Example"
///   value: "header value"
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// max_upload_batch_size: 100
/// max_upload_batch_write_delay_ms: 250
/// batch_aggregation_shard_count: 32
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
///
/// Configuration serving the aggregator API relative to the DAP API:
///
/// ```
/// let yaml_config = r#"
/// ---
/// listen_address: "0.0.0.0:8080"
/// aggregator_api:
///   path_prefix: "aggregator-api"
/// response_headers:
/// - name: "Example"
///   value: "header value"
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// max_upload_batch_size: 100
/// max_upload_batch_write_delay_ms: 250
/// batch_aggregation_shard_count: 32
/// taskprov_config:
///   enabled: false
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,

    #[serde(default)]
    taskprov_config: TaskprovConfig,

    #[serde(default)]
    garbage_collection: Option<GarbageCollectorConfig>,

    /// Address on which this server should listen for connections to the DAP aggregator API and
    /// serve its API endpoints.
    // TODO(#232): options for terminating TLS, unless that gets handled in a load balancer?
    listen_address: SocketAddr,

    /// How to serve the Janus aggregator API. If not set, the aggregator API is not served.
    aggregator_api: Option<AggregatorApi>,

    /// Additional headers that will be added to all responses.
    #[serde(default)]
    response_headers: Vec<HeaderEntry>,

    /// Defines the maximum size of a batch of uploaded reports which will be written in a single
    /// transaction.
    max_upload_batch_size: usize,

    /// Defines the maximum delay in milliseconds before writing a batch of uploaded reports, even
    /// if it has not yet reached `max_batch_upload_size`.
    max_upload_batch_write_delay_ms: u64,

    /// Defines the number of shards to break each batch aggregation into. Increasing this value
    /// will reduce the amount of database contention during helper aggregation, while increasing
    /// the cost of collection.
    batch_aggregation_shard_count: u64,

    /// Defines how often to refresh the global HPKE configs cache in milliseconds. This affects
    /// how often an aggregator becomes aware of key state changes. If unspecified, default is
    /// defined by [`GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL`]. You shouldn't normally
    /// have to specify this.
    #[serde(default)]
    global_hpke_configs_refresh_interval: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GarbageCollectorConfig {
    /// How frequently garbage collection is run, in seconds.
    gc_frequency_s: u64,

    /// The limit to the number of client report artifacts deleted for a single task by a single run
    /// of the garbage collector.
    report_limit: u64,

    /// The limit to the number of aggregation jobs, and related aggregation artifacts, deleted for
    /// a single task by a single run of the garbage collector.
    aggregation_limit: u64,

    /// The limit to the number of batches, and related collection artifacts, deleted for a single
    /// task by a single run of the garbage collector.
    collection_limit: u64,
}

impl Config {
    fn response_headers(&self) -> anyhow::Result<Headers> {
        self.response_headers
            .iter()
            .map(|entry| {
                Ok((
                    entry.name.as_str().to_owned(),
                    entry.value.as_str().to_owned(),
                ))
            })
            .collect()
    }

    fn aggregator_config(&self) -> aggregator::Config {
        aggregator::Config {
            max_upload_batch_size: self.max_upload_batch_size,
            max_upload_batch_write_delay: Duration::from_millis(
                self.max_upload_batch_write_delay_ms,
            ),
            batch_aggregation_shard_count: self.batch_aggregation_shard_count,
            taskprov_config: self.taskprov_config.clone(),
            global_hpke_configs_refresh_interval: match self.global_hpke_configs_refresh_interval {
                Some(duration) => Duration::from_millis(duration),
                None => GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL,
            },
        }
    }
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
    use super::{AggregatorApi, Config, GarbageCollectorConfig, HeaderEntry, Options};
    use clap::CommandFactory;
    use janus_aggregator::{
        aggregator,
        config::{
            test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
            BinaryConfig, CommonConfig, TaskprovConfig,
        },
        metrics::{MetricsExporterConfiguration, OtlpExporterConfiguration},
        trace::{
            OpenTelemetryTraceConfiguration, OtlpTraceConfiguration, TokioConsoleConfiguration,
        },
    };
    use janus_core::test_util::roundtrip_encoding;
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    #[test]
    fn verify_app() {
        Options::command().debug_assert()
    }

    #[rstest::rstest]
    #[case::listen_address(AggregatorApi::ListenAddress {
        listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8081)),
    })]
    #[case::path_prefix(AggregatorApi::PathPrefix { path_prefix: "prefix".to_string() })]
    #[test]
    fn roundtrip_config(#[case] aggregator_api: AggregatorApi) {
        roundtrip_encoding(Config {
            listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
            garbage_collection: Some(GarbageCollectorConfig {
                gc_frequency_s: 60,
                report_limit: 25,
                aggregation_limit: 50,
                collection_limit: 75,
            }),
            aggregator_api: Some(aggregator_api),
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: generate_trace_config(),
                metrics_config: generate_metrics_config(),
                health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
            },
            response_headers: Vec::from([HeaderEntry {
                name: "name".to_owned(),
                value: "value".to_owned(),
            }]),
            max_upload_batch_size: 100,
            max_upload_batch_write_delay_ms: 250,
            batch_aggregation_shard_count: 32,
            taskprov_config: TaskprovConfig::default(),
            global_hpke_configs_refresh_interval: None,
        })
    }

    #[test]
    fn config_no_aggregator_api() {
        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .aggregator_api,
            None
        );
    }

    #[test]
    fn config_garbage_collection() {
        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    garbage_collection:
        gc_frequency_s: 60
        report_limit: 25
        aggregation_limit: 50
        collection_limit: 75
    "#
            )
            .unwrap()
            .garbage_collection,
            Some(GarbageCollectorConfig {
                gc_frequency_s: 60,
                report_limit: 25,
                aggregation_limit: 50,
                collection_limit: 75,
            }),
        );
    }

    #[test]
    fn config_taskprov() {
        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    taskprov_config:
        enabled: true
    "#
            )
            .unwrap()
            .taskprov_config,
            TaskprovConfig { enabled: true },
        );
    }

    #[test]
    fn config_aggregator_api_listen_address() {
        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    aggregator_api:
        listen_address: "0.0.0.0:8081"
    "#
            )
            .unwrap()
            .aggregator_api,
            Some(AggregatorApi::ListenAddress {
                listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8081))
            })
        );
    }

    #[test]
    fn config_aggregator_api_path_prefix() {
        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    aggregator_api:
        path_prefix: "aggregator-api"
    "#
            )
            .unwrap()
            .aggregator_api,
            Some(AggregatorApi::PathPrefix {
                path_prefix: "aggregator-api".to_string()
            })
        );
    }

    /// Check that configuration fragments in the README and other documentation can be parsed
    /// correctly.
    #[test]
    fn documentation_config_examples() {
        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    health_check_listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    logging_config:
        tokio_console_config:
            enabled: true
            listen_address: 127.0.0.1:6669
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .common_config()
            .logging_config
            .tokio_console_config,
            TokioConsoleConfiguration {
                enabled: true,
                listen_address: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    6669,
                )),
            },
        );

        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    health_check_listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    logging_config:
        tokio_console_config:
            enabled: true
            listen_address: 127.0.0.1:6669
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .aggregator_config(),
            aggregator::Config {
                max_upload_batch_size: 100,
                max_upload_batch_write_delay: Duration::from_millis(250),
                batch_aggregation_shard_count: 32,
                taskprov_config: TaskprovConfig::default(),
                ..Default::default()
            }
        );

        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    health_check_listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    logging_config:
        open_telemetry_config:
            otlp:
                endpoint: "http://localhost:4317"
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .common_config()
            .logging_config
            .open_telemetry_config,
            Some(OpenTelemetryTraceConfiguration::Otlp(
                OtlpTraceConfiguration {
                    endpoint: "http://localhost:4317".to_string(),
                    metadata: HashMap::new()
                }
            )),
        );

        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    health_check_listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    logging_config:
        open_telemetry_config:
            otlp:
                endpoint: "https://api.honeycomb.io:443"
                metadata:
                    x-honeycomb-team: "YOUR_API_KEY"
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .common_config()
            .logging_config
            .open_telemetry_config,
            Some(OpenTelemetryTraceConfiguration::Otlp(
                OtlpTraceConfiguration {
                    endpoint: "https://api.honeycomb.io:443".to_string(),
                    metadata: HashMap::from([(
                        "x-honeycomb-team".to_string(),
                        "YOUR_API_KEY".to_string(),
                    )]),
                },
            )),
        );

        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    health_check_listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    metrics_config:
        exporter:
            prometheus:
                host: 0.0.0.0
                port: 9464
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .common_config()
            .metrics_config
            .exporter,
            Some(MetricsExporterConfiguration::Prometheus {
                host: Some("0.0.0.0".to_string()),
                port: Some(9464),
            }),
        );

        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    health_check_listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
        connection_pool_timeouts_secs: 60
    metrics_config:
        exporter:
            otlp:
                endpoint: "https://api.honeycomb.io:443"
                metadata:
                    x-honeycomb-team: "YOUR_API_KEY"
                    x-honeycomb-dataset: "YOUR_METRICS_DATASET"
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .common_config()
            .metrics_config
            .exporter,
            Some(MetricsExporterConfiguration::Otlp(
                OtlpExporterConfiguration {
                    endpoint: "https://api.honeycomb.io:443".to_string(),
                    metadata: HashMap::from([
                        ("x-honeycomb-team".to_string(), "YOUR_API_KEY".to_string()),
                        (
                            "x-honeycomb-dataset".to_string(),
                            "YOUR_METRICS_DATASET".to_string(),
                        ),
                    ]),
                },
            )),
        );

        serde_yaml::from_str::<Config>(include_str!(
            "../../../docs/samples/basic_config/aggregator.yaml"
        ))
        .unwrap();
        serde_yaml::from_str::<Config>(include_str!(
            "../../../docs/samples/advanced_config/aggregator.yaml"
        ))
        .unwrap();
    }
}
