use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use janus_aggregator::{
    aggregator::{self, http_handlers::aggregator_handler},
    binary_utils::{
        janus_main, setup_server, setup_signal_handler, BinaryOptions, CommonBinaryOptions,
    },
    config::{BinaryConfig, CommonConfig},
};
use janus_aggregator_api::{self, aggregator_api_handler};
use janus_aggregator_core::SecretBytes;
use janus_core::time::RealClock;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use std::{iter::Iterator, net::SocketAddr, sync::Arc, time::Duration};
use tokio::join;
use tracing::info;
use trillium::Headers;

#[tokio::main]
async fn main() -> Result<()> {
    janus_main::<_, Options, Config, _, _>(RealClock::default(), |ctx| async move {
        let datastore = Arc::new(ctx.datastore);
        let shutdown_signal =
            setup_signal_handler().context("failed to register SIGTERM signal handler")?;
        let response_headers = ctx
            .config
            .response_headers()
            .context("failed to parse response headers")?;

        let aggregator_handler = aggregator_handler(
            Arc::clone(&datastore),
            ctx.clock,
            ctx.config.aggregator_config(),
        )?;

        let (aggregator_bound_address, aggregator_server) = setup_server(
            ctx.config.listen_address,
            response_headers.clone(),
            shutdown_signal,
            aggregator_handler,
        )
        .await
        .context("failed to create aggregator server")?;

        info!(?aggregator_bound_address, "Running aggregator");

        let aggregator_api_server =
            if let Some(aggregator_api_listen_address) = ctx.config.aggregator_api_listen_address {
                let auth_tokens = ctx
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

                let aggregator_api_handler = aggregator_api_handler(
                    Arc::clone(&datastore),
                    janus_aggregator_api::Config { auth_tokens },
                );

                let shutdown_signal =
                    setup_signal_handler().context("failed to register SIGTERM signal handler")?;
                let (aggregator_api_bound_address, aggregator_api_server) = setup_server(
                    aggregator_api_listen_address,
                    response_headers,
                    shutdown_signal,
                    aggregator_api_handler,
                )
                .await
                .context("failed to create aggregator API server")?;

                info!(?aggregator_api_bound_address, "Running aggregator API");

                Box::pin(aggregator_api_server) as Pin<Box<dyn Future<Output = ()>>>
            } else {
                // No-op closure to unconditionally pass to tokio::join!
                Box::pin(async {}) as Pin<Box<dyn Future<Output = ()>>>
            };

        join!(aggregator_server, aggregator_api_server);
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

/// Non-secret configuration options for a Janus aggregator, deserialized from YAML.
///
/// # Examples
///
/// ```
/// let yaml_config = r#"
/// ---
/// listen_address: "0.0.0.0:8080"
/// aggregator_api_listen_address: "0.0.0.0:8081"
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,

    /// Address on which this server should listen for connections to the DAP aggregator API and
    /// serve its API endpoints.
    // TODO(#232): options for terminating TLS, unless that gets handled in a load balancer?
    listen_address: SocketAddr,

    /// Address on which this server should listen for connections to the Janus aggregator API and
    /// serve its API endpoints. If not set, the aggregator API is not served.
    aggregator_api_listen_address: Option<SocketAddr>,

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
    use super::{Config, HeaderEntry, Options};
    use clap::CommandFactory;
    use janus_aggregator::{
        aggregator,
        config::{
            test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
            BinaryConfig, CommonConfig,
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

    #[test]
    fn roundtrip_config() {
        roundtrip_encoding(Config {
            listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
            aggregator_api_listen_address: Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8081))),
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
        })
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
        open_telemetry_config: jaeger
    max_upload_batch_size: 100
    max_upload_batch_write_delay_ms: 250
    batch_aggregation_shard_count: 32
    "#
            )
            .unwrap()
            .common_config()
            .logging_config
            .open_telemetry_config,
            Some(OpenTelemetryTraceConfiguration::Jaeger),
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
