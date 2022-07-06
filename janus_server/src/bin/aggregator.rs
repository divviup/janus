use anyhow::{Context, Result};
use futures::StreamExt;
use janus_core::time::RealClock;
use janus_server::{
    aggregator::aggregator_server,
    binary_utils::{janus_main, BinaryOptions, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
};
use serde::{Deserialize, Serialize};
use std::{future::Future, iter::Iterator, net::SocketAddr, sync::Arc};
use structopt::StructOpt;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    janus_main::<Options, _, Config, _, _>(RealClock::default(), |ctx| async move {
        let shutdown_signal =
            setup_signal_handler().context("failed to register SIGTERM signal handler")?;

        let (bound_address, server) = aggregator_server(
            Arc::new(ctx.datastore),
            ctx.clock,
            ctx.config.listen_address,
            shutdown_signal,
        )
        .context("failed to create aggregator server")?;
        info!(?bound_address, "running aggregator");

        server.await;
        Ok(())
    })
    .await
}

/// Register a signal handler for SIGTERM, and return a future that will become ready when a
/// SIGTERM signal is received.
fn setup_signal_handler() -> Result<impl Future<Output = ()>, std::io::Error> {
    let mut signal_stream = signal_hook_tokio::Signals::new([signal_hook::consts::SIGTERM])?;
    let handle = signal_stream.handle();
    let (sender, receiver) = futures::channel::oneshot::channel();
    let mut sender = Some(sender);
    tokio::spawn(async move {
        while let Some(signal) = signal_stream.next().await {
            if signal == signal_hook::consts::SIGTERM {
                if let Some(sender) = sender.take() {
                    // This may return Err(()) if the receiver has been dropped already. If
                    // that is the case, the warp server must be shut down already, so we can
                    // safely ignore the error case.
                    let _ = sender.send(());
                    handle.close();
                    break;
                }
            }
        }
    });
    Ok(async move {
        // The receiver may return Err(Canceled) if the sender has been dropped. By inspection, the
        // sender always has a message sent across it before it is dropped, and the async task it
        // is owned by will not terminate before that happens.
        receiver.await.unwrap_or_default()
    })
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-aggregator",
    about = "PPM aggregator server",
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

/// Non-secret configuration options for a Janus aggregator, deserialized from YAML.
///
/// # Examples
///
/// ```
/// let yaml_config = r#"
/// ---
/// listen_address: "0.0.0.0:8080"
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,

    /// Address on which this server should listen for connections and serve its
    /// API endpoints.
    // TODO(#232): options for terminating TLS, unless that gets handled in a load balancer?
    listen_address: SocketAddr,
}

impl BinaryConfig for Config {
    fn common_config(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use janus_server::{
        config::{
            test_util::{
                generate_db_config, generate_metrics_config, generate_trace_config,
                roundtrip_encoding,
            },
            BinaryConfig, CommonConfig,
        },
        metrics::{MetricsExporterConfiguration, OtlpExporterConfiguration},
        trace::{
            OpenTelemetryTraceConfiguration, OtlpTraceConfiguration, TokioConsoleConfiguration,
        },
    };
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    #[test]
    fn roundtrip_config() {
        roundtrip_encoding(Config {
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: generate_trace_config(),
                metrics_config: generate_metrics_config(),
            },
        })
    }

    /// Check that configuration fragments in the README can be parsed correctly.
    #[test]
    fn readme_config_examples() {
        assert_eq!(
            serde_yaml::from_str::<Config>(
                r#"---
    listen_address: "0.0.0.0:8080"
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
    logging_config:
        tokio_console_config:
            enabled: true
            listen_address: 127.0.0.1:6669
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
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
    logging_config:
        open_telemetry_config:
            jaeger:
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
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
    logging_config:
        open_telemetry_config:
            otlp:
                endpoint: "https://api.honeycomb.io:443"
                metadata:
                    x-honeycomb-team: "YOUR_API_KEY"
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
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
    metrics_config:
        exporter:
            prometheus:
                host: 0.0.0.0
                port: 9464
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
    database:
        url: "postgres://postgres:postgres@localhost:5432/postgres"
    metrics_config:
        exporter:
            otlp:
                endpoint: "https://api.honeycomb.io:443"
                metadata:
                    x-honeycomb-team: "YOUR_API_KEY"
                    x-honeycomb-dataset: "YOUR_METRICS_DATASET"
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
    }
}
