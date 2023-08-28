//! Collection and exporting of application-level metrics for Janus.

#[cfg(any(not(feature = "prometheus"), not(feature = "otlp")))]
use anyhow::anyhow;
use opentelemetry::sdk::metrics::{reader::AggregationSelector, Aggregation, InstrumentKind};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::AddrParseError};

#[cfg(feature = "prometheus")]
use {
    anyhow::Context,
    opentelemetry::global::set_meter_provider,
    prometheus::Registry,
    std::net::{IpAddr, Ipv4Addr},
    tokio::{sync::oneshot, task::JoinHandle},
    trillium::{Info, Init},
};

#[cfg(feature = "otlp")]
use {
    opentelemetry::runtime::Tokio,
    opentelemetry_otlp::WithExportConfig,
    tonic::metadata::{MetadataKey, MetadataMap, MetadataValue},
};

#[cfg(any(feature = "otlp", feature = "prometheus"))]
use {
    git_version::git_version,
    opentelemetry::{
        sdk::{metrics::MeterProvider, Resource},
        KeyValue,
    },
    std::str::FromStr,
};

/// Errors from initializing metrics provider, registry, and exporter.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad IP address: {0}")]
    IpAddress(#[from] AddrParseError),
    #[error(transparent)]
    OpenTelemetry(#[from] opentelemetry::metrics::MetricsError),
    #[cfg(feature = "otlp")]
    #[error(transparent)]
    TonicMetadataKey(#[from] tonic::metadata::errors::InvalidMetadataKey),
    #[cfg(feature = "otlp")]
    #[error(transparent)]
    TonicMetadataValue(#[from] tonic::metadata::errors::InvalidMetadataValue),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Configuration for collection/exporting of application-level metrics.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MetricsConfiguration {
    /// Configuration for OpenTelemetry metrics, with a choice of exporters.
    #[serde(default, with = "serde_yaml::with::singleton_map")]
    pub exporter: Option<MetricsExporterConfiguration>,
}

/// Selection of an exporter for OpenTelemetry metrics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricsExporterConfiguration {
    Prometheus {
        host: Option<String>,
        port: Option<u16>,
    },
    Otlp(OtlpExporterConfiguration),
}

/// Configuration options specific to the OpenTelemetry OTLP metrics exporter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpExporterConfiguration {
    /// gRPC endpoint for OTLP exporter.
    pub endpoint: String,
    /// Additional metadata/HTTP headers to be sent with OTLP requests.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Choice of OpenTelemetry metrics exporter implementation.
pub enum MetricsExporterHandle {
    #[cfg(feature = "prometheus")]
    Prometheus {
        handle: JoinHandle<()>,
        port: u16,
    },
    #[cfg(feature = "otlp")]
    Otlp(MeterProvider),
    Noop,
}

#[derive(Debug)]
struct CustomAggregationSelector;

impl AggregationSelector for CustomAggregationSelector {
    fn aggregation(&self, kind: InstrumentKind) -> Aggregation {
        /// These boundaries are intended to be able to capture the length of short-lived operations
        /// (e.g HTTP requests) as well as longer-running operations.
        const DEFAULT_HISTOGRAM_BOUNDARIES: &[f64] = &[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 90.0, 300.0,
        ];

        match kind {
            InstrumentKind::Histogram => Aggregation::ExplicitBucketHistogram {
                boundaries: Vec::from(DEFAULT_HISTOGRAM_BOUNDARIES),
                record_min_max: true,
            },
            InstrumentKind::ObservableGauge => Aggregation::LastValue,
            _ => Aggregation::Sum,
        }
    }
}

/// Install a metrics provider and exporter, per the given configuration. The OpenTelemetry global
/// API can be used to create and update meters, and they will be sent through this exporter. The
/// returned handle should not be dropped until the application shuts down.
pub async fn install_metrics_exporter(
    config: &MetricsConfiguration,
) -> Result<MetricsExporterHandle, Error> {
    match &config.exporter {
        #[cfg(feature = "prometheus")]
        Some(MetricsExporterConfiguration::Prometheus {
            host: config_exporter_host,
            port: config_exporter_port,
        }) => {
            let registry = Registry::new();
            let exporter = opentelemetry_prometheus::exporter()
                .with_aggregation_selector(CustomAggregationSelector)
                .with_registry(registry.clone())
                .build()?;

            set_meter_provider(
                MeterProvider::builder()
                    .with_reader(exporter)
                    .with_resource(resource())
                    .build(),
            );

            let host = config_exporter_host
                .as_ref()
                .map(|host| IpAddr::from_str(host))
                .unwrap_or_else(|| Ok(Ipv4Addr::UNSPECIFIED.into()))?;
            let port = config_exporter_port.unwrap_or_else(|| 9464);

            let router = trillium_prometheus::text_format_handler(registry.clone());

            let (sender, receiver) = oneshot::channel();
            let init = Init::new(|info: Info| async move {
                // Ignore error if the receiver is dropped.
                let _ = sender.send(info.tcp_socket_addr().map(|socket_addr| socket_addr.port()));
            });

            let handle = tokio::task::spawn(
                trillium_tokio::config()
                    .with_port(port)
                    .with_host(&host.to_string())
                    .without_signals()
                    .run_async((init, router)),
            );

            let port = receiver
                .await
                .context("Init handler was dropped before sending port")?
                .context("server does not have a TCP port")?;

            Ok(MetricsExporterHandle::Prometheus { handle, port })
        }
        #[cfg(not(feature = "prometheus"))]
        Some(MetricsExporterConfiguration::Prometheus { .. }) => Err(Error::Other(anyhow!(
            "The OpenTelemetry Prometheus metrics exporter was enabled in the configuration file, \
             but support was not enabled at compile time. Rebuild with `--features prometheus`.",
        ))),

        #[cfg(feature = "otlp")]
        Some(MetricsExporterConfiguration::Otlp(otlp_config)) => {
            let mut map = MetadataMap::with_capacity(otlp_config.metadata.len());
            for (key, value) in otlp_config.metadata.iter() {
                map.insert(MetadataKey::from_str(key)?, MetadataValue::try_from(value)?);
            }

            let meter_provider = opentelemetry_otlp::new_pipeline()
                .metrics(Tokio)
                .with_aggregation_selector(CustomAggregationSelector)
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_endpoint(otlp_config.endpoint.clone()),
                )
                .with_resource(resource())
                .build()?;
            // We can't drop the PushController, as that would stop pushes, so return it to the
            // caller.
            Ok(MetricsExporterHandle::Otlp(meter_provider))
        }
        #[cfg(not(feature = "otlp"))]
        Some(MetricsExporterConfiguration::Otlp(_)) => Err(Error::Other(anyhow!(
            "The OpenTelemetry OTLP metrics exporter was enabled in the configuration file, but \
             support was not enabled at compile time. Rebuild with `--features otlp`.",
        ))),

        // If neither exporter is configured, leave the default NoopMeterProvider in place.
        None => Ok(MetricsExporterHandle::Noop),
    }
}

/// Produces a [`opentelemetry::sdk::Resource`] representing this process.
#[cfg(any(feature = "otlp", feature = "prometheus"))]
fn resource() -> Resource {
    // Note that the implementation of `Default` pulls in attributes set via environment variables.
    let default_resource = Resource::default();

    let mut git_revision = git_version!(fallback = "unknown");
    if git_revision == "unknown" {
        if let Some(value) = option_env!("GIT_REVISION") {
            git_revision = value;
        }
    }

    let version_info_resource = Resource::new([
        KeyValue::new(
            "service.version",
            format!("{}-{}", env!("CARGO_PKG_VERSION"), git_revision),
        ),
        KeyValue::new("process.runtime.name", "Rust"),
        KeyValue::new("process.runtime.version", env!("RUSTC_SEMVER")),
    ]);

    version_info_resource.merge(&default_resource)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "prometheus")]
    use super::{
        install_metrics_exporter, MetricsConfiguration, MetricsExporterConfiguration,
        MetricsExporterHandle,
    };
    #[cfg(feature = "prometheus")]
    use http::StatusCode;
    #[cfg(feature = "prometheus")]
    use janus_core::retries::{retry_http_request, test_http_request_exponential_backoff};

    #[cfg(feature = "prometheus")]
    #[tokio::test]
    async fn prometheus_metrics_pull() {
        let handle = install_metrics_exporter(&MetricsConfiguration {
            exporter: Some(MetricsExporterConfiguration::Prometheus {
                host: Some("127.0.0.1".to_owned()),
                port: Some(0),
            }),
        })
        .await
        .unwrap();
        let port = match handle {
            MetricsExporterHandle::Prometheus { port, .. } => port,
            _ => unreachable!(),
        };

        opentelemetry::global::meter("tests")
            .u64_observable_gauge("test_metric")
            .with_description("Gauge for test purposes")
            .init()
            .observe(1, &[]);

        let url = format!("http://127.0.0.1:{port}/metrics");
        let response = retry_http_request(test_http_request_exponential_backoff(), || {
            reqwest::get(&url)
        })
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/plain; version=0.0.4"
        );
        let text = response.text().await.unwrap();
        assert!(
            text.contains("HELP") && text.contains("TYPE"),
            "Exported metrics: {:?}",
            text
        );

        match handle {
            MetricsExporterHandle::Prometheus { handle, .. } => handle.abort(),
            _ => unreachable!(),
        }
    }
}
