//! Collection and exporting of application-level metrics for Janus.

use opentelemetry::{
    metrics::Descriptor,
    sdk::export::metrics::{Aggregator, AggregatorSelector},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::AddrParseError, sync::Arc};

#[cfg(feature = "prometheus")]
use {
    http::StatusCode,
    hyper::Response,
    prometheus::{Encoder, TextEncoder},
    std::net::SocketAddr,
    tokio::task::JoinHandle,
    warp::{Filter, Reply},
};

#[cfg(feature = "otlp")]
use {
    opentelemetry::{
        sdk::metrics::controllers::PushController, util::tokio_interval_stream, KeyValue,
    },
    opentelemetry_otlp::WithExportConfig,
    opentelemetry_semantic_conventions::resource::SERVICE_NAME,
    std::str::FromStr,
    tonic::metadata::{MetadataKey, MetadataMap, MetadataValue},
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
    Other(&'static str),
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
    Prometheus(JoinHandle<()>),
    #[cfg(feature = "otlp")]
    Otlp(PushController),
    Noop,
}

#[derive(Debug)]
struct CustomAggregatorSelector;

impl AggregatorSelector for CustomAggregatorSelector {
    fn aggregator_for(&self, descriptor: &Descriptor) -> Option<Arc<dyn Aggregator + Send + Sync>> {
        match descriptor.instrument_kind() {
            opentelemetry::metrics::InstrumentKind::ValueRecorder => {
                // The following boundaries are copied from the Ruby and Go Prometheus clients.
                // Buckets could be specialized per-metric by matching on `descriptor.name()`.
                let boundaries = &[
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ][..];
                Some(Arc::new(
                    opentelemetry::sdk::metrics::aggregators::histogram(descriptor, boundaries),
                ))
            }
            opentelemetry::metrics::InstrumentKind::ValueObserver => Some(Arc::new(
                opentelemetry::sdk::metrics::aggregators::last_value(),
            )),
            _ => Some(Arc::new(opentelemetry::sdk::metrics::aggregators::sum())),
        }
    }
}

/// Install a metrics provider and exporter, per the given configuration. The OpenTelemetry global
/// API can be used to create and update meters, and they will be sent through this exporter. The
/// returned handle should not be dropped until the application shuts down.
pub fn install_metrics_exporter(
    config: &MetricsConfiguration,
) -> Result<MetricsExporterHandle, Error> {
    match &config.exporter {
        #[cfg(feature = "prometheus")]
        Some(MetricsExporterConfiguration::Prometheus {
            host: config_exporter_host,
            port: config_exporter_port,
        }) => {
            let mut builder = opentelemetry_prometheus::exporter()
                .with_aggregator_selector(CustomAggregatorSelector);
            if let Some(host) = config_exporter_host {
                builder = builder.with_host(host.clone());
            }
            if let Some(port) = config_exporter_port {
                builder = builder.with_port(*port);
            }
            let exporter = builder.try_init()?;
            let host = exporter.host().parse()?;
            let port = exporter.port();

            let filter = warp::path("metrics").and(warp::get()).map({
                move || {
                    let mut buffer = Vec::new();
                    let encoder = TextEncoder::new();
                    match encoder.encode(&exporter.registry().gather(), &mut buffer) {
                        Ok(()) => Response::builder()
                            .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                            .body(buffer)
                            // This unwrap is OK because the only possible source of errors is the
                            // `header()` call, and its arguments are always valid.
                            .unwrap()
                            .into_response(),
                        Err(error) => {
                            tracing::error!(%error, "Failed to encode Prometheus metrics");
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
            });
            let listen_address = SocketAddr::new(host, port);
            let handle = tokio::task::spawn(warp::serve(filter).bind(listen_address));

            Ok(MetricsExporterHandle::Prometheus(handle))
        }
        #[cfg(not(feature = "prometheus"))]
        Some(MetricsExporterConfiguration::Prometheus { .. }) => Err(Error::Other(
            "The OpenTelemetry Prometheus metrics exporter was enabled in the \
            configuration file, but support was not enabled at compile time. \
            Rebuild with `--features prometheus`.",
        )),

        #[cfg(feature = "otlp")]
        Some(MetricsExporterConfiguration::Otlp(otlp_config)) => {
            let mut map = MetadataMap::with_capacity(otlp_config.metadata.len());
            for (key, value) in otlp_config.metadata.iter() {
                map.insert(MetadataKey::from_str(key)?, MetadataValue::from_str(value)?);
            }

            let push_controller = opentelemetry_otlp::new_pipeline()
                .metrics(tokio::spawn, tokio_interval_stream)
                .with_aggregator_selector(CustomAggregatorSelector)
                .with_resource([KeyValue::new(SERVICE_NAME, "janus_server")])
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_endpoint(otlp_config.endpoint.clone()),
                )
                .build()?;
            // We can't drop the PushController, as that would stop pushes, so return it to the
            // caller.
            Ok(MetricsExporterHandle::Otlp(push_controller))
        }
        #[cfg(not(feature = "otlp"))]
        Some(MetricsExporterConfiguration::Otlp(_)) => Err(Error::Other(
            "The OpenTelemetry OTLP metrics exporter was enabled in the \
            configuration file, but support was not enabled at compile time. \
            Rebuild with `--features otlp`.",
        )),

        // If neither exporter is configured, leave the default NoopMeterProvider in place.
        None => Ok(MetricsExporterHandle::Noop),
    }
}
