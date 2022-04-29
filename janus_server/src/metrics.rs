//! Collection and exporting of application-level metrics for Janus.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::AddrParseError};

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
    #[serde(default)]
    pub exporter: Option<MetricsExporterConfiguration>,
}

/// Selection of an exporter for OpenTelemetry metrics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricsExporterConfiguration {
    #[serde(rename = "prometheus")]
    Prometheus,
    #[serde(rename = "otlp")]
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
    Prometheus(
        opentelemetry_prometheus::PrometheusExporter,
        tokio::task::JoinHandle<()>,
    ),
    #[cfg(feature = "otlp")]
    Otlp(opentelemetry::sdk::metrics::controllers::PushController),
    Noop,
}

/// Install a metrics provider and exporter, per the given configuration. The OpenTelemetry global
/// API can be used to create and update meters, and they will be sent through this exporter. The
/// returned handle should not be dropped until the application shuts down.
pub fn install_metrics_exporter(
    config: &MetricsConfiguration,
) -> Result<MetricsExporterHandle, Error> {
    match &config.exporter {
        #[cfg(feature = "prometheus")]
        Some(MetricsExporterConfiguration::Prometheus) => {
            use http::StatusCode;
            use hyper::Response;
            use prometheus::{Encoder, TextEncoder};
            use std::net::SocketAddr;
            use warp::{Filter, Reply};

            let exporter = opentelemetry_prometheus::exporter().try_init()?;

            let filter = warp::path("metrics").and(warp::get()).map({
                let exporter = exporter.clone();
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
                        Err(err) => {
                            tracing::error!(%err, "failed to encode Prometheus metrics");
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
            });
            let listen_address = SocketAddr::new(exporter.host().parse()?, exporter.port());
            let handle = tokio::task::spawn(warp::serve(filter).bind(listen_address));

            Ok(MetricsExporterHandle::Prometheus(exporter, handle))
        }
        #[cfg(not(feature = "prometheus"))]
        Some(MetricsExporterConfiguration::Prometheus) => Err(Error::Other(
            "The OpenTelemetry Prometheus metrics exporter was enabled in the \
            configuration file, but support was not enabled at compile time. \
            Rebuild with `--features prometheus`.",
        )),

        #[cfg(feature = "otlp")]
        Some(MetricsExporterConfiguration::Otlp(otlp_config)) => {
            use opentelemetry::{util::tokio_interval_stream, KeyValue};
            use opentelemetry_otlp::WithExportConfig;
            use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
            use std::str::FromStr;
            use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};

            let mut map = MetadataMap::with_capacity(otlp_config.metadata.len());
            for (key, value) in otlp_config.metadata.iter() {
                map.insert(MetadataKey::from_str(key)?, MetadataValue::from_str(value)?);
            }

            let push_controller = opentelemetry_otlp::new_pipeline()
                .metrics(tokio::spawn, tokio_interval_stream)
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
