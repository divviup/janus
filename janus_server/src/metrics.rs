//! Collection and exporting of application-level metrics for Janus.

use opentelemetry::sdk::{
    export::metrics::AggregatorSelector,
    metrics::{
        aggregators::Aggregator,
        sdk_api::{Descriptor, InstrumentKind},
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::AddrParseError, sync::Arc};

#[cfg(feature = "prometheus")]
use {
    http::StatusCode,
    hyper::Response,
    opentelemetry::sdk::metrics::{controllers, processors},
    prometheus::{Encoder, TextEncoder},
    std::net::SocketAddr,
    std::net::{IpAddr, Ipv4Addr},
    tokio::task::JoinHandle,
    warp::{Filter, Reply},
};

#[cfg(feature = "otlp")]
use {
    opentelemetry::{
        runtime::Tokio,
        sdk::{metrics::controllers::BasicController, Resource},
        KeyValue,
    },
    opentelemetry_otlp::WithExportConfig,
    opentelemetry_semantic_conventions::resource::SERVICE_NAME,
    tonic::metadata::{MetadataKey, MetadataMap, MetadataValue},
};

#[cfg(any(feature = "otlp", feature = "prometheus"))]
use {
    opentelemetry::sdk::export::metrics::aggregation::stateless_temporality_selector,
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
    Otlp(BasicController),
    Noop,
}

#[derive(Debug)]
struct CustomAggregatorSelector;

impl AggregatorSelector for CustomAggregatorSelector {
    fn aggregator_for(&self, descriptor: &Descriptor) -> Option<Arc<dyn Aggregator + Send + Sync>> {
        match descriptor.instrument_kind() {
            InstrumentKind::Histogram => match descriptor.name() {
                "janus_job_acquire_time" => Some(Arc::new(
                    opentelemetry::sdk::metrics::aggregators::histogram(&[
                        0.01, 0.03, 0.1, 0.3, 1.0, 3.0, 10.0, 30.0, 90.0, 300.0,
                    ]),
                )),
                // The following boundaries are copied from the Ruby and Go Prometheus clients.
                // They are well-suited for HTTP request latencies.
                _ => Some(Arc::new(
                    opentelemetry::sdk::metrics::aggregators::histogram(&[
                        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                    ]),
                )),
            },
            InstrumentKind::GaugeObserver => Some(Arc::new(
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
            let exporter = opentelemetry_prometheus::exporter(
                controllers::basic(processors::factory(
                    CustomAggregatorSelector,
                    stateless_temporality_selector(),
                ))
                .build(),
            )
            .try_init()?;

            let host = config_exporter_host
                .as_ref()
                .map(|host| IpAddr::from_str(host))
                .unwrap_or_else(|| Ok(Ipv4Addr::UNSPECIFIED.into()))?;
            let port = config_exporter_port.unwrap_or_else(|| 9464);

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
                            tracing::error!(?error, "Failed to encode Prometheus metrics");
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
                map.insert(MetadataKey::from_str(key)?, MetadataValue::try_from(value)?);
            }

            let basic_controller = opentelemetry_otlp::new_pipeline()
                .metrics(
                    CustomAggregatorSelector,
                    stateless_temporality_selector(),
                    Tokio,
                )
                .with_resource(Resource::new([KeyValue::new(SERVICE_NAME, "janus_server")]))
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_endpoint(otlp_config.endpoint.clone()),
                )
                .build()?;
            // We can't drop the PushController, as that would stop pushes, so return it to the
            // caller.
            Ok(MetricsExporterHandle::Otlp(basic_controller))
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
