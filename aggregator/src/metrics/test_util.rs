use std::collections::HashMap;

use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_sdk::{
    metrics::{PeriodicReader, SdkMeterProvider, data::Metric},
    runtime,
    testing::metrics::InMemoryMetricExporter,
};
use tokio::task::spawn_blocking;

/// Encapsulates an OpenTelemetry exporter, meter provider, and meter, for use in metrics tests.
#[derive(Clone)]
pub struct InMemoryMetricInfrastructure {
    /// The in-memory metric exporter
    pub exporter: InMemoryMetricExporter,
    /// The meter provider.
    pub meter_provider: SdkMeterProvider,
    /// A meter, with the name "test".
    pub meter: Meter,
}

impl InMemoryMetricInfrastructure {
    /// Create an [`InMemoryMetricExporter`], then use it to create an [`SdkMeterProvider`] and
    /// [`Meter`].
    pub fn new() -> InMemoryMetricInfrastructure {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone(), runtime::Tokio).build();
        let meter_provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = meter_provider.meter("test");
        InMemoryMetricInfrastructure {
            exporter,
            meter_provider,
            meter,
        }
    }

    /// Flush all pending metrics, and return data indexed by metric name. All resource and scope
    /// information is ignored.
    pub async fn collect(&self) -> HashMap<String, Metric> {
        spawn_blocking({
            let meter_provider = self.meter_provider.clone();
            move || meter_provider.force_flush().unwrap()
        })
        .await
        .unwrap();

        // Discard resource and scope information, collect all metrics by name.
        self.exporter
            .get_finished_metrics()
            .unwrap()
            .into_iter()
            .flat_map(|resource_metrics| resource_metrics.scope_metrics)
            .flat_map(|scope_metrics| scope_metrics.metrics.into_iter())
            .map(|metric| (metric.name.to_string(), metric))
            .collect::<HashMap<_, _>>()
    }

    /// Shut down the periodic reader.
    pub async fn shutdown(&self) {
        spawn_blocking({
            let meter_provider = self.meter_provider.clone();
            move || meter_provider.shutdown().unwrap()
        })
        .await
        .unwrap();
    }
}

impl Default for InMemoryMetricInfrastructure {
    fn default() -> Self {
        Self::new()
    }
}
