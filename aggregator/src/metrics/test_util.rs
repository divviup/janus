use std::collections::HashMap;

use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_sdk::{
    metrics::{data::Metric, PeriodicReader, SdkMeterProvider},
    runtime,
    testing::metrics::InMemoryMetricsExporter,
};
use tokio::task::spawn_blocking;

#[derive(Clone)]
pub(crate) struct InMemoryMetricsInfrastructure {
    /// The in-memory metrics exporter
    pub exporter: InMemoryMetricsExporter,
    /// The meter provider.
    pub meter_provider: SdkMeterProvider,
    /// A meter, with the name "test".
    pub meter: Meter,
}

impl InMemoryMetricsInfrastructure {
    /// Create an [`InMemoryMetricsExporter`], then use it to create an [`SdkMeterProvider`] and
    /// [`Meter`].
    pub(crate) fn new() -> InMemoryMetricsInfrastructure {
        let exporter = InMemoryMetricsExporter::default();
        let reader = PeriodicReader::builder(exporter.clone(), runtime::Tokio).build();
        let meter_provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = meter_provider.meter("test");
        InMemoryMetricsInfrastructure {
            exporter,
            meter_provider,
            meter,
        }
    }

    /// Flush all pending metrics, and return data indexed by metric name. All resource and scope
    /// information is ignored.
    pub(crate) async fn collect(&self) -> HashMap<String, Metric> {
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
    pub(crate) async fn shutdown(&self) {
        spawn_blocking({
            let meter_provider = self.meter_provider.clone();
            move || meter_provider.shutdown().unwrap()
        })
        .await
        .unwrap();
    }
}
