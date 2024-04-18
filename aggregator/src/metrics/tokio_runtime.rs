use std::time::Duration;

use tokio::runtime::{self, HistogramScale};

use crate::metrics::{HistogramScale as ConfigHistogramScale, TokioMetricsConfiguration};

impl From<ConfigHistogramScale> for HistogramScale {
    fn from(value: ConfigHistogramScale) -> Self {
        match value {
            ConfigHistogramScale::Linear => HistogramScale::Linear,
            ConfigHistogramScale::Log => HistogramScale::Log,
        }
    }
}

pub(crate) fn configure_runtime(
    runtime_builder: &mut runtime::Builder,
    config: &TokioMetricsConfiguration,
) {
    if config.enable_poll_time_histogram {
        runtime_builder.enable_metrics_poll_count_histogram();
        runtime_builder.metrics_poll_count_histogram_scale(config.poll_time_histogram_scale.into());
        if let Some(resolution) = config.poll_time_histogram_resolution_microseconds {
            let resolution = Duration::from_micros(resolution);
            runtime_builder.metrics_poll_count_histogram_resolution(resolution);
        }
        if let Some(buckets) = config.poll_time_histogram_buckets {
            runtime_builder.metrics_poll_count_histogram_buckets(buckets);
        }
    }
}
