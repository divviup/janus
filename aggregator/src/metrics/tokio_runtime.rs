use tokio::runtime::HistogramScale;

use crate::metrics::HistogramScale as ConfigHistogramScale;

impl From<ConfigHistogramScale> for HistogramScale {
    fn from(value: ConfigHistogramScale) -> Self {
        match value {
            ConfigHistogramScale::Linear => HistogramScale::Linear,
            ConfigHistogramScale::Log => HistogramScale::Log,
        }
    }
}
