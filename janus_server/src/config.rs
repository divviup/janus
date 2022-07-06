//! Configuration for various Janus binaries.

use crate::{metrics::MetricsConfiguration, trace::TraceConfiguration};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use url::Url;

/// Configuration options common to all Janus binaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonConfig {
    /// The database configuration.
    pub database: DbConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging_config: TraceConfiguration,
    /// Application-level metrics configuration
    #[serde(default)]
    pub metrics_config: MetricsConfiguration,
}

/// Trait describing configuration structures for various Janus binaries.
pub trait BinaryConfig: Debug + DeserializeOwned {
    /// Get common configuration.
    fn common_config(&mut self) -> &mut CommonConfig;
}

/// Configuration for a Janus server using a database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbConfig {
    /// URL at which to connect to the database.
    pub url: Url,
    // TODO(#231): add option for connecting to database over TLS, if necessary
}

/// Non-secret configuration options for Janus Job Driver jobs.
///
/// # Examples
///
/// ```
/// use janus_server::config::JobDriverConfig;
///
/// let yaml_config = r#"
/// ---
/// min_job_discovery_delay_secs: 10
/// max_job_discovery_delay_secs: 60
/// max_concurrent_job_workers: 10
/// worker_lease_duration_secs: 600
/// worker_lease_clock_skew_allowance_secs: 60
/// maximum_attempts_before_failure: 5
/// "#;
///
/// let _decoded: JobDriverConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDriverConfig {
    /// The minimum delay between checking for jobs ready to be stepped, in seconds. Applies only
    /// when there are no jobs to be stepped.
    pub min_job_discovery_delay_secs: u64,
    /// The maximum delay between checking for jobs ready to be stepped, in seconds. Applies only
    /// when there are no jobs to be stepped.
    pub max_job_discovery_delay_secs: u64,
    /// The maximum number of jobs being stepped at once. This parameter determines the amount of
    /// per-process concurrency.
    pub max_concurrent_job_workers: usize,
    /// The length of time, in seconds, workers will acquire a lease for the jobs they are stepping.
    /// Along with worker_lease_clock_skew_allowance, determines the effective timeout of stepping a
    /// single job.
    pub worker_lease_duration_secs: u64,
    /// The length of time, in seconds, workers decrease their timeouts from the lease length in
    /// order to guard against the possibility of clock skew. Along with worker_lease_duration_secs,
    /// determines the effective timeout of stepping a single job.
    pub worker_lease_clock_skew_allowance_secs: u64,
    /// The number of attempts to drive a work item before it is placed in a permanent failure
    /// state.
    pub maximum_attempts_before_failure: usize,
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::DbConfig;
    use crate::{
        metrics::{MetricsConfiguration, MetricsExporterConfiguration},
        trace::{
            OpenTelemetryTraceConfiguration, OtlpTraceConfiguration, TokioConsoleConfiguration,
            TraceConfiguration,
        },
    };
    use reqwest::Url;
    use serde::{de::DeserializeOwned, Serialize};
    use std::{collections::HashMap, fmt::Debug};

    pub fn roundtrip_encoding<T: Serialize + DeserializeOwned + Debug + Eq>(value: T) {
        let encoded = serde_yaml::to_string(&value).unwrap();
        let decoded = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(value, decoded);
    }

    pub fn generate_db_config() -> DbConfig {
        DbConfig {
            url: Url::parse("postgres://postgres:postgres@localhost:5432/postgres").unwrap(),
        }
    }

    pub fn generate_trace_config() -> TraceConfiguration {
        TraceConfiguration {
            use_test_writer: true,
            force_json_output: false,
            tokio_console_config: TokioConsoleConfiguration {
                enabled: true,
                listen_address: Some("127.0.0.1:6667".parse().unwrap()),
            },
            open_telemetry_config: Some(OpenTelemetryTraceConfiguration::Otlp(
                OtlpTraceConfiguration {
                    endpoint: "127.0.0.1:6668".to_string(),
                    metadata: HashMap::from([
                        ("metadata_key_0".to_string(), "metadata_value_0".to_string()),
                        ("metadata_key_1".to_string(), "metadata_value_1".to_string()),
                    ]),
                },
            )),
        }
    }

    pub fn generate_metrics_config() -> MetricsConfiguration {
        MetricsConfiguration {
            exporter: Some(MetricsExporterConfiguration::Prometheus {
                host: Some("prometheus_host".to_string()),
                port: Some(6669),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        test_util::{
            generate_db_config, generate_metrics_config, generate_trace_config, roundtrip_encoding,
        },
        CommonConfig, JobDriverConfig,
    };

    #[test]
    fn roundtrip_db_config() {
        roundtrip_encoding(generate_db_config())
    }

    #[test]
    fn roundtrip_common_config() {
        roundtrip_encoding(CommonConfig {
            database: generate_db_config(),
            logging_config: generate_trace_config(),
            metrics_config: generate_metrics_config(),
        })
    }

    #[test]
    fn roundtrip_job_driver_config() {
        roundtrip_encoding(JobDriverConfig {
            min_job_discovery_delay_secs: 10,
            max_job_discovery_delay_secs: 60,
            max_concurrent_job_workers: 10,
            worker_lease_duration_secs: 600,
            worker_lease_clock_skew_allowance_secs: 60,
            maximum_attempts_before_failure: 5,
        })
    }
}
