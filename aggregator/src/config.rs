//! Configuration for various Janus binaries.

use crate::{metrics::MetricsConfiguration, trace::TraceConfiguration};
use derivative::Derivative;
use janus_core::hpke::HpkeKeypair;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use url::Url;

/// Configuration options common to all Janus binaries.
///
/// # Examples
///
/// ```
/// use janus_aggregator::config::CommonConfig;
///
/// let yaml_config = r#"
/// ---
/// database:
///   url: postgres://postgres:postgres@localhost:5432/postgres
/// "#;
///
/// let _decoded: CommonConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
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

    /// Address to serve HTTP health check requests on.
    #[serde(default = "default_health_check_listen_address")]
    pub health_check_listen_address: SocketAddr,
}

fn default_health_check_listen_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9001)
}

/// Trait describing configuration structures for various Janus binaries.
pub trait BinaryConfig: Debug + DeserializeOwned {
    /// Get common configuration.
    fn common_config(&self) -> &CommonConfig;

    /// Get mutable reference to common configuration.
    fn common_config_mut(&mut self) -> &mut CommonConfig;
}

/// Configuration for a Janus server using a database.
#[derive(Clone, Derivative, PartialEq, Eq, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct DbConfig {
    /// URL at which to connect to the database.
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    pub url: Url,
    /// Timeout in seconds to apply when creating, waiting for, or recycling
    /// connection pool objects. This value will be used to construct a
    /// `deadpool_postgres::Timeouts` value.
    #[serde(default = "DbConfig::default_connection_pool_timeout")]
    pub connection_pool_timeouts_secs: u64,
    /// If false, the program will not check whether the database's current
    /// schema version is supported.
    #[serde(default = "DbConfig::default_check_schema_version")]
    pub check_schema_version: bool,
    // TODO(#231): add option for connecting to database over TLS, if necessary
}

impl DbConfig {
    fn default_connection_pool_timeout() -> u64 {
        60
    }

    fn default_check_schema_version() -> bool {
        true
    }
}

/// Configuration options for the Taskprov extension. This extension is
/// described in [draft-wang-ppm-dap-taskprov][spec], although its configuration
/// options are implementation-specific.
///
/// [spec]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TaskprovConfig {
    /// Whether to enable the extension or not. Enabling this changes the behavior
    /// of the aggregator consistent with the taskprov [specification][spec].
    ///
    /// [spec]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/
    pub enabled: bool,

    /// The global HPKE config to advertise when no task ID is provided in the HPKE config request.
    /// It's suggested to keep this configuration in the database instead of providing it in the
    /// plaintext config.
    #[serde(default)]
    pub global_hpke_keypair: Option<HpkeKeypair>,
}

/// Non-secret configuration options for Janus Job Driver jobs.
///
/// # Examples
///
/// ```
/// use janus_aggregator::config::JobDriverConfig;
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
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
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
    use std::collections::HashMap;

    pub fn generate_db_config() -> DbConfig {
        DbConfig {
            url: Url::parse("postgres://postgres:postgres@localhost:5432/postgres").unwrap(),
            connection_pool_timeouts_secs: DbConfig::default_connection_pool_timeout(),
            check_schema_version: DbConfig::default_check_schema_version(),
        }
    }

    pub fn generate_trace_config() -> TraceConfiguration {
        TraceConfiguration {
            use_test_writer: true,
            force_json_output: false,
            stackdriver_json_output: false,
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
            chrome: false,
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
    use crate::{
        config::{
            test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
            CommonConfig, DbConfig, JobDriverConfig,
        },
        metrics::MetricsExporterConfiguration,
        trace::OpenTelemetryTraceConfiguration,
    };
    use assert_matches::assert_matches;
    use janus_core::test_util::roundtrip_encoding;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn roundtrip_db_config() {
        roundtrip_encoding(generate_db_config())
    }

    #[test]
    fn db_config_default_timeout() {
        let db_config: DbConfig =
            serde_yaml::from_str("url: \"postgres://postgres:postgres@localhost:5432/postgres\"")
                .unwrap();
        assert_eq!(db_config.connection_pool_timeouts_secs, 60);
    }

    #[test]
    fn roundtrip_common_config() {
        roundtrip_encoding(CommonConfig {
            database: generate_db_config(),
            logging_config: generate_trace_config(),
            metrics_config: generate_metrics_config(),
            health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
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

    #[test]
    fn otlp_config() {
        let input = concat!(
            "database:\n",
            "  url: \"postgres://postgres@localhost/postgres\"\n",
            "logging_config:\n",
            "  open_telemetry_config:\n",
            "    otlp:\n",
            "      endpoint: \"https://example.com/\"\n",
            "      metadata:\n",
            "        key: \"value\"\n",
            "metrics_config:\n",
            "  exporter:\n",
            "    otlp:\n",
            "      endpoint: \"https://example.com/\"\n",
            "      metadata:\n",
            "        key: \"value\"\n",
        );
        let config: CommonConfig = serde_yaml::from_str(input).unwrap();
        assert_matches!(
            config.logging_config.open_telemetry_config.unwrap(),
            OpenTelemetryTraceConfiguration::Otlp(otlp_config) => {
                assert_eq!(otlp_config.endpoint, "https://example.com/");
                assert_eq!(otlp_config.metadata.len(), 1);
                assert_eq!(otlp_config.metadata.get("key").unwrap(), "value");
            }
        );
        assert_matches!(
            config.metrics_config.exporter.unwrap(),
            MetricsExporterConfiguration::Otlp(otlp_config) => {
                assert_eq!(otlp_config.endpoint, "https://example.com/");
                assert_eq!(otlp_config.metadata.len(), 1);
                assert_eq!(otlp_config.metadata.get("key").unwrap(), "value");
            }
        )
    }
}
