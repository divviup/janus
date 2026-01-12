//! Configuration for various Janus binaries.

use crate::{metrics::MetricsConfiguration, trace::TraceConfiguration};
use educe::Educe;
use janus_core::retries::ExponentialWithTotalDelayBuilder;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// The maximum number of times a transaction can be retried. The intent is to guard against bugs
    /// that induce infinite retries. It should be set to a reasonably high limit to prevent legitimate
    /// work from being cancelled.
    #[serde(default = "default_max_transaction_retries")]
    pub max_transaction_retries: u64,

    /// Stack size, in bytes, for threads used for VDAF preparation.
    ///
    /// Optional. If not set, the default stack size will be used. This is currently 2 MiB on most
    /// platforms. See <https://doc.rust-lang.org/std/thread/index.html#stack-size>.
    #[serde(default)]
    pub thread_pool_stack_size: Option<usize>,
}

fn default_health_check_listen_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9001)
}

pub fn default_max_transaction_retries() -> u64 {
    1000
}

/// Trait describing configuration structures for various Janus binaries.
pub trait BinaryConfig: Debug + DeserializeOwned {
    /// Get common configuration.
    fn common_config(&self) -> &CommonConfig;

    /// Get mutable reference to common configuration.
    fn common_config_mut(&mut self) -> &mut CommonConfig;
}

/// Configuration for a Janus server using a database.
#[derive(Clone, Educe, PartialEq, Eq, Serialize, Deserialize)]
#[educe(Debug)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    /// URL at which to connect to the database.
    #[educe(Debug(method(format_database_url)))]
    pub url: Url,

    /// Timeout in seconds to apply when creating, waiting for, or recycling
    /// connection pool objects. This value will be used to construct a
    /// `deadpool_postgres::Timeouts` value.
    #[serde(default = "DbConfig::default_connection_pool_timeout")]
    pub connection_pool_timeouts_s: u64,

    /// Maximum size of the connection pool. Affects the number of concurrent database operations.
    /// If unspecified, the default is `cpu_count * 4`, see [`deadpool_postgres::PoolConfig`].
    ///
    /// Be aware that each connection pool slot consumes a database connection. Ensure that the
    /// database has sufficient resources to handle the maximum number of connections, and that
    /// the database `max_connections` limit is high enough.
    pub connection_pool_max_size: Option<usize>,

    /// If false, the program will not check whether the database's current
    /// schema version is supported.
    #[serde(default = "DbConfig::default_check_schema_version")]
    pub check_schema_version: bool,

    /// Path to a PEM file with root certificates to trust for TLS database connections.
    #[serde(default)]
    pub tls_trust_store_path: Option<PathBuf>,
}

impl DbConfig {
    fn default_connection_pool_timeout() -> u64 {
        60
    }

    fn default_check_schema_version() -> bool {
        true
    }
}

/// Makes a best-effort attempt to redact the password from the database URL, so that it is safe
/// to display in logs.
fn format_database_url(url: &Url, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
    match url.password() {
        Some(_) => {
            let mut url = url.clone();
            let _ = url.set_password(Some("REDACTED"));
            fmt.write_str(url.as_str())
        }
        None => fmt.write_str(url.as_str()),
    }
}

/// Configuration options for the Taskprov extension. This extension is
/// described in [draft-wang-ppm-dap-taskprov][spec], although its configuration
/// options are implementation-specific.
///
/// [spec]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TaskprovConfig {
    /// Whether to enable the extension or not. Enabling this changes the behavior
    /// of the aggregator consistent with the taskprov [specification][spec].
    ///
    /// [spec]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/
    pub enabled: bool,
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
/// job_discovery_interval_s: 10
/// max_concurrent_job_workers: 10
/// worker_lease_duration_s: 600
/// worker_lease_clock_skew_allowance_s: 60
/// maximum_attempts_before_failure: 5
/// retry_initial_interval_ms: 1000
/// retry_max_interval_ms: 30000
/// retry_max_elapsed_time_ms: 300000
/// "#;
///
/// let _decoded: JobDriverConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobDriverConfig {
    /// The delay between checking for jobs ready to be stepped, in seconds. Applies only when
    /// there are no jobs to be stepped.
    pub job_discovery_interval_s: u64,
    /// The maximum number of jobs being stepped at once. This parameter determines the amount of
    /// per-process concurrency.
    pub max_concurrent_job_workers: usize,
    /// The length of time, in seconds, workers will acquire a lease for the jobs they are stepping.
    /// Along with worker_lease_clock_skew_allowance, determines the effective timeout of stepping a
    /// single job.
    pub worker_lease_duration_s: u64,
    /// The length of time, in seconds, workers decrease their timeouts from the lease length in
    /// order to guard against the possibility of clock skew. Along with worker_lease_duration_s,
    /// determines the effective timeout of stepping a single job.
    pub worker_lease_clock_skew_allowance_s: u64,
    /// The number of attempts to drive a work item before it is placed in a permanent failure
    /// state.
    pub maximum_attempts_before_failure: usize,

    /// Timeout to apply when establishing connections to the helper for HTTP requests. See
    /// [`reqwest::ClientBuilder::connect_timeout`] for details.
    #[serde(default = "JobDriverConfig::default_http_connection_timeout_s")]
    pub http_request_connection_timeout_s: u64,
    /// Timeout to apply to HTTP requests overall (including connection establishment) when
    /// communicating with the helper. See [`reqwest::ClientBuilder::timeout`] for details.
    #[serde(default = "JobDriverConfig::default_http_request_timeout_s")]
    pub http_request_timeout_s: u64,

    /// The initial interval, in milliseconds, to wait before retrying a retryable HTTP request.
    #[serde(default = "JobDriverConfig::default_retry_initial_interval_ms")]
    pub retry_initial_interval_ms: u64,
    /// The maximum interval, in milliseconds, to wait before retrying a retryable HTTP request.
    #[serde(default = "JobDriverConfig::default_retry_max_interval_ms")]
    pub retry_max_interval_ms: u64,
    /// The maximum retry time, in milliseconds, to wait before giving up on retrying a retryable
    /// HTTP request. Note this is the sum of the retry intervals, not wall-clock time.
    #[serde(default = "JobDriverConfig::default_retry_max_elapsed_time_ms")]
    pub retry_max_elapsed_time_ms: u64,
}

impl JobDriverConfig {
    pub fn retry_config(&self) -> ExponentialWithTotalDelayBuilder {
        ExponentialWithTotalDelayBuilder::new()
            .without_max_times()
            .with_min_delay(Duration::from_millis(self.retry_initial_interval_ms))
            .with_max_delay(Duration::from_millis(self.retry_max_interval_ms))
            .with_total_delay(Some(Duration::from_millis(self.retry_max_elapsed_time_ms)))
    }

    fn default_http_connection_timeout_s() -> u64 {
        10
    }

    fn default_http_request_timeout_s() -> u64 {
        30
    }

    fn default_retry_initial_interval_ms() -> u64 {
        1000
    }

    fn default_retry_max_interval_ms() -> u64 {
        30_000
    }

    fn default_retry_max_elapsed_time_ms() -> u64 {
        300_000
    }
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

    pub fn generate_db_config() -> DbConfig {
        DbConfig {
            url: Url::parse("postgres://postgres:postgres@localhost:5432/postgres").unwrap(),
            connection_pool_timeouts_s: DbConfig::default_connection_pool_timeout(),
            connection_pool_max_size: None,
            check_schema_version: DbConfig::default_check_schema_version(),
            tls_trust_store_path: None,
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
            tokio: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{
            CommonConfig, DbConfig, JobDriverConfig, default_max_transaction_retries,
            test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
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
        assert_eq!(db_config.connection_pool_timeouts_s, 60);
    }

    #[test]
    fn db_config_max_retries() {
        let db_config: DbConfig =
            serde_yaml::from_str("url: \"postgres://postgres:postgres@localhost:5432/postgres\"")
                .unwrap();
        assert_eq!(db_config.connection_pool_max_size, None);

        let db_config: DbConfig = serde_yaml::from_str(
            "url: \"postgres://postgres:postgres@localhost:5432/postgres\"
connection_pool_max_size: 42",
        )
        .unwrap();
        assert_eq!(db_config.connection_pool_max_size, Some(42));
    }

    #[test]
    fn roundtrip_common_config() {
        roundtrip_encoding(CommonConfig {
            database: generate_db_config(),
            logging_config: generate_trace_config(),
            metrics_config: generate_metrics_config(),
            health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
            max_transaction_retries: default_max_transaction_retries(),
            thread_pool_stack_size: None,
        })
    }

    #[test]
    fn roundtrip_job_driver_config() {
        roundtrip_encoding(JobDriverConfig {
            job_discovery_interval_s: 10,
            max_concurrent_job_workers: 10,
            worker_lease_duration_s: 600,
            worker_lease_clock_skew_allowance_s: 60,
            maximum_attempts_before_failure: 5,
            http_request_connection_timeout_s: 10,
            http_request_timeout_s: 30,
            retry_initial_interval_ms: 1000,
            retry_max_interval_ms: 30_000,
            retry_max_elapsed_time_ms: 300_000,
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
            "metrics_config:\n",
            "  exporter:\n",
            "    otlp:\n",
            "      endpoint: \"https://example.com/\"\n",
        );
        let config: CommonConfig = serde_yaml::from_str(input).unwrap();
        assert_matches!(
            config.logging_config.open_telemetry_config.unwrap(),
            OpenTelemetryTraceConfiguration::Otlp(otlp_config) => {
                assert_eq!(otlp_config.endpoint, "https://example.com/");
            }
        );
        assert_matches!(
            config.metrics_config.exporter.unwrap(),
            MetricsExporterConfiguration::Otlp(otlp_config) => {
                assert_eq!(otlp_config.endpoint, "https://example.com/");
            }
        )
    }

    #[test]
    fn tokio_metrics_config() {
        let input = "---
database:
  url: postgres://postgres@localhost/postgres
metrics_config:
  exporter:
    prometheus:
      host: 0.0.0.0
      port: 9464
  tokio:
    enabled: true
";
        let config: CommonConfig = serde_yaml::from_str(input).unwrap();
        let tokio_config = config.metrics_config.tokio.unwrap();
        assert!(tokio_config.enabled);
    }
}
