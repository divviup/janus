//! Configuration for various Janus actors.

use crate::{metrics::MetricsConfiguration, trace::TraceConfiguration};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use url::Url;

/// Configuration for a Janus server using a database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbConfig {
    /// URL at which to connect to the database.
    pub url: Url,
    // TODO: add option for connecting to database over TLS, if necessary
}

/// Non-secret configuration options for a Janus aggregator, deserialized from
/// YAML.
///
/// # Examples
///
/// ```
/// use janus_server::config::AggregatorConfig;
///
/// let yaml_config = r#"
/// ---
/// listen_address: "0.0.0.0:8080"
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// "#;
///
/// let _decoded: AggregatorConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorConfig {
    /// Address on which this server should listen for connections and serve its
    /// API endpoints.
    // TODO: Options for terminating TLS, unless that gets handled in a load
    // balancer?
    pub listen_address: SocketAddr,
    /// The aggregator's database configuration.
    pub database: DbConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging_config: TraceConfiguration,
    /// Application-level metrics configuration
    #[serde(default)]
    pub metrics_config: MetricsConfiguration,
}

/// Non-secret configuration options for the Janus Aggregation Job Creator job.
///
/// # Examples
///
/// ```
/// use janus_server::config::AggregationJobCreatorConfig;
///
/// let yaml_config = r#"
/// ---
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// tasks_update_frequency_secs: 3600
/// aggregation_job_creation_interval_secs: 60
/// min_aggregation_job_size: 100
/// max_aggregation_job_size: 500
/// "#;
///
/// let _decoded: AggregationJobCreatorConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationJobCreatorConfig {
    /// Configuration for the database backend to connect to.
    pub database: DbConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging_config: TraceConfiguration,
    /// How frequently we look for new tasks to start creating aggregation jobs for, in seconds.
    pub tasks_update_frequency_secs: u64,
    /// How frequently we attempt to create new aggregation jobs for each task, in seconds.
    pub aggregation_job_creation_interval_secs: u64,
    /// The minimum number of client reports to include in an aggregation job. Applies to the
    /// "current" batch unit only; historical batch units will create aggregation jobs of any size,
    /// on the theory that almost all reports will have be received for these batch units already.
    pub min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    pub max_aggregation_job_size: usize,
}

/// Non-secret configuration options for the Janus Aggregation Job Driver job.
///
/// # Examples
///
/// ```
/// use janus_server::config::AggregationJobDriverConfig;
///
/// let yaml_config = r#"
/// ---
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// min_aggregation_job_discovery_delay_secs: 10
/// max_aggregation_job_discovery_delay_secs: 60
/// max_concurrent_aggregation_job_workers: 10
/// aggregation_worker_lease_duration_secs: 600
/// aggregation_worker_lease_clock_skew_allowance_secs: 60
/// "#;
///
/// let _decoded: AggregationJobDriverConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationJobDriverConfig {
    /// Configuration for the database backend to connect to.
    pub database: DbConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging_config: TraceConfiguration,
    /// The minimum delay between checking for aggregation jobs ready to be stepped, in seconds.
    /// Applies only when there are no aggregation jobs to be stepped.
    pub min_aggregation_job_discovery_delay_secs: u64,
    /// The maximum delay between checking for aggregation jobs ready to be stepped, in seconds.
    /// Applies only when there are no aggregation jobs to be stepped.
    pub max_aggregation_job_discovery_delay_secs: u64,
    /// The maximum number of aggregation jobs being stepped at once. This parameter determines the
    /// amount of per-process concurrency.
    pub max_concurrent_aggregation_job_workers: usize,
    /// The length of time, in seconds, workers will acquire a lease for the aggregation jobs they
    /// are stepping. Along with aggregation_worker_lease_clock_skew_allowance, determines the
    /// effective timeout of stepping a single aggregation job.
    pub aggregation_worker_lease_duration_secs: u64,
    /// The length of time, in seconds, workers decrease their timeouts from the lease length in
    /// order to guard against the possibility of clock skew. Along with
    /// aggregation_worker_lease_duration_secs, determines the effective timeout of stepping
    /// a single aggregation job.
    pub aggregation_worker_lease_clock_skew_allowance_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metrics::{MetricsExporterConfiguration, OtlpExporterConfiguration},
        trace::{
            OpenTelemetryTraceConfiguration, OtlpTraceConfiguration, TokioConsoleConfiguration,
        },
    };
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
    };

    fn generate_db_config() -> DbConfig {
        DbConfig {
            url: Url::parse("postgres://postgres:postgres@localhost:5432/postgres").unwrap(),
        }
    }

    #[test]
    fn roundtrip_db_config() {
        let db_config = generate_db_config();
        let encoded = serde_yaml::to_string(&db_config).unwrap();
        let decoded: DbConfig = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(db_config, decoded);
    }

    #[test]
    fn roundtrip_aggregator_config() {
        let aggregator_config = AggregatorConfig {
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
            database: generate_db_config(),
            logging_config: TraceConfiguration::default(),
            metrics_config: MetricsConfiguration::default(),
        };

        let encoded = serde_yaml::to_string(&aggregator_config).unwrap();
        let decoded: AggregatorConfig = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(aggregator_config, decoded);
    }

    #[test]
    fn roundtrip_aggregation_job_creator_config() {
        let config = AggregationJobCreatorConfig {
            database: generate_db_config(),
            logging_config: TraceConfiguration::default(),
            tasks_update_frequency_secs: 3600,
            aggregation_job_creation_interval_secs: 60,
            min_aggregation_job_size: 100,
            max_aggregation_job_size: 500,
        };

        let encoded = serde_yaml::to_string(&config).unwrap();
        let decoded_config: AggregationJobCreatorConfig = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(config, decoded_config);
    }

    #[test]
    fn roundtrip_aggregation_job_driver_config() {
        let config = AggregationJobDriverConfig {
            database: generate_db_config(),
            logging_config: TraceConfiguration::default(),
            min_aggregation_job_discovery_delay_secs: 10,
            max_aggregation_job_discovery_delay_secs: 60,
            max_concurrent_aggregation_job_workers: 10,
            aggregation_worker_lease_duration_secs: 600,
            aggregation_worker_lease_clock_skew_allowance_secs: 60,
        };

        let encoded = serde_yaml::to_string(&config).unwrap();
        let decoded_config: AggregationJobDriverConfig = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(config, decoded_config);
    }

    /// Check that configuration fragments in the README can be parsed correctly.
    #[test]
    fn readme_config_examples() {
        assert_eq!(
            serde_yaml::from_str::<AggregatorConfig>(
                r#"---
listen_address: "0.0.0.0:8080"
database:
    url: "postgres://postgres:postgres@localhost:5432/postgres"
logging_config:
    tokio_console_config:
        enabled: true
        listen_address: 127.0.0.1:6669
"#
            )
            .unwrap()
            .logging_config
            .tokio_console_config,
            TokioConsoleConfiguration {
                enabled: true,
                listen_address: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    6669,
                )),
            },
        );

        assert_eq!(
            serde_yaml::from_str::<AggregatorConfig>(
                r#"---
listen_address: "0.0.0.0:8080"
database:
    url: "postgres://postgres:postgres@localhost:5432/postgres"
logging_config:
    open_telemetry_config:
        jaeger:
"#
            )
            .unwrap()
            .logging_config
            .open_telemetry_config,
            Some(OpenTelemetryTraceConfiguration::Jaeger),
        );

        assert_eq!(
            serde_yaml::from_str::<AggregatorConfig>(
                r#"---
listen_address: "0.0.0.0:8080"
database:
    url: "postgres://postgres:postgres@localhost:5432/postgres"
logging_config:
    open_telemetry_config:
        otlp:
            endpoint: "https://api.honeycomb.io:443"
            metadata:
                x-honeycomb-team: "YOUR_API_KEY"
"#
            )
            .unwrap()
            .logging_config
            .open_telemetry_config,
            Some(OpenTelemetryTraceConfiguration::Otlp(
                OtlpTraceConfiguration {
                    endpoint: "https://api.honeycomb.io:443".to_string(),
                    metadata: HashMap::from([(
                        "x-honeycomb-team".to_string(),
                        "YOUR_API_KEY".to_string(),
                    )]),
                },
            )),
        );

        assert_eq!(
            serde_yaml::from_str::<AggregatorConfig>(
                r#"---
listen_address: "0.0.0.0:8080"
database:
    url: "postgres://postgres:postgres@localhost:5432/postgres"
metrics_config:
    exporter:
        prometheus:
            host: 0.0.0.0
            port: 9464
"#
            )
            .unwrap()
            .metrics_config
            .exporter,
            Some(MetricsExporterConfiguration::Prometheus {
                host: Some("0.0.0.0".to_string()),
                port: Some(9464),
            }),
        );

        assert_eq!(
            serde_yaml::from_str::<AggregatorConfig>(
                r#"---
listen_address: "0.0.0.0:8080"
database:
    url: "postgres://postgres:postgres@localhost:5432/postgres"
metrics_config:
    exporter:
        otlp:
            endpoint: "https://api.honeycomb.io:443"
            metadata:
                x-honeycomb-team: "YOUR_API_KEY"
                x-honeycomb-dataset: "YOUR_METRICS_DATASET"
"#
            )
            .unwrap()
            .metrics_config
            .exporter,
            Some(MetricsExporterConfiguration::Otlp(
                OtlpExporterConfiguration {
                    endpoint: "https://api.honeycomb.io:443".to_string(),
                    metadata: HashMap::from([
                        ("x-honeycomb-team".to_string(), "YOUR_API_KEY".to_string()),
                        (
                            "x-honeycomb-dataset".to_string(),
                            "YOUR_METRICS_DATASET".to_string(),
                        ),
                    ]),
                },
            )),
        );
    }
}
