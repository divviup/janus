//! Configuration for various Janus binaries.

use crate::{metrics::MetricsConfiguration, trace::TraceConfiguration};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Debug, net::SocketAddr};
use url::Url;

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
    // TODO: add option for connecting to database over TLS, if necessary
}

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

    #[serde(flatten)]
    pub common_config: CommonConfig,
}

impl BinaryConfig for AggregatorConfig {
    fn common_config(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

/// Non-secret configuration options for the Janus Job Creator jobs.
///
/// # Examples
///
/// ```
/// use janus_server::config::JobCreatorConfig;
///
/// let yaml_config = r#"
/// ---
/// tasks_update_frequency_secs: 3600
/// job_creation_interval_secs: 60
/// "#;
///
/// let _decoded: JobCreatorConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobCreatorConfig {
    /// How frequently we look for new tasks to start creating jobs for, in seconds.
    pub tasks_update_frequency_secs: u64,
    /// How frequently we attempt to create new jobs for each task, in seconds.
    pub job_creation_interval_secs: u64,
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
/// job_creation_interval_secs: 60
/// min_aggregation_job_size: 100
/// max_aggregation_job_size: 500
/// "#;
///
/// let _decoded: AggregationJobCreatorConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationJobCreatorConfig {
    #[serde(flatten)]
    pub common_config: CommonConfig,

    #[serde(flatten)]
    pub job_creator_config: JobCreatorConfig,

    /// The minimum number of client reports to include in an aggregation job. Applies to the
    /// "current" batch unit only; historical batch units will create aggregation jobs of any size,
    /// on the theory that almost all reports will have be received for these batch units already.
    pub min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    pub max_aggregation_job_size: usize,
}

impl BinaryConfig for AggregationJobCreatorConfig {
    fn common_config(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

/// Non-secret configuration options for the Janus Collect Job Creator job.
///
/// # Examples
///
/// ```
/// use janus_server::config::CollectJobCreatorConfig;
///
/// let yaml_config = r#"
/// ---
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// tasks_update_frequency_secs: 3600
/// job_creation_interval_secs: 60
/// "#;
///
/// let _decoded: CollectJobCreatorConfig = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectJobCreatorConfig {
    #[serde(flatten)]
    pub common_config: CommonConfig,

    #[serde(flatten)]
    pub job_creator_config: JobCreatorConfig,
    // More config options to come?
}

impl BinaryConfig for CollectJobCreatorConfig {
    fn common_config(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
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
    #[serde(flatten)]
    pub common_config: CommonConfig,

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

impl BinaryConfig for AggregationJobDriverConfig {
    fn common_config(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
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

    fn roundtrip_encoding<T: Serialize + DeserializeOwned + Debug + Eq>(value: T) {
        let encoded = serde_yaml::to_string(&value).unwrap();
        let decoded = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(value, decoded);
    }

    fn generate_db_config() -> DbConfig {
        DbConfig {
            url: Url::parse("postgres://postgres:postgres@localhost:5432/postgres").unwrap(),
        }
    }

    #[test]
    fn roundtrip_db_config() {
        roundtrip_encoding(generate_db_config())
    }

    #[test]
    fn roundtrip_common_config() {
        roundtrip_encoding(CommonConfig {
            database: generate_db_config(),
            logging_config: TraceConfiguration::default(),
            metrics_config: MetricsConfiguration::default(),
        })
    }

    #[test]
    fn roundtrip_aggregator_config() {
        roundtrip_encoding(AggregatorConfig {
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: TraceConfiguration::default(),
                metrics_config: MetricsConfiguration::default(),
            },
        })
    }

    #[test]
    fn roundtrip_job_creator_config() {
        roundtrip_encoding(JobCreatorConfig {
            tasks_update_frequency_secs: 3600,
            job_creation_interval_secs: 60,
        })
    }

    #[test]
    fn roundtrip_aggregation_job_creator_config() {
        roundtrip_encoding(AggregationJobCreatorConfig {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: TraceConfiguration::default(),
                metrics_config: MetricsConfiguration::default(),
            },
            job_creator_config: JobCreatorConfig {
                tasks_update_frequency_secs: 3600,
                job_creation_interval_secs: 60,
            },
            min_aggregation_job_size: 100,
            max_aggregation_job_size: 500,
        })
    }

    #[test]
    fn roundtrip_collect_job_creator_config() {
        roundtrip_encoding(CollectJobCreatorConfig {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: TraceConfiguration::default(),
                metrics_config: MetricsConfiguration::default(),
            },
            job_creator_config: JobCreatorConfig {
                tasks_update_frequency_secs: 3600,
                job_creation_interval_secs: 60,
            },
        })
    }

    #[test]
    fn roundtrip_aggregation_job_driver_config() {
        roundtrip_encoding(AggregationJobDriverConfig {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: TraceConfiguration::default(),
                metrics_config: MetricsConfiguration::default(),
            },
            min_aggregation_job_discovery_delay_secs: 10,
            max_aggregation_job_discovery_delay_secs: 60,
            max_concurrent_aggregation_job_workers: 10,
            aggregation_worker_lease_duration_secs: 600,
            aggregation_worker_lease_clock_skew_allowance_secs: 60,
        })
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
            .common_config
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
            .common_config
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
            .common_config
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
            .common_config
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
            .common_config
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
