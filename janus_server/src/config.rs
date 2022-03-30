//! Configuration for various Janus actors

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
        };

        let encoded = serde_yaml::to_string(&aggregator_config).unwrap();
        let decoded: AggregatorConfig = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(aggregator_config, decoded);
    }
}
