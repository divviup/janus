use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use janus_core::time::RealClock;
use serde::{Deserialize, Serialize};

use crate::{
    aggregator::key_rotator::{
        deserialize_hpke_key_rotator_config, HpkeKeyRotatorConfig, KeyRotator,
    },
    binary_utils::{BinaryContext, BinaryOptions, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
};

pub async fn main_callback(ctx: BinaryContext<RealClock, Options, Config>) -> Result<()> {
    let BinaryContext {
        config, datastore, ..
    } = ctx;

    KeyRotator::new(Arc::new(datastore), config.key_rotator.hpke)
        .run()
        .await
}

#[derive(Debug, Default, Parser)]
#[clap(
    name = "key-rotator",
    about = "Janus key rotator",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
pub struct Options {
    #[clap(flatten)]
    pub common: CommonBinaryOptions,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        &self.common
    }
}

/// Non-secret configuration options for a Janus key rotator, deserialized from YAML.
///
/// # Examples
///
/// ```
/// # use janus_aggregator::binaries::key_rotator::Config;
/// let yaml_config = r#"
/// ---
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// key_rotator:
///   hpke: {}
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(flatten)]
    pub common_config: CommonConfig,
    pub key_rotator: KeyRotatorConfig,
}

impl BinaryConfig for Config {
    fn common_config(&self) -> &CommonConfig {
        &self.common_config
    }

    fn common_config_mut(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotatorConfig {
    #[serde(deserialize_with = "deserialize_hpke_key_rotator_config")]
    pub hpke: HpkeKeyRotatorConfig,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::{Ipv4Addr, SocketAddr},
    };

    use clap::CommandFactory;
    use janus_core::{hpke::HpkeCiphersuite, test_util::roundtrip_encoding};
    use janus_messages::{Duration, HpkeAeadId, HpkeKdfId, HpkeKemId};
    use rand::random;

    use crate::{
        aggregator::key_rotator::{
            default_active_duration, default_expired_duration, default_hpke_ciphersuites,
            default_pending_duration, HpkeKeyRotatorConfig,
        },
        config::{
            default_max_transaction_retries,
            test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
            CommonConfig,
        },
    };

    use super::{Config, KeyRotatorConfig, Options};

    #[test]
    fn verify_app() {
        Options::command().debug_assert();
    }

    #[test]
    fn roundtrip_config() {
        roundtrip_encoding(Config {
            common_config: CommonConfig {
                database: generate_db_config(),
                logging_config: generate_trace_config(),
                metrics_config: generate_metrics_config(),
                health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
                max_transaction_retries: default_max_transaction_retries(),
            },
            key_rotator: KeyRotatorConfig {
                hpke: HpkeKeyRotatorConfig {
                    pending_duration: Duration::from_seconds(random()),
                    active_duration: Duration::from_seconds(random()),
                    expired_duration: Duration::from_seconds(random()),
                    ciphersuites: HashSet::from([
                        HpkeCiphersuite::new(
                            HpkeKemId::P256HkdfSha256,
                            HpkeKdfId::HkdfSha256,
                            HpkeAeadId::Aes128Gcm,
                        ),
                        HpkeCiphersuite::new(
                            HpkeKemId::P521HkdfSha512,
                            HpkeKdfId::HkdfSha512,
                            HpkeAeadId::Aes256Gcm,
                        ),
                    ]),
                },
            },
        });
    }

    #[test]
    fn default_config() {
        let config = serde_yaml::from_str::<KeyRotatorConfig>(
            r#"---
hpke: {}
"#,
        )
        .unwrap();
        assert_eq!(
            config,
            KeyRotatorConfig {
                hpke: HpkeKeyRotatorConfig {
                    pending_duration: default_pending_duration(),
                    active_duration: default_active_duration(),
                    expired_duration: default_expired_duration(),
                    ciphersuites: default_hpke_ciphersuites(),
                }
            }
        )
    }

    #[test]
    fn documentation_config_examples() {
        serde_yaml::from_str::<Config>(include_str!(
            "../../../docs/samples/basic_config/key_rotator.yaml"
        ))
        .unwrap();
        serde_yaml::from_str::<Config>(include_str!(
            "../../../docs/samples/advanced_config/key_rotator.yaml"
        ))
        .unwrap();
    }
}
