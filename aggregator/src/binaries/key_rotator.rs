use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use janus_core::time::RealClock;
use serde::{Deserialize, Serialize};

use crate::{
    aggregator::key_rotator::{
        HpkeKeyRotatorConfig, KeyRotator, deserialize_hpke_key_rotator_config,
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
/// let _decoded: Config = yaml_serde::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    use janus_messages::{HpkeAeadId, HpkeKdfId, HpkeKemId};
    use rand::random;

    use super::{Config, KeyRotatorConfig, Options};
    use crate::{
        aggregator::key_rotator::HpkeKeyRotatorConfig,
        config::{
            CommonConfig, default_max_transaction_retries,
            test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
        },
    };

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
                thread_pool_stack_size: None,
            },
            key_rotator: KeyRotatorConfig {
                hpke: HpkeKeyRotatorConfig::new(
                    random(),
                    random(),
                    random(),
                    HashSet::from([
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
                ),
            },
        });
    }

    #[test]
    fn default_config() {
        let config = yaml_serde::from_str::<KeyRotatorConfig>(
            r#"---
hpke: {}
"#,
        )
        .unwrap();
        assert_eq!(config, KeyRotatorConfig::default(),)
    }

    #[test]
    fn documentation_config_examples() {
        yaml_serde::from_str::<Config>(include_str!(
            "../../../docs/samples/basic_config/key_rotator.yaml"
        ))
        .unwrap();
        yaml_serde::from_str::<Config>(include_str!(
            "../../../docs/samples/advanced_config/key_rotator.yaml"
        ))
        .unwrap();
    }
}
