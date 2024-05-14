use std::{sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use janus_aggregator_core::datastore::Datastore;
use janus_core::{hpke::HpkeCiphersuite, time::RealClock};
use opentelemetry::metrics::Meter;
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::error;
use trillium_tokio::Stopper;

use crate::{
    aggregator::{garbage_collector::GarbageCollector, key_rotator::HpkeKeyRotatorConfig},
    binary_utils::{BinaryContext, BinaryOptions, CommonBinaryOptions},
    config::{BinaryConfig, CommonConfig},
};

use super::aggregator::GarbageCollectorConfig;

pub async fn main_callback(ctx: BinaryContext<RealClock, Options, Config>) -> Result<()> {
    let BinaryContext {
        config,
        datastore,
        meter,
        stopper,
        ..
    } = ctx;

    let datastore = Arc::new(datastore);

    run_key_rotator(datastore, config.key_rotator, meter, stopper).await;

    Ok(())
}

pub(super) async fn run_key_rotator(
    datastore: Arc<Datastore<RealClock>>,
    config: KeyRotatorConfig,
    meter: Meter,
    stopper: Stopper,
) {
    // oneshot?

    // let gc = GarbageCollector::new(
    //     datastore,
    //     &meter,
    //     gc_config.report_limit,
    //     gc_config.aggregation_limit,
    //     gc_config.collection_limit,
    //     gc_config.tasks_per_tx,
    //     gc_config.concurrent_tx_limit,
    // );
    // let mut interval = interval(Duration::from_secs(gc_config.gc_frequency_s));
    // while stopper.stop_future(interval.tick()).await.is_some() {
    //     if let Err(err) = gc.run().await {
    //         error!(?err, "GC error");
    //     }
    // }
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
/// # use janus_aggregator::binaries::garbage_collector::Config;
/// let yaml_config = r#"
/// ---
/// database:
///   url: "postgres://postgres:postgres@localhost:5432/postgres"
/// logging_config: # logging_config is optional
///   force_json_output: true
/// garbage_collection:
///   gc_frequency_s: 60
///   report_limit: 5000
///   aggregation_limit: 500
///   collection_limit: 50
/// "#;
///
/// let _decoded: Config = serde_yaml::from_str(yaml_config).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotatorConfig {
    /// How frequently key rotator is run, in seconds.
    pub frequency_secs: Option<u64>,

    pub hpke: HpkeKeyRotatorConfig,
    // hpke options
    // how long until pending->active
    // how long until active->expired
    // how long until expired->deleted
    // ciphersuite to use (array)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use clap::CommandFactory;
    use janus_core::test_util::roundtrip_encoding;

    use crate::config::{
        default_max_transaction_retries,
        test_util::{generate_db_config, generate_metrics_config, generate_trace_config},
        CommonConfig,
    };

    use super::{Config, Options};

    #[test]
    fn verify_app() {
        Options::command().debug_assert();
    }

    // #[test]
    // fn roundtrip_config() {
    //     roundtrip_encoding(Config {
    //         common_config: CommonConfig {
    //             database: generate_db_config(),
    //             logging_config: generate_trace_config(),
    //             metrics_config: generate_metrics_config(),
    //             health_check_listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
    //             max_transaction_retries: default_max_transaction_retries(),
    //         },
    //         key_rotator: super::KeyRotatorConfig {},
    //     });
    // }

    // #[test]
    // fn documentation_config_examples() {
    //     serde_yaml::from_str::<Config>(include_str!(
    //         "../../../docs/samples/basic_config/key_rotator.yaml"
    //     ))
    //     .unwrap();
    //     serde_yaml::from_str::<Config>(include_str!(
    //         "../../../docs/samples/advanced_config/key_rotator.yaml"
    //     ))
    //     .unwrap();
    // }
}
