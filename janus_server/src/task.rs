//! Shared parameters for a PPM task.

use std::collections::HashMap;

use crate::{
    hpke::HpkePrivateKey,
    message::{Duration, HpkeConfig, HpkeConfigId, Role, TaskId},
};
use ::rand::{thread_rng, Rng};
use postgres_types::{FromSql, ToSql};
use ring::{
    digest::SHA256_OUTPUT_LEN,
    hmac::{self, HMAC_SHA256},
};
use url::Url;

/// Errors that methods and functions in this module may return.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid parameter {0}")]
    InvalidParameter(&'static str),
    #[error("URL parse error")]
    Url(#[from] url::ParseError),
    #[error("aggregator auth key size out of range")]
    AggregatorAuthKeySize,
}

/// Identifiers for VDAFs supported by this aggregator, corresponding to
/// definitions in [draft-patton-cfrg-vdaf][1] and implementations in
/// [`prio::vdaf::prio3`].
///
/// [1]: https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "vdaf_identifier")]
pub enum Vdaf {
    /// A `prio3` counter using the AES 128 pseudorandom generator.
    #[postgres(name = "PRIO3_AES128_COUNT")]
    Prio3Aes128Count,
    /// A `prio3` sum using the AES 128 pseudorandom generator.
    #[postgres(name = "PRIO3_AES128_SUM")]
    Prio3Aes128Sum,
    /// A `prio3` histogram using the AES 128 pseudorandom generator.
    #[postgres(name = "PRIO3_AES128_HISTOGRAM")]
    Prio3Aes128Histogram,
    /// The `poplar1` VDAF. Support for this VDAF is experimental.
    #[postgres(name = "POPLAR1")]
    Poplar1,
}

/// An HMAC-SHA-256 key used to authenticate messages exchanged between
/// aggregators. See `agg_auth_key` in draft-gpew-priv-ppm §4.2.
// We define the type this way because while we can use `ring::hmac::Key::new`
// to get a `ring::hmac::Key` from a slice of bytes, we can't get the bytes
// back out of the key.
#[derive(Clone, Debug)]
pub struct AggregatorAuthKey(Vec<u8>, hmac::Key);

// TODO(brandon): use a ring constant once one is exposed. This is the correct value per ring:
//   https://docs.rs/ring/0.16.20/src/ring/digest.rs.html#339
// (but we can't use the value in ring as a const because it's not const, it's static)
const SHA256_BLOCK_LEN: usize = 512 / 8;

impl AggregatorAuthKey {
    pub fn new(key_bytes: &[u8]) -> Result<Self, Error> {
        if key_bytes.len() < SHA256_OUTPUT_LEN || key_bytes.len() > SHA256_BLOCK_LEN {
            return Err(Error::AggregatorAuthKeySize);
        }
        Ok(Self(
            Vec::from(key_bytes),
            hmac::Key::new(HMAC_SHA256, key_bytes),
        ))
    }

    /// Randomly generate an [`AggregatorAuthKey`].
    pub fn generate() -> Self {
        let mut key_bytes = [0u8; SHA256_BLOCK_LEN];
        thread_rng().fill(&mut key_bytes);
        // Won't panic: key_bytes is constructed as SHA256_BLOCK_LEN bytes, which will pass the
        // validation check.
        Self::new(&key_bytes).unwrap()
    }
}

impl AsRef<[u8]> for AggregatorAuthKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<hmac::Key> for AggregatorAuthKey {
    fn as_ref(&self) -> &hmac::Key {
        &self.1
    }
}

impl PartialEq for AggregatorAuthKey {
    fn eq(&self, other: &Self) -> bool {
        // The key is ignored because it is derived from the key bytes.
        // (also, ring::hmac::Key doesn't implement PartialEq)
        self.0 == other.0
    }
}

impl Eq for AggregatorAuthKey {}

/// The parameters for a PPM task, corresponding to draft-gpew-priv-ppm §4.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskParameters {
    /// Unique identifier for the task
    pub(crate) id: TaskId,
    /// URLs relative to which aggregator API endpoints are found. The first
    /// entry is the leader's.
    pub(crate) aggregator_endpoints: Vec<Url>,
    /// The VDAF this task executes.
    pub(crate) vdaf: Vdaf,
    /// The role performed by the aggregator.
    pub(crate) role: Role,
    /// Secret verification parameter shared by the aggregators.
    pub(crate) vdaf_verify_parameter: Vec<u8>,
    /// The maximum number of times a given batch may be collected.
    pub(crate) max_batch_lifetime: u64,
    /// The minimum number of reports in a batch to allow it to be collected.
    pub(crate) min_batch_size: u64,
    /// The minimum batch interval for a collect request. Batch intervals must
    /// be multiples of this duration.
    pub(crate) min_batch_duration: Duration,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    pub(crate) tolerable_clock_skew: Duration,
    /// HPKE configuration for the collector.
    pub(crate) collector_hpke_config: HpkeConfig,
    /// Key used to authenticate messages sent to or received from the other aggregators.
    pub(crate) agg_auth_key: AggregatorAuthKey,
    /// HPKE configurations & private keys used by this aggregator to decrypt client reports.
    pub(crate) hpke_configs: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
}

impl TaskParameters {
    /// Create a new [`TaskParameters`] from the provided values
    pub fn new<I: IntoIterator<Item = (HpkeConfig, HpkePrivateKey)>>(
        task_id: TaskId,
        aggregator_endpoints: Vec<Url>,
        vdaf: Vdaf,
        role: Role,
        vdaf_verify_parameter: Vec<u8>,
        max_batch_lifetime: u64,
        min_batch_size: u64,
        min_batch_duration: Duration,
        tolerable_clock_skew: Duration,
        collector_hpke_config: HpkeConfig,
        agg_auth_key: AggregatorAuthKey,
        hpke_configs: I,
    ) -> Self {
        // All currently defined VDAFs have exactly two aggregators
        assert_eq!(aggregator_endpoints.len(), 2);

        // Compute hpke_configs mapping cfg.id -> (cfg, key).
        let hpke_configs = hpke_configs
            .into_iter()
            .map(|(cfg, key)| (cfg.id, (cfg, key)))
            .collect();

        Self {
            id: task_id,
            aggregator_endpoints,
            vdaf,
            role,
            vdaf_verify_parameter,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            tolerable_clock_skew,
            collector_hpke_config,
            agg_auth_key,
            hpke_configs,
        }
    }
}

// This is public to allow use in integration tests.
#[doc(hidden)]
pub mod test_util {
    use super::{TaskParameters, Vdaf};
    use crate::{
        message::{Duration, Role, TaskId},
        task::AggregatorAuthKey,
    };

    /// Create a dummy [`TaskParameters`] from the provided [`TaskId`], with
    /// dummy values for the other fields. This is pub because it is needed for
    /// integration tests.
    pub fn new_dummy_task_parameters(task_id: TaskId, vdaf: Vdaf, role: Role) -> TaskParameters {
        use crate::hpke::test_util::generate_hpke_config_and_private_key;

        let (collector_config, _) = generate_hpke_config_and_private_key();
        let (aggregator_config, aggregator_private_key) = generate_hpke_config_and_private_key();

        TaskParameters::new(
            task_id,
            vec![
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ],
            vdaf,
            role,
            vec![],
            0,
            0,
            Duration(1),
            Duration(1),
            collector_config,
            AggregatorAuthKey::generate(),
            vec![(aggregator_config, aggregator_private_key)],
        )
    }
}
