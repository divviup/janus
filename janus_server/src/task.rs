//! Shared parameters for a PPM task.

use crate::message::Interval;
use ::rand::{thread_rng, Rng};
use derivative::Derivative;
use janus::{
    hpke::HpkePrivateKey,
    message::{Duration, HpkeConfig, HpkeConfigId, Role, TaskId},
};
use ring::{
    digest::SHA256_OUTPUT_LEN,
    hmac::{self, HMAC_SHA256},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "Vdaf")]
pub enum VdafInstance {
    /// A `prio3` counter using the AES 128 pseudorandom generator.
    Prio3Aes128Count,
    /// A `prio3` sum using the AES 128 pseudorandom generator.
    Prio3Aes128Sum { bits: u32 },
    /// A `prio3` histogram using the AES 128 pseudorandom generator.
    Prio3Aes128Histogram { buckets: Vec<u64> },
    /// The `poplar1` VDAF. Support for this VDAF is experimental.
    Poplar1 { bits: usize },

    #[cfg(test)]
    Fake,
    #[cfg(test)]
    FakeFailsPrepInit,
    #[cfg(test)]
    FakeFailsPrepStep,
}

/// An HMAC-SHA-256 key used to authenticate messages exchanged between
/// aggregators. See `agg_auth_key` in draft-gpew-priv-ppm §4.2.
// We define the type this way because while we can use `ring::hmac::Key::new`
// to get a `ring::hmac::Key` from a slice of bytes, we can't get the bytes
// back out of the key.
#[derive(Clone, Debug)]
pub struct AggregatorAuthKey {
    bytes: Vec<u8>,
    hmac_key: hmac::Key,
}

// TODO(brandon): use a ring constant once one is exposed. This is the correct value per ring:
//   https://docs.rs/ring/0.16.20/src/ring/digest.rs.html#339
// (but we can't use the value in ring as a const because it's not const, it's static)
const SHA256_BLOCK_LEN: usize = 512 / 8;

impl AggregatorAuthKey {
    pub fn new(key_bytes: &[u8]) -> Result<Self, Error> {
        if key_bytes.len() < SHA256_OUTPUT_LEN || key_bytes.len() > SHA256_BLOCK_LEN {
            return Err(Error::AggregatorAuthKeySize);
        }
        Ok(Self {
            bytes: Vec::from(key_bytes),
            hmac_key: hmac::Key::new(HMAC_SHA256, key_bytes),
        })
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
        &self.bytes
    }
}

impl AsRef<hmac::Key> for AggregatorAuthKey {
    fn as_ref(&self) -> &hmac::Key {
        &self.hmac_key
    }
}

impl PartialEq for AggregatorAuthKey {
    fn eq(&self, other: &Self) -> bool {
        // The key is ignored because it is derived from the key bytes.
        // (also, ring::hmac::Key doesn't implement PartialEq)
        self.bytes == other.bytes
    }
}

impl Eq for AggregatorAuthKey {}

/// The parameters for a PPM task, corresponding to draft-gpew-priv-ppm §4.2.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct Task {
    /// Unique identifier for the task.
    pub id: TaskId,
    /// URLs relative to which aggregator API endpoints are found. The first
    /// entry is the leader's.
    pub(crate) aggregator_endpoints: Vec<Url>,
    /// The VDAF this task executes.
    pub vdaf: VdafInstance,
    /// The role performed by the aggregator.
    pub role: Role,
    /// Secret verification parameters shared by the aggregators.
    #[derivative(Debug = "ignore")]
    pub(crate) vdaf_verify_parameters: Vec<Vec<u8>>,
    /// The maximum number of times a given batch may be collected.
    pub(crate) max_batch_lifetime: u64,
    /// The minimum number of reports in a batch to allow it to be collected.
    pub(crate) min_batch_size: u64,
    /// The minimum batch interval for a collect request. Batch intervals must
    /// be multiples of this duration.
    pub min_batch_duration: Duration,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    pub(crate) tolerable_clock_skew: Duration,
    /// HPKE configuration for the collector.
    pub(crate) collector_hpke_config: HpkeConfig,
    /// Key used to authenticate messages sent to or received from the other
    /// aggregators.
    #[derivative(Debug = "ignore")]
    pub(crate) agg_auth_keys: Vec<AggregatorAuthKey>,
    /// HPKE configurations & private keys used by this aggregator to decrypt client reports.
    pub(crate) hpke_keys: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
}

impl Task {
    /// Create a new [`Task`] from the provided values
    pub fn new<I: IntoIterator<Item = (HpkeConfig, HpkePrivateKey)>>(
        task_id: TaskId,
        aggregator_endpoints: Vec<Url>,
        vdaf: VdafInstance,
        role: Role,
        vdaf_verify_parameters: Vec<Vec<u8>>,
        max_batch_lifetime: u64,
        min_batch_size: u64,
        min_batch_duration: Duration,
        tolerable_clock_skew: Duration,
        collector_hpke_config: HpkeConfig,
        agg_auth_keys: Vec<AggregatorAuthKey>,
        hpke_keys: I,
    ) -> Result<Self, Error> {
        // PPM currently only supports configurations of exactly two aggregators.
        if aggregator_endpoints.len() != 2 {
            return Err(Error::InvalidParameter("aggregator_endpoints"));
        }
        if !role.is_aggregator() {
            return Err(Error::InvalidParameter("role"));
        }
        if agg_auth_keys.is_empty() {
            return Err(Error::InvalidParameter("agg_auth_keys"));
        }
        if vdaf_verify_parameters.is_empty() {
            return Err(Error::InvalidParameter("vdaf_verify_parameters"));
        }

        // Compute hpke_configs mapping cfg.id -> (cfg, key).
        let hpke_configs: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)> = hpke_keys
            .into_iter()
            .map(|(cfg, key)| (cfg.id(), (cfg, key)))
            .collect();
        if hpke_configs.is_empty() {
            return Err(Error::InvalidParameter("hpke_configs"));
        }

        Ok(Self {
            id: task_id,
            aggregator_endpoints,
            vdaf,
            role,
            vdaf_verify_parameters,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            tolerable_clock_skew,
            collector_hpke_config,
            agg_auth_keys,
            hpke_keys: hpke_configs,
        })
    }

    /// Returns true if `batch_interval` is valid, per §4.6 of draft-gpew-priv-ppm.
    pub(crate) fn validate_batch_interval(&self, batch_interval: Interval) -> bool {
        // Batch interval should be greater than task's minimum batch duration
        batch_interval.duration().as_seconds() >= self.min_batch_duration.as_seconds()
            // Batch interval start must be a multiple of minimum batch duration
            && batch_interval.start().as_seconds_since_epoch() % self.min_batch_duration.as_seconds() == 0
            // Batch interval duration must be a multiple of minimum batch duration
            && batch_interval.duration().as_seconds() % self.min_batch_duration.as_seconds() == 0
    }

    /// Returns the [`Url`] relative to which the server performing `role` serves its API.
    pub(crate) fn aggregator_url(&self, role: Role) -> Result<&Url, Error> {
        let index = role.index().ok_or(Error::InvalidParameter(role.as_str()))?;
        Ok(&self.aggregator_endpoints[index])
    }
}

// This is public to allow use in integration tests.
#[doc(hidden)]
pub mod test_util {
    use super::{Task, VdafInstance};
    use crate::task::AggregatorAuthKey;
    use janus::{
        hpke::test_util::generate_hpke_config_and_private_key,
        message::{Duration, HpkeConfig, HpkeConfigId, Role, TaskId},
    };
    use prio::{
        codec::Encode,
        field::Field128,
        vdaf::{
            self,
            poplar1::{Poplar1, ToyIdpf},
            prg::PrgAes128,
            prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        },
    };

    /// Create a dummy [`Task`] from the provided [`TaskId`], with
    /// dummy values for the other fields. This is pub because it is needed for
    /// integration tests.
    pub fn new_dummy_task(task_id: TaskId, vdaf: VdafInstance, role: Role) -> Task {
        let (collector_config, _) = generate_hpke_config_and_private_key();
        let (aggregator_config_0, aggregator_private_key_0) =
            generate_hpke_config_and_private_key();
        let (mut aggregator_config_1, aggregator_private_key_1) =
            generate_hpke_config_and_private_key();
        aggregator_config_1 = HpkeConfig::new(
            HpkeConfigId::from(1),
            aggregator_config_1.kem_id(),
            aggregator_config_1.kdf_id(),
            aggregator_config_1.aead_id(),
            aggregator_config_1.public_key().clone(),
        );

        let vdaf_verify_parameter = verify_param_dispatch(&vdaf, role);

        Task::new(
            task_id,
            vec![
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ],
            vdaf,
            role,
            vec![vdaf_verify_parameter],
            0,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            collector_config,
            vec![AggregatorAuthKey::generate(), AggregatorAuthKey::generate()],
            vec![
                (aggregator_config_0, aggregator_private_key_0),
                (aggregator_config_1, aggregator_private_key_1),
            ],
        )
        .unwrap()
    }

    fn verify_param_dispatch(vdaf: &VdafInstance, role: Role) -> Vec<u8> {
        match &vdaf {
            VdafInstance::Prio3Aes128Count => verify_param(Prio3Aes128Count::new(2).unwrap(), role),
            VdafInstance::Prio3Aes128Sum { bits } => {
                verify_param(Prio3Aes128Sum::new(2, *bits).unwrap(), role)
            }
            VdafInstance::Prio3Aes128Histogram { buckets } => {
                verify_param(Prio3Aes128Histogram::new(2, &*buckets).unwrap(), role)
            }
            VdafInstance::Poplar1 { bits } => verify_param(
                Poplar1::<ToyIdpf<Field128>, PrgAes128, 16>::new(*bits),
                role,
            ),

            #[cfg(test)]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => Vec::new(),
        }
    }

    fn verify_param<V: vdaf::Vdaf>(vdaf: V, role: Role) -> Vec<u8>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
        V::VerifyParam: Encode,
    {
        let (_, verify_params) = vdaf.setup().unwrap();
        verify_params
            .get(role.index().unwrap())
            .unwrap()
            .get_encoded()
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::new_dummy_task;
    use super::*;
    use janus::message::{Duration, TaskId, Time};
    use serde_test::{assert_tokens, Token};

    #[test]
    fn validate_batch_interval() {
        let mut task = new_dummy_task(TaskId::random(), VdafInstance::Fake, Role::Leader);
        let min_batch_duration_secs = 3600;
        task.min_batch_duration = Duration::from_seconds(min_batch_duration_secs);

        struct TestCase {
            name: &'static str,
            input: Interval,
            expected: bool,
        }

        let test_cases = vec![
            TestCase {
                name: "same duration as minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(min_batch_duration_secs),
                    Duration::from_seconds(min_batch_duration_secs),
                )
                .unwrap(),
                expected: true,
            },
            TestCase {
                name: "interval too short",
                input: Interval::new(
                    Time::from_seconds_since_epoch(min_batch_duration_secs),
                    Duration::from_seconds(min_batch_duration_secs - 1),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                name: "interval larger than minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(min_batch_duration_secs),
                    Duration::from_seconds(min_batch_duration_secs * 2),
                )
                .unwrap(),
                expected: true,
            },
            TestCase {
                name: "interval duration not aligned with minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(min_batch_duration_secs),
                    Duration::from_seconds(min_batch_duration_secs + 1800),
                )
                .unwrap(),
                expected: false,
            },
            TestCase {
                name: "interval start not aligned with minimum",
                input: Interval::new(
                    Time::from_seconds_since_epoch(1800),
                    Duration::from_seconds(min_batch_duration_secs),
                )
                .unwrap(),
                expected: false,
            },
        ];

        for test_case in test_cases {
            assert_eq!(
                test_case.expected,
                task.validate_batch_interval(test_case.input),
                "test case: {}",
                test_case.name
            );
        }
    }

    #[test]
    fn vdaf_serialization() {
        // The `Vdaf` type must have a stable serialization, as it gets stored in a JSON database
        // column.
        assert_tokens(
            &VdafInstance::Prio3Aes128Count,
            &[Token::UnitVariant {
                name: "Vdaf",
                variant: "Prio3Aes128Count",
            }],
        );
        assert_tokens(
            &VdafInstance::Prio3Aes128Sum { bits: 64 },
            &[
                Token::StructVariant {
                    name: "Vdaf",
                    variant: "Prio3Aes128Sum",
                    len: 1,
                },
                Token::Str("bits"),
                Token::U32(64),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Prio3Aes128Histogram {
                buckets: vec![0, 100, 200, 400],
            },
            &[
                Token::StructVariant {
                    name: "Vdaf",
                    variant: "Prio3Aes128Histogram",
                    len: 1,
                },
                Token::Str("buckets"),
                Token::Seq { len: Some(4) },
                Token::U64(0),
                Token::U64(100),
                Token::U64(200),
                Token::U64(400),
                Token::SeqEnd,
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Poplar1 { bits: 64 },
            &[
                Token::StructVariant {
                    name: "Vdaf",
                    variant: "Poplar1",
                    len: 1,
                },
                Token::Str("bits"),
                Token::U64(64),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Fake,
            &[Token::UnitVariant {
                name: "Vdaf",
                variant: "Fake",
            }],
        );
        assert_tokens(
            &VdafInstance::FakeFailsPrepInit,
            &[Token::UnitVariant {
                name: "Vdaf",
                variant: "FakeFailsPrepInit",
            }],
        );
        assert_tokens(
            &VdafInstance::FakeFailsPrepStep,
            &[Token::UnitVariant {
                name: "Vdaf",
                variant: "FakeFailsPrepStep",
            }],
        );
    }
}
