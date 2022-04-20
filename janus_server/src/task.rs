//! Shared parameters for a PPM task.

use std::collections::HashMap;

use crate::{
    hpke::HpkePrivateKey,
    message::{HpkeConfig, HpkeConfigId, Interval, Role, TaskId},
};
use ::rand::{thread_rng, Rng};
use chrono::Duration;
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

    #[cfg(test)]
    #[postgres(name = "FAKE")]
    Fake,
    #[cfg(test)]
    #[postgres(name = "FAKE_FAILS_PREP_INIT")]
    FakeFailsPrepInit,
    #[cfg(test)]
    #[postgres(name = "FAKE_FAILS_PREP_STEP")]
    FakeFailsPrepStep,
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
pub struct Task {
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
    /// Key used to authenticate messages sent to or received from the other
    /// aggregators.
    pub(crate) agg_auth_keys: Vec<AggregatorAuthKey>,
    /// HPKE configurations & private keys used by this aggregator to decrypt client reports.
    pub(crate) hpke_keys: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
}

impl Task {
    /// Create a new [`Task`] from the provided values
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
        if min_batch_duration < Duration::zero() {
            return Err(Error::InvalidParameter("min_batch_duration"));
        }
        if tolerable_clock_skew < Duration::zero() {
            return Err(Error::InvalidParameter("tolerable_clock_skew"));
        }
        if agg_auth_keys.is_empty() {
            return Err(Error::InvalidParameter("agg_auth_keys"));
        }

        // Compute hpke_configs mapping cfg.id -> (cfg, key).
        let hpke_configs: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)> = hpke_keys
            .into_iter()
            .map(|(cfg, key)| (cfg.id, (cfg, key)))
            .collect();
        if hpke_configs.is_empty() {
            return Err(Error::InvalidParameter("hpke_configs"));
        }

        Ok(Self {
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
            agg_auth_keys,
            hpke_keys: hpke_configs,
        })
    }

    /// Returns true if `batch_interval` is valid, per §4.6 of draft-gpew-priv-ppm.
    pub(crate) fn validate_batch_interval(&self, batch_interval: Interval) -> bool {
        let min_batch_duration = self.min_batch_duration.num_seconds() as u64;

        // Batch interval should be greater than task's minimum batch duration
        batch_interval.duration.0 >= min_batch_duration
            // Batch interval start must be a multiple of minimum batch duration
            && batch_interval.start.0 % min_batch_duration == 0
            // Batch interval duration must be a multiple of minimum batch duration
            && batch_interval.duration.0 % min_batch_duration == 0
    }
}

// This is public to allow use in integration tests.
#[doc(hidden)]
pub mod test_util {
    use super::{Task, Vdaf};
    use crate::{
        hpke::test_util::generate_hpke_config_and_private_key,
        message::{HpkeConfigId, Role, TaskId},
        task::AggregatorAuthKey,
    };
    use chrono::Duration;
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
    pub fn new_dummy_task(task_id: TaskId, vdaf: Vdaf, role: Role) -> Task {
        let (collector_config, _) = generate_hpke_config_and_private_key();
        let (aggregator_config_0, aggregator_private_key_0) =
            generate_hpke_config_and_private_key();
        let (mut aggregator_config_1, aggregator_private_key_1) =
            generate_hpke_config_and_private_key();
        aggregator_config_1.id = HpkeConfigId(1);

        let vdaf_verify_parameter = match vdaf {
            Vdaf::Prio3Aes128Count => verify_param(Prio3Aes128Count::new(2).unwrap(), role),
            Vdaf::Prio3Aes128Sum => verify_param(Prio3Aes128Sum::new(2, 64).unwrap(), role),
            Vdaf::Prio3Aes128Histogram => verify_param(
                Prio3Aes128Histogram::new(2, &[0, 100, 200, 400]).unwrap(),
                role,
            ),
            Vdaf::Poplar1 => {
                verify_param(Poplar1::<ToyIdpf<Field128>, PrgAes128, 16>::new(64), role)
            }

            #[cfg(test)]
            Vdaf::Fake | Vdaf::FakeFailsPrepInit | Vdaf::FakeFailsPrepStep => Vec::new(),
        };

        Task::new(
            task_id,
            vec![
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ],
            vdaf,
            role,
            vdaf_verify_parameter,
            0,
            0,
            Duration::hours(8),
            Duration::minutes(10),
            collector_config,
            vec![AggregatorAuthKey::generate(), AggregatorAuthKey::generate()],
            vec![
                (aggregator_config_0, aggregator_private_key_0),
                (aggregator_config_1, aggregator_private_key_1),
            ],
        )
        .unwrap()
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
    use crate::message::{self, TaskId, Time};

    #[test]
    fn validate_batch_interval() {
        let mut task = new_dummy_task(TaskId::random(), Vdaf::Fake, Role::Leader);
        let min_batch_duration_secs = 3600;
        task.min_batch_duration = Duration::seconds(min_batch_duration_secs as i64);

        struct TestCase {
            name: &'static str,
            input: Interval,
            expected: bool,
        }

        let test_cases = vec![
            TestCase {
                name: "same duration as minimum",
                input: Interval {
                    start: Time(min_batch_duration_secs),
                    duration: message::Duration(min_batch_duration_secs),
                },
                expected: true,
            },
            TestCase {
                name: "interval too short",
                input: Interval {
                    start: Time(min_batch_duration_secs),
                    duration: message::Duration(min_batch_duration_secs - 1),
                },
                expected: false,
            },
            TestCase {
                name: "interval larger than minimum",
                input: Interval {
                    start: Time(min_batch_duration_secs),
                    duration: message::Duration(min_batch_duration_secs * 2),
                },
                expected: true,
            },
            TestCase {
                name: "interval duration not aligned with minimum",
                input: Interval {
                    start: Time(min_batch_duration_secs),
                    duration: message::Duration(min_batch_duration_secs + 1800),
                },
                expected: false,
            },
            TestCase {
                name: "interval start not aligned with minimum",
                input: Interval {
                    start: Time(1800),
                    duration: message::Duration(min_batch_duration_secs),
                },
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
}
