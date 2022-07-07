//! Shared parameters for a PPM task.

use base64::URL_SAFE_NO_PAD;
use derivative::Derivative;
use janus_core::{
    hpke::HpkePrivateKey,
    message::{Duration, HpkeConfig, HpkeConfigId, Interval, Role, TaskId},
};
use ring::constant_time;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use url::Url;

/// HTTP header where auth tokens are provided in inter-aggregator messages.
pub const DAP_AUTH_HEADER: &str = "DAP-Auth-Token";

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
/// definitions in [draft-irtf-cfrg-vdaf-00][1] and implementations in
/// [`prio::vdaf::prio3`].
///
/// [1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/00/
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum VdafInstance {
    Real(janus_core::task::VdafInstance),

    #[cfg(test)]
    Fake,
    #[cfg(test)]
    FakeFailsPrepInit,
    #[cfg(test)]
    FakeFailsPrepStep,
}

impl From<janus_core::task::VdafInstance> for VdafInstance {
    fn from(vdaf: janus_core::task::VdafInstance) -> Self {
        VdafInstance::Real(vdaf)
    }
}

/// The length of the verify key parameter for Prio3 AES-128 VDAF instantiations.
pub const PRIO3_AES128_VERIFY_KEY_LENGTH: usize = 16;

impl Serialize for VdafInstance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let flattened = match self {
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
                VdafSerialization::Prio3Aes128Count
            }
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { bits }) => {
                VdafSerialization::Prio3Aes128Sum { bits: *bits }
            }
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram {
                buckets,
            }) => VdafSerialization::Prio3Aes128Histogram {
                buckets: buckets.clone(),
            },
            VdafInstance::Real(janus_core::task::VdafInstance::Poplar1 { bits }) => {
                VdafSerialization::Poplar1 { bits: *bits }
            }
            #[cfg(test)]
            VdafInstance::Fake => VdafSerialization::Fake,
            #[cfg(test)]
            VdafInstance::FakeFailsPrepInit => VdafSerialization::FakeFailsPrepInit,
            #[cfg(test)]
            VdafInstance::FakeFailsPrepStep => VdafSerialization::FakeFailsPrepStep,
        };
        flattened.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VdafInstance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let flattened = <VdafSerialization as Deserialize<'de>>::deserialize(deserializer)?;
        match flattened {
            VdafSerialization::Prio3Aes128Count => Ok(VdafInstance::Real(
                janus_core::task::VdafInstance::Prio3Aes128Count,
            )),
            VdafSerialization::Prio3Aes128Sum { bits } => Ok(VdafInstance::Real(
                janus_core::task::VdafInstance::Prio3Aes128Sum { bits },
            )),
            VdafSerialization::Prio3Aes128Histogram { buckets } => Ok(VdafInstance::Real(
                janus_core::task::VdafInstance::Prio3Aes128Histogram { buckets },
            )),
            VdafSerialization::Poplar1 { bits } => Ok(VdafInstance::Real(
                janus_core::task::VdafInstance::Poplar1 { bits },
            )),
            #[cfg(test)]
            VdafSerialization::Fake => Ok(VdafInstance::Fake),
            #[cfg(test)]
            VdafSerialization::FakeFailsPrepInit => Ok(VdafInstance::FakeFailsPrepInit),
            #[cfg(test)]
            VdafSerialization::FakeFailsPrepStep => Ok(VdafInstance::FakeFailsPrepStep),
        }
    }
}

/// An internal helper enum to allow representing [`VdafInstance`] flattened as a
/// single JSON object, without having to implement [`Serialize`] and
/// [`Deserialize`] by hand.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename = "Vdaf")]
enum VdafSerialization {
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

/// An authentication (bearer) token used by aggregators for aggregator-to-aggregator
/// authentication.
#[derive(Clone)]
pub struct AggregatorAuthenticationToken(Vec<u8>);

impl From<Vec<u8>> for AggregatorAuthenticationToken {
    fn from(token: Vec<u8>) -> Self {
        Self(token)
    }
}

impl AggregatorAuthenticationToken {
    /// Returns a view of the aggregator authentication token as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for AggregatorAuthenticationToken {
    fn eq(&self, other: &Self) -> bool {
        // We attempt constant-time comparisons of the token data. Note that this function still
        // leaks whether the lengths of the tokens are equal -- this is acceptable because we expect
        // the content of the tokens to provide enough randomness that needs to be guessed even if
        // the length is known.
        constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl Eq for AggregatorAuthenticationToken {}

/// The parameters for a PPM task, corresponding to draft-gpew-priv-ppm §4.2.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct Task {
    /// Unique identifier for the task.
    pub id: TaskId,
    /// URLs relative to which aggregator API endpoints are found. The first
    /// entry is the leader's.
    pub aggregator_endpoints: Vec<Url>,
    /// The VDAF this task executes.
    pub vdaf: VdafInstance,
    /// The role performed by the aggregator.
    pub role: Role,
    /// Secret verification keys shared by the aggregators.
    #[derivative(Debug = "ignore")]
    pub vdaf_verify_keys: Vec<Vec<u8>>,
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
    /// Tokens used to authenticate messages sent to or received from the other aggregators.
    #[derivative(Debug = "ignore")]
    pub agg_auth_tokens: Vec<AggregatorAuthenticationToken>,
    /// HPKE configurations & private keys used by this aggregator to decrypt client reports.
    pub hpke_keys: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
}

impl Task {
    /// Create a new [`Task`] from the provided values
    pub fn new<I: IntoIterator<Item = (HpkeConfig, HpkePrivateKey)>>(
        task_id: TaskId,
        aggregator_endpoints: Vec<Url>,
        vdaf: VdafInstance,
        role: Role,
        vdaf_verify_keys: Vec<Vec<u8>>,
        max_batch_lifetime: u64,
        min_batch_size: u64,
        min_batch_duration: Duration,
        tolerable_clock_skew: Duration,
        collector_hpke_config: HpkeConfig,
        agg_auth_tokens: Vec<AggregatorAuthenticationToken>,
        hpke_keys: I,
    ) -> Result<Self, Error> {
        // PPM currently only supports configurations of exactly two aggregators.
        if aggregator_endpoints.len() != 2 {
            return Err(Error::InvalidParameter("aggregator_endpoints"));
        }
        if !role.is_aggregator() {
            return Err(Error::InvalidParameter("role"));
        }
        if agg_auth_tokens.is_empty() {
            return Err(Error::InvalidParameter("agg_auth_tokens"));
        }
        if vdaf_verify_keys.is_empty() {
            return Err(Error::InvalidParameter("vdaf_verify_keys"));
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
            vdaf_verify_keys,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            tolerable_clock_skew,
            collector_hpke_config,
            agg_auth_tokens,
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
    pub fn aggregator_url(&self, role: Role) -> Result<&Url, Error> {
        let index = role.index().ok_or(Error::InvalidParameter(role.as_str()))?;
        Ok(&self.aggregator_endpoints[index])
    }

    /// Returns the [`AggregatorAuthenticationToken`] currently used by this task to authenticate
    /// aggregate messages.
    pub fn primary_aggregator_auth_token(&self) -> &AggregatorAuthenticationToken {
        self.agg_auth_tokens.iter().rev().next().unwrap()
    }

    /// Checks if the given aggregator authentication token is valid (i.e. matches with an
    /// authentication token recognized by this task).
    pub(crate) fn check_aggregator_auth_token(
        &self,
        auth_token: &AggregatorAuthenticationToken,
    ) -> bool {
        self.agg_auth_tokens.iter().rev().any(|t| t == auth_token)
    }
}

/// SerializedTask is an intermediate representation for tasks being serialized via the Serialize &
/// Deserialize traits.
#[derive(Serialize, Deserialize)]
struct SerializedTask {
    id: String, // in unpadded base64url
    aggregator_endpoints: Vec<Url>,
    vdaf: VdafInstance,
    role: Role,
    vdaf_verify_keys: Vec<String>, // in unpadded base64url
    max_batch_lifetime: u64,
    min_batch_size: u64,
    min_batch_duration: Duration,
    tolerable_clock_skew: Duration,
    collector_hpke_config: HpkeConfig,
    agg_auth_tokens: Vec<String>,         // in unpadded base64url
    hpke_keys: Vec<(HpkeConfig, String)>, // values in unpadded base64url
}

impl Serialize for Task {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let id = base64::encode_config(self.id.as_bytes(), URL_SAFE_NO_PAD);
        let vdaf_verify_keys: Vec<_> = self
            .vdaf_verify_keys
            .iter()
            .map(|key| base64::encode_config(key, URL_SAFE_NO_PAD))
            .collect();
        let agg_auth_tokens: Vec<_> = self
            .agg_auth_tokens
            .iter()
            .map(|token| base64::encode_config(token.as_bytes(), URL_SAFE_NO_PAD))
            .collect();
        let hpke_keys = self
            .hpke_keys
            .values()
            .map(|(cfg, priv_key)| {
                (
                    cfg.clone(),
                    base64::encode_config(priv_key.as_ref(), URL_SAFE_NO_PAD),
                )
            })
            .collect();

        SerializedTask {
            id,
            aggregator_endpoints: self.aggregator_endpoints.clone(),
            vdaf: self.vdaf.clone(),
            role: self.role,
            vdaf_verify_keys,
            max_batch_lifetime: self.max_batch_lifetime,
            min_batch_size: self.min_batch_size,
            min_batch_duration: self.min_batch_duration,
            tolerable_clock_skew: self.tolerable_clock_skew,
            collector_hpke_config: self.collector_hpke_config.clone(),
            agg_auth_tokens,
            hpke_keys,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Task {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize into intermediate representation.
        let serialized_task = SerializedTask::deserialize(deserializer)?;

        // task_id
        let task_id_bytes =
            base64::decode_config(serialized_task.id, URL_SAFE_NO_PAD).map_err(D::Error::custom)?;
        let task_id = TaskId::new(
            task_id_bytes
                .try_into()
                .map_err(|_| D::Error::custom("task_id length incorrect"))?,
        );

        // vdaf_verify_keys
        let vdaf_verify_keys: Vec<_> = serialized_task
            .vdaf_verify_keys
            .into_iter()
            .map(|key| base64::decode_config(key, URL_SAFE_NO_PAD).map_err(D::Error::custom))
            .collect::<Result<_, _>>()?;

        // agg_auth_tokens
        let agg_auth_tokens: Vec<_> = serialized_task
            .agg_auth_tokens
            .into_iter()
            .map(|token| {
                let token_bytes =
                    base64::decode_config(token, URL_SAFE_NO_PAD).map_err(D::Error::custom)?;
                Ok(AggregatorAuthenticationToken::from(token_bytes))
            })
            .collect::<Result<_, _>>()?;

        // hpke_keys
        let hpke_keys: HashMap<_, _> = serialized_task
            .hpke_keys
            .into_iter()
            .map(|(hpke_config, hpke_private_key)| {
                let hpke_private_key_bytes =
                    base64::decode_config(hpke_private_key, URL_SAFE_NO_PAD)
                        .map_err(D::Error::custom)?;
                Ok((
                    hpke_config.id(),
                    (hpke_config, HpkePrivateKey::new(hpke_private_key_bytes)),
                ))
            })
            .collect::<Result<_, _>>()?;

        Ok(Task {
            id: task_id,
            aggregator_endpoints: serialized_task.aggregator_endpoints,
            vdaf: serialized_task.vdaf,
            role: serialized_task.role,
            vdaf_verify_keys,
            max_batch_lifetime: serialized_task.max_batch_lifetime,
            min_batch_size: serialized_task.min_batch_size,
            min_batch_duration: serialized_task.min_batch_duration,
            tolerable_clock_skew: serialized_task.tolerable_clock_skew,
            collector_hpke_config: serialized_task.collector_hpke_config,
            agg_auth_tokens,
            hpke_keys,
        })
    }
}

// This is public to allow use in integration tests.
#[cfg(feature = "test-util")]
pub mod test_util {
    use std::iter;

    use super::{
        AggregatorAuthenticationToken, Task, VdafInstance, PRIO3_AES128_VERIFY_KEY_LENGTH,
    };
    use janus_core::{
        hpke::test_util::generate_hpke_config_and_private_key,
        message::{Duration, HpkeConfig, HpkeConfigId, Role, TaskId},
    };
    use rand::{thread_rng, Rng};

    impl VdafInstance {
        /// Returns the expected length of a VDAF verification key for a VDAF of this type.
        fn verify_key_length(&self) -> usize {
            match self {
                // All "real" VDAFs use a verify key of length 16 currently. (Poplar1 may not, but it's
                // not yet done being specified, so choosing 16 bytes is fine for testing.)
                VdafInstance::Real(_) => PRIO3_AES128_VERIFY_KEY_LENGTH,

                #[cfg(test)]
                VdafInstance::Fake
                | VdafInstance::FakeFailsPrepInit
                | VdafInstance::FakeFailsPrepStep => 0,
            }
        }
    }

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

        let vdaf_verify_key = iter::repeat_with(|| thread_rng().gen())
            .take(vdaf.verify_key_length())
            .collect();

        Task::new(
            task_id,
            vec![
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ],
            vdaf,
            role,
            vec![vdaf_verify_key],
            0,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            collector_config,
            vec![
                generate_aggregator_auth_token(),
                generate_aggregator_auth_token(),
            ],
            vec![
                (aggregator_config_0, aggregator_private_key_0),
                (aggregator_config_1, aggregator_private_key_1),
            ],
        )
        .unwrap()
    }

    pub fn generate_aggregator_auth_token() -> AggregatorAuthenticationToken {
        let mut buf = [0; 16];
        thread_rng().fill(&mut buf);
        base64::encode_config(&buf, base64::URL_SAFE_NO_PAD)
            .into_bytes()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use crate::config::test_util::roundtrip_encoding;

    use super::test_util::new_dummy_task;
    use super::*;
    use janus_core::message::{Duration, TaskId, Time};
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
            &VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
            &[Token::UnitVariant {
                name: "Vdaf",
                variant: "Prio3Aes128Count",
            }],
        );
        assert_tokens(
            &VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { bits: 64 }),
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
            &VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram {
                buckets: vec![0, 100, 200, 400],
            }),
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
            &VdafInstance::Real(janus_core::task::VdafInstance::Poplar1 { bits: 64 }),
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

    #[test]
    fn task_serialization() {
        roundtrip_encoding(new_dummy_task(
            TaskId::random(),
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
            Role::Leader,
        ));
    }
}
