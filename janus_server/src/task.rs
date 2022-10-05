//! Shared parameters for a DAP task.

use crate::SecretBytes;
use base64::URL_SAFE_NO_PAD;
use derivative::Derivative;
use janus_core::{
    hpke::HpkePrivateKey,
    task::{url_ensure_trailing_slash, AuthenticationToken},
};
use janus_messages::{
    Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, Interval,
    Role, TaskId,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    array::TryFromSliceError,
    collections::HashMap,
    fmt::{self, Formatter},
};
use url::Url;

/// Errors that methods and functions in this module may return.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid parameter {0}")]
    InvalidParameter(&'static str),
    #[error("URL parse error")]
    Url(#[from] url::ParseError),
    #[error("aggregator verification key size out of range")]
    AggregatorVerifyKeySize,
}

/// Identifiers for VDAFs supported by this aggregator, corresponding to
/// definitions in [draft-irtf-cfrg-vdaf-03][1] and implementations in
/// [`prio::vdaf::prio3`].
///
/// [1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/03/
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
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128CountVec { length }) => {
                VdafSerialization::Prio3Aes128CountVec { length: *length }
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
            VdafSerialization::Prio3Aes128CountVec { length } => Ok(VdafInstance::Real(
                janus_core::task::VdafInstance::Prio3Aes128CountVec { length },
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
    /// A vector of `prio3` counters using the AES 128 pseudorandom generator.
    Prio3Aes128CountVec { length: usize },
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

/// A verification key for a VDAF, with a fixed length. It must be kept secret from clients to
/// maintain robustness, and it must be shared between aggregators.
pub struct VerifyKey<const L: usize>([u8; L]);

impl<const L: usize> VerifyKey<L> {
    pub fn new(array: [u8; L]) -> VerifyKey<L> {
        VerifyKey(array)
    }

    pub fn as_bytes(&self) -> &[u8; L] {
        &self.0
    }
}

impl<const L: usize> TryFrom<&SecretBytes> for VerifyKey<L> {
    type Error = TryFromSliceError;

    fn try_from(value: &SecretBytes) -> Result<VerifyKey<L>, TryFromSliceError> {
        let array = <[u8; L] as TryFrom<&[u8]>>::try_from(&value.0)?;
        Ok(VerifyKey::new(array))
    }
}

/// The parameters for a DAP task, corresponding to draft-gpew-priv-ppm §4.2.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct Task {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// URLs relative to which aggregator API endpoints are found. The first
    /// entry is the leader's.
    #[derivative(Debug(format_with = "fmt_vector_of_urls"))]
    aggregator_endpoints: Vec<Url>,
    /// The VDAF this task executes.
    vdaf: VdafInstance,
    /// The role performed by the aggregator.
    role: Role,
    /// Secret verification keys shared by the aggregators.
    #[derivative(Debug = "ignore")]
    vdaf_verify_keys: Vec<SecretBytes>,
    /// The maximum number of times a given batch may be collected.
    max_batch_lifetime: u64,
    /// The minimum number of reports in a batch to allow it to be collected.
    min_batch_size: u64,
    /// The minimum batch interval for a collect request. Batch intervals must
    /// be multiples of this duration.
    min_batch_duration: Duration,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    tolerable_clock_skew: Duration,
    /// HPKE configuration for the collector.
    collector_hpke_config: HpkeConfig,
    /// Tokens used to authenticate messages sent to or received from the other aggregator.
    #[derivative(Debug = "ignore")]
    aggregator_auth_tokens: Vec<AuthenticationToken>,
    /// Tokens used to authenticate messages sent to or received from the collector.
    #[derivative(Debug = "ignore")]
    collector_auth_tokens: Vec<AuthenticationToken>,
    /// HPKE configurations & private keys used by this aggregator to decrypt client reports.
    hpke_keys: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
}

impl Task {
    /// Create a new [`Task`] from the provided values
    pub fn new<I: IntoIterator<Item = (HpkeConfig, HpkePrivateKey)>>(
        task_id: TaskId,
        mut aggregator_endpoints: Vec<Url>,
        vdaf: VdafInstance,
        role: Role,
        vdaf_verify_keys: Vec<SecretBytes>,
        max_batch_lifetime: u64,
        min_batch_size: u64,
        min_batch_duration: Duration,
        tolerable_clock_skew: Duration,
        collector_hpke_config: HpkeConfig,
        aggregator_auth_tokens: Vec<AuthenticationToken>,
        collector_auth_tokens: Vec<AuthenticationToken>,
        hpke_keys: I,
    ) -> Result<Self, Error> {
        // DAP currently only supports configurations of exactly two aggregators.
        if aggregator_endpoints.len() != 2 {
            return Err(Error::InvalidParameter("aggregator_endpoints"));
        }
        if !role.is_aggregator() {
            return Err(Error::InvalidParameter("role"));
        }
        if aggregator_auth_tokens.is_empty() {
            return Err(Error::InvalidParameter("aggregator_auth_tokens"));
        }
        if (role == Role::Leader) == (collector_auth_tokens.is_empty()) {
            // Collector auth tokens are allowed & required if and only if this task is in the
            // leader role.
            return Err(Error::InvalidParameter("collector_auth_tokens"));
        }
        if vdaf_verify_keys.is_empty() {
            return Err(Error::InvalidParameter("vdaf_verify_keys"));
        }

        // Ensure provided aggregator endpoints end with a slash, as we will be joining additional
        // path segments into these endpoints & the Url::join implementation is persnickety about
        // the slash at the end of the path.
        for url in &mut aggregator_endpoints {
            url_ensure_trailing_slash(url);
        }

        // Compute hpke_configs mapping cfg.id -> (cfg, key).
        let hpke_keys: HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)> = hpke_keys
            .into_iter()
            .map(|(cfg, key)| (*cfg.id(), (cfg, key)))
            .collect();
        if hpke_keys.is_empty() {
            return Err(Error::InvalidParameter("hpke_configs"));
        }

        Ok(Self {
            task_id,
            aggregator_endpoints,
            vdaf,
            role,
            vdaf_verify_keys,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            tolerable_clock_skew,
            collector_hpke_config,
            aggregator_auth_tokens,
            collector_auth_tokens,
            hpke_keys,
        })
    }

    /// Retrieves the task ID associated with this task.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Retrieves the aggregator endpoints associated with this task in natural order.
    pub fn aggregator_endpoints(&self) -> &[Url] {
        &self.aggregator_endpoints
    }

    /// Retrieves the VDAF associated with this task.
    pub fn vdaf(&self) -> &VdafInstance {
        &self.vdaf
    }

    /// Retrieves the role associated with this task.
    pub fn role(&self) -> &Role {
        &self.role
    }

    /// Retrieves the VDAF verification keys associated with this task.
    pub fn vdaf_verify_keys(&self) -> &[SecretBytes] {
        &self.vdaf_verify_keys
    }

    /// Retrieves the max batch lifetime parameter associated with this task.
    pub fn max_batch_lifetime(&self) -> u64 {
        self.max_batch_lifetime
    }

    /// Retrieves the min batch size parameter associated with this task.
    pub fn min_batch_size(&self) -> u64 {
        self.min_batch_size
    }

    /// Retrieves the min batch duration parameter associated with this task.
    pub fn min_batch_duration(&self) -> &Duration {
        &self.min_batch_duration
    }

    /// Retrieves the tolerable clock skew parameter associated with this task.
    pub fn tolerable_clock_skew(&self) -> &Duration {
        &self.tolerable_clock_skew
    }

    /// Retrieves the collector HPKE config associated with this task.
    pub fn collector_hpke_config(&self) -> &HpkeConfig {
        &self.collector_hpke_config
    }

    /// Retrieves the aggregator authentication tokens associated with this task.
    pub fn aggregator_auth_tokens(&self) -> &[AuthenticationToken] {
        &self.aggregator_auth_tokens
    }

    /// Retrieves the collector authentication tokens associated with this task.
    pub fn collector_auth_tokens(&self) -> &[AuthenticationToken] {
        &self.collector_auth_tokens
    }

    /// Retrieves the HPKE keys in use associated with this task.
    pub fn hpke_keys(&self) -> &HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)> {
        &self.hpke_keys
    }

    /// Returns true if `batch_interval` is valid, per §4.6 of draft-gpew-priv-ppm.
    pub(crate) fn validate_batch_interval(&self, batch_interval: &Interval) -> bool {
        // Batch interval should be greater than task's minimum batch duration
        batch_interval.duration().as_seconds() >= self.min_batch_duration.as_seconds()
            // Batch interval start must be a multiple of minimum batch duration
            && batch_interval.start().as_seconds_since_epoch() % self.min_batch_duration.as_seconds() == 0
            // Batch interval duration must be a multiple of minimum batch duration
            && batch_interval.duration().as_seconds() % self.min_batch_duration.as_seconds() == 0
    }

    /// Returns the [`Url`] relative to which the server performing `role` serves its API.
    pub fn aggregator_url(&self, role: &Role) -> Result<&Url, Error> {
        let index = role.index().ok_or(Error::InvalidParameter(role.as_str()))?;
        Ok(&self.aggregator_endpoints[index])
    }

    /// Returns the [`AuthenticationToken`] currently used by this aggregator to authenticate itself
    /// to other aggregators.
    pub fn primary_aggregator_auth_token(&self) -> &AuthenticationToken {
        self.aggregator_auth_tokens.iter().rev().next().unwrap()
    }

    /// Checks if the given aggregator authentication token is valid (i.e. matches with an
    /// authentication token recognized by this task).
    pub(crate) fn check_aggregator_auth_token(&self, auth_token: &AuthenticationToken) -> bool {
        self.aggregator_auth_tokens
            .iter()
            .rev()
            .any(|t| t == auth_token)
    }

    /// Returns the [`AuthenticationToken`] currently used by the collector to authenticate itself
    /// to the aggregators.
    pub fn primary_collector_auth_token(&self) -> &AuthenticationToken {
        self.collector_auth_tokens.iter().rev().next().unwrap()
    }

    /// Checks if the given collector authentication token is valid (i.e. matches with an
    /// authentication token recognized by this task).
    pub(crate) fn check_collector_auth_token(&self, auth_token: &AuthenticationToken) -> bool {
        self.collector_auth_tokens
            .iter()
            .rev()
            .any(|t| t == auth_token)
    }

    /// Returns the [`VerifyKey`] currently used by this aggregator to prepare report shares with
    /// other aggregators.
    ///
    /// # Errors
    ///
    /// If the verify key is not the correct length as required by the VDAF, an error will be
    /// returned.
    pub fn primary_vdaf_verify_key<const L: usize>(&self) -> Result<VerifyKey<L>, Error> {
        // We can safely unwrap this because we maintain an invariant that this vector is
        // non-empty.
        let secret_bytes = self.vdaf_verify_keys.first().unwrap();
        VerifyKey::try_from(secret_bytes).map_err(|_| Error::AggregatorVerifyKeySize)
    }
}

fn fmt_vector_of_urls(urls: &Vec<Url>, f: &mut Formatter<'_>) -> fmt::Result {
    let mut list = f.debug_list();
    for url in urls {
        list.entry(&format!("{}", url));
    }
    list.finish()
}

/// SerializedTask is an intermediate representation for tasks being serialized via the Serialize &
/// Deserialize traits.
#[derive(Serialize, Deserialize)]
struct SerializedTask {
    task_id: String, // in unpadded base64url
    aggregator_endpoints: Vec<Url>,
    vdaf: VdafInstance,
    role: Role,
    vdaf_verify_keys: Vec<String>, // in unpadded base64url
    max_batch_lifetime: u64,
    min_batch_size: u64,
    min_batch_duration: Duration,
    tolerable_clock_skew: Duration,
    collector_hpke_config: SerializedHpkeConfig,
    aggregator_auth_tokens: Vec<String>, // in unpadded base64url
    collector_auth_tokens: Vec<String>,  // in unpadded base64url
    hpke_keys: Vec<SerializedHpkeKeypair>, // in unpadded base64url
}

impl Serialize for Task {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let task_id = base64::encode_config(self.task_id.as_ref(), URL_SAFE_NO_PAD);
        let vdaf_verify_keys: Vec<_> = self
            .vdaf_verify_keys
            .iter()
            .map(|key| base64::encode_config(key.as_ref(), URL_SAFE_NO_PAD))
            .collect();
        let aggregator_auth_tokens = self
            .aggregator_auth_tokens
            .iter()
            .map(|token| base64::encode_config(token.as_bytes(), URL_SAFE_NO_PAD))
            .collect();
        let collector_auth_tokens = self
            .collector_auth_tokens
            .iter()
            .map(|token| base64::encode_config(token.as_bytes(), URL_SAFE_NO_PAD))
            .collect();
        let hpke_keys = self
            .hpke_keys
            .values()
            .map(|keypair| keypair.clone().into())
            .collect();

        SerializedTask {
            task_id,
            aggregator_endpoints: self.aggregator_endpoints.clone(),
            vdaf: self.vdaf.clone(),
            role: self.role,
            vdaf_verify_keys,
            max_batch_lifetime: self.max_batch_lifetime,
            min_batch_size: self.min_batch_size,
            min_batch_duration: self.min_batch_duration,
            tolerable_clock_skew: self.tolerable_clock_skew,
            collector_hpke_config: self.collector_hpke_config.clone().into(),
            aggregator_auth_tokens,
            collector_auth_tokens,
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
        let task_id_bytes: [u8; TaskId::LEN] =
            base64::decode_config(serialized_task.task_id, URL_SAFE_NO_PAD)
                .map_err(D::Error::custom)?
                .try_into()
                .map_err(|_| D::Error::custom("task_id length incorrect"))?;
        let task_id = TaskId::from(task_id_bytes);

        // vdaf_verify_keys
        let vdaf_verify_keys: Vec<_> = serialized_task
            .vdaf_verify_keys
            .into_iter()
            .map(|key| {
                Ok(SecretBytes::new(
                    base64::decode_config(key, URL_SAFE_NO_PAD).map_err(D::Error::custom)?,
                ))
            })
            .collect::<Result<_, _>>()?;

        // collector_hpke_config
        let collector_hpke_config = serialized_task
            .collector_hpke_config
            .try_into()
            .map_err(D::Error::custom)?;

        // aggregator_auth_tokens
        let aggregator_auth_tokens = serialized_task
            .aggregator_auth_tokens
            .into_iter()
            .map(|token| {
                Ok(AuthenticationToken::from(
                    base64::decode_config(token, URL_SAFE_NO_PAD).map_err(D::Error::custom)?,
                ))
            })
            .collect::<Result<_, _>>()?;

        // collector_auth_tokens
        let collector_auth_tokens = serialized_task
            .collector_auth_tokens
            .into_iter()
            .map(|token| {
                Ok(AuthenticationToken::from(
                    base64::decode_config(token, URL_SAFE_NO_PAD).map_err(D::Error::custom)?,
                ))
            })
            .collect::<Result<_, _>>()?;

        // hpke_keys
        let hpke_keys: Vec<(_, _)> = serialized_task
            .hpke_keys
            .into_iter()
            .map(|keypair| keypair.try_into().map_err(D::Error::custom))
            .collect::<Result<_, _>>()?;

        Task::new(
            task_id,
            serialized_task.aggregator_endpoints,
            serialized_task.vdaf,
            serialized_task.role,
            vdaf_verify_keys,
            serialized_task.max_batch_lifetime,
            serialized_task.min_batch_size,
            serialized_task.min_batch_duration,
            serialized_task.tolerable_clock_skew,
            collector_hpke_config,
            aggregator_auth_tokens,
            collector_auth_tokens,
            hpke_keys,
        )
        .map_err(D::Error::custom)
    }
}

/// This is a serialization-helper type corresponding to an HpkeConfig.
#[derive(Serialize, Deserialize)]
struct SerializedHpkeConfig {
    id: HpkeConfigId,
    kem_id: HpkeKemId,
    kdf_id: HpkeKdfId,
    aead_id: HpkeAeadId,
    public_key: String, // in unpadded base64url
}

impl From<HpkeConfig> for SerializedHpkeConfig {
    fn from(cfg: HpkeConfig) -> Self {
        Self {
            id: *cfg.id(),
            kem_id: *cfg.kem_id(),
            kdf_id: *cfg.kdf_id(),
            aead_id: *cfg.aead_id(),
            public_key: base64::encode_config(cfg.public_key().as_ref(), URL_SAFE_NO_PAD),
        }
    }
}

impl TryFrom<SerializedHpkeConfig> for HpkeConfig {
    type Error = base64::DecodeError;

    fn try_from(cfg: SerializedHpkeConfig) -> Result<Self, Self::Error> {
        let public_key =
            HpkePublicKey::from(base64::decode_config(cfg.public_key, URL_SAFE_NO_PAD)?);
        Ok(Self::new(
            cfg.id,
            cfg.kem_id,
            cfg.kdf_id,
            cfg.aead_id,
            public_key,
        ))
    }
}

/// This is a serialization-helper type corresponding to an (HpkeConfig, HpkePrivateKey).
#[derive(Serialize, Deserialize)]
struct SerializedHpkeKeypair {
    config: SerializedHpkeConfig,
    private_key: String, // in unpadded base64url
}

impl From<(HpkeConfig, HpkePrivateKey)> for SerializedHpkeKeypair {
    fn from(keypair: (HpkeConfig, HpkePrivateKey)) -> Self {
        Self {
            config: keypair.0.into(),
            private_key: base64::encode_config(&keypair.1, URL_SAFE_NO_PAD),
        }
    }
}

impl TryFrom<SerializedHpkeKeypair> for (HpkeConfig, HpkePrivateKey) {
    type Error = base64::DecodeError;

    fn try_from(keypair: SerializedHpkeKeypair) -> Result<Self, Self::Error> {
        Ok((
            keypair.config.try_into()?,
            HpkePrivateKey::new(base64::decode_config(keypair.private_key, URL_SAFE_NO_PAD)?),
        ))
    }
}

// This is public to allow use in integration tests.
#[cfg(feature = "test-util")]
pub mod test_util {
    use super::{
        AuthenticationToken, SecretBytes, Task, VdafInstance, PRIO3_AES128_VERIFY_KEY_LENGTH,
    };
    use crate::messages::DurationExt;
    use janus_core::hpke::test_util::generate_test_hpke_config_and_private_key;
    use janus_messages::{Duration, HpkeConfig, HpkeConfigId, Role, TaskId};
    use rand::{distributions::Standard, random, thread_rng, Rng};
    use url::Url;

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

    /// TaskBuilder is a testing utility allowing tasks to be built based on a template.
    pub struct TaskBuilder(Task);

    impl TaskBuilder {
        /// Create a [`TaskBuilder`] from the provided values, with arbitrary values for the other
        /// task parameters.
        pub fn new(vdaf: VdafInstance, role: Role) -> Self {
            let task_id = random();
            let (aggregator_config_0, aggregator_private_key_0) =
                generate_test_hpke_config_and_private_key();
            let (mut aggregator_config_1, aggregator_private_key_1) =
                generate_test_hpke_config_and_private_key();
            aggregator_config_1 = HpkeConfig::new(
                HpkeConfigId::from(1),
                *aggregator_config_1.kem_id(),
                *aggregator_config_1.kdf_id(),
                *aggregator_config_1.aead_id(),
                aggregator_config_1.public_key().clone(),
            );

            let vdaf_verify_key = SecretBytes::new(
                thread_rng()
                    .sample_iter(Standard)
                    .take(vdaf.verify_key_length())
                    .collect(),
            );

            let collector_auth_tokens = if role == Role::Leader {
                Vec::from([generate_auth_token(), generate_auth_token()])
            } else {
                Vec::new()
            };

            Self(
                Task::new(
                    task_id,
                    Vec::from([
                        "https://leader.endpoint".parse().unwrap(),
                        "https://helper.endpoint".parse().unwrap(),
                    ]),
                    vdaf,
                    role,
                    Vec::from([vdaf_verify_key]),
                    1,
                    0,
                    Duration::from_hours(8).unwrap(),
                    Duration::from_minutes(10).unwrap(),
                    generate_test_hpke_config_and_private_key().0,
                    Vec::from([generate_auth_token(), generate_auth_token()]),
                    collector_auth_tokens,
                    Vec::from([
                        (aggregator_config_0, aggregator_private_key_0),
                        (aggregator_config_1, aggregator_private_key_1),
                    ]),
                )
                .unwrap(),
            )
        }

        /// Associates the eventual task with the given task ID.
        pub fn with_task_id(self, task_id: TaskId) -> Self {
            Self(Task { task_id, ..self.0 })
        }

        /// Associates the eventual task with the given aggregator endpoints.
        pub fn with_aggregator_endpoints(self, aggregator_endpoints: Vec<Url>) -> Self {
            Self(Task {
                aggregator_endpoints,
                ..self.0
            })
        }

        /// Associates the eventual task with the given max batch lifetime parameter.
        pub fn with_max_batch_lifetime(self, max_batch_lifetime: u64) -> Self {
            Self(Task {
                max_batch_lifetime,
                ..self.0
            })
        }

        /// Associates the eventual task with the given min batch size parameter.
        pub fn with_min_batch_size(self, min_batch_size: u64) -> Self {
            Self(Task {
                min_batch_size,
                ..self.0
            })
        }

        /// Associates the eventual task with the given min batch duration parameter.
        pub fn with_min_batch_duration(self, min_batch_duration: Duration) -> Self {
            Self(Task {
                min_batch_duration,
                ..self.0
            })
        }

        /// Associates the eventual task with the given collector HPKE config.
        pub fn with_collector_hpke_config(self, collector_hpke_config: HpkeConfig) -> Self {
            Self(Task {
                collector_hpke_config,
                ..self.0
            })
        }

        /// Associates the eventual task with the given aggregator authentication tokens.
        pub fn with_aggregator_auth_tokens(
            self,
            aggregator_auth_tokens: Vec<AuthenticationToken>,
        ) -> Self {
            Self(Task {
                aggregator_auth_tokens,
                ..self.0
            })
        }

        /// Consumes this task builder & produces a [`Task`] with the given specifications.
        pub fn build(self) -> Task {
            self.0
        }
    }

    pub fn generate_auth_token() -> AuthenticationToken {
        let buf: [u8; 16] = random();
        base64::encode_config(&buf, base64::URL_SAFE_NO_PAD)
            .into_bytes()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        test_util::generate_auth_token, SecretBytes, Task, PRIO3_AES128_VERIFY_KEY_LENGTH,
    };
    use crate::{
        config::test_util::roundtrip_encoding,
        messages::DurationExt,
        task::{test_util::TaskBuilder, VdafInstance},
    };
    use janus_core::hpke::test_util::generate_test_hpke_config_and_private_key;
    use janus_messages::{Duration, Interval, Role, Time};
    use rand::random;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn validate_batch_interval() {
        let min_batch_duration_secs = 3600;
        let task = TaskBuilder::new(VdafInstance::Fake, Role::Leader)
            .with_min_batch_duration(Duration::from_seconds(min_batch_duration_secs))
            .build();

        struct TestCase {
            name: &'static str,
            input: Interval,
            expected: bool,
        }

        for test_case in Vec::from([
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
        ]) {
            assert_eq!(
                test_case.expected,
                task.validate_batch_interval(&test_case.input),
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
            &VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128CountVec { length: 8 }),
            &[
                Token::StructVariant {
                    name: "Vdaf",
                    variant: "Prio3Aes128CountVec",
                    len: 1,
                },
                Token::Str("length"),
                Token::U64(8),
                Token::StructVariantEnd,
            ],
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
                buckets: Vec::from([0, 100, 200, 400]),
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
        roundtrip_encoding(
            TaskBuilder::new(
                VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
                Role::Leader,
            )
            .build(),
        );
    }

    #[test]
    fn collector_auth_tokens() {
        // As leader, we receive an error if no collector auth token is specified.
        Task::new(
            random(),
            Vec::from([
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ]),
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
            Role::Leader,
            Vec::from([SecretBytes::new([0; PRIO3_AES128_VERIFY_KEY_LENGTH].into())]),
            0,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            generate_test_hpke_config_and_private_key().0,
            Vec::from([generate_auth_token()]),
            Vec::new(),
            Vec::from([generate_test_hpke_config_and_private_key()]),
        )
        .unwrap_err();

        // As leader, we receive no error if a collector auth token is specified.
        Task::new(
            random(),
            Vec::from([
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ]),
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
            Role::Leader,
            Vec::from([SecretBytes::new([0; PRIO3_AES128_VERIFY_KEY_LENGTH].into())]),
            0,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            generate_test_hpke_config_and_private_key().0,
            Vec::from([generate_auth_token()]),
            Vec::from([generate_auth_token()]),
            Vec::from([generate_test_hpke_config_and_private_key()]),
        )
        .unwrap();

        // As helper, we receive no error if no collector auth token is specified.
        Task::new(
            random(),
            Vec::from([
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ]),
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
            Role::Helper,
            Vec::from([SecretBytes::new([0; PRIO3_AES128_VERIFY_KEY_LENGTH].into())]),
            0,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            generate_test_hpke_config_and_private_key().0,
            Vec::from([generate_auth_token()]),
            Vec::new(),
            Vec::from([generate_test_hpke_config_and_private_key()]),
        )
        .unwrap();

        // As helper, we receive an error if a collector auth token is specified.
        Task::new(
            random(),
            Vec::from([
                "http://leader_endpoint".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ]),
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
            Role::Helper,
            Vec::from([SecretBytes::new([0; PRIO3_AES128_VERIFY_KEY_LENGTH].into())]),
            0,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            generate_test_hpke_config_and_private_key().0,
            Vec::from([generate_auth_token()]),
            Vec::from([generate_auth_token()]),
            Vec::from([generate_test_hpke_config_and_private_key()]),
        )
        .unwrap_err();
    }

    #[test]
    fn aggregator_endpoints_end_in_slash() {
        let task = Task::new(
            random(),
            Vec::from([
                "http://leader_endpoint/foo/bar".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ]),
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count),
            Role::Leader,
            Vec::from([SecretBytes::new([0; PRIO3_AES128_VERIFY_KEY_LENGTH].into())]),
            0,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            generate_test_hpke_config_and_private_key().0,
            Vec::from([generate_auth_token()]),
            Vec::from([generate_auth_token()]),
            Vec::from([generate_test_hpke_config_and_private_key()]),
        )
        .unwrap();

        assert_eq!(
            task.aggregator_endpoints,
            Vec::from([
                "http://leader_endpoint/foo/bar/".parse().unwrap(),
                "http://helper_endpoint/".parse().unwrap()
            ])
        );
    }
}
