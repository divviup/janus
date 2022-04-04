//! Shared parameters for a PPM task.

use crate::{
    hpke::{HpkeRecipient, Label},
    message::{Duration, HpkeConfig, Role, TaskId},
};
use postgres_types::{FromSql, ToSql};
use ring::{
    digest::SHA256_OUTPUT_LEN,
    hmac::{self, HMAC_SHA256},
    rand::{self, SystemRandom},
};
use url::Url;

/// Errors that methods and functions in this module may return.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid parameter {0}")]
    InvalidParameter(&'static str),
    #[error("failed to generate aggregator authentication key")]
    AggregatorAuthenticationKeyGeneration,
    #[error("URL parse error")]
    Url(#[from] url::ParseError),
    #[error("could not convert slice to array: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
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

/// An HMAC SHA-256 key used to authenticate messages exchanged between
/// aggregators. See `agg_auth_key` in draft-gpew-priv-ppm §4.2. We define this
/// because while we can use [`ring::hmac::Key::new`] to get a
/// [`ring::hmac::Key`] from a slice of bytes, we can't get the bytes back out
/// of the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregatorAuthKey([u8; SHA256_OUTPUT_LEN]);

impl AggregatorAuthKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into()?))
    }

    /// Randomly generate an [`AggregatorAuthKey`].
    pub fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        Ok(Self(
            rand::generate(&rng)
                .map_err(|_| Error::AggregatorAuthenticationKeyGeneration)?
                .expose(),
        ))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_hmac_key(&self) -> hmac::Key {
        hmac::Key::new(HMAC_SHA256, &self.0)
    }
}

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
    /// HPKE configuration for the collector.
    pub(crate) collector_hpke_config: HpkeConfig,
    /// Key used to authenticate messages sent to or received from the other
    /// aggregators.
    pub(crate) agg_auth_key: AggregatorAuthKey,
    /// HPKE recipient used by this aggregator to decrypt client reports
    pub(crate) hpke_recipient: HpkeRecipient,
}

impl TaskParameters {
    /// Create a new [`TaskParameters`] from the provided values
    pub fn new(
        id: TaskId,
        aggregator_endpoints: Vec<Url>,
        vdaf: Vdaf,
        role: Role,
        vdaf_verify_parameter: Vec<u8>,
        max_batch_lifetime: u64,
        min_batch_size: u64,
        min_batch_duration: Duration,
        collector_hpke_config: &HpkeConfig,
        agg_auth_key: AggregatorAuthKey,
        hpke_recipient: &HpkeRecipient,
    ) -> Self {
        // All currently defined VDAFs have exactly two aggregators
        assert_eq!(aggregator_endpoints.len(), 2);

        Self {
            id,
            aggregator_endpoints,
            vdaf,
            role,
            vdaf_verify_parameter,
            max_batch_lifetime,
            min_batch_size,
            min_batch_duration,
            collector_hpke_config: collector_hpke_config.clone(),
            agg_auth_key,
            hpke_recipient: hpke_recipient.clone(),
        }
    }

    /// Create a dummy [`TaskParameters`] from the provided [`TaskId`], with
    /// dummy values for the other fields. This is pub because it is needed for
    /// integration tests.
    #[doc(hidden)]
    pub fn new_dummy(
        task_id: TaskId,
        aggregator_endpoints: Vec<Url>,
        vdaf: Vdaf,
        role: Role,
    ) -> Self {
        Self {
            id: task_id,
            aggregator_endpoints,
            vdaf,
            role,
            vdaf_verify_parameter: vec![],
            max_batch_lifetime: 0,
            min_batch_size: 0,
            min_batch_duration: Duration(1),
            collector_hpke_config: HpkeRecipient::generate(
                task_id,
                Label::AggregateShare,
                Role::Leader,
                Role::Collector,
            )
            .config()
            .clone(),
            agg_auth_key: AggregatorAuthKey::generate().unwrap(),
            hpke_recipient: HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, role),
        }
    }
}
