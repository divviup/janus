//! Shared parameters for a PPM task.

use crate::{
    hpke::{HpkeRecipient, Label},
    message::{Duration, HpkeConfig, Role, TaskId},
};
use postgres_types::{FromSql, ToSql};
use url::Url;

/// Errors that methods and functions in this module may return.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid parameter {0}")]
    InvalidParameter(&'static str),
    #[error("URL parse error")]
    Url(#[from] url::ParseError),
}

/// Identifiers for VDAFs supported by this aggregator, corresponding to
/// definitions in [draft-patton-cfrg-vdaf][1] and implementations in
/// [`prio::vdaf::prio3`].
///
/// [1]: https://datatracker.ietf.org/doc/draft-patton-cfrg-vdaf/
#[derive(Debug, Clone, ToSql, FromSql)]
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

/// The parameters for a PPM task, corresponding to draft-gpew-priv-ppm §4.2.
#[derive(Clone, Debug)]
pub struct TaskParameters {
    /// Unique identifier for the task
    pub(crate) id: TaskId,
    /// URLs relative to which aggregator API endpoints are found. The first
    /// entry is the leader's.
    pub(crate) aggregator_endpoints: Vec<Url>,
    /// The VDAF this task executes.
    _vdaf: Vdaf,
    /// Secret verification parameter shared by the aggregators.
    _vdaf_verify_parameter: Vec<u8>,
    /// The maximum number of times a given batch may be collected.
    _max_batch_lifetime: u64,
    /// The minimum number of reports in a batch to allow it to be collected.
    _min_batch_size: u64,
    /// The minimum batch interval for a collect request. Batch intervals must
    /// be multiples of this duration.
    _min_batch_duration: Duration,
    /// HPKE configuration for the collector
    _collector_hpke_config: HpkeConfig,
}

impl TaskParameters {
    /// Create a new [`TaskParameters`] from the provided values
    pub fn new(
        id: TaskId,
        aggregator_endpoints: Vec<Url>,
        vdaf: Vdaf,
        vdaf_verify_parameter: Vec<u8>,
        max_batch_lifetime: u64,
        min_batch_size: u64,
        min_batch_duration: Duration,
        collector_hpke_config: &HpkeConfig,
    ) -> Self {
        // All currently defined VDAFs have exactly two aggregators
        assert_eq!(aggregator_endpoints.len(), 2);

        Self {
            id,
            aggregator_endpoints,
            _vdaf: vdaf,
            _vdaf_verify_parameter: vdaf_verify_parameter,
            _max_batch_lifetime: max_batch_lifetime,
            _min_batch_size: min_batch_size,
            _min_batch_duration: min_batch_duration,
            _collector_hpke_config: collector_hpke_config.clone(),
        }
    }

    /// Create a dummy [`TaskParameters`] from the provided [`TaskId`], with
    /// dummy values for the other fields. This is pub because it is needed for
    /// integration tests.
    #[doc(hidden)]
    pub fn new_dummy(task_id: TaskId, aggregator_endpoints: Vec<Url>) -> Self {
        Self {
            id: task_id,
            aggregator_endpoints,
            _vdaf: Vdaf::Prio3Aes128Count,
            _vdaf_verify_parameter: vec![],
            _max_batch_lifetime: 0,
            _min_batch_size: 0,
            _min_batch_duration: Duration(1),
            _collector_hpke_config: HpkeRecipient::generate(
                task_id,
                Label::AggregateShare,
                Role::Leader,
                Role::Collector,
            )
            .config,
        }
    }

    /// The URL relative to which the API endpoints for the aggregator may be
    /// found, if the role is an aggregator, or an error otherwise.
    fn aggregator_endpoint(&self, role: Role) -> Result<&Url, Error> {
        Ok(&self.aggregator_endpoints[role
            .index()
            .ok_or(Error::InvalidParameter("role is not an aggregator"))?])
    }

    /// URL from which the HPKE configuration for the server filling `role` may
    /// be fetched per draft-gpew-priv-ppm §4.3.1
    pub(crate) fn hpke_config_endpoint(&self, role: Role) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(role)?.join("hpke_config")?)
    }

    /// URL to which reports may be uploaded by clients per draft-gpew-priv-ppm
    /// §4.3.2
    pub(crate) fn upload_endpoint(&self) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(Role::Leader)?.join("upload")?)
    }
}
