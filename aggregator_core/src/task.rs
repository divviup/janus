//! Shared parameters for a DAP task.

use crate::SecretBytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use derivative::Derivative;
use janus_core::{
    auth_tokens::{AuthenticationToken, AuthenticationTokenHash},
    hpke::{generate_hpke_config_and_private_key, HpkeKeypair},
    time::TimeExt,
    vdaf::VdafInstance,
};
use janus_messages::{
    taskprov, AggregationJobId, Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId,
    HpkeKemId, Role, TaskId, Time,
};
use rand::{distributions::Standard, random, thread_rng, Rng};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{array::TryFromSliceError, collections::HashMap};
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
    #[error("base64 decode error")]
    Base64Decode(#[from] base64::DecodeError),
}

/// Identifiers for query types used by a task, along with query-type specific configuration.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QueryType {
    /// Time-interval: used to support a collection style based on fixed time intervals.
    TimeInterval,

    /// Fixed-size: used to support collection of batches as quickly as possible, without the
    /// latency of waiting for batch time intervals to pass, and with direct control over the number
    /// of reports per batch.
    FixedSize {
        /// The maximum number of reports in a batch to allow it to be collected.
        max_batch_size: u64,
        /// If present, reports will be separated into different batches by timestamp, such that
        /// the client timestamp interval duration will not exceed this value. The minimum and
        /// maximum allowed report timestamps for each batch will be multiples of this value as
        /// well. This must be a multiple of the task's time precision.
        ///
        /// This is an implementation-specific configuration parameter, and not part of the query
        /// type as defined in DAP.
        batch_time_window_size: Option<Duration>,
    },
}

impl TryFrom<&taskprov::Query> for QueryType {
    type Error = Error;

    fn try_from(value: &taskprov::Query) -> Result<Self, Self::Error> {
        match value {
            taskprov::Query::TimeInterval => Ok(Self::TimeInterval),
            taskprov::Query::FixedSize { max_batch_size } => Ok(Self::FixedSize {
                max_batch_size: *max_batch_size as u64,
                batch_time_window_size: None,
            }),
            _ => Err(Error::InvalidParameter("unknown query type")),
        }
    }
}

/// A verification key for a VDAF, with a fixed length. It must be kept secret from clients to
/// maintain robustness, and it must be shared between aggregators.
pub struct VerifyKey<const SEED_SIZE: usize>([u8; SEED_SIZE]);

impl<const SEED_SIZE: usize> VerifyKey<SEED_SIZE> {
    pub fn new(array: [u8; SEED_SIZE]) -> VerifyKey<SEED_SIZE> {
        VerifyKey(array)
    }

    pub fn as_bytes(&self) -> &[u8; SEED_SIZE] {
        &self.0
    }
}

impl<const SEED_SIZE: usize> TryFrom<&SecretBytes> for VerifyKey<SEED_SIZE> {
    type Error = TryFromSliceError;

    fn try_from(value: &SecretBytes) -> Result<VerifyKey<SEED_SIZE>, TryFromSliceError> {
        let array = <[u8; SEED_SIZE] as TryFrom<&[u8]>>::try_from(&value.0)?;
        Ok(VerifyKey::new(array))
    }
}

/// Task parameters common to all views of a DAP task.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
struct CommonTaskParameters {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// The query type this task uses to generate batches.
    query_type: QueryType,
    /// The VDAF this task executes.
    vdaf: VdafInstance,
    /// Secret verification key shared by the aggregators.
    vdaf_verify_key: SecretBytes,
    /// The maximum number of times a given batch may be collected.
    max_batch_query_count: u64,
    /// The time after which the task is considered invalid.
    task_expiration: Option<Time>,
    /// The age after which a report is considered to be "expired" and will be considered a
    /// candidate for garbage collection. A value of `None` indicates that garbage collection is
    /// disabled.
    report_expiry_age: Option<Duration>,
    /// The minimum number of reports in a batch to allow it to be collected.
    min_batch_size: u64,
    /// The duration to which clients should round their reported timestamps to. For time-interval
    /// tasks, batch intervals must be multiples of this duration.
    time_precision: Duration,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    tolerable_clock_skew: Duration,
}

impl CommonTaskParameters {
    /// Create a new [`CommonTaskParameters`] with the provided values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        query_type: QueryType,
        vdaf: VdafInstance,
        vdaf_verify_key: SecretBytes,
        max_batch_query_count: u64,
        task_expiration: Option<Time>,
        report_expiry_age: Option<Duration>,
        min_batch_size: u64,
        time_precision: Duration,
        tolerable_clock_skew: Duration,
    ) -> Result<Self, Error> {
        if let QueryType::FixedSize { max_batch_size, .. } = query_type {
            if max_batch_size < min_batch_size {
                return Err(Error::InvalidParameter("max_batch_size"));
            }
        }

        // These fields are stored as 64-bit signed integers in the database but are held in
        // memory as unsigned. Reject values that are too large. (perhaps these should be
        // represented by different types?)
        if let Some(report_expiry_age) = report_expiry_age {
            if report_expiry_age > Duration::from_seconds(i64::MAX as u64) {
                return Err(Error::InvalidParameter("report_expiry_age too large"));
            }
        }
        if let Some(task_expiration) = task_expiration {
            task_expiration
                .as_naive_date_time()
                .map_err(|_| Error::InvalidParameter("task_expiration out of range"))?;
        }

        Ok(Self {
            task_id,
            query_type,
            vdaf,
            vdaf_verify_key,
            max_batch_query_count,
            task_expiration,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
        })
    }

    /// Returns the [`VerifyKey`] used by this aggregator to prepare report shares with other
    /// aggregators.
    ///
    /// # Errors
    ///
    /// If the verify key is not the correct length as required by the VDAF, an error will be
    /// returned.
    pub fn vdaf_verify_key<const SEED_SIZE: usize>(&self) -> Result<VerifyKey<SEED_SIZE>, Error> {
        VerifyKey::try_from(&self.vdaf_verify_key).map_err(|_| Error::AggregatorVerifyKeySize)
    }
}

/// An aggregator's view of the task's parameters.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct AggregatorTask {
    /// Common task parameters
    common_parameters: CommonTaskParameters,
    /// URL relative to which the peer aggregator's API endpoints are found.
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    peer_aggregator_endpoint: Url,
    /// Parameters specific to either aggregator role
    aggregator_parameters: AggregatorTaskParameters,
    /// HPKE configurations & private keys used by this aggregator to decrypt client reports.
    hpke_keys: HashMap<HpkeConfigId, HpkeKeypair>,
}

impl AggregatorTask {
    /// Create a new [`AggregatorTask`] with the provided values.
    #[allow(clippy::too_many_arguments)]
    pub fn new<I: IntoIterator<Item = HpkeKeypair>>(
        task_id: TaskId,
        peer_aggregator_endpoint: Url,
        query_type: QueryType,
        vdaf: VdafInstance,
        vdaf_verify_key: SecretBytes,
        max_batch_query_count: u64,
        task_expiration: Option<Time>,
        report_expiry_age: Option<Duration>,
        min_batch_size: u64,
        time_precision: Duration,
        tolerable_clock_skew: Duration,
        hpke_keys: I,
        aggregator_parameters: AggregatorTaskParameters,
    ) -> Result<Self, Error> {
        let common_parameters = CommonTaskParameters::new(
            task_id,
            query_type,
            vdaf,
            vdaf_verify_key,
            max_batch_query_count,
            task_expiration,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
        )?;
        Self::new_with_common_parameters(
            common_parameters,
            peer_aggregator_endpoint,
            hpke_keys,
            aggregator_parameters,
        )
    }

    fn new_with_common_parameters<I: IntoIterator<Item = HpkeKeypair>>(
        common_parameters: CommonTaskParameters,
        peer_aggregator_endpoint: Url,
        hpke_keys: I,
        aggregator_parameters: AggregatorTaskParameters,
    ) -> Result<Self, Error> {
        // Compute hpke_configs mapping cfg.id -> (cfg, key).
        let hpke_keys: HashMap<HpkeConfigId, HpkeKeypair> = hpke_keys
            .into_iter()
            .map(|keypair| (*keypair.config().id(), keypair))
            .collect();

        if !matches!(
            aggregator_parameters,
            AggregatorTaskParameters::TaskprovHelper
        ) && hpke_keys.is_empty()
        {
            return Err(Error::InvalidParameter("hpke_keys"));
        }

        if let QueryType::FixedSize {
            batch_time_window_size: Some(batch_time_window_size),
            ..
        } = common_parameters.query_type
        {
            if matches!(
                aggregator_parameters,
                AggregatorTaskParameters::TaskprovHelper
            ) {
                return Err(Error::InvalidParameter(
                    "batch_time_window_size is not supported for taskprov",
                ));
            } else if batch_time_window_size.as_seconds()
                % common_parameters.time_precision.as_seconds()
                != 0
            {
                return Err(Error::InvalidParameter("batch_time_window_size"));
            }
        }

        Ok(Self {
            common_parameters,
            peer_aggregator_endpoint,
            hpke_keys,
            aggregator_parameters,
        })
    }

    /// Retrieves the task ID associated with this task.
    pub fn id(&self) -> &TaskId {
        &self.common_parameters.task_id
    }

    /// Retrieves the DAP role played by this aggregator.
    pub fn role(&self) -> &Role {
        self.aggregator_parameters.role()
    }

    /// Retrieves the peer aggregator endpoint associated with this task.
    pub fn peer_aggregator_endpoint(&self) -> &Url {
        &self.peer_aggregator_endpoint
    }

    /// Retrieves the query type associated with this task.
    pub fn query_type(&self) -> &QueryType {
        &self.common_parameters.query_type
    }

    /// Retrieves the VDAF associated with this task.
    pub fn vdaf(&self) -> &VdafInstance {
        &self.common_parameters.vdaf
    }

    /// Retrieves the VDAF verification key associated with this task, as opaque secret bytes.
    pub fn opaque_vdaf_verify_key(&self) -> &SecretBytes {
        &self.common_parameters.vdaf_verify_key
    }

    /// Retrieves the max batch query count parameter associated with this task.
    pub fn max_batch_query_count(&self) -> u64 {
        self.common_parameters.max_batch_query_count
    }

    /// Retrieves the task expiration associated with this task.
    pub fn task_expiration(&self) -> Option<&Time> {
        self.common_parameters.task_expiration.as_ref()
    }

    /// Retrieves the report expiry age associated with this task.
    pub fn report_expiry_age(&self) -> Option<&Duration> {
        self.common_parameters.report_expiry_age.as_ref()
    }

    /// Retrieves the min batch size parameter associated with this task.
    pub fn min_batch_size(&self) -> u64 {
        self.common_parameters.min_batch_size
    }

    /// Retrieves the time precision parameter associated with this task.
    pub fn time_precision(&self) -> &Duration {
        &self.common_parameters.time_precision
    }

    /// Retrieves the tolerable clock skew parameter associated with this task.
    pub fn tolerable_clock_skew(&self) -> &Duration {
        &self.common_parameters.tolerable_clock_skew
    }

    /// Returns true if the `batch_size` is valid given this task's query type and batch size
    /// parameters, per
    /// <https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6>
    pub fn validate_batch_size(&self, batch_size: u64) -> bool {
        match self.common_parameters.query_type {
            QueryType::TimeInterval => {
                // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6.1.2
                batch_size >= self.common_parameters.min_batch_size
            }
            QueryType::FixedSize { max_batch_size, .. } => {
                // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6.2.2
                batch_size >= self.common_parameters.min_batch_size && batch_size <= max_batch_size
            }
        }
    }

    /// Returns the [`VerifyKey`] used by this aggregator to prepare report shares with other
    /// aggregators.
    ///
    /// # Errors
    ///
    /// If the verify key is not the correct length as required by the VDAF, an error will be
    /// returned.
    pub fn vdaf_verify_key<const SEED_SIZE: usize>(&self) -> Result<VerifyKey<SEED_SIZE>, Error> {
        self.common_parameters.vdaf_verify_key()
    }

    /// Returns the [`AggregatorTaskParameters`] for this task.
    pub fn aggregator_parameters(&self) -> &AggregatorTaskParameters {
        &self.aggregator_parameters
    }

    /// Returns the relative path for tasks, relative to which other API endpoints are defined.
    fn tasks_path(&self) -> String {
        format!("tasks/{}", self.id())
    }

    /// Returns the URI at which the helper resource for the specified aggregation job ID can be
    /// accessed.
    pub fn aggregation_job_uri(
        &self,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Option<Url>, Error> {
        if matches!(
            self.aggregator_parameters,
            AggregatorTaskParameters::Leader { .. }
        ) {
            Ok(Some(self.peer_aggregator_endpoint().join(&format!(
                "{}/aggregation_jobs/{aggregation_job_id}",
                self.tasks_path()
            ))?))
        } else {
            Ok(None)
        }
    }

    /// Returns the URI at which the helper aggregate shares resource can be accessed.
    pub fn aggregate_shares_uri(&self) -> Result<Option<Url>, Error> {
        if matches!(
            self.aggregator_parameters,
            AggregatorTaskParameters::Leader { .. }
        ) {
            Ok(Some(self.peer_aggregator_endpoint().join(&format!(
                "{}/aggregate_shares",
                self.tasks_path()
            ))?))
        } else {
            Ok(None)
        }
    }

    /// Returns the aggregator authentication token for this task, or `None` for taskprov tasks.
    /// TODO(#1509): add `fn aggregator_auth_token_hash(&self) -> Option<&AuthenticationTokenHash>`
    pub fn aggregator_auth_token(&self) -> Option<&AuthenticationToken> {
        self.aggregator_parameters.aggregator_auth_token()
    }

    /// Returns the collector HPKE configuration for this task, or `None` for taskprov tasks.
    pub fn collector_hpke_config(&self) -> Option<&HpkeConfig> {
        self.aggregator_parameters.collector_hpke_config()
    }

    /// Returns the collector authentication token for this task, if this aggregator is the leader.
    /// TODO(#1509): make this an AuthenticationTokenHash
    pub fn collector_auth_token(&self) -> Option<&AuthenticationToken> {
        self.aggregator_parameters.collector_auth_token()
    }

    /// Return the HPKE keypairs used by this aggregator to decrypt client reports, or an empty map
    /// for taskprov tasks.
    pub fn hpke_keys(&self) -> &HashMap<HpkeConfigId, HpkeKeypair> {
        &self.hpke_keys
    }

    /// Retrieve the "current" HPKE in use for this task.
    #[cfg(feature = "test-util")]
    pub fn current_hpke_key(&self) -> &HpkeKeypair {
        self.hpke_keys
            .values()
            .max_by_key(|keypair| u8::from(*keypair.config().id()))
            .unwrap()
    }

    /// Checks if the given aggregator authentication token is valid (i.e. matches with the
    /// authentication token recognized by this task).
    pub fn check_aggregator_auth_token(
        &self,
        incoming_auth_token: Option<&AuthenticationToken>,
    ) -> bool {
        // TODO(#1509): leader should hold only an AuthenticationToken and refuse to use it for
        // incoming token validation. Helper should hold only an AuthenticationTokenHash, making the
        // AuthenticationTokenHash::from call here unnecessary.
        self.aggregator_auth_token()
            .map(AuthenticationTokenHash::from)
            .zip(incoming_auth_token)
            .map(|(own_token_hash, incoming_token)| own_token_hash.validate(incoming_token))
            .unwrap_or(false)
    }

    /// Checks if the given collector authentication token is valid (i.e. matches with the
    /// authentication token recognized by this task).
    pub fn check_collector_auth_token(
        &self,
        incoming_auth_token: Option<&AuthenticationToken>,
    ) -> bool {
        // TODO(#1509): Leader should hold only an AuthenticaitonTokenHash, making the
        // AuthenticationTokenHash::from call here unnecessary.
        self.collector_auth_token()
            .map(AuthenticationTokenHash::from)
            .zip(incoming_auth_token)
            .map(|(own_token_hash, incoming_token)| own_token_hash.validate(incoming_token))
            .unwrap_or(false)
    }
}

/// Role-specific task parameters for the aggregator DAP roles.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub enum AggregatorTaskParameters {
    /// Task parameters held exclusively by the DAP leader.
    Leader {
        /// Authentication token used to make requests to the helper during the aggregation
        /// sub-protocol.
        aggregator_auth_token: AuthenticationToken,
        /// Authentication token used to validate requests from the collector during the collection
        /// sub-protocol.
        /// TODO(#1509): make this an AuthenticationTokenHash
        collector_auth_token: AuthenticationToken,
        /// HPKE configuration for the collector.
        collector_hpke_config: HpkeConfig,
    },
    /// Task parameters held exclusively by the DAP helper.
    Helper {
        /// Authentication token used to validate requests from the leader during the aggregation
        /// sub-protocol.
        /// TODO(#1509): make this an AuthenticationTokenHash
        aggregator_auth_token: AuthenticationToken,
        /// HPKE configuration for the collector.
        collector_hpke_config: HpkeConfig,
    },
    /// Task parameters held exclusively by a DAP helper provisioned via taskprov. Currently there
    /// are no such parameters.
    TaskprovHelper,
}

impl AggregatorTaskParameters {
    /// Returns the [`Role`] that this aggregator plays.
    pub fn role(&self) -> &Role {
        match self {
            Self::Leader { .. } => &Role::Leader,
            Self::Helper { .. } | Self::TaskprovHelper => &Role::Helper,
        }
    }

    /// Returns the aggregator authentication token for this task, or `None` for taskprov tasks.
    /// TODO(#1509): add `fn aggregator_auth_token_hash(&self) -> Option<&AuthenticationTokenHash>`
    fn aggregator_auth_token(&self) -> Option<&AuthenticationToken> {
        match self {
            Self::Leader {
                aggregator_auth_token,
                ..
            }
            | Self::Helper {
                aggregator_auth_token,
                ..
            } => Some(aggregator_auth_token),
            _ => None,
        }
    }

    /// Returns the collector HPKE configuration for this task, or `None` for taskprov tasks.
    fn collector_hpke_config(&self) -> Option<&HpkeConfig> {
        match self {
            Self::Leader {
                collector_hpke_config,
                ..
            }
            | Self::Helper {
                collector_hpke_config,
                ..
            } => Some(collector_hpke_config),
            _ => None,
        }
    }

    /// Returns the collector authentication token for this task, if this aggregator is the leader.
    /// TODO(#1509): make this an AuthenticationTokenHash
    fn collector_auth_token(&self) -> Option<&AuthenticationToken> {
        match self {
            Self::Leader {
                collector_auth_token,
                ..
            } => Some(collector_auth_token),
            _ => None,
        }
    }
}

/// SerializedAggregatorTask is an intermediate representation for the aggregator view of tasks
/// being serialized via the Serialize and Deserialize traits.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializedAggregatorTask {
    task_id: Option<TaskId>,
    peer_aggregator_endpoint: Url,
    query_type: QueryType,
    vdaf: VdafInstance,
    role: Role,
    vdaf_verify_key: Option<String>, // in unpadded base64url
    max_batch_query_count: u64,
    task_expiration: Option<Time>,
    report_expiry_age: Option<Duration>,
    min_batch_size: u64,
    time_precision: Duration,
    tolerable_clock_skew: Duration,
    collector_hpke_config: HpkeConfig,
    aggregator_auth_token: Option<AuthenticationToken>,
    collector_auth_token: Option<AuthenticationToken>,
    hpke_keys: Vec<HpkeKeypair>, // uses unpadded base64url
}

impl SerializedAggregatorTask {
    /// Returns the task ID, if one is set.
    pub fn task_id(&self) -> Option<TaskId> {
        self.task_id
    }

    /// Randomly generates and fills values for the following fields if they are not set in the
    /// [`SerializedAggregatorTask`]
    ///
    /// - Task ID
    /// - VDAF verify key
    /// - Aggregator authentication token
    /// - Collector authentication token (only if the task's role is leader)
    /// - The aggregator's HPKE keypair (only one keypair is generated)
    pub fn generate_missing_fields(&mut self) {
        if self.task_id.is_none() {
            let task_id: TaskId = random();
            self.task_id = Some(task_id);
        }

        if self.vdaf_verify_key.is_none() {
            let vdaf_verify_key = SecretBytes::new(
                thread_rng()
                    .sample_iter(Standard)
                    .take(self.vdaf.verify_key_length())
                    .collect(),
            );

            self.vdaf_verify_key = Some(URL_SAFE_NO_PAD.encode(vdaf_verify_key.as_ref()));
        }

        if self.aggregator_auth_token.is_none() {
            self.aggregator_auth_token = Some(random());
        }

        if self.collector_auth_token.is_none() && self.role == Role::Leader {
            self.collector_auth_token = Some(random());
        }

        if self.hpke_keys.is_empty() {
            // Unwrap safety: we always use a supported KEM.
            let hpke_keypair = generate_hpke_config_and_private_key(
                random(),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
            )
            .unwrap();

            self.hpke_keys = Vec::from([hpke_keypair]);
        }
    }
}

impl Serialize for AggregatorTask {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hpke_keys = self.hpke_keys().values().cloned().collect();

        SerializedAggregatorTask {
            task_id: Some(*self.id()),
            peer_aggregator_endpoint: self.peer_aggregator_endpoint().clone(),
            query_type: *self.query_type(),
            vdaf: self.vdaf().clone(),
            role: *self.role(),
            vdaf_verify_key: Some(URL_SAFE_NO_PAD.encode(self.opaque_vdaf_verify_key())),
            max_batch_query_count: self.max_batch_query_count(),
            task_expiration: self.task_expiration().copied(),
            report_expiry_age: self.report_expiry_age().copied(),
            min_batch_size: self.min_batch_size(),
            time_precision: *self.time_precision(),
            tolerable_clock_skew: *self.tolerable_clock_skew(),
            collector_hpke_config: self
                .aggregator_parameters
                .collector_hpke_config()
                .expect("serializable tasks must have collector_hpke_config")
                .clone(),
            aggregator_auth_token: self.aggregator_parameters.aggregator_auth_token().cloned(),
            collector_auth_token: self.aggregator_parameters.collector_auth_token().cloned(),
            hpke_keys,
        }
        .serialize(serializer)
    }
}

impl TryFrom<SerializedAggregatorTask> for AggregatorTask {
    type Error = Error;

    fn try_from(serialized_task: SerializedAggregatorTask) -> Result<Self, Self::Error> {
        // task_id
        let task_id = serialized_task
            .task_id
            .ok_or(Error::InvalidParameter("missing field task_id"))?;

        // vdaf_verify_key
        let vdaf_verify_key = serialized_task
            .vdaf_verify_key
            .ok_or(Error::InvalidParameter("missing vdaf_verify_key"))?;

        let aggregator_parameters = match serialized_task.role {
            Role::Leader => AggregatorTaskParameters::Leader {
                aggregator_auth_token: serialized_task
                    .aggregator_auth_token
                    .ok_or(Error::InvalidParameter("missing aggregator auth token"))?,
                collector_auth_token: serialized_task
                    .collector_auth_token
                    .ok_or(Error::InvalidParameter("missing collector auth token"))?,
                collector_hpke_config: serialized_task.collector_hpke_config,
            },
            Role::Helper => AggregatorTaskParameters::Helper {
                aggregator_auth_token: serialized_task
                    .aggregator_auth_token
                    .ok_or(Error::InvalidParameter("missing aggregator auth token"))?,
                collector_hpke_config: serialized_task.collector_hpke_config,
            },
            _ => return Err(Error::InvalidParameter("unexpected role")),
        };

        AggregatorTask::new(
            task_id,
            serialized_task.peer_aggregator_endpoint,
            serialized_task.query_type,
            serialized_task.vdaf,
            SecretBytes::new(URL_SAFE_NO_PAD.decode(vdaf_verify_key)?),
            serialized_task.max_batch_query_count,
            serialized_task.task_expiration,
            serialized_task.report_expiry_age,
            serialized_task.min_batch_size,
            serialized_task.time_precision,
            serialized_task.tolerable_clock_skew,
            serialized_task.hpke_keys,
            aggregator_parameters,
        )
    }
}

impl<'de> Deserialize<'de> for AggregatorTask {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize into intermediate representation.
        let serialized_task = SerializedAggregatorTask::deserialize(deserializer)?;
        AggregatorTask::try_from(serialized_task).map_err(D::Error::custom)
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use crate::{
        task::{
            AggregatorTask, AggregatorTaskParameters, CommonTaskParameters, Error, QueryType,
            VerifyKey,
        },
        SecretBytes,
    };
    use derivative::Derivative;
    use janus_core::{
        auth_tokens::AuthenticationToken,
        hpke::{
            test_util::{
                generate_test_hpke_config_and_private_key,
                generate_test_hpke_config_and_private_key_with_id,
            },
            HpkeKeypair,
        },
        time::DurationExt,
        url_ensure_trailing_slash,
        vdaf::{VdafInstance, VERIFY_KEY_LENGTH},
    };
    use janus_messages::{
        AggregationJobId, CollectionJobId, Duration, HpkeConfigId, Role, TaskId, Time,
    };
    use rand::{distributions::Standard, random, thread_rng, Rng};
    use std::collections::HashMap;
    use url::Url;

    /// Returns the expected length of a VDAF verification key for a VDAF of this type.
    fn verify_key_length(vdaf: &VdafInstance) -> usize {
        match vdaf {
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => 0,

            // All "real" VDAFs use a verify key of length 16 currently. (Poplar1 may not, but it's
            // not yet done being specified, so choosing 16 bytes is fine for testing.)
            _ => VERIFY_KEY_LENGTH,
        }
    }

    /// All parameters and secrets for a task, for all participants.
    #[derive(Clone, Derivative, PartialEq, Eq)]
    #[derivative(Debug)]
    pub struct Task {
        /// Common task parameters
        common_parameters: CommonTaskParameters,
        /// URL relative to which the leader aggregator's API endpoints are found.
        #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
        leader_aggregator_endpoint: Url,
        /// URL relative to which the leader aggregator's API endpoints are found.
        #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
        helper_aggregator_endpoint: Url,
        /// HPKE configuration and private key used by the collector to decrypt aggregate shares.
        collector_hpke_keypair: HpkeKeypair,
        /// Token used to authenticate messages exchanged between the aggregators in the aggregation
        /// sub-protocol.
        aggregator_auth_token: AuthenticationToken,
        /// Token used to authenticate messages exchanged between the collector and leader in the
        /// collection sub-protocol.
        collector_auth_token: AuthenticationToken,
        /// HPKE configurations & private keys used by the leader to decrypt client reports.
        leader_hpke_keys: HashMap<HpkeConfigId, HpkeKeypair>,
        /// HPKE configurations & private keys used by the helper to decrypt client reports.
        helper_hpke_keys: HashMap<HpkeConfigId, HpkeKeypair>,
    }

    impl Task {
        /// Create a new [`Task`] from the provided values.
        #[allow(clippy::too_many_arguments, dead_code)]
        pub(crate) fn new<I: IntoIterator<Item = HpkeKeypair>>(
            task_id: TaskId,
            leader_aggregator_endpoint: Url,
            helper_aggregator_endpoint: Url,
            query_type: QueryType,
            vdaf: VdafInstance,
            vdaf_verify_key: SecretBytes,
            max_batch_query_count: u64,
            task_expiration: Option<Time>,
            report_expiry_age: Option<Duration>,
            min_batch_size: u64,
            time_precision: Duration,
            tolerable_clock_skew: Duration,
            collector_hpke_keypair: HpkeKeypair,
            aggregator_auth_token: AuthenticationToken,
            collector_auth_token: AuthenticationToken,
            leader_hpke_keys: I,
            helper_hpke_keys: I,
        ) -> Self {
            // Compute hpke_configs mapping cfg.id -> (cfg, key).
            let leader_hpke_keys: HashMap<HpkeConfigId, HpkeKeypair> = leader_hpke_keys
                .into_iter()
                .map(|keypair| (*keypair.config().id(), keypair))
                .collect();

            let helper_hpke_keys: HashMap<HpkeConfigId, HpkeKeypair> = helper_hpke_keys
                .into_iter()
                .map(|keypair| (*keypair.config().id(), keypair))
                .collect();

            Self {
                common_parameters: CommonTaskParameters {
                    task_id,
                    query_type,
                    vdaf,
                    vdaf_verify_key,
                    max_batch_query_count,
                    task_expiration,
                    report_expiry_age,
                    min_batch_size,
                    time_precision,
                    tolerable_clock_skew,
                },
                // Ensure provided aggregator endpoints end with a slash, as we will be joining
                // additional path segments into these endpoints & the Url::join implementation is
                // persnickety about the slash at the end of the path.
                leader_aggregator_endpoint: url_ensure_trailing_slash(leader_aggregator_endpoint),
                helper_aggregator_endpoint: url_ensure_trailing_slash(helper_aggregator_endpoint),
                aggregator_auth_token,
                collector_auth_token,
                collector_hpke_keypair,
                leader_hpke_keys,
                helper_hpke_keys,
            }
        }

        /// Retrieves the task ID associated with this task.
        pub fn id(&self) -> &TaskId {
            &self.common_parameters.task_id
        }

        /// Retrieves the Leader's aggregator endpoint associated with this task.
        pub fn leader_aggregator_endpoint(&self) -> &Url {
            &self.leader_aggregator_endpoint
        }

        /// Retrieves the Helper's aggregator endpoint associated with this task.
        pub fn helper_aggregator_endpoint(&self) -> &Url {
            &self.helper_aggregator_endpoint
        }

        /// Retrieves the query type associated with this task.
        pub fn query_type(&self) -> &QueryType {
            &self.common_parameters.query_type
        }

        /// Retrieves the VDAF associated with this task.
        pub fn vdaf(&self) -> &VdafInstance {
            &self.common_parameters.vdaf
        }

        /// Retrieves the VDAF verification key associated with this task, as opaque secret bytes.
        pub fn opaque_vdaf_verify_key(&self) -> &SecretBytes {
            &self.common_parameters.vdaf_verify_key
        }

        /// Retrieves the max batch query count parameter associated with this task.
        pub fn max_batch_query_count(&self) -> u64 {
            self.common_parameters.max_batch_query_count
        }

        /// Retrieves the task expiration associated with this task.
        pub fn task_expiration(&self) -> Option<&Time> {
            self.common_parameters.task_expiration.as_ref()
        }

        /// Retrieves the report expiry age associated with this task.
        pub fn report_expiry_age(&self) -> Option<&Duration> {
            self.common_parameters.report_expiry_age.as_ref()
        }

        /// Retrieves the min batch size parameter associated with this task.
        pub fn min_batch_size(&self) -> u64 {
            self.common_parameters.min_batch_size
        }

        /// Retrieves the time precision parameter associated with this task.
        pub fn time_precision(&self) -> &Duration {
            &self.common_parameters.time_precision
        }

        /// Retrieves the tolerable clock skew parameter associated with this task.
        pub fn tolerable_clock_skew(&self) -> &Duration {
            &self.common_parameters.tolerable_clock_skew
        }

        /// Retrieves the collector HPKE keypair associated with this task.
        pub fn collector_hpke_keypair(&self) -> &HpkeKeypair {
            &self.collector_hpke_keypair
        }

        /// Retrieves the aggregator authentication token associated with this task.
        pub fn aggregator_auth_token(&self) -> &AuthenticationToken {
            &self.aggregator_auth_token
        }

        /// Retrieves the collector authentication token associated with this task.
        pub fn collector_auth_token(&self) -> &AuthenticationToken {
            &self.collector_auth_token
        }

        /// Returns the [`VerifyKey`] used by this aggregator to prepare report shares with other
        /// aggregators.
        ///
        /// # Errors
        ///
        /// If the verify key is not the correct length as required by the VDAF, an error will be
        /// returned.
        pub fn vdaf_verify_key<const SEED_SIZE: usize>(
            &self,
        ) -> Result<VerifyKey<SEED_SIZE>, Error> {
            self.common_parameters.vdaf_verify_key()
        }

        /// Returns the relative path for tasks, relative to which other API endpoints are defined.
        fn tasks_path(&self) -> String {
            format!("tasks/{}", self.id())
        }

        /// Returns the URI at which reports may be uploaded for this task.
        pub fn report_upload_uri(&self) -> Result<Url, Error> {
            Ok(self
                .leader_aggregator_endpoint()
                .join(&format!("{}/reports", self.tasks_path()))?)
        }

        /// Returns the URI at which the helper resource for the specified aggregation job ID can be
        /// accessed.
        pub fn aggregation_job_uri(
            &self,
            aggregation_job_id: &AggregationJobId,
        ) -> Result<Url, Error> {
            Ok(self.helper_aggregator_endpoint().join(&format!(
                "{}/aggregation_jobs/{aggregation_job_id}",
                self.tasks_path()
            ))?)
        }

        /// Returns the URI at which the helper aggregate shares resource can be accessed.
        pub fn aggregate_shares_uri(&self) -> Result<Url, Error> {
            Ok(self
                .helper_aggregator_endpoint()
                .join(&format!("{}/aggregate_shares", self.tasks_path()))?)
        }

        /// Returns the URI at which the leader resource for the specified collection job ID can be
        /// accessed.
        pub fn collection_job_uri(
            &self,
            collection_job_id: &CollectionJobId,
        ) -> Result<Url, Error> {
            Ok(self.leader_aggregator_endpoint().join(&format!(
                "{}/collection_jobs/{collection_job_id}",
                self.tasks_path()
            ))?)
        }

        /// Render the leader aggregator's view of this task.
        pub fn leader_view(&self) -> Result<AggregatorTask, Error> {
            AggregatorTask::new_with_common_parameters(
                self.common_parameters.clone(),
                self.helper_aggregator_endpoint.clone(),
                self.leader_hpke_keys.values().cloned().collect::<Vec<_>>(),
                AggregatorTaskParameters::Leader {
                    aggregator_auth_token: self.aggregator_auth_token.clone(),
                    collector_auth_token: self.collector_auth_token.clone(),
                    collector_hpke_config: self.collector_hpke_keypair.config().clone(),
                },
            )
        }

        /// Render the helper aggregator's view of this task.
        pub fn helper_view(&self) -> Result<AggregatorTask, Error> {
            AggregatorTask::new_with_common_parameters(
                self.common_parameters.clone(),
                self.leader_aggregator_endpoint.clone(),
                self.helper_hpke_keys.values().cloned().collect::<Vec<_>>(),
                AggregatorTaskParameters::Helper {
                    aggregator_auth_token: self.aggregator_auth_token.clone(),
                    collector_hpke_config: self.collector_hpke_keypair.config().clone(),
                },
            )
        }

        /// Render a taskprov helper aggregator's view of this task.
        pub fn taskprov_helper_view(&self) -> Result<AggregatorTask, Error> {
            AggregatorTask::new_with_common_parameters(
                self.common_parameters.clone(),
                self.leader_aggregator_endpoint.clone(),
                [],
                AggregatorTaskParameters::TaskprovHelper,
            )
        }

        /// Render the view of the specified aggregator of this task.
        ///
        /// # Errors
        ///
        /// Returns an error if `role` is not an aggregator role.
        pub fn view_for_role(&self, role: Role) -> Result<AggregatorTask, Error> {
            match role {
                Role::Leader => self.leader_view(),
                Role::Helper => self.helper_view(),
                _ => Err(Error::InvalidParameter("role is not an aggregator")),
            }
        }
    }

    /// TaskBuilder is a testing utility allowing tasks to be built based on a template.
    #[derive(Clone)]
    pub struct TaskBuilder(Task);

    impl TaskBuilder {
        /// Create a [`TaskBuilder`] from the provided values, with arbitrary values for the other
        /// task parameters. Defaults to using `AuthenticationToken::Bearer` for the aggregator and
        /// collector authentication tokens.
        pub fn new(query_type: QueryType, vdaf: VdafInstance) -> Self {
            let task_id = random();

            let leader_hpke_keypairs = [
                generate_test_hpke_config_and_private_key(),
                generate_test_hpke_config_and_private_key_with_id(1),
            ];
            let helper_hpke_keypairs = [
                generate_test_hpke_config_and_private_key(),
                generate_test_hpke_config_and_private_key_with_id(1),
            ];

            let vdaf_verify_key = SecretBytes::new(
                thread_rng()
                    .sample_iter(Standard)
                    .take(verify_key_length(&vdaf))
                    .collect(),
            );

            Self(Task::new(
                task_id,
                "https://leader.endpoint".parse().unwrap(),
                "https://helper.endpoint".parse().unwrap(),
                query_type,
                vdaf,
                vdaf_verify_key,
                1,
                None,
                None,
                0,
                Duration::from_hours(8).unwrap(),
                Duration::from_minutes(10).unwrap(),
                /* Collector HPKE keypair */ generate_test_hpke_config_and_private_key(),
                /* Aggregator auth token */ random(),
                /* Collector auth token */ random(),
                leader_hpke_keypairs,
                helper_hpke_keypairs,
            ))
        }

        /// Gets the leader aggregator endpoint for the eventual task.
        pub fn leader_aggregator_endpoint(&self) -> &Url {
            self.0.leader_aggregator_endpoint()
        }

        /// Gets the helper aggregator endpoint for the eventual task.
        pub fn helper_aggregator_endpoint(&self) -> &Url {
            self.0.helper_aggregator_endpoint()
        }

        /// Gets the task ID for the eventual task
        pub fn task_id(&self) -> &TaskId {
            self.0.id()
        }

        /// Associates the eventual task with the given task ID.
        pub fn with_id(self, task_id: TaskId) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    task_id,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Associates the eventual task with the given aggregator endpoint for the Leader.
        pub fn with_leader_aggregator_endpoint(self, leader_aggregator_endpoint: Url) -> Self {
            Self(Task {
                leader_aggregator_endpoint: url_ensure_trailing_slash(leader_aggregator_endpoint),
                ..self.0
            })
        }

        /// Associates the eventual task with the given aggregator endpoint for the Helper.
        pub fn with_helper_aggregator_endpoint(self, helper_aggregator_endpoint: Url) -> Self {
            Self(Task {
                helper_aggregator_endpoint: url_ensure_trailing_slash(helper_aggregator_endpoint),
                ..self.0
            })
        }

        /// Associates the eventual task with the given VDAF verification key.
        pub fn with_vdaf_verify_key(self, vdaf_verify_key: SecretBytes) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    vdaf_verify_key,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Associates the eventual task with the given max batch query count parameter.
        pub fn with_max_batch_query_count(self, max_batch_query_count: u64) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    max_batch_query_count,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Associates the eventual task with the given min batch size parameter.
        pub fn with_min_batch_size(self, min_batch_size: u64) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    min_batch_size,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Gets the minimum batch size associated with the eventual task.
        pub fn min_batch_size(&self) -> u64 {
            self.0.min_batch_size()
        }

        /// Associates the eventual task with the given time precision parameter.
        pub fn with_time_precision(self, time_precision: Duration) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    time_precision,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Gets the time precision associated with the eventual task.
        pub fn time_precision(&self) -> &Duration {
            self.0.time_precision()
        }

        /// Associates the eventual task with the given tolerable clock skew.
        pub fn with_tolerable_clock_skew(self, tolerable_clock_skew: Duration) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    tolerable_clock_skew,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Associates the eventual task with the given aggregator authentication token.
        pub fn with_aggregator_auth_token(
            self,
            aggregator_auth_token: AuthenticationToken,
        ) -> Self {
            Self(Task {
                aggregator_auth_token,
                ..self.0
            })
        }

        /// Associates the eventual task with a random [`AuthenticationToken::DapAuth`] aggregator
        /// auth token.
        pub fn with_dap_auth_aggregator_token(self) -> Self {
            Self(Task {
                aggregator_auth_token: AuthenticationToken::DapAuth(random()),
                ..self.0
            })
        }

        /// Associates the eventual task with the given collector authentication token.
        pub fn with_collector_auth_token(self, collector_auth_token: AuthenticationToken) -> Self {
            Self(Task {
                collector_auth_token,
                ..self.0
            })
        }

        /// Gets the collector auth token associated with the eventual task.
        pub fn collector_auth_token(&self) -> &AuthenticationToken {
            self.0.collector_auth_token()
        }

        /// Associates the eventual task with a random [`AuthenticationToken::DapAuth`] collector
        /// auth token.
        pub fn with_dap_auth_collector_token(self) -> Self {
            Self(Task {
                collector_auth_token: AuthenticationToken::DapAuth(random()),
                ..self.0
            })
        }

        /// Sets the task expiration time.
        pub fn with_task_expiration(self, task_expiration: Option<Time>) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    task_expiration,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Sets the report expiry age.
        pub fn with_report_expiry_age(self, report_expiry_age: Option<Duration>) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    report_expiry_age,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Gets the colector HPKE keypair for the eventual task.
        pub fn collector_hpke_keypair(&self) -> &HpkeKeypair {
            self.0.collector_hpke_keypair()
        }

        /// Consumes this task builder & produces a [`Task`] with the given specifications.
        pub fn build(self) -> Task {
            self.0
        }
    }

    impl From<Task> for TaskBuilder {
        fn from(task: Task) -> Self {
            Self(task)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        task::{
            test_util::TaskBuilder, AggregatorTask, AggregatorTaskParameters, QueryType,
            VdafInstance,
        },
        SecretBytes,
    };
    use assert_matches::assert_matches;
    use janus_core::{
        auth_tokens::AuthenticationToken,
        hpke::{HpkeKeypair, HpkePrivateKey},
        test_util::roundtrip_encoding,
        time::DurationExt,
    };
    use janus_messages::{
        Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, TaskId,
    };
    use rand::random;
    use serde_json::json;
    use serde_test::{assert_de_tokens, assert_tokens, Token};

    #[test]
    fn leader_task_serialization() {
        roundtrip_encoding(
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
                .build()
                .leader_view()
                .unwrap(),
        );
    }

    #[test]
    fn helper_task_serialization() {
        roundtrip_encoding(
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
                .build()
                .helper_view()
                .unwrap(),
        );
    }

    #[test]
    fn deserialize_docs_sample_tasks() {
        serde_yaml::from_str::<Vec<AggregatorTask>>(include_str!("../../docs/samples/tasks.yaml"))
            .unwrap();
    }

    #[test]
    fn aggregator_endpoints_end_in_slash() {
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .with_leader_aggregator_endpoint("http://leader_endpoint/foo/bar".parse().unwrap())
            .with_helper_aggregator_endpoint("http://helper_endpoint".parse().unwrap())
            .build();

        assert_eq!(
            task.leader_aggregator_endpoint(),
            &"http://leader_endpoint/foo/bar/".parse().unwrap(),
        );
        assert_eq!(
            task.helper_aggregator_endpoint(),
            &"http://helper_endpoint/".parse().unwrap(),
        );
    }

    #[test]
    fn aggregator_request_paths() {
        for (prefix, task) in [
            (
                "",
                TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build(),
            ),
            (
                "/prefix",
                TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
                    .with_leader_aggregator_endpoint("https://leader.com/prefix/".parse().unwrap())
                    .with_helper_aggregator_endpoint("https://helper.com/prefix/".parse().unwrap())
                    .build(),
            ),
        ] {
            let prefix = format!("{prefix}/tasks");

            for uri in [
                task.report_upload_uri().unwrap(),
                task.aggregation_job_uri(&random()).unwrap(),
                task.collection_job_uri(&random()).unwrap(),
                task.aggregate_shares_uri().unwrap(),
            ] {
                // Check that path starts with / so it is suitable for use with mockito and that any
                // path components in the aggregator endpoint are still present.
                assert!(
                    uri.path().starts_with(&prefix),
                    "request path {} lacks prefix {prefix}",
                    uri.path()
                );
            }
        }
    }

    #[test]
    fn aggregator_task_serde() {
        assert_tokens(
            &AggregatorTask::new(
                TaskId::from([0; 32]),
                "https://example.net/".parse().unwrap(),
                QueryType::TimeInterval,
                VdafInstance::Prio3Count,
                SecretBytes::new(b"1234567812345678".to_vec()),
                1,
                None,
                None,
                10,
                Duration::from_seconds(3600),
                Duration::from_seconds(60),
                [HpkeKeypair::new(
                    HpkeConfig::new(
                        HpkeConfigId::from(255),
                        HpkeKemId::X25519HkdfSha256,
                        HpkeKdfId::HkdfSha256,
                        HpkeAeadId::Aes128Gcm,
                        HpkePublicKey::from(b"leader hpke public key".to_vec()),
                    ),
                    HpkePrivateKey::new(b"leader hpke private key".to_vec()),
                )],
                AggregatorTaskParameters::Leader {
                    aggregator_auth_token: AuthenticationToken::new_dap_auth_token_from_string(
                        "YWdncmVnYXRvciB0b2tlbg",
                    )
                    .unwrap(),
                    collector_auth_token: AuthenticationToken::new_bearer_token_from_string(
                        "Y29sbGVjdG9yIHRva2Vu",
                    )
                    .unwrap(),
                    collector_hpke_config: HpkeConfig::new(
                        HpkeConfigId::from(8),
                        HpkeKemId::X25519HkdfSha256,
                        HpkeKdfId::HkdfSha256,
                        HpkeAeadId::Aes128Gcm,
                        HpkePublicKey::from(b"collector hpke public key".to_vec()),
                    ),
                },
            )
            .unwrap(),
            &[
                Token::Struct {
                    name: "SerializedAggregatorTask",
                    len: 16,
                },
                Token::Str("task_id"),
                Token::Some,
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::Str("peer_aggregator_endpoint"),
                Token::Str("https://example.net/"),
                Token::Str("query_type"),
                Token::UnitVariant {
                    name: "QueryType",
                    variant: "TimeInterval",
                },
                Token::Str("vdaf"),
                Token::UnitVariant {
                    name: "VdafInstance",
                    variant: "Prio3Count",
                },
                Token::Str("role"),
                Token::UnitVariant {
                    name: "Role",
                    variant: "Leader",
                },
                Token::Str("vdaf_verify_key"),
                Token::Some,
                Token::Str("MTIzNDU2NzgxMjM0NTY3OA"),
                Token::Str("max_batch_query_count"),
                Token::U64(1),
                Token::Str("task_expiration"),
                Token::None,
                Token::Str("report_expiry_age"),
                Token::None,
                Token::Str("min_batch_size"),
                Token::U64(10),
                Token::Str("time_precision"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(3600),
                Token::Str("tolerable_clock_skew"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(60),
                Token::Str("collector_hpke_config"),
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(8),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("Y29sbGVjdG9yIGhwa2UgcHVibGljIGtleQ"),
                Token::StructEnd,
                Token::Str("aggregator_auth_token"),
                Token::Some,
                Token::Struct {
                    name: "AuthenticationToken",
                    len: 2,
                },
                Token::Str("type"),
                Token::UnitVariant {
                    name: "AuthenticationToken",
                    variant: "DapAuth",
                },
                Token::Str("token"),
                Token::Str("YWdncmVnYXRvciB0b2tlbg"),
                Token::StructEnd,
                Token::Str("collector_auth_token"),
                Token::Some,
                Token::Struct {
                    name: "AuthenticationToken",
                    len: 2,
                },
                Token::Str("type"),
                Token::UnitVariant {
                    name: "AuthenticationToken",
                    variant: "Bearer",
                },
                Token::Str("token"),
                Token::Str("Y29sbGVjdG9yIHRva2Vu"),
                Token::StructEnd,
                Token::Str("hpke_keys"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "HpkeKeypair",
                    len: 2,
                },
                Token::Str("config"),
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(255),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("bGVhZGVyIGhwa2UgcHVibGljIGtleQ"),
                Token::StructEnd,
                Token::Str("private_key"),
                Token::Str("bGVhZGVyIGhwa2UgcHJpdmF0ZSBrZXk"),
                Token::StructEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );

        assert_tokens(
            &AggregatorTask::new(
                TaskId::from([255; 32]),
                "https://example.com/".parse().unwrap(),
                QueryType::FixedSize {
                    max_batch_size: 10,
                    batch_time_window_size: None,
                },
                VdafInstance::Prio3CountVec {
                    length: 8,
                    chunk_length: 3,
                },
                SecretBytes::new(b"1234567812345678".to_vec()),
                1,
                None,
                Some(Duration::from_seconds(1800)),
                10,
                Duration::from_seconds(3600),
                Duration::from_seconds(60),
                [HpkeKeypair::new(
                    HpkeConfig::new(
                        HpkeConfigId::from(255),
                        HpkeKemId::X25519HkdfSha256,
                        HpkeKdfId::HkdfSha256,
                        HpkeAeadId::Aes128Gcm,
                        HpkePublicKey::from(b"helper hpke public key".to_vec()),
                    ),
                    HpkePrivateKey::new(b"helper hpke private key".to_vec()),
                )],
                AggregatorTaskParameters::Helper {
                    aggregator_auth_token: AuthenticationToken::new_bearer_token_from_string(
                        "YWdncmVnYXRvciB0b2tlbg",
                    )
                    .unwrap(),
                    collector_hpke_config: HpkeConfig::new(
                        HpkeConfigId::from(8),
                        HpkeKemId::X25519HkdfSha256,
                        HpkeKdfId::HkdfSha256,
                        HpkeAeadId::Aes128Gcm,
                        HpkePublicKey::from(b"collector hpke public key".to_vec()),
                    ),
                },
            )
            .unwrap(),
            &[
                Token::Struct {
                    name: "SerializedAggregatorTask",
                    len: 16,
                },
                Token::Str("task_id"),
                Token::Some,
                Token::Str("__________________________________________8"),
                Token::Str("peer_aggregator_endpoint"),
                Token::Str("https://example.com/"),
                Token::Str("query_type"),
                Token::StructVariant {
                    name: "QueryType",
                    variant: "FixedSize",
                    len: 2,
                },
                Token::Str("max_batch_size"),
                Token::U64(10),
                Token::Str("batch_time_window_size"),
                Token::None,
                Token::StructVariantEnd,
                Token::Str("vdaf"),
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3CountVec",
                    len: 2,
                },
                Token::Str("length"),
                Token::U64(8),
                Token::Str("chunk_length"),
                Token::U64(3),
                Token::StructVariantEnd,
                Token::Str("role"),
                Token::UnitVariant {
                    name: "Role",
                    variant: "Helper",
                },
                Token::Str("vdaf_verify_key"),
                Token::Some,
                Token::Str("MTIzNDU2NzgxMjM0NTY3OA"),
                Token::Str("max_batch_query_count"),
                Token::U64(1),
                Token::Str("task_expiration"),
                Token::None,
                Token::Str("report_expiry_age"),
                Token::Some,
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(1800),
                Token::Str("min_batch_size"),
                Token::U64(10),
                Token::Str("time_precision"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(3600),
                Token::Str("tolerable_clock_skew"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(60),
                Token::Str("collector_hpke_config"),
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(8),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("Y29sbGVjdG9yIGhwa2UgcHVibGljIGtleQ"),
                Token::StructEnd,
                Token::Str("aggregator_auth_token"),
                Token::Some,
                Token::Struct {
                    name: "AuthenticationToken",
                    len: 2,
                },
                Token::Str("type"),
                Token::UnitVariant {
                    name: "AuthenticationToken",
                    variant: "Bearer",
                },
                Token::Str("token"),
                Token::Str("YWdncmVnYXRvciB0b2tlbg"),
                Token::StructEnd,
                Token::Str("collector_auth_token"),
                Token::None,
                Token::Str("hpke_keys"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "HpkeKeypair",
                    len: 2,
                },
                Token::Str("config"),
                Token::Struct {
                    name: "HpkeConfig",
                    len: 5,
                },
                Token::Str("id"),
                Token::NewtypeStruct {
                    name: "HpkeConfigId",
                },
                Token::U8(255),
                Token::Str("kem_id"),
                Token::UnitVariant {
                    name: "HpkeKemId",
                    variant: "X25519HkdfSha256",
                },
                Token::Str("kdf_id"),
                Token::UnitVariant {
                    name: "HpkeKdfId",
                    variant: "HkdfSha256",
                },
                Token::Str("aead_id"),
                Token::UnitVariant {
                    name: "HpkeAeadId",
                    variant: "Aes128Gcm",
                },
                Token::Str("public_key"),
                Token::Str("aGVscGVyIGhwa2UgcHVibGljIGtleQ"),
                Token::StructEnd,
                Token::Str("private_key"),
                Token::Str("aGVscGVyIGhwa2UgcHJpdmF0ZSBrZXk"),
                Token::StructEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn query_type_serde() {
        assert_tokens(
            &QueryType::TimeInterval,
            &[Token::UnitVariant {
                name: "QueryType",
                variant: "TimeInterval",
            }],
        );
        assert_tokens(
            &QueryType::FixedSize {
                max_batch_size: 10,
                batch_time_window_size: None,
            },
            &[
                Token::StructVariant {
                    name: "QueryType",
                    variant: "FixedSize",
                    len: 2,
                },
                Token::Str("max_batch_size"),
                Token::U64(10),
                Token::Str("batch_time_window_size"),
                Token::None,
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &QueryType::FixedSize {
                max_batch_size: 10,
                batch_time_window_size: Some(Duration::from_hours(1).unwrap()),
            },
            &[
                Token::StructVariant {
                    name: "QueryType",
                    variant: "FixedSize",
                    len: 2,
                },
                Token::Str("max_batch_size"),
                Token::U64(10),
                Token::Str("batch_time_window_size"),
                Token::Some,
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(3600),
                Token::StructVariantEnd,
            ],
        );

        // Backwards compatibility cases:
        assert_de_tokens(
            &QueryType::FixedSize {
                max_batch_size: 10,
                batch_time_window_size: None,
            },
            &[
                Token::StructVariant {
                    name: "QueryType",
                    variant: "FixedSize",
                    len: 2,
                },
                Token::Str("max_batch_size"),
                Token::U64(10),
                Token::StructVariantEnd,
            ],
        );
        assert_matches!(
            serde_json::from_value(json!({ "FixedSize": { "max_batch_size": 10 } })),
            Ok(QueryType::FixedSize {
                max_batch_size: 10,
                batch_time_window_size: None,
            })
        );
        assert_matches!(
            serde_yaml::from_str("!FixedSize { max_batch_size: 10 }"),
            Ok(QueryType::FixedSize {
                max_batch_size: 10,
                batch_time_window_size: None,
            })
        );
    }
}
