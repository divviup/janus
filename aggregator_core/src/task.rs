//! Shared parameters for a DAP task.

use std::{array::TryFromSliceError, str::FromStr};

use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use educe::Educe;
use janus_core::{
    auth_tokens::{AuthenticationToken, AuthenticationTokenHash},
    task_config::build_task_configuration,
    url_for_join,
    vdaf::VdafInstance,
};
use janus_messages::{
    AggregateShareId, AggregationJobId, AggregationJobStep, BatchConfig, Duration, HpkeConfig,
    Interval, Role, TaskConfiguration, TaskId, Time, TimePrecision, Url as DapUrl, batch_mode,
};
use postgres_types::{FromSql, ToSql};
use rand::{RngExt, distr::StandardUniform, random, rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use url::Url;

use crate::SecretBytes;

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
    #[error(transparent)]
    Message(#[from] janus_messages::Error),
}

/// Identifiers for batch modes used by a task, along with batch mode-specific configuration.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BatchMode {
    /// Time-interval: used to support a collection style based on fixed time intervals.
    TimeInterval,

    /// Leader-selected: used to support collection of batches as quickly as possible, without the
    /// latency of waiting for batch time intervals to pass, and with direct control over the number
    /// of reports per batch.
    LeaderSelected {
        /// If present, reports will be separated into different batches by timestamp, such that
        /// the client timestamp interval duration will not exceed this value. The minimum and
        /// maximum allowed report timestamps for each batch will be multiples of this value as
        /// well.
        ///
        /// This is an implementation-specific configuration parameter, and not part of the query
        /// type as defined in DAP.
        batch_time_window_size: Option<Duration>,
    },
}

impl BatchMode {
    /// Returns the [`BatchConfig`] message representation of this batch mode, for inclusion in a
    /// [`TaskConfiguration`].
    ///
    /// This is the inverse of [`BatchMode::try_from(&BatchConfig)`](TryFrom). The
    /// `batch_time_window_size` of [`BatchMode::LeaderSelected`] is a Janus-specific parameter that
    /// is not part of the DAP batch configuration, and is silently dropped. Therefore, the HPKE AAD
    /// does not force the aggregators to agree on the `batch_time_window_size`.
    pub fn to_batch_config(&self) -> BatchConfig {
        match self {
            BatchMode::TimeInterval => BatchConfig::TimeInterval,
            BatchMode::LeaderSelected { .. } => BatchConfig::LeaderSelected,
        }
    }
}

impl TryFrom<batch_mode::Code> for BatchMode {
    type Error = Error;

    fn try_from(value: batch_mode::Code) -> Result<Self, Self::Error> {
        match value {
            batch_mode::Code::TimeInterval => Ok(Self::TimeInterval),
            batch_mode::Code::LeaderSelected => Ok(Self::LeaderSelected {
                batch_time_window_size: None,
            }),
            batch_mode::Code::Reserved => Err(Error::InvalidParameter("reserved batch mode")),
            _ => Err(Error::InvalidParameter("unknown batch mode")),
        }
    }
}

impl TryFrom<&BatchConfig> for BatchMode {
    type Error = Error;

    fn try_from(value: &BatchConfig) -> Result<Self, Self::Error> {
        match value {
            BatchConfig::TimeInterval => Ok(Self::TimeInterval),
            BatchConfig::LeaderSelected => Ok(Self::LeaderSelected {
                batch_time_window_size: None,
            }),
            BatchConfig::Reserved => Err(Error::InvalidParameter("reserved batch mode")),
            _ => Err(Error::InvalidParameter("unknown batch mode")),
        }
    }
}

/// A verification key for a VDAF, with a fixed length. It must be kept secret from clients to
/// maintain robustness, and it must be shared between aggregators.
#[derive(Educe, Clone, Copy)]
#[educe(Debug)]
pub struct VerifyKey<const SEED_SIZE: usize>(#[educe(Debug(ignore))] [u8; SEED_SIZE]);

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
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommonTaskParameters {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// The batch mode this task uses to generate batches.
    batch_mode: BatchMode,
    /// The VDAF this task executes.
    vdaf: VdafInstance,
    /// Secret verification key shared by the aggregators.
    vdaf_verify_key: SecretBytes,
    /// The interval of time during which the task is valid. Reports with timestamps before the
    /// interval's start or at-or-after its end are rejected. `None` indicates that the task has no
    /// time bounds.
    task_interval: Option<Interval>,
    /// The age after which a report is considered to be "expired" and will be considered a
    /// candidate for garbage collection. A value of `None` indicates that garbage collection is
    /// disabled.
    report_expiry_age: Option<Duration>,
    /// The minimum number of reports in a batch to allow it to be collected.
    min_batch_size: u64,
    /// The duration to which clients should round their reported timestamps to. For time-interval
    /// tasks, batch intervals must be multiples of this duration.
    time_precision: TimePrecision,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    tolerable_clock_skew: Duration,
    /// The `task_info` byte string from a `TaskConfiguration` struct, used to distinguish tasks
    /// with otherwise equivalent DAP task parameters. Must be at most 255 bytes.
    task_info: Vec<u8>,
}

impl CommonTaskParameters {
    /// Create a new [`CommonTaskParameters`] with the provided values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        batch_mode: BatchMode,
        vdaf: VdafInstance,
        vdaf_verify_key: SecretBytes,
        task_interval: Option<Interval>,
        report_expiry_age: Option<Duration>,
        min_batch_size: u64,
        time_precision: TimePrecision,
        tolerable_clock_skew: Duration,
        task_info: Vec<u8>,
    ) -> Result<Self, Error> {
        if min_batch_size == 0 {
            return Err(Error::InvalidParameter("min_batch_size"));
        }

        // task_info may be empty: DAP-19 (draft-ietf-ppm-dap#787) relaxes the bound to <0..255>.
        if task_info.len() > u8::MAX as usize {
            return Err(Error::InvalidParameter(
                "task_info must not exceed 255 bytes",
            ));
        }

        if let BatchMode::LeaderSelected {
            batch_time_window_size: Some(batch_time_window_size),
        } = batch_mode
        {
            if batch_time_window_size == Duration::ZERO {
                return Err(Error::InvalidParameter("batch_time_window_size is zero"));
            }
        }

        // These fields are stored as 64-bit signed integers in the database but are held in
        // memory as unsigned. Reject values that are too large. (perhaps these should be
        // represented by different types?)
        if let Some(report_expiry_age) = report_expiry_age {
            report_expiry_age
                .as_signed_time_precision_units()
                .map_err(|_| Error::InvalidParameter("report_expiry_age too large"))?;
        }
        // The interval's ordering and half-open-ness are already enforced by `Interval` itself; we
        // only need to range-check that the start and duration fit in the signed 64-bit DB columns.
        if let Some(task_interval) = task_interval {
            task_interval
                .start()
                .as_signed_time_precision_units()
                .map_err(|_| Error::InvalidParameter("task_interval start out of range"))?;
            task_interval
                .duration()
                .as_signed_time_precision_units()
                .map_err(|_| Error::InvalidParameter("task_interval duration out of range"))?;
        }

        if time_precision.as_seconds() == 0 {
            return Err(Error::InvalidParameter("time_precision is zero"));
        }

        Ok(Self {
            task_id,
            batch_mode,
            vdaf,
            vdaf_verify_key,
            task_interval,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
            task_info,
        })
    }

    /// Returns the [`VerifyKey`] used by this aggregator to verify report shares with other
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
#[derive(Clone, Educe, PartialEq, Eq)]
#[educe(Debug)]
pub struct AggregatorTask {
    /// Common task parameters
    common_parameters: CommonTaskParameters,
    /// URL relative to which the peer aggregator's API endpoints are found.
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    peer_aggregator_endpoint: DapUrl,
    /// URL relative to which this aggregator's own API endpoints are found.
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    own_aggregator_endpoint: DapUrl,
    /// Parameters specific to either aggregator role
    aggregator_parameters: AggregatorTaskParameters,
    /// Deactivation instant. When set and reached (per the aggregator's clock), the
    /// aggregator stops accepting reports for this task. This is Janus-specific state.
    deactivate_at: Option<DateTime<Utc>>,
    /// For taskprov tasks, the `TaskConfiguration` exactly as received on the wire, bound verbatim
    /// into HPKE AADs. `None` for API-provisioned tasks, whose `TaskConfiguration` is synthesized
    /// from the stored parameters. Reconstructing a taskprov config from those parameters is not
    /// byte-safe (it would drop DP strategies and unknown extensions), so the wire bytes are kept.
    ///
    /// Persisted only via the datastore, not [`SerializedAggregatorTask`] (like `deactivate_at`);
    /// taskprov tasks are never provisioned through that serde form.
    taskprov_task_config: Option<TaskConfiguration>,
}

impl AggregatorTask {
    /// Create a new [`AggregatorTask`] with the provided values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        peer_aggregator_endpoint: DapUrl,
        own_aggregator_endpoint: DapUrl,
        batch_mode: BatchMode,
        vdaf: VdafInstance,
        vdaf_verify_key: SecretBytes,
        task_interval: Option<Interval>,
        report_expiry_age: Option<Duration>,
        min_batch_size: u64,
        time_precision: TimePrecision,
        tolerable_clock_skew: Duration,
        task_info: Vec<u8>,
        aggregator_parameters: AggregatorTaskParameters,
    ) -> Result<Self, Error> {
        let common_parameters = CommonTaskParameters::new(
            task_id,
            batch_mode,
            vdaf,
            vdaf_verify_key,
            task_interval,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
            task_info,
        )?;
        Self::new_with_common_parameters(
            common_parameters,
            peer_aggregator_endpoint,
            own_aggregator_endpoint,
            aggregator_parameters,
        )
    }

    fn new_with_common_parameters(
        common_parameters: CommonTaskParameters,
        peer_aggregator_endpoint: DapUrl,
        own_aggregator_endpoint: DapUrl,
        aggregator_parameters: AggregatorTaskParameters,
    ) -> Result<Self, Error> {
        // Reject an unparseable endpoint at construction. Without this check a
        // malformed endpoint would persist and never surface a user-visible error.
        Url::try_from(&peer_aggregator_endpoint)?;
        Url::try_from(&own_aggregator_endpoint)?;

        if let BatchMode::LeaderSelected {
            batch_time_window_size: Some(batch_time_window_size),
            ..
        } = common_parameters.batch_mode
        {
            if matches!(
                aggregator_parameters,
                AggregatorTaskParameters::TaskprovHelper { .. },
            ) {
                return Err(Error::InvalidParameter(
                    "batch_time_window_size is not supported for taskprov",
                ));
            } else if batch_time_window_size == Duration::ZERO {
                return Err(Error::InvalidParameter("batch_time_window_size is zero"));
            }
        }

        Ok(Self {
            common_parameters,
            peer_aggregator_endpoint,
            own_aggregator_endpoint,
            aggregator_parameters,
            deactivate_at: None,
            taskprov_task_config: None,
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

    /// Retrieves the aggregation mode of the task for the Helper, or None for the Leader.
    pub fn aggregation_mode(&self) -> Option<&AggregationMode> {
        self.aggregator_parameters().aggregation_mode()
    }

    /// Retrieves the peer aggregator endpoint associated with this task.
    pub fn peer_aggregator_endpoint(&self) -> &DapUrl {
        &self.peer_aggregator_endpoint
    }

    /// Retrieves this aggregator's own endpoint associated with this task.
    pub fn own_aggregator_endpoint(&self) -> &DapUrl {
        &self.own_aggregator_endpoint
    }

    /// The received wire `TaskConfiguration` for a taskprov task, or `None` for an API-provisioned
    /// task.
    pub fn taskprov_task_config(&self) -> Option<&TaskConfiguration> {
        self.taskprov_task_config.as_ref()
    }

    /// Returns the canonical [`TaskConfiguration`] for this task, as bound into HPKE AADs.
    ///
    /// For taskprov tasks this is the wire configuration verbatim; for API-provisioned tasks it is
    /// synthesized from the stored parameters, pairing this aggregator's own and peer endpoints
    /// into leader/helper by role.
    pub fn task_configuration(&self) -> Result<TaskConfiguration, Error> {
        if let Some(task_config) = &self.taskprov_task_config {
            return Ok(task_config.clone());
        }

        // A taskprov task must carry its wire configuration verbatim (set in `taskprov_opt_in` and
        // rehydrated on DB read); synthesizing one from the stored parameters is not byte-faithful.
        // Reaching here for a taskprov task means the config was lost, so fail loudly rather than
        // bind a wrong AAD.
        if matches!(
            self.aggregator_parameters,
            AggregatorTaskParameters::TaskprovHelper { .. }
        ) {
            return Err(Error::InvalidParameter(
                "taskprov task is missing its verbatim TaskConfiguration",
            ));
        }

        let (leader_endpoint, helper_endpoint) = match self.role() {
            Role::Leader => (
                &self.own_aggregator_endpoint,
                &self.peer_aggregator_endpoint,
            ),
            Role::Helper => (
                &self.peer_aggregator_endpoint,
                &self.own_aggregator_endpoint,
            ),
            _ => return Err(Error::InvalidParameter("task role is not an aggregator")),
        };

        Ok(build_task_configuration(
            self.task_info().to_vec(),
            leader_endpoint.clone(),
            helper_endpoint.clone(),
            *self.time_precision(),
            self.min_batch_size(),
            self.batch_mode().to_batch_config(),
            self.vdaf()
                .to_vdaf_config()
                .map_err(Error::InvalidParameter)?,
            self.task_interval().copied(),
        )?)
    }

    /// Retrieves the batch mode associated with this task.
    pub fn batch_mode(&self) -> &BatchMode {
        &self.common_parameters.batch_mode
    }

    /// Retrieves the VDAF associated with this task.
    pub fn vdaf(&self) -> &VdafInstance {
        &self.common_parameters.vdaf
    }

    /// Retrieves the VDAF verification key associated with this task, as opaque secret bytes.
    pub fn opaque_vdaf_verify_key(&self) -> &SecretBytes {
        &self.common_parameters.vdaf_verify_key
    }

    /// Retrieves the validity interval associated with this task, if any.
    pub fn task_interval(&self) -> Option<&Interval> {
        self.common_parameters.task_interval.as_ref()
    }

    /// Retrieves the task start time (the start of the validity interval), if any.
    pub fn task_start(&self) -> Option<Time> {
        self.common_parameters.task_interval.map(|i| i.start())
    }

    /// Retrieves the task end time (the end of the validity interval), if any.
    pub fn task_end(&self) -> Option<Time> {
        self.common_parameters.task_interval.map(|i| i.end())
    }

    /// Retrieves the deactivation instant, if set. (Janus-specific)
    pub fn deactivate_at(&self) -> Option<DateTime<Utc>> {
        self.deactivate_at
    }

    /// Returns this task with its deactivation instant set. (Janus-specific)
    pub fn with_deactivate_at(mut self, deactivate_at: Option<DateTime<Utc>>) -> Self {
        self.deactivate_at = deactivate_at;
        self
    }

    /// Returns this task with its verbatim taskprov [`TaskConfiguration`] set.
    pub fn with_taskprov_task_config(mut self, task_config: TaskConfiguration) -> Self {
        self.taskprov_task_config = Some(task_config);
        self
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
    pub fn time_precision(&self) -> &TimePrecision {
        &self.common_parameters.time_precision
    }

    /// Retrieves the tolerable clock skew parameter associated with this task.
    pub fn tolerable_clock_skew(&self) -> &Duration {
        &self.common_parameters.tolerable_clock_skew
    }

    /// Returns true if the `batch_size` is valid given this task's batch mode and batch size
    /// parameters, per
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-09#name-batch-validation>
    pub fn validate_batch_size(&self, batch_size: u64) -> bool {
        batch_size >= self.common_parameters.min_batch_size
    }

    /// Returns the [`VerifyKey`] used by this aggregator to verify report shares with other
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
        step: Option<AggregationJobStep>,
    ) -> Result<Option<Url>, Error> {
        if matches!(
            self.aggregator_parameters,
            AggregatorTaskParameters::Leader { .. }
        ) {
            let mut uri = url_for_join(self.peer_aggregator_endpoint())?.join(&format!(
                "{}/aggregation_jobs/{aggregation_job_id}",
                self.tasks_path()
            ))?;

            if let Some(step) = step {
                uri.query_pairs_mut()
                    .append_pair("step", &u16::from(step).to_string());
            }

            Ok(Some(uri))
        } else {
            Ok(None)
        }
    }

    /// Returns the URI at which the helper aggregate shares resource can be accessed.
    pub fn aggregate_shares_uri(
        &self,
        aggregate_share_id: &AggregateShareId,
    ) -> Result<Option<Url>, Error> {
        if matches!(
            self.aggregator_parameters,
            AggregatorTaskParameters::Leader { .. }
        ) {
            Ok(Some(url_for_join(self.peer_aggregator_endpoint())?.join(
                &format!(
                    "{}/aggregate_shares/{}",
                    self.tasks_path(),
                    aggregate_share_id,
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Returns the aggregator [`AuthenticationToken`] for this task, used by the leader to
    /// authenticate aggregation sub-protocol requests sent to the helper, or `None` for the helper.
    pub fn aggregator_auth_token(&self) -> Option<&AuthenticationToken> {
        self.aggregator_parameters.aggregator_auth_token()
    }

    /// Returns the aggregator [`AuthenticationTokenHash`] for this task, used by the helper to
    /// authenticate aggregation sub-protocol requests received from the leader, or `None` for the
    /// leader.
    pub fn aggregator_auth_token_hash(&self) -> Option<&AuthenticationTokenHash> {
        self.aggregator_parameters.aggregator_auth_token_hash()
    }

    /// Returns the collector HPKE configuration for this task, or `None` for taskprov tasks.
    pub fn collector_hpke_config(&self) -> Option<&HpkeConfig> {
        self.aggregator_parameters.collector_hpke_config()
    }

    /// Returns the collector [`AuthenticationTokenHash`] for this task, used by the leader to
    /// authenticate collection sub-protocol requests received from the collector, or `None` for the
    /// helper.
    pub fn collector_auth_token_hash(&self) -> Option<&AuthenticationTokenHash> {
        self.aggregator_parameters.collector_auth_token_hash()
    }

    /// Checks if the given aggregator authentication token is valid (i.e. matches with the
    /// authentication token recognized by this task).
    pub fn check_aggregator_auth_token(
        &self,
        incoming_auth_token: Option<&AuthenticationToken>,
    ) -> bool {
        self.aggregator_auth_token_hash()
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
        self.collector_auth_token_hash()
            .zip(incoming_auth_token)
            .map(|(own_token_hash, incoming_token)| own_token_hash.validate(incoming_token))
            .unwrap_or(false)
    }

    /// Return the `task_info` field for this task.
    pub fn task_info(&self) -> &[u8] {
        &self.common_parameters.task_info
    }
}

/// Role-specific task parameters for the aggregator DAP roles.
#[derive(Clone, Educe, PartialEq, Eq)]
#[educe(Debug)]
pub enum AggregatorTaskParameters {
    /// Task parameters held exclusively by the DAP leader.
    Leader {
        /// Authentication token used to make requests to the helper during the aggregation
        /// sub-protocol.
        aggregator_auth_token: AuthenticationToken,
        /// Authentication token hash used to validate requests from the collector during the
        /// collection sub-protocol.
        collector_auth_token_hash: AuthenticationTokenHash,
        /// HPKE configuration for the collector.
        collector_hpke_config: HpkeConfig,
    },

    /// Task parameters held exclusively by the DAP helper.
    Helper {
        /// Authentication token hash used to validate requests from the leader during the
        /// aggregation sub-protocol.
        aggregator_auth_token_hash: AuthenticationTokenHash,
        /// HPKE configuration for the collector.
        collector_hpke_config: HpkeConfig,
        /// The aggregation mode to use for this task.
        aggregation_mode: AggregationMode,
    },

    /// Task parameters held exclusively by a DAP helper provisioned via taskprov.
    TaskprovHelper { aggregation_mode: AggregationMode },
}

/// Indicates an aggregation mode: synchronous or asynchronous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSql, FromSql)]
#[postgres(name = "aggregation_mode")]
pub enum AggregationMode {
    /// Aggregation is completed synchronously, i.e. every successful aggregation initialization or
    /// continuation request will be responded to with a response in the "finished" status.
    #[postgres(name = "SYNCHRONOUS")]
    Synchronous,

    /// Aggregation is completed asynchronously, i.e. every successful aggregation initialization or
    /// continuation request will be responded to with a response in the "processing" status.
    #[postgres(name = "ASYNCHRONOUS")]
    Asynchronous,
}

impl FromStr for AggregationMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "synchronous" => Ok(Self::Synchronous),
            "asynchronous" => Ok(Self::Asynchronous),
            _ => Err(anyhow!("couldn't parse AggregationMode value: {s}")),
        }
    }
}

impl AggregatorTaskParameters {
    /// Returns the [`Role`] that this aggregator plays.
    pub fn role(&self) -> &Role {
        match self {
            Self::Leader { .. } => &Role::Leader,
            Self::Helper { .. } | Self::TaskprovHelper { .. } => &Role::Helper,
        }
    }

    /// Returns the [`AggregationMode`] for this task for the helper, or `None` for the leader.
    fn aggregation_mode(&self) -> Option<&AggregationMode> {
        match self {
            Self::Leader { .. } => None,
            Self::Helper {
                aggregation_mode, ..
            } => Some(aggregation_mode),
            Self::TaskprovHelper {
                aggregation_mode, ..
            } => Some(aggregation_mode),
        }
    }

    /// Returns the aggregator [`AuthenticationToken`] for this task, used by the leader to
    /// authenticate aggregation sub-protocol requests sent to the helper, or `None` for the helper.
    fn aggregator_auth_token(&self) -> Option<&AuthenticationToken> {
        match self {
            Self::Leader {
                aggregator_auth_token,
                ..
            } => Some(aggregator_auth_token),
            _ => None,
        }
    }

    /// Returns the aggregator [`AuthenticationTokenHash`] for this task, used by the helper to
    /// authenticate aggregation sub-protocol requests received from the leader, or `None` for the
    /// leader.
    fn aggregator_auth_token_hash(&self) -> Option<&AuthenticationTokenHash> {
        match self {
            Self::Helper {
                aggregator_auth_token_hash,
                ..
            } => Some(aggregator_auth_token_hash),
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

    /// Returns the collector [`AuthenticationTokenHash`] for this task, used by the leader to
    /// authenticate collection sub-protocol requests received from the collector, or `None` for the
    /// helper.
    fn collector_auth_token_hash(&self) -> Option<&AuthenticationTokenHash> {
        match self {
            Self::Leader {
                collector_auth_token_hash,
                ..
            } => Some(collector_auth_token_hash),
            _ => None,
        }
    }
}

/// SerializedAggregatorTask is an intermediate representation for the aggregator view of tasks
/// being serialized via the Serialize and Deserialize traits.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializedAggregatorTask {
    task_id: Option<TaskId>,
    peer_aggregator_endpoint: DapUrl,
    own_aggregator_endpoint: DapUrl,
    batch_mode: BatchMode,
    aggregation_mode: Option<AggregationMode>,
    vdaf: VdafInstance,
    role: Role,
    vdaf_verify_key: Option<String>, // in unpadded base64url
    task_info: String,               // in unpadded base64url
    task_start: Option<Time>,
    task_duration: Option<Duration>,
    report_expiry_age: Option<Duration>,
    min_batch_size: u64,
    time_precision: TimePrecision,
    tolerable_clock_skew: Duration,
    collector_hpke_config: HpkeConfig,
    aggregator_auth_token: Option<AuthenticationToken>,
    aggregator_auth_token_hash: Option<AuthenticationTokenHash>,
    collector_auth_token_hash: Option<AuthenticationTokenHash>,
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
    /// - Aggregator authentication token (only if the task's role is helper)
    /// - The aggregator's HPKE keypair (only one keypair is generated)
    /// - The aggregate share ID (only if the task's role is leader)
    pub fn generate_missing_fields(&mut self) {
        if self.task_id.is_none() {
            let task_id: TaskId = random();
            self.task_id = Some(task_id);
        }

        if self.vdaf_verify_key.is_none() {
            let vdaf_verify_key = SecretBytes::new(
                rng()
                    .sample_iter(StandardUniform)
                    .take(self.vdaf.verify_key_length())
                    .collect(),
            );

            self.vdaf_verify_key = Some(URL_SAFE_NO_PAD.encode(vdaf_verify_key.as_ref()));
        }

        if self.aggregator_auth_token.is_none() && self.role == Role::Helper {
            self.aggregator_auth_token = Some(random());
        }
    }
}

impl Serialize for AggregatorTask {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SerializedAggregatorTask {
            task_id: Some(*self.id()),
            peer_aggregator_endpoint: self.peer_aggregator_endpoint().clone(),
            own_aggregator_endpoint: self.own_aggregator_endpoint().clone(),
            batch_mode: *self.batch_mode(),
            aggregation_mode: self.aggregator_parameters.aggregation_mode().copied(),
            vdaf: self.vdaf().clone(),
            role: *self.role(),
            vdaf_verify_key: Some(URL_SAFE_NO_PAD.encode(self.opaque_vdaf_verify_key())),
            task_info: URL_SAFE_NO_PAD.encode(self.task_info()),
            task_start: self.task_start(),
            task_duration: self.task_interval().map(|i| i.duration()),
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
            aggregator_auth_token_hash: self
                .aggregator_parameters
                .aggregator_auth_token_hash()
                .cloned(),
            collector_auth_token_hash: self
                .aggregator_parameters
                .collector_auth_token_hash()
                .cloned(),
        }
        .serialize(serializer)
    }
}

/// Reconstructs an optional task validity [`Interval`] from a separately-stored start and duration.
///
/// Both must be present (yielding `Some(Interval)`) or both absent (yielding `None`); a lone bound
/// is rejected, as a half-open task interval is not representable.
pub fn reconstruct_task_interval(
    task_start: Option<Time>,
    task_duration: Option<Duration>,
) -> Result<Option<Interval>, Error> {
    match (task_start, task_duration) {
        (Some(start), Some(duration)) => {
            Ok(Some(Interval::new(start, duration).map_err(|_| {
                Error::InvalidParameter("task interval start + duration overflows")
            })?))
        }
        (None, None) => Ok(None),
        _ => Err(Error::InvalidParameter(
            "task_start and task_duration must both be set or both be unset",
        )),
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
                collector_auth_token_hash: serialized_task
                    .collector_auth_token_hash
                    .ok_or(Error::InvalidParameter("missing collector auth token hash"))?,
                collector_hpke_config: serialized_task.collector_hpke_config,
            },
            Role::Helper => AggregatorTaskParameters::Helper {
                aggregator_auth_token_hash: serialized_task.aggregator_auth_token_hash.ok_or(
                    Error::InvalidParameter("missing aggregator auth token hash"),
                )?,
                collector_hpke_config: serialized_task.collector_hpke_config,
                aggregation_mode: serialized_task
                    .aggregation_mode
                    .ok_or(Error::InvalidParameter("missing aggregation mode"))?,
            },
            _ => return Err(Error::InvalidParameter("unexpected role")),
        };

        let task_interval =
            reconstruct_task_interval(serialized_task.task_start, serialized_task.task_duration)?;

        AggregatorTask::new(
            task_id,
            serialized_task.peer_aggregator_endpoint,
            serialized_task.own_aggregator_endpoint,
            serialized_task.batch_mode,
            serialized_task.vdaf,
            SecretBytes::new(URL_SAFE_NO_PAD.decode(vdaf_verify_key)?),
            task_interval,
            serialized_task.report_expiry_age,
            serialized_task.min_batch_size,
            serialized_task.time_precision,
            serialized_task.tolerable_clock_skew,
            URL_SAFE_NO_PAD.decode(serialized_task.task_info)?,
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
    use std::collections::HashMap;

    use educe::Educe;
    use janus_core::{
        UrlExt,
        auth_tokens::{AuthenticationToken, AuthenticationTokenHash},
        hpke::HpkeKeypair,
        vdaf::VdafInstance,
    };
    use janus_messages::{
        AggregateShareId, AggregationJobId, AggregationJobStep, CollectionJobId, Duration,
        HpkeConfigId, Interval, Role, TaskId, Time, TimePrecision, Url as DapUrl,
    };
    use rand::{RngExt, distr::StandardUniform, random, rng};
    use url::Url;

    use crate::{
        SecretBytes,
        task::{
            AggregationMode, AggregatorTask, AggregatorTaskParameters, BatchMode,
            CommonTaskParameters, Error, VerifyKey,
        },
    };

    /// Converts a routing [`url::Url`] into the [`janus_messages::Url`] the aggregator view stores.
    /// Test-only: a `url::Url` always serializes to non-empty ASCII, so this cannot fail here.
    fn to_dap_url(url: &Url) -> DapUrl {
        DapUrl::try_from(url.as_str().as_bytes()).unwrap()
    }

    /// All parameters and secrets for a task, for all participants.
    #[derive(Clone, Educe, PartialEq, Eq)]
    #[educe(Debug)]
    pub struct Task {
        /// Common task parameters
        common_parameters: CommonTaskParameters,
        /// URL relative to which the leader aggregator's API endpoints are found.
        #[educe(Debug(method(std::fmt::Display::fmt)))]
        leader_aggregator_endpoint: Url,
        /// URL relative to which the leader aggregator's API endpoints are found.
        #[educe(Debug(method(std::fmt::Display::fmt)))]
        helper_aggregator_endpoint: Url,
        /// The mode used for aggregation by the Helper (synchronous vs asynchronous).
        helper_aggregation_mode: AggregationMode,
        /// HPKE configuration and private key used by the collector to decrypt aggregate shares.
        collector_hpke_keypair: HpkeKeypair,
        /// Token used to authenticate messages exchanged between the aggregators in the
        /// aggregation sub-protocol.
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
            batch_mode: BatchMode,
            helper_aggregation_mode: AggregationMode,
            vdaf: VdafInstance,
            vdaf_verify_key: SecretBytes,
            task_interval: Option<Interval>,
            report_expiry_age: Option<Duration>,
            min_batch_size: u64,
            time_precision: TimePrecision,
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
                    batch_mode,
                    vdaf,
                    vdaf_verify_key,
                    task_interval,
                    report_expiry_age,
                    min_batch_size,
                    time_precision,
                    tolerable_clock_skew,
                    task_info: b"task-info".to_vec(),
                },
                // Ensure provided aggregator endpoints end with a slash, as we will be joining
                // additional path segments into these endpoints & the Url::join implementation is
                // persnickety about the slash at the end of the path.
                leader_aggregator_endpoint: leader_aggregator_endpoint.ensure_trailing_slash(),
                helper_aggregator_endpoint: helper_aggregator_endpoint.ensure_trailing_slash(),
                helper_aggregation_mode,
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

        /// Retrieves the batch mode associated with this task.
        pub fn batch_mode(&self) -> &BatchMode {
            &self.common_parameters.batch_mode
        }

        pub fn helper_aggregation_mode(&self) -> &AggregationMode {
            &self.helper_aggregation_mode
        }

        /// Retrieves the VDAF associated with this task.
        pub fn vdaf(&self) -> &VdafInstance {
            &self.common_parameters.vdaf
        }

        /// Retrieves the VDAF verification key associated with this task, as opaque secret bytes.
        pub fn opaque_vdaf_verify_key(&self) -> &SecretBytes {
            &self.common_parameters.vdaf_verify_key
        }

        /// Retrieves the validity interval associated with this task, if any.
        pub fn task_interval(&self) -> Option<&Interval> {
            self.common_parameters.task_interval.as_ref()
        }

        /// Retrieves the task start time (the start of the validity interval), if any.
        pub fn task_start(&self) -> Option<Time> {
            self.common_parameters.task_interval.map(|i| i.start())
        }

        /// Retrieves the task end time (the end of the validity interval), if any.
        pub fn task_end(&self) -> Option<Time> {
            self.common_parameters.task_interval.map(|i| i.end())
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
        pub fn time_precision(&self) -> &TimePrecision {
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

        /// Returns the [`VerifyKey`] used by this aggregator to verify report shares with other
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
            step: Option<AggregationJobStep>,
        ) -> Result<Url, Error> {
            let mut uri = self.helper_aggregator_endpoint().join(&format!(
                "{}/aggregation_jobs/{aggregation_job_id}",
                self.tasks_path()
            ))?;

            if let Some(step) = step {
                uri.query_pairs_mut()
                    .append_pair("step", &u16::from(step).to_string());
            }

            Ok(uri)
        }

        /// Returns the URI at which the helper aggregate shares resource can be accessed.
        pub fn aggregate_shares_uri(
            &self,
            aggregate_share_id: &AggregateShareId,
        ) -> Result<Url, Error> {
            Ok(self.helper_aggregator_endpoint().join(&format!(
                "{}/aggregate_shares/{}",
                self.tasks_path(),
                aggregate_share_id
            ))?)
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
                to_dap_url(&self.helper_aggregator_endpoint),
                to_dap_url(&self.leader_aggregator_endpoint),
                AggregatorTaskParameters::Leader {
                    aggregator_auth_token: self.aggregator_auth_token.clone(),
                    collector_auth_token_hash: AuthenticationTokenHash::from(
                        &self.collector_auth_token,
                    ),
                    collector_hpke_config: self.collector_hpke_keypair.config().clone(),
                },
            )
        }

        /// Render the helper aggregator's view of this task.
        pub fn helper_view(&self) -> Result<AggregatorTask, Error> {
            AggregatorTask::new_with_common_parameters(
                self.common_parameters.clone(),
                to_dap_url(&self.leader_aggregator_endpoint),
                to_dap_url(&self.helper_aggregator_endpoint),
                AggregatorTaskParameters::Helper {
                    aggregator_auth_token_hash: AuthenticationTokenHash::from(
                        &self.aggregator_auth_token,
                    ),
                    collector_hpke_config: self.collector_hpke_keypair.config().clone(),
                    aggregation_mode: self.helper_aggregation_mode,
                },
            )
        }

        /// Render a taskprov helper aggregator's view of this task.
        pub fn taskprov_helper_view(&self) -> Result<AggregatorTask, Error> {
            AggregatorTask::new_with_common_parameters(
                self.common_parameters.clone(),
                to_dap_url(&self.leader_aggregator_endpoint),
                to_dap_url(&self.helper_aggregator_endpoint),
                AggregatorTaskParameters::TaskprovHelper {
                    aggregation_mode: self.helper_aggregation_mode,
                },
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
        pub fn new(
            batch_mode: BatchMode,
            helper_aggregation_mode: AggregationMode,
            vdaf: VdafInstance,
        ) -> Self {
            let task_id = random();

            let leader_hpke_keypairs = [
                HpkeKeypair::test(),
                HpkeKeypair::test_with_id(HpkeConfigId::from(1)),
            ];
            let helper_hpke_keypairs = [
                HpkeKeypair::test(),
                HpkeKeypair::test_with_id(HpkeConfigId::from(1)),
            ];

            let vdaf_verify_key = SecretBytes::new(
                rng()
                    .sample_iter(StandardUniform)
                    .take(vdaf.verify_key_length())
                    .collect(),
            );

            Self(Task::new(
                task_id,
                "https://leader.endpoint".parse().unwrap(),
                "https://helper.endpoint".parse().unwrap(),
                batch_mode,
                helper_aggregation_mode,
                vdaf,
                vdaf_verify_key,
                /* task_interval */ None,
                /* report_expiry_age */ None,
                /* Min batch size */ 1,
                /* Time precision */
                TimePrecision::from_hours(8),
                /* Tolerable clock skew */
                Duration::ZERO, // If ZERO, we'll copy the time precision at build time
                /* Collector HPKE keypair */ HpkeKeypair::test(),
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

        /// Gets the batch mode for the eventual task.
        pub fn batch_mode(&self) -> &BatchMode {
            self.0.batch_mode()
        }

        /// Gets the aggregation mode used by the helper for the eventual task.
        pub fn helper_aggregation_mode(&self) -> &AggregationMode {
            self.0.helper_aggregation_mode()
        }

        /// Gets the VDAF for the eventual task
        pub fn vdaf(&self) -> &VdafInstance {
            self.0.vdaf()
        }

        /// Associates the eventual task with the given aggregator endpoint for the Leader.
        pub fn with_leader_aggregator_endpoint(self, leader_aggregator_endpoint: Url) -> Self {
            Self(Task {
                leader_aggregator_endpoint: leader_aggregator_endpoint.ensure_trailing_slash(),
                ..self.0
            })
        }

        /// Associates the eventual task with the given aggregator endpoint for the Helper.
        pub fn with_helper_aggregator_endpoint(self, helper_aggregator_endpoint: Url) -> Self {
            Self(Task {
                helper_aggregator_endpoint: helper_aggregator_endpoint.ensure_trailing_slash(),
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
        pub fn with_time_precision(self, time_precision: TimePrecision) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    time_precision,
                    ..self.0.common_parameters
                },
                ..self.0
            })
        }

        /// Gets the time precision associated with the eventual task.
        pub fn time_precision(&self) -> &TimePrecision {
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

        /// Sets the task validity interval.
        pub fn with_task_interval(self, task_interval: Option<Interval>) -> Self {
            Self(Task {
                common_parameters: CommonTaskParameters {
                    task_interval,
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

        /// Set the `task_info` field for this task.
        pub fn with_task_info(mut self, task_info: Vec<u8>) -> Self {
            self.0.common_parameters.task_info = task_info;
            self
        }

        /// Gets the colector HPKE keypair for the eventual task.
        pub fn collector_hpke_keypair(&self) -> &HpkeKeypair {
            self.0.collector_hpke_keypair()
        }

        /// Consumes this task builder & produces a [`Task`] with the given specifications.
        pub fn build(self) -> Task {
            // If the tolerable clock skew is unset, copy the time_precision
            if *self.0.tolerable_clock_skew() == Duration::ZERO {
                return self.with_tolerable_clock_skew(Duration::ONE).0;
            }
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
    use assert_matches::assert_matches;
    use chrono::TimeDelta;
    use janus_core::{
        auth_tokens::{AuthenticationToken, AuthenticationTokenHash},
        task_config::build_task_configuration,
        test_util::roundtrip_encoding,
        vdaf::vdaf_dp_strategies,
    };
    use janus_messages::{
        BatchConfig, Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId,
        HpkePublicKey, Interval, TaskId, Time, TimePrecision, Url as DapUrl, VdafConfig,
    };
    use rand::random;
    use serde_json::json;
    use serde_test::{Token, assert_de_tokens, assert_tokens};

    use crate::{
        SecretBytes,
        task::{
            AggregationMode, AggregatorTask, AggregatorTaskParameters, BatchMode, Error,
            VdafInstance, test_util::TaskBuilder,
        },
    };

    #[test]
    fn batch_mode_to_batch_config() {
        assert_eq!(
            BatchMode::TimeInterval.to_batch_config(),
            BatchConfig::TimeInterval
        );
        // The Janus-specific batch_time_window_size is dropped, so both leader-selected variants
        // map to the same BatchConfig.
        assert_eq!(
            BatchMode::LeaderSelected {
                batch_time_window_size: None,
            }
            .to_batch_config(),
            BatchConfig::LeaderSelected
        );
        assert_eq!(
            BatchMode::LeaderSelected {
                batch_time_window_size: Some(Duration::from_seconds(
                    3600,
                    &TimePrecision::from_seconds(3600)
                )),
            }
            .to_batch_config(),
            BatchConfig::LeaderSelected
        );
    }

    #[test]
    fn leader_task_serialization() {
        roundtrip_encoding(
            TaskBuilder::new(
                BatchMode::TimeInterval,
                AggregationMode::Synchronous,
                VdafInstance::Prio3Count,
            )
            .build()
            .leader_view()
            .unwrap(),
        );
    }

    #[test]
    fn helper_task_serialization() {
        roundtrip_encoding(
            TaskBuilder::new(
                BatchMode::TimeInterval,
                AggregationMode::Synchronous,
                VdafInstance::Prio3Count,
            )
            .build()
            .helper_view()
            .unwrap(),
        );
    }

    #[test]
    fn deserialize_docs_sample_tasks() {
        yaml_serde::from_str::<Vec<AggregatorTask>>(include_str!("../../docs/samples/tasks.yaml"))
            .unwrap();
    }

    #[test]
    fn aggregator_endpoints_end_in_slash() {
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
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
    fn own_endpoint_is_this_aggregators_endpoint() {
        // Each aggregator's own endpoint is its own side of the pair (not the peer's); a swap here
        // would produce a mismatched TaskConfiguration and break every AAD decryption.
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_leader_aggregator_endpoint("https://leader.example.com/".parse().unwrap())
        .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
        .build();

        let leader = task.leader_view().unwrap();
        assert_eq!(
            leader.own_aggregator_endpoint().as_str(),
            "https://leader.example.com/"
        );
        assert_eq!(
            leader.peer_aggregator_endpoint().as_str(),
            "https://helper.example.com/"
        );

        let helper = task.helper_view().unwrap();
        assert_eq!(
            helper.own_aggregator_endpoint().as_str(),
            "https://helper.example.com/"
        );
        assert_eq!(
            helper.peer_aggregator_endpoint().as_str(),
            "https://leader.example.com/"
        );
    }

    #[test]
    fn own_endpoint_stored_verbatim() {
        // The production constructor must not re-encode the own endpoint: a non-canonical value
        // (mixed-case host, no trailing slash) is bound verbatim into the task's TaskConfiguration
        // (DAP-18 §4.1). A `url::Url`-normalizing path would silently canonicalize it.
        let noncanonical = "https://Example.COM/DAP";
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .build()
        .leader_view()
        .unwrap();
        let task = AggregatorTask::new(
            *task.id(),
            task.peer_aggregator_endpoint().clone(),
            noncanonical.try_into().unwrap(),
            *task.batch_mode(),
            task.vdaf().clone(),
            task.opaque_vdaf_verify_key().clone(),
            task.task_interval().copied(),
            task.report_expiry_age().copied(),
            task.min_batch_size(),
            *task.time_precision(),
            *task.tolerable_clock_skew(),
            task.task_info().to_vec(),
            task.aggregator_parameters().clone(),
        )
        .unwrap();
        assert_eq!(task.own_aggregator_endpoint().as_str(), noncanonical);
    }

    #[test]
    fn task_configuration_synthesized_for_api_task() {
        // For an API-provisioned task, task_configuration() synthesizes from stored parameters,
        // pairing own/peer endpoints into leader/helper by role. Both aggregators' views must
        // produce byte-identical configurations, or their AADs would not match.
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_leader_aggregator_endpoint("https://leader.example.com/".parse().unwrap())
        .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
        .build();

        let leader_config = task.leader_view().unwrap().task_configuration().unwrap();
        assert_eq!(
            leader_config.leader_aggregator_endpoint().as_str(),
            "https://leader.example.com/"
        );
        assert_eq!(
            leader_config.helper_aggregator_endpoint().as_str(),
            "https://helper.example.com/"
        );
        assert_eq!(
            leader_config,
            task.helper_view().unwrap().task_configuration().unwrap()
        );
    }

    #[test]
    fn task_configuration_verbatim_for_taskprov() {
        // A taskprov task binds the received wire configuration verbatim, not one synthesized from
        // its stored parameters. Prove this by giving the wire config a distinct task_info: if the
        // task re-synthesized, it would use the task's own task_info instead.
        let wire = build_task_configuration(
            b"wire-specific-task-info".to_vec(),
            "https://leader.example.com/".try_into().unwrap(),
            "https://helper.example.com/".try_into().unwrap(),
            TimePrecision::from_seconds(3600),
            100,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
            None,
        )
        .unwrap();

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .build()
        .taskprov_helper_view()
        .unwrap()
        .with_taskprov_task_config(wire.clone());

        assert_eq!(task.task_configuration().unwrap(), wire);
        assert_eq!(
            task.task_configuration().unwrap().task_info(),
            b"wire-specific-task-info"
        );
    }

    #[test]
    fn task_configuration_taskprov_without_config_errors() {
        // A taskprov task whose verbatim wire config is absent must fail loudly rather than
        // silently synthesize a (non-byte-faithful) config from its stored parameters.
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .build()
        .taskprov_helper_view()
        .unwrap();
        assert_matches!(task.task_configuration(), Err(Error::InvalidParameter(_)));
    }

    #[test]
    fn aggregator_request_paths() {
        for (prefix, task) in [
            (
                "",
                TaskBuilder::new(
                    BatchMode::TimeInterval,
                    AggregationMode::Synchronous,
                    VdafInstance::Prio3Count,
                )
                .build(),
            ),
            (
                "/prefix",
                TaskBuilder::new(
                    BatchMode::TimeInterval,
                    AggregationMode::Synchronous,
                    VdafInstance::Prio3Count,
                )
                .with_leader_aggregator_endpoint("https://leader.com/prefix/".parse().unwrap())
                .with_helper_aggregator_endpoint("https://helper.com/prefix/".parse().unwrap())
                .build(),
            ),
        ] {
            let prefix = format!("{prefix}/tasks");

            for uri in [
                task.report_upload_uri().unwrap(),
                task.aggregation_job_uri(&random(), None).unwrap(),
                task.collection_job_uri(&random()).unwrap(),
                task.aggregate_shares_uri(&random()).unwrap(),
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
    fn request_authentication() {
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .build();

        let leader_task = task.leader_view().unwrap();
        let helper_task = task.helper_view().unwrap();

        let incorrect_auth_token = random();

        // Helper should accept valid aggregator auth token
        assert!(helper_task.check_aggregator_auth_token(Some(task.aggregator_auth_token())));
        // Leader should accept valid collector auth token
        assert!(leader_task.check_collector_auth_token(Some(task.collector_auth_token())));

        // Leader should reject absent collector auth token
        assert!(!leader_task.check_collector_auth_token(None));
        // Helper should reject absent aggregator auth token
        assert!(!helper_task.check_aggregator_auth_token(None));
        // Leader should not be able to validate aggregation sub protocol requests
        assert!(!leader_task.check_aggregator_auth_token(Some(task.aggregator_auth_token())));
        // Helper should not be able to validate collection sub protocol requests
        assert!(!helper_task.check_collector_auth_token(Some(task.collector_auth_token())));
        // Incorrect collector token should be rejected by leader
        assert!(!leader_task.check_collector_auth_token(Some(&incorrect_auth_token)));
        // Incorrect aggregator token should be rejected by helper
        assert!(!helper_task.check_aggregator_auth_token(Some(&incorrect_auth_token)));
    }

    /// Builds an [`AggregatorTask`] through the production [`AggregatorTask::new`] constructor
    /// (which validates `task_info`), with a caller-supplied `task_info` and otherwise fixed
    /// values.
    fn aggregator_task_with_task_info(task_info: Vec<u8>) -> Result<AggregatorTask, Error> {
        aggregator_task_with_endpoint("https://example.net/".parse().unwrap(), task_info)
    }

    /// Builds an [`AggregatorTask`] through the production [`AggregatorTask::new`] constructor,
    /// with a caller-supplied peer endpoint and `task_info` and otherwise fixed values.
    fn aggregator_task_with_endpoint(
        peer_aggregator_endpoint: DapUrl,
        task_info: Vec<u8>,
    ) -> Result<AggregatorTask, Error> {
        let time_precision = TimePrecision::from_seconds(60);
        AggregatorTask::new(
            TaskId::from([0; 32]),
            peer_aggregator_endpoint,
            "https://example.com/".parse().unwrap(),
            BatchMode::TimeInterval,
            VdafInstance::Prio3Count,
            SecretBytes::new(b"1234567812345678".to_vec()),
            None,
            None,
            10,
            time_precision,
            Duration::from_seconds(60, &time_precision),
            task_info,
            AggregatorTaskParameters::Leader {
                aggregator_auth_token: AuthenticationToken::new_dap_auth_token_from_string(
                    "YWdncmVnYXRvciB0b2tlbg",
                )
                .unwrap(),
                collector_auth_token_hash: AuthenticationTokenHash::from(
                    &AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu")
                        .unwrap(),
                ),
                collector_hpke_config: HpkeConfig::new(
                    HpkeConfigId::from(8),
                    HpkeKemId::X25519HkdfSha256,
                    HpkeKdfId::HkdfSha256,
                    HpkeAeadId::Aes128Gcm,
                    HpkePublicKey::from(b"collector hpke public key".to_vec()),
                ),
            },
        )
    }

    #[test]
    fn task_info_validation() {
        // Empty is accepted (DAP-19, draft-ietf-ppm-dap#787); oversized rejected; boundaries OK.
        aggregator_task_with_task_info(Vec::new()).unwrap();
        assert_matches!(
            aggregator_task_with_task_info(vec![b'a'; 256]),
            Err(Error::InvalidParameter(_))
        );
        aggregator_task_with_task_info(vec![b'a'; 255]).unwrap();
        aggregator_task_with_task_info(b"x".to_vec()).unwrap();
    }

    #[test]
    fn rejects_unparseable_peer_endpoint() {
        // The endpoint is ASCII (so it is a valid `DapUrl`) but not a parseable URL; construction
        // must reject it rather than persist it to surface only at request time.
        assert_matches!(
            aggregator_task_with_endpoint("not a url".try_into().unwrap(), b"task-info".to_vec()),
            Err(Error::Url(_))
        );
        aggregator_task_with_endpoint(
            "https://example.net/".try_into().unwrap(),
            b"task-info".to_vec(),
        )
        .unwrap();
    }

    #[test]
    fn aggregator_task_serde() {
        let time_precision = TimePrecision::from_seconds(60);
        assert_tokens(
            &aggregator_task_with_task_info(b"task-info".to_vec()).unwrap(),
            &[
                Token::Struct {
                    name: "SerializedAggregatorTask",
                    len: 19,
                },
                Token::Str("task_id"),
                Token::Some,
                Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Token::Str("peer_aggregator_endpoint"),
                Token::Str("https://example.net/"),
                Token::Str("own_aggregator_endpoint"),
                Token::Str("https://example.com/"),
                Token::Str("batch_mode"),
                Token::UnitVariant {
                    name: "BatchMode",
                    variant: "TimeInterval",
                },
                Token::Str("aggregation_mode"),
                Token::None,
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
                Token::Str("task_info"),
                Token::Str("dGFzay1pbmZv"),
                Token::Str("task_start"),
                Token::None,
                Token::Str("task_duration"),
                Token::None,
                Token::Str("report_expiry_age"),
                Token::None,
                Token::Str("min_batch_size"),
                Token::U64(10),
                Token::Str("time_precision"),
                Token::NewtypeStruct {
                    name: "TimePrecision",
                },
                Token::U64(60),
                Token::Str("tolerable_clock_skew"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(1),
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
                Token::Str("aggregator_auth_token_hash"),
                Token::None,
                Token::Str("collector_auth_token_hash"),
                Token::Some,
                Token::Struct {
                    name: "AuthenticationTokenHash",
                    len: 2,
                },
                Token::Str("type"),
                Token::UnitVariant {
                    name: "AuthenticationTokenHash",
                    variant: "Bearer",
                },
                Token::Str("hash"),
                Token::Str("LdjsTjGZXsaitZonqNIi2LcDLce3OLP6SeWv2eUx4rY"),
                Token::StructEnd,
                Token::StructEnd,
            ],
        );

        assert_tokens(
            &AggregatorTask::new(
                TaskId::from([255; 32]),
                "https://example.com/".parse().unwrap(),
                "https://example.net/".parse().unwrap(),
                BatchMode::LeaderSelected {
                    batch_time_window_size: None,
                },
                VdafInstance::Prio3SumVec {
                    max_measurement: 4096,
                    length: 8,
                    chunk_length: 3,
                    dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
                },
                SecretBytes::new(b"1234567812345678".to_vec()),
                Some(
                    Interval::new(
                        Time::from_seconds_since_epoch(1000, &time_precision),
                        Duration::from_time_precision_units(17),
                    )
                    .unwrap(),
                ),
                Some(Duration::from_seconds(1800, &time_precision)),
                10,
                time_precision,
                Duration::from_seconds(60, &time_precision),
                b"task-info".to_vec(),
                AggregatorTaskParameters::Helper {
                    aggregator_auth_token_hash: AuthenticationTokenHash::from(
                        &AuthenticationToken::new_bearer_token_from_string(
                            "YWdncmVnYXRvciB0b2tlbg",
                        )
                        .unwrap(),
                    ),
                    collector_hpke_config: HpkeConfig::new(
                        HpkeConfigId::from(8),
                        HpkeKemId::X25519HkdfSha256,
                        HpkeKdfId::HkdfSha256,
                        HpkeAeadId::Aes128Gcm,
                        HpkePublicKey::from(b"collector hpke public key".to_vec()),
                    ),
                    aggregation_mode: AggregationMode::Synchronous,
                },
            )
            .unwrap(),
            &[
                Token::Struct {
                    name: "SerializedAggregatorTask",
                    len: 19,
                },
                Token::Str("task_id"),
                Token::Some,
                Token::Str("__________________________________________8"),
                Token::Str("peer_aggregator_endpoint"),
                Token::Str("https://example.com/"),
                Token::Str("own_aggregator_endpoint"),
                Token::Str("https://example.net/"),
                Token::Str("batch_mode"),
                Token::StructVariant {
                    name: "BatchMode",
                    variant: "LeaderSelected",
                    len: 1,
                },
                Token::Str("batch_time_window_size"),
                Token::None,
                Token::StructVariantEnd,
                Token::Str("aggregation_mode"),
                Token::Some,
                Token::UnitVariant {
                    name: "AggregationMode",
                    variant: "Synchronous",
                },
                Token::Str("vdaf"),
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3SumVec",
                    len: 4,
                },
                Token::Str("max_measurement"),
                Token::U64(4096),
                Token::Str("length"),
                Token::U64(8),
                Token::Str("chunk_length"),
                Token::U64(3),
                Token::Str("dp_strategy"),
                Token::Struct {
                    name: "Prio3SumVec",
                    len: 1,
                },
                Token::Str("dp_strategy"),
                Token::Str("NoDifferentialPrivacy"),
                Token::StructEnd,
                Token::StructVariantEnd,
                Token::Str("role"),
                Token::UnitVariant {
                    name: "Role",
                    variant: "Helper",
                },
                Token::Str("vdaf_verify_key"),
                Token::Some,
                Token::Str("MTIzNDU2NzgxMjM0NTY3OA"),
                Token::Str("task_info"),
                Token::Str("dGFzay1pbmZv"),
                Token::Str("task_start"),
                Token::Some,
                Token::NewtypeStruct { name: "Time" },
                Token::U64(16),
                Token::Str("task_duration"),
                Token::Some,
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(17),
                Token::Str("report_expiry_age"),
                Token::Some,
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(30),
                Token::Str("min_batch_size"),
                Token::U64(10),
                Token::Str("time_precision"),
                Token::NewtypeStruct {
                    name: "TimePrecision",
                },
                Token::U64(60),
                Token::Str("tolerable_clock_skew"),
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(1),
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
                Token::None,
                Token::Str("aggregator_auth_token_hash"),
                Token::Some,
                Token::Struct {
                    name: "AuthenticationTokenHash",
                    len: 2,
                },
                Token::Str("type"),
                Token::UnitVariant {
                    name: "AuthenticationTokenHash",
                    variant: "Bearer",
                },
                Token::Str("hash"),
                Token::Str("MJOoBO_ysLEuG_lv2C37eEOf1Ngetsr-Ers0ZYj4vdQ"),
                Token::StructEnd,
                Token::Str("collector_auth_token_hash"),
                Token::None,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn batch_mode_serde() {
        assert_tokens(
            &BatchMode::TimeInterval,
            &[Token::UnitVariant {
                name: "BatchMode",
                variant: "TimeInterval",
            }],
        );
        assert_tokens(
            &BatchMode::LeaderSelected {
                batch_time_window_size: None,
            },
            &[
                Token::StructVariant {
                    name: "BatchMode",
                    variant: "LeaderSelected",
                    len: 1,
                },
                Token::Str("batch_time_window_size"),
                Token::None,
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &BatchMode::LeaderSelected {
                batch_time_window_size: Some(Duration::from_chrono(
                    TimeDelta::hours(1),
                    &TimePrecision::from_seconds(1),
                )),
            },
            &[
                Token::StructVariant {
                    name: "BatchMode",
                    variant: "LeaderSelected",
                    len: 1,
                },
                Token::Str("batch_time_window_size"),
                Token::Some,
                Token::NewtypeStruct { name: "Duration" },
                Token::U64(3600),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &BatchMode::LeaderSelected {
                batch_time_window_size: None,
            },
            &[
                Token::StructVariant {
                    name: "BatchMode",
                    variant: "LeaderSelected",
                    len: 1,
                },
                Token::Str("batch_time_window_size"),
                Token::None,
                Token::StructVariantEnd,
            ],
        );

        // Backwards compatibility cases:
        assert_de_tokens(
            &BatchMode::LeaderSelected {
                batch_time_window_size: None,
            },
            &[
                Token::StructVariant {
                    name: "BatchMode",
                    variant: "LeaderSelected",
                    len: 1,
                },
                Token::StructVariantEnd,
            ],
        );
        assert_matches!(
            serde_json::from_value(json!({ "LeaderSelected": {} })),
            Ok(BatchMode::LeaderSelected {
                batch_time_window_size: None,
            })
        );
        assert_matches!(
            yaml_serde::from_str("!LeaderSelected {}"),
            Ok(BatchMode::LeaderSelected {
                batch_time_window_size: None,
            })
        );
        assert_matches!(
            yaml_serde::from_str(
                "---
!LeaderSelected
  batch_time_window_size: 3600"
            ),
            Ok(BatchMode::LeaderSelected {
                batch_time_window_size: Some(duration),
            }) => {
                assert_eq!(
                    duration,
                    Duration::from_seconds(3600, &TimePrecision::from_seconds(1))
                );
            }
        );
    }
}
