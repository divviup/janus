//! This module contains models used by the datastore that are not DAP messages.

use crate::{datastore::Error, task};
use base64::{display::Base64Display, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::NaiveDateTime;
use derivative::Derivative;
use janus_core::{
    hpke::HpkeKeypair,
    report_id::ReportIdChecksumExt,
    task::{AuthenticationToken, VdafInstance},
    time::{DurationExt, IntervalExt, TimeExt},
};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    AggregationJobId, BatchId, CollectionJobId, Duration, HpkeCiphertext, Interval, ReportId,
    ReportIdChecksum, ReportMetadata, ReportShareError, Role, TaskId, Time,
};
use postgres_protocol::types::{
    range_from_sql, range_to_sql, timestamp_from_sql, timestamp_to_sql, Range, RangeBound,
};
use postgres_types::{accepts, to_sql_checked, FromSql, ToSql};
use prio::{
    codec::Encode,
    vdaf::{self, Aggregatable},
};
use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    ops::RangeInclusive,
};

// We have to manually implement [Partial]Eq for a number of types because the derived
// implementations don't play nice with generic fields, even if those fields are constrained to
// themselves implement [Partial]Eq.

/// AuthenticationTokenType represents the type of an authentication token. It corresponds to enum
/// `AUTH_TOKEN_TYPE` in the schema.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "auth_token_type")]
pub enum AuthenticationTokenType {
    #[postgres(name = "DAP_AUTH")]
    DapAuthToken,
    #[postgres(name = "BEARER")]
    AuthorizationBearerToken,
}

impl AuthenticationTokenType {
    pub fn as_authentication(&self, token_bytes: &[u8]) -> Result<AuthenticationToken, Error> {
        match self {
            Self::DapAuthToken => AuthenticationToken::new_dap_auth_token_from_bytes(token_bytes),
            Self::AuthorizationBearerToken => {
                AuthenticationToken::new_bearer_token_from_bytes(token_bytes)
            }
        }
        .map_err(|e| Error::DbState(format!("invalid DAP auth token in database: {e:?}")))
    }
}

impl From<&AuthenticationToken> for AuthenticationTokenType {
    fn from(value: &AuthenticationToken) -> Self {
        match value {
            AuthenticationToken::DapAuth(_) => Self::DapAuthToken,
            AuthenticationToken::Bearer(_) => Self::AuthorizationBearerToken,
            _ => unreachable!(),
        }
    }
}

/// Represents a report as it is stored in the leader's database, corresponding to a row in
/// `client_reports`, where `leader_input_share` and `helper_encrypted_input_share` are required
/// to be populated.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct LeaderStoredReport<const SEED_SIZE: usize, A>
where
    A: vdaf::Aggregator<SEED_SIZE>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    task_id: TaskId,
    metadata: ReportMetadata,
    #[derivative(Debug = "ignore")]
    public_share: A::PublicShare,
    #[derivative(Debug = "ignore")]
    leader_input_share: A::InputShare,
    #[derivative(Debug = "ignore")]
    helper_encrypted_input_share: HpkeCiphertext,
}

impl<const SEED_SIZE: usize, A> LeaderStoredReport<SEED_SIZE, A>
where
    A: vdaf::Aggregator<SEED_SIZE>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    pub fn new(
        task_id: TaskId,
        metadata: ReportMetadata,
        public_share: A::PublicShare,
        leader_input_share: A::InputShare,
        helper_encrypted_input_share: HpkeCiphertext,
    ) -> Self {
        Self {
            task_id,
            metadata,
            public_share,
            leader_input_share,
            helper_encrypted_input_share,
        }
    }

    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub fn metadata(&self) -> &ReportMetadata {
        &self.metadata
    }

    pub fn public_share(&self) -> &A::PublicShare {
        &self.public_share
    }

    pub fn leader_input_share(&self) -> &A::InputShare {
        &self.leader_input_share
    }

    pub fn helper_encrypted_input_share(&self) -> &HpkeCiphertext {
        &self.helper_encrypted_input_share
    }
}

impl<const SEED_SIZE: usize, A> PartialEq for LeaderStoredReport<SEED_SIZE, A>
where
    A: vdaf::Aggregator<SEED_SIZE>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::InputShare: PartialEq,
    A::PublicShare: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.metadata == other.metadata
            && self.public_share == other.public_share
            && self.leader_input_share == other.leader_input_share
            && self.helper_encrypted_input_share == other.helper_encrypted_input_share
    }
}

impl<const SEED_SIZE: usize, A> Eq for LeaderStoredReport<SEED_SIZE, A>
where
    A: vdaf::Aggregator<SEED_SIZE>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::InputShare: Eq,
    A::PublicShare: PartialEq,
{
}

#[cfg(feature = "test-util")]
impl LeaderStoredReport<0, janus_core::test_util::dummy_vdaf::Vdaf> {
    pub fn new_dummy(task_id: TaskId, when: Time) -> Self {
        use janus_messages::HpkeConfigId;
        use rand::random;

        Self::new(
            task_id,
            ReportMetadata::new(random(), when, Vec::new()),
            (),
            janus_core::test_util::dummy_vdaf::InputShare::default(),
            HpkeCiphertext::new(
                HpkeConfigId::from(13),
                Vec::from("encapsulated_context_0"),
                Vec::from("payload_0"),
            ),
        )
    }
}

/// AggregatorRole corresponds to the `AGGREGATOR_ROLE` enum in the schema.
#[derive(Clone, Debug, ToSql, FromSql)]
#[postgres(name = "aggregator_role")]
pub enum AggregatorRole {
    #[postgres(name = "LEADER")]
    Leader,
    #[postgres(name = "HELPER")]
    Helper,
}

impl AggregatorRole {
    /// If the provided [`Role`] is an aggregator, returns the corresponding
    /// [`AggregatorRole`], or `None` otherwise.
    pub fn from_role(role: Role) -> Result<Self, Error> {
        match role {
            Role::Leader => Ok(Self::Leader),
            Role::Helper => Ok(Self::Helper),
            _ => Err(Error::Task(task::Error::InvalidParameter(
                "role is not an aggregator",
            ))),
        }
    }

    /// Returns the [`Role`] corresponding to this value.
    pub fn as_role(&self) -> Role {
        match self {
            Self::Leader => Role::Leader,
            Self::Helper => Role::Helper,
        }
    }
}

/// AggregationJob represents an aggregation job from the DAP specification.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct AggregationJob<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// The ID of the task this aggregation job belongs to.
    task_id: TaskId,
    /// The ID of this aggregation job.
    aggregation_job_id: AggregationJobId,
    /// The aggregation parameter this job is run with.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: A::AggregationParam,
    /// The partial identifier for the batch this aggregation job contributes to (fixed size
    /// tasks only; for time interval tasks, aggregation jobs may span multiple batches).
    batch_id: Q::PartialBatchIdentifier,
    /// The minimal interval of time spanned by the reports included in this aggregation job.
    client_timestamp_interval: Interval,
    /// The overall state of this aggregation job.
    state: AggregationJobState,
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
    AggregationJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Creates a new [`AggregationJob`].
    pub fn new(
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        aggregation_parameter: A::AggregationParam,
        batch_id: Q::PartialBatchIdentifier,
        client_timestamp_interval: Interval,
        state: AggregationJobState,
    ) -> Self {
        Self {
            task_id,
            aggregation_job_id,
            aggregation_parameter,
            batch_id,
            client_timestamp_interval,
            state,
        }
    }

    /// Returns the task ID associated with this aggregation job.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Returns the aggregation job ID associated with this aggregation job.
    pub fn id(&self) -> &AggregationJobId {
        &self.aggregation_job_id
    }

    /// Returns the aggregation parameter associated with this aggregation job.
    pub fn aggregation_parameter(&self) -> &A::AggregationParam {
        &self.aggregation_parameter
    }

    /// Gets the partial batch identifier associated with this aggregation job.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call [`Self::batch_id`].
    pub fn partial_batch_identifier(&self) -> &Q::PartialBatchIdentifier {
        &self.batch_id
    }

    /// Returns the minimal interval containing all of the client timestamps associated with
    /// this aggregation job.
    pub fn client_timestamp_interval(&self) -> &Interval {
        &self.client_timestamp_interval
    }

    /// Returns the state of the aggregation job.
    pub fn state(&self) -> &AggregationJobState {
        &self.state
    }

    /// Returns a new [`AggregationJob`] corresponding to this aggregation job updated to have
    /// the given state.
    pub fn with_state(self, state: AggregationJobState) -> Self {
        AggregationJob { state, ..self }
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> AggregationJob<SEED_SIZE, FixedSize, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Gets the batch ID associated with this aggregation job.
    pub fn batch_id(&self) -> &BatchId {
        self.partial_batch_identifier()
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for AggregationJob<SEED_SIZE, Q, A>
where
    A::AggregationParam: PartialEq,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.aggregation_job_id == other.aggregation_job_id
            && self.aggregation_parameter == other.aggregation_parameter
            && self.batch_id == other.batch_id
            && self.client_timestamp_interval == other.client_timestamp_interval
            && self.state == other.state
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> Eq
    for AggregationJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: Eq,
{
}

/// AggregationJobState represents the state of an aggregation job. It corresponds to the
/// AGGREGATION_JOB_STATE enum in the schema.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "aggregation_job_state")]
pub enum AggregationJobState {
    #[postgres(name = "IN_PROGRESS")]
    InProgress,
    #[postgres(name = "FINISHED")]
    Finished,
    #[postgres(name = "ABANDONED")]
    Abandoned,
}

/// LeaseToken represents an opaque value used to determine the identity of a lease.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct LeaseToken([u8; Self::LEN]);

impl LeaseToken {
    /// The length of a lease token in bytes.
    pub const LEN: usize = 16;
}

impl Debug for LeaseToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LeaseToken({})",
            Base64Display::new(&self.0, &URL_SAFE_NO_PAD)
        )
    }
}

impl Display for LeaseToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

impl<'a> TryFrom<&'a [u8]> for LeaseToken {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            "byte slice has incorrect length for LeaseToken"
        })?))
    }
}

impl AsRef<[u8; Self::LEN]> for LeaseToken {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Distribution<LeaseToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> LeaseToken {
        LeaseToken(rng.gen())
    }
}

/// Lease represents a time-constrained lease for exclusive access to some entity in Janus. It
/// has an expiry after which it is no longer valid; another process can take a lease on the
/// same entity after the expiration time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease<T> {
    leased: T,
    lease_expiry_time: NaiveDateTime,
    lease_token: LeaseToken,
    lease_attempts: usize,
}

impl<T> Lease<T> {
    /// Creates a new [`Lease`].
    pub fn new(
        leased: T,
        lease_expiry_time: NaiveDateTime,
        lease_token: LeaseToken,
        lease_attempts: usize,
    ) -> Self {
        Self {
            leased,
            lease_expiry_time,
            lease_token,
            lease_attempts,
        }
    }

    /// Create a new artificial lease with a random lease token, acquired for the first time;
    /// intended for use in unit tests.
    #[cfg(feature = "test-util")]
    pub fn new_dummy(leased: T, lease_expiry_time: NaiveDateTime) -> Self {
        use rand::random;
        Self {
            leased,
            lease_expiry_time,
            lease_token: random(),
            lease_attempts: 1,
        }
    }

    /// Returns a reference to the leased entity associated with this lease.
    pub fn leased(&self) -> &T {
        &self.leased
    }

    /// Returns the lease expiry time associated with this lease.
    pub fn lease_expiry_time(&self) -> &NaiveDateTime {
        &self.lease_expiry_time
    }

    /// Returns the lease token associated with this lease.
    pub fn lease_token(&self) -> &LeaseToken {
        &self.lease_token
    }

    /// Returns the number of lease acquiries since the last successful release.
    pub fn lease_attempts(&self) -> usize {
        self.lease_attempts
    }
}

/// AcquiredAggregationJob represents an incomplete aggregation job whose lease has been
/// acquired.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AcquiredAggregationJob {
    task_id: TaskId,
    aggregation_job_id: AggregationJobId,
    query_type: task::QueryType,
    vdaf: VdafInstance,
}

impl AcquiredAggregationJob {
    /// Creates a new [`AcquiredAggregationJob`].
    pub fn new(
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        query_type: task::QueryType,
        vdaf: VdafInstance,
    ) -> Self {
        Self {
            task_id,
            aggregation_job_id,
            query_type,
            vdaf,
        }
    }

    /// Returns the task ID associated with this acquired aggregation job.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Returns the aggregation job ID associated with this acquired aggregation job.
    pub fn aggregation_job_id(&self) -> &AggregationJobId {
        &self.aggregation_job_id
    }

    /// Returns the query type associated with this acquired aggregation job.
    pub fn query_type(&self) -> &task::QueryType {
        &self.query_type
    }

    /// Returns the VDAF associated with this acquired aggregation job.
    pub fn vdaf(&self) -> &VdafInstance {
        &self.vdaf
    }
}

/// AcquiredCollectionJob represents an incomplete collection job whose lease has been acquired.
#[derive(Clone, Debug, PartialOrd, Ord, Eq, PartialEq)]
pub struct AcquiredCollectionJob {
    task_id: TaskId,
    collection_job_id: CollectionJobId,
    query_type: task::QueryType,
    vdaf: VdafInstance,
}

impl AcquiredCollectionJob {
    /// Creates a new [`AcquiredCollectionJob`].
    pub fn new(
        task_id: TaskId,
        collection_job_id: CollectionJobId,
        query_type: task::QueryType,
        vdaf: VdafInstance,
    ) -> Self {
        Self {
            task_id,
            collection_job_id,
            query_type,
            vdaf,
        }
    }

    /// Returns the task ID associated with this acquired collection job.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Returns the collection job ID associated with this acquired collection job.
    pub fn collection_job_id(&self) -> &CollectionJobId {
        &self.collection_job_id
    }

    /// Returns the query type associated with this acquired collection job.
    pub fn query_type(&self) -> &task::QueryType {
        &self.query_type
    }

    /// Returns the VDAF associated with this acquired collection job.
    pub fn vdaf(&self) -> &VdafInstance {
        &self.vdaf
    }
}

/// ReportAggregation represents a the state of a single client report's ongoing aggregation.
#[derive(Clone, Debug)]
pub struct ReportAggregation<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    task_id: TaskId,
    aggregation_job_id: AggregationJobId,
    report_id: ReportId,
    time: Time,
    ord: u64,
    state: ReportAggregationState<SEED_SIZE, A>,
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> ReportAggregation<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Creates a new [`ReportAggregation`].
    pub fn new(
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        report_id: ReportId,
        time: Time,
        ord: u64,
        state: ReportAggregationState<SEED_SIZE, A>,
    ) -> Self {
        Self {
            task_id,
            aggregation_job_id,
            report_id,
            time,
            ord,
            state,
        }
    }

    /// Returns the task ID associated with this report aggregation.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Returns the aggregation job ID associated with this report aggregation.
    pub fn aggregation_job_id(&self) -> &AggregationJobId {
        &self.aggregation_job_id
    }

    /// Returns the report ID associated with this report aggregation.
    pub fn report_id(&self) -> &ReportId {
        &self.report_id
    }

    /// Returns the client timestamp associated with this report aggregation.
    pub fn time(&self) -> &Time {
        &self.time
    }

    /// Returns the order of this report aggregation in its aggregation job.
    pub fn ord(&self) -> u64 {
        self.ord
    }

    /// Returns the state of the report aggregation.
    pub fn state(&self) -> &ReportAggregationState<SEED_SIZE, A> {
        &self.state
    }

    /// Returns a new [`ReportAggregation`] corresponding to this report aggregation updated to
    /// have the given state.
    pub fn with_state(self, state: ReportAggregationState<SEED_SIZE, A>) -> Self {
        Self { state, ..self }
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for ReportAggregation<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::PrepareState: PartialEq,
    A::PrepareMessage: PartialEq,
    A::PrepareShare: PartialEq,
    A::OutputShare: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.aggregation_job_id == other.aggregation_job_id
            && self.report_id == other.report_id
            && self.time == other.time
            && self.ord == other.ord
            && self.state == other.state
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> Eq for ReportAggregation<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::PrepareState: Eq,
    A::PrepareMessage: Eq,
    A::PrepareShare: Eq,
    A::OutputShare: Eq,
{
}

/// ReportAggregationState represents the state of a single report aggregation. It corresponds
/// to the REPORT_AGGREGATION_STATE enum in the schema, along with the state-specific data.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub enum ReportAggregationState<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    Start,
    Waiting(
        #[derivative(Debug = "ignore")] A::PrepareState,
        #[derivative(Debug = "ignore")] Option<A::PrepareMessage>,
    ),
    Finished,
    Failed(ReportShareError),
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> ReportAggregationState<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    pub fn state_code(&self) -> ReportAggregationStateCode {
        match self {
            ReportAggregationState::Start => ReportAggregationStateCode::Start,
            ReportAggregationState::Waiting(_, _) => ReportAggregationStateCode::Waiting,
            ReportAggregationState::Finished => ReportAggregationStateCode::Finished,
            ReportAggregationState::Failed(_) => ReportAggregationStateCode::Failed,
        }
    }

    /// Returns the encoded values for the various messages which might be included in a
    /// ReportAggregationState. The order of returned values is preparation state, preparation
    /// message, output share, transition error.
    pub(super) fn encoded_values_from_state(&self) -> EncodedReportAggregationStateValues
    where
        A::PrepareState: Encode,
    {
        match self {
            ReportAggregationState::Start => EncodedReportAggregationStateValues::default(),
            ReportAggregationState::Waiting(prep_state, prep_msg) => {
                EncodedReportAggregationStateValues {
                    prep_state: Some(prep_state.get_encoded()),
                    prep_msg: prep_msg.as_ref().map(Encode::get_encoded),
                    ..Default::default()
                }
            }
            ReportAggregationState::Finished => EncodedReportAggregationStateValues::default(),
            ReportAggregationState::Failed(report_share_err) => {
                EncodedReportAggregationStateValues {
                    report_share_err: Some(*report_share_err as i16),
                    ..Default::default()
                }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct EncodedReportAggregationStateValues {
    pub(super) prep_state: Option<Vec<u8>>,
    pub(super) prep_msg: Option<Vec<u8>>,
    pub(super) report_share_err: Option<i16>,
}

// The private ReportAggregationStateCode exists alongside the public ReportAggregationState
// because there is no apparent way to denote a Postgres enum literal without deriving
// FromSql/ToSql on a Rust enum type, but it is not possible to derive FromSql/ToSql on a
// non-C-style enum.
#[derive(Debug, FromSql, ToSql)]
#[postgres(name = "report_aggregation_state")]
pub enum ReportAggregationStateCode {
    #[postgres(name = "START")]
    Start,
    #[postgres(name = "WAITING")]
    Waiting,
    #[postgres(name = "FINISHED")]
    Finished,
    #[postgres(name = "FAILED")]
    Failed,
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for ReportAggregationState<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::PrepareState: PartialEq,
    A::PrepareMessage: PartialEq,
    A::PrepareShare: PartialEq,
    A::OutputShare: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Waiting(lhs_prep_state, lhs_prep_msg),
                Self::Waiting(rhs_prep_state, rhs_prep_msg),
            ) => lhs_prep_state == rhs_prep_state && lhs_prep_msg == rhs_prep_msg,
            (Self::Failed(lhs_report_share_err), Self::Failed(rhs_report_share_err)) => {
                lhs_report_share_err == rhs_report_share_err
            }
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> Eq
    for ReportAggregationState<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::PrepareState: Eq,
    A::PrepareMessage: Eq,
    A::PrepareShare: Eq,
    A::OutputShare: Eq,
{
}

/// BatchAggregation corresponds to a row in the `batch_aggregations` table and represents the
/// possibly-ongoing aggregation of the set of input shares that fall within the batch
/// identified by `batch_identifier`. This is the finest-grained possible aggregate share we can
/// emit for this task. The aggregate share constructed to service a collect or aggregate share
/// request consists of one or more `BatchAggregation`s merged together.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct BatchAggregation<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// The task ID for this aggregation result.
    task_id: TaskId,
    /// The identifier of the batch being aggregated over.
    batch_identifier: Q::BatchIdentifier,
    /// The VDAF aggregation parameter used to prepare and accumulate input shares.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: A::AggregationParam,
    /// The index of this batch aggregation among all batch aggregations for
    /// this (task_id, batch_identifier, aggregation_parameter).
    ord: u64,
    /// The current state of the batch aggregation.
    state: BatchAggregationState,
    /// The aggregate over all the input shares that have been prepared so far by this
    /// aggregator. Will only be None if there are no reports.
    #[derivative(Debug = "ignore")]
    aggregate_share: Option<A::AggregateShare>,
    /// The number of reports currently included in this aggregate sahre.
    report_count: u64,
    /// The minimal interval of time spanned by the reports included in this batch aggregation,
    /// which may be smaller than the batch interval (for time interval tasks).
    client_timestamp_interval: Interval,
    /// Checksum over the aggregated report shares, as described in §4.4.4.3.
    #[derivative(Debug = "ignore")]
    checksum: ReportIdChecksum,
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
    BatchAggregation<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Creates a new [`BatchAggregation`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_parameter: A::AggregationParam,
        ord: u64,
        state: BatchAggregationState,
        aggregate_share: Option<A::AggregateShare>,
        report_count: u64,
        client_timestamp_interval: Interval,
        checksum: ReportIdChecksum,
    ) -> Self {
        Self {
            task_id,
            batch_identifier,
            aggregation_parameter,
            ord,
            state,
            aggregate_share,
            report_count,
            client_timestamp_interval,
            checksum,
        }
    }

    /// Returns the task ID associated with this batch aggregation.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the batch identifier included in this batch aggregation.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::batch_interval`] or
    /// [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
        &self.batch_identifier
    }

    /// Returns the aggregation parameter associated with this batch aggregation.
    pub fn aggregation_parameter(&self) -> &A::AggregationParam {
        &self.aggregation_parameter
    }

    /// Returns the index of this batch aggregations among all batch aggregations for this
    /// (task_id, batch_identifier, aggregation_parameter).
    pub fn ord(&self) -> u64 {
        self.ord
    }

    /// Returns the current state associated with this batch aggregation.
    pub fn state(&self) -> &BatchAggregationState {
        &self.state
    }

    // Returns a [`BatchAggregation`] identical to this one, with the given batch aggregation
    // state.
    pub fn with_state(self, state: BatchAggregationState) -> Self {
        Self { state, ..self }
    }

    /// Returns the aggregate share associated with this batch aggregation.
    pub fn aggregate_share(&self) -> Option<&A::AggregateShare> {
        self.aggregate_share.as_ref()
    }

    /// Returns the report count associated with this batch aggregation.
    pub fn report_count(&self) -> u64 {
        self.report_count
    }

    /// Returns the minimal interval of time spanned by the reports included in this batch
    /// aggregation, which may be smaller than the batch interval (for time interval tasks).
    pub fn client_timestamp_interval(&self) -> &Interval {
        &self.client_timestamp_interval
    }

    /// Returns the checksum associated with this batch aggregation.
    pub fn checksum(&self) -> &ReportIdChecksum {
        &self.checksum
    }

    /// Returns a new [`BatchAggregation`] corresponding to the current batch aggregation merged
    /// with the given batch aggregation. Only uncollected batch aggregations may be merged.
    pub fn merged_with(self, other: &Self) -> Result<Self, Error> {
        if self.state() == &BatchAggregationState::Collected
            || other.state() == &BatchAggregationState::Collected
        {
            return Err(Error::AlreadyCollected);
        }

        let merged_aggregate_share = match (self.aggregate_share, other.aggregate_share()) {
            (Some(mut my_agg), Some(other_agg)) => Some({
                my_agg
                    .merge(other_agg)
                    .map_err(|err| Error::User(err.into()))?;
                my_agg
            }),
            (Some(my_agg), None) => Some(my_agg),
            (None, Some(other_agg)) => Some(other_agg.clone()),
            (None, None) => None,
        };

        Ok(Self {
            aggregate_share: merged_aggregate_share,
            report_count: self.report_count + other.report_count(),
            client_timestamp_interval: self
                .client_timestamp_interval
                .merge(&other.client_timestamp_interval)
                .map_err(|err| Error::User(err.into()))?,
            checksum: self.checksum.combined_with(other.checksum()),
            ..self
        })
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
    BatchAggregation<SEED_SIZE, TimeInterval, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Gets the batch interval associated with this batch aggregation.
    pub fn batch_interval(&self) -> &Interval {
        self.batch_identifier()
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
    BatchAggregation<SEED_SIZE, FixedSize, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Gets the batch ID associated with this batch aggregation.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for BatchAggregation<SEED_SIZE, Q, A>
where
    A::AggregationParam: PartialEq,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregateShare: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.batch_identifier == other.batch_identifier
            && self.aggregation_parameter == other.aggregation_parameter
            && self.ord == other.ord
            && self.state == other.state
            && self.aggregate_share == other.aggregate_share
            && self.report_count == other.report_count
            && self.client_timestamp_interval == other.client_timestamp_interval
            && self.checksum == other.checksum
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> Eq
    for BatchAggregation<SEED_SIZE, Q, A>
where
    A::AggregationParam: Eq,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregateShare: Eq,
{
}

/// Represents the state of a batch aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromSql, ToSql)]
#[postgres(name = "batch_aggregation_state")]
pub enum BatchAggregationState {
    /// This batch aggregation has not been collected & permits further aggregation.
    #[postgres(name = "AGGREGATING")]
    Aggregating,
    /// This batch aggregation has been collected & no longer permits aggregation.
    #[postgres(name = "COLLECTED")]
    Collected,
}

/// CollectionJob represents a row in the `collection_jobs` table, used by leaders to represent
/// running collection jobs and store the results of completed ones.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct CollectionJob<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// The task ID for this collection job.
    task_id: TaskId,
    /// The unique identifier for the collection job.
    collection_job_id: CollectionJobId,
    /// The batch interval covered by the collection job.
    batch_identifier: Q::BatchIdentifier,
    /// The VDAF aggregation parameter used to prepare and aggregate input shares.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: A::AggregationParam,
    /// The current state of the collection job.
    state: CollectionJobState<SEED_SIZE, A>,
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
    CollectionJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Creates a new [`CollectionJob`].
    pub fn new(
        task_id: TaskId,
        collection_job_id: CollectionJobId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_parameter: A::AggregationParam,
        state: CollectionJobState<SEED_SIZE, A>,
    ) -> Self {
        Self {
            task_id,
            collection_job_id,
            batch_identifier,
            aggregation_parameter,
            state,
        }
    }

    /// Returns the task ID associated with this collection job.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Returns the collection job ID associated with this collection job.
    pub fn id(&self) -> &CollectionJobId {
        &self.collection_job_id
    }

    /// Gets the batch identifier associated with this collection job.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::batch_interval`] or
    /// [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
        &self.batch_identifier
    }

    /// Returns the aggregation parameter associated with this collection job.
    pub fn aggregation_parameter(&self) -> &A::AggregationParam {
        &self.aggregation_parameter
    }

    /// Returns the state associated with this collection job.
    pub fn state(&self) -> &CollectionJobState<SEED_SIZE, A> {
        &self.state
    }

    /// Returns a new [`CollectionJob`] corresponding to this collection job updated to have the given
    /// state.
    pub fn with_state(self, state: CollectionJobState<SEED_SIZE, A>) -> Self {
        Self { state, ..self }
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
    CollectionJob<SEED_SIZE, TimeInterval, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Gets the batch interval associated with this collection job.
    pub fn batch_interval(&self) -> &Interval {
        self.batch_identifier()
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> CollectionJob<SEED_SIZE, FixedSize, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Gets the batch ID associated with this collection job.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for CollectionJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: PartialEq,
    CollectionJobState<SEED_SIZE, A>: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.collection_job_id == other.collection_job_id
            && self.batch_identifier == other.batch_identifier
            && self.aggregation_parameter == other.aggregation_parameter
            && self.state == other.state
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> Eq
    for CollectionJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: Eq,
    CollectionJobState<SEED_SIZE, A>: Eq,
{
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub enum CollectionJobState<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    Start,
    Collectable,
    Finished {
        /// The number of reports included in this collection job.
        report_count: u64,
        /// The helper's encrypted aggregate share over the input shares in the interval.
        encrypted_helper_aggregate_share: HpkeCiphertext,
        /// The leader's aggregate share over the input shares in the interval.
        #[derivative(Debug = "ignore")]
        leader_aggregate_share: A::AggregateShare,
    },
    Abandoned,
    Deleted,
}

impl<const SEED_SIZE: usize, A> CollectionJobState<SEED_SIZE, A>
where
    A: vdaf::Aggregator<SEED_SIZE>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    pub fn collection_job_state_code(&self) -> CollectionJobStateCode {
        match self {
            Self::Start => CollectionJobStateCode::Start,
            Self::Collectable => CollectionJobStateCode::Collectable,
            Self::Finished { .. } => CollectionJobStateCode::Finished,
            Self::Abandoned => CollectionJobStateCode::Abandoned,
            Self::Deleted => CollectionJobStateCode::Deleted,
        }
    }
}

impl<const SEED_SIZE: usize, A> Display for CollectionJobState<SEED_SIZE, A>
where
    A: vdaf::Aggregator<SEED_SIZE>,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Start => "start",
                Self::Collectable => "collectable",
                Self::Finished { .. } => "finished",
                Self::Abandoned => "abandoned",
                Self::Deleted => "deleted",
            }
        )
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for CollectionJobState<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregateShare: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Finished {
                    report_count: self_report_count,
                    encrypted_helper_aggregate_share: self_helper_agg_share,
                    leader_aggregate_share: self_leader_agg_share,
                },
                Self::Finished {
                    report_count: other_report_count,
                    encrypted_helper_aggregate_share: other_helper_agg_share,
                    leader_aggregate_share: other_leader_agg_share,
                },
            ) => {
                self_report_count == other_report_count
                    && self_helper_agg_share == other_helper_agg_share
                    && self_leader_agg_share == other_leader_agg_share
            }
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>> Eq for CollectionJobState<SEED_SIZE, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregateShare: Eq,
{
}

#[derive(Debug, FromSql, ToSql)]
#[postgres(name = "collection_job_state")]
pub enum CollectionJobStateCode {
    #[postgres(name = "START")]
    Start,
    #[postgres(name = "COLLECTABLE")]
    Collectable,
    #[postgres(name = "FINISHED")]
    Finished,
    #[postgres(name = "ABANDONED")]
    Abandoned,
    #[postgres(name = "DELETED")]
    Deleted,
}

/// AggregateShareJob represents a row in the `aggregate_share_jobs` table, used by helpers to
/// store the results of handling an AggregateShareReq from the leader.

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct AggregateShareJob<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// The task ID for this aggregate share.
    task_id: TaskId,
    /// The batch identifier for the batch covered by the aggregate share.
    batch_identifier: Q::BatchIdentifier,
    /// The VDAF aggregation parameter used to prepare and aggregate input shares.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: A::AggregationParam,
    /// The aggregate share over the input shares in the interval.
    #[derivative(Debug = "ignore")]
    helper_aggregate_share: A::AggregateShare,
    /// The number of reports included in the aggregate share.
    report_count: u64,
    /// Checksum over the aggregated report shares, as described in §4.4.4.3.
    #[derivative(Debug = "ignore")]
    checksum: ReportIdChecksum,
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
    AggregateShareJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Creates a new [`AggregateShareJob`].
    pub fn new(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_parameter: A::AggregationParam,
        helper_aggregate_share: A::AggregateShare,
        report_count: u64,
        checksum: ReportIdChecksum,
    ) -> Self {
        Self {
            task_id,
            batch_identifier,
            aggregation_parameter,
            helper_aggregate_share,
            report_count,
            checksum,
        }
    }

    /// Gets the task ID associated with this aggregate share job.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the batch identifier associated with this aggregate share job.
    pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
        &self.batch_identifier
    }

    /// Gets the aggregation parameter associated with this aggregate share job.
    pub fn aggregation_parameter(&self) -> &A::AggregationParam {
        &self.aggregation_parameter
    }

    /// Gets the helper aggregate share associated with this aggregate share job.
    pub fn helper_aggregate_share(&self) -> &A::AggregateShare {
        &self.helper_aggregate_share
    }

    /// Gets the report count associated with this aggregate share job.
    pub fn report_count(&self) -> u64 {
        self.report_count
    }

    /// Gets the checksum associated with this aggregate share job.
    pub fn checksum(&self) -> &ReportIdChecksum {
        &self.checksum
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
    AggregateShareJob<SEED_SIZE, TimeInterval, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Gets the batch interval associated with this aggregate share job.
    pub fn batch_interval(&self) -> &Interval {
        self.batch_identifier()
    }
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE>>
    AggregateShareJob<SEED_SIZE, FixedSize, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Gets the batch ID associated with this aggregate share job.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for AggregateShareJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: PartialEq,
    A::AggregateShare: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.batch_identifier == other.batch_identifier
            && self.aggregation_parameter == other.aggregation_parameter
            && self.helper_aggregate_share == other.helper_aggregate_share
            && self.report_count == other.report_count
            && self.checksum == other.checksum
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> Eq
    for AggregateShareJob<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: Eq,
    A::AggregateShare: Eq,
{
}

/// An outstanding batch, which is a batch which has not yet started collection. Such a batch
/// may have additional reports allocated to it. Only applies to fixed-size batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutstandingBatch {
    /// The task ID for this outstanding batch.
    task_id: TaskId,
    /// The batch ID for this outstanding batch.
    batch_id: BatchId,
    /// The range of possible sizes of this batch. The minimum size is the count of reports
    /// which have successfully completed the aggregation process, while the maximum size is the
    /// count of reports which are currently being aggregated or have successfully completed the
    /// aggregation process.
    size: RangeInclusive<usize>,
}

impl OutstandingBatch {
    /// Creates a new [`OutstandingBatch`].
    pub fn new(task_id: TaskId, batch_id: BatchId, size: RangeInclusive<usize>) -> Self {
        Self {
            task_id,
            batch_id,
            size,
        }
    }

    /// Gets the [`TaskId`] associated with this outstanding batch.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the [`BatchId`] associated with this outstanding batch.
    pub fn id(&self) -> &BatchId {
        &self.batch_id
    }

    /// Gets the range of possible sizes of this batch. The minimum size is the count of reports
    /// which have successfully completed the aggregation process, while the maximum size is the
    /// count of reports which are currently being aggregated or have successfully completed the
    /// aggregation process.
    pub fn size(&self) -> &RangeInclusive<usize> {
        &self.size
    }
}

/// Represents the state of a `Batch`.
#[derive(Copy, Clone, Debug, FromSql, ToSql, PartialEq, Eq, Hash)]
#[postgres(name = "batch_state")]
pub enum BatchState {
    /// This batch can accept the creation of additional aggregation jobs.
    #[postgres(name = "OPEN")]
    Open,
    /// This batch can accept the creation of additional aggregation jobs, but will transition
    /// to state `CLOSED` once there are no outstanding aggregation jobs remaining.
    #[postgres(name = "CLOSING")]
    Closing,
    /// This batch can no longer accept the creation of additional aggregation jobs.
    #[postgres(name = "CLOSED")]
    Closed,
}

/// Represents the state of a given batch (and aggregation parameter).

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Batch<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    task_id: TaskId,
    batch_identifier: Q::BatchIdentifier,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: A::AggregationParam,
    state: BatchState,
    outstanding_aggregation_jobs: u64,
    client_timestamp_interval: Interval,
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> Batch<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    /// Creates a new [`Batch`].
    pub fn new(
        task_id: TaskId,
        batch_identifier: Q::BatchIdentifier,
        aggregation_parameter: A::AggregationParam,
        state: BatchState,
        outstanding_aggregation_jobs: u64,
        client_timestamp_interval: Interval,
    ) -> Self {
        Self {
            task_id,
            batch_identifier,
            aggregation_parameter,
            state,
            outstanding_aggregation_jobs,
            client_timestamp_interval,
        }
    }

    /// Gets the task ID associated with this batch.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the batch identifier associated with this batch.
    pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
        &self.batch_identifier
    }

    /// Gets the aggregation parameter associated with this batch.
    pub fn aggregation_parameter(&self) -> &A::AggregationParam {
        &self.aggregation_parameter
    }

    /// Gets the state associated with this batch.
    pub fn state(&self) -> &BatchState {
        &self.state
    }

    /// Returns a new batch equivalent to the current batch, but with the given state.
    pub fn with_state(self, state: BatchState) -> Self {
        Self { state, ..self }
    }

    /// Gets the count of outstanding aggregation jobs associated with this batch.
    pub fn outstanding_aggregation_jobs(&self) -> u64 {
        self.outstanding_aggregation_jobs
    }

    /// Returns a new batch equivalent to the current batch, but with the given count of
    /// outstanding aggregation jobs.
    pub fn with_outstanding_aggregation_jobs(self, outstanding_aggregation_jobs: u64) -> Self {
        Self {
            outstanding_aggregation_jobs,
            ..self
        }
    }

    /// Gets the minimal interval of time spanned by the reports included in this batch.
    pub fn client_timestamp_interval(&self) -> &Interval {
        &self.client_timestamp_interval
    }

    /// Returns a new batch equivalent to the current batch, but with the given client timestamp
    /// interval.
    pub fn with_client_timestamp_interval(self, client_timestamp_interval: Interval) -> Self {
        Self {
            client_timestamp_interval,
            ..self
        }
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> PartialEq
    for Batch<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: PartialEq,
    Q::BatchIdentifier: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.batch_identifier == other.batch_identifier
            && self.aggregation_parameter == other.aggregation_parameter
            && self.state == other.state
            && self.outstanding_aggregation_jobs == other.outstanding_aggregation_jobs
            && self.client_timestamp_interval == other.client_timestamp_interval
    }
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> Eq
    for Batch<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: Eq,
    Q::BatchIdentifier: Eq,
{
}

impl<const SEED_SIZE: usize, Q: QueryType, A: vdaf::Aggregator<SEED_SIZE>> Hash
    for Batch<SEED_SIZE, Q, A>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.task_id.hash(state);
        self.batch_identifier.hash(state);
        self.aggregation_parameter.hash(state);
        self.state.hash(state);
        self.outstanding_aggregation_jobs.hash(state);
        self.client_timestamp_interval.hash(state);
    }
}

/// The SQL timestamp epoch, midnight UTC on 2000-01-01.
const SQL_EPOCH_TIME: Time = Time::from_seconds_since_epoch(946_684_800);

/// Wrapper around [`janus_messages::Interval`] that supports conversions to/from SQL.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SqlInterval(Interval);

impl SqlInterval {
    pub fn as_interval(&self) -> Interval {
        self.0
    }
}

impl From<Interval> for SqlInterval {
    fn from(interval: Interval) -> Self {
        Self(interval)
    }
}

impl From<&Interval> for SqlInterval {
    fn from(interval: &Interval) -> Self {
        Self::from(*interval)
    }
}

impl<'a> FromSql<'a> for SqlInterval {
    fn from_sql(
        _: &postgres_types::Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        match range_from_sql(raw)? {
            Range::Empty => Ok(SqlInterval(Interval::EMPTY)),
            Range::Nonempty(RangeBound::Inclusive(None), _)
            | Range::Nonempty(RangeBound::Exclusive(None), _)
            | Range::Nonempty(_, RangeBound::Inclusive(None))
            | Range::Nonempty(_, RangeBound::Exclusive(None)) => {
                Err("Interval cannot represent a timestamp range with a null bound".into())
            }
            Range::Nonempty(RangeBound::Unbounded, _)
            | Range::Nonempty(_, RangeBound::Unbounded) => {
                Err("Interval cannot represent an unbounded timestamp range".into())
            }
            Range::Nonempty(RangeBound::Exclusive(_), _)
            | Range::Nonempty(_, RangeBound::Inclusive(_)) => Err(Into::into(
                "Interval can only represent timestamp ranges that are closed at the start \
                     and open at the end",
            )),
            Range::Nonempty(
                RangeBound::Inclusive(Some(start_raw)),
                RangeBound::Exclusive(Some(end_raw)),
            ) => {
                // These timestamps represent the number of microseconds before (if negative) or
                // after (if positive) midnight, 1/1/2000.
                let start_timestamp = timestamp_from_sql(start_raw)?;
                let end_timestamp = timestamp_from_sql(end_raw)?;

                // Convert from SQL timestamp representation to the internal representation.
                let negative = start_timestamp < 0;
                let abs_start_us = start_timestamp.unsigned_abs();
                let abs_start_duration = Duration::from_microseconds(abs_start_us);
                let time = if negative {
                    SQL_EPOCH_TIME.sub(&abs_start_duration).map_err(|_| {
                        "Interval cannot represent timestamp ranges starting before the Unix \
                             epoch"
                    })?
                } else {
                    SQL_EPOCH_TIME
                        .add(&abs_start_duration)
                        .map_err(|_| "overflow when converting to Interval")?
                };

                if end_timestamp < start_timestamp {
                    return Err("timestamp range ends before it starts".into());
                }
                let duration_us = end_timestamp.abs_diff(start_timestamp);
                let duration = Duration::from_microseconds(duration_us);

                Ok(SqlInterval(Interval::new(time, duration)?))
            }
        }
    }

    accepts!(TS_RANGE);
}

fn time_to_sql_timestamp(time: Time) -> Result<i64, Error> {
    if time.is_after(&SQL_EPOCH_TIME) {
        let absolute_difference_us = time.difference(&SQL_EPOCH_TIME)?.as_microseconds()?;
        Ok(absolute_difference_us.try_into()?)
    } else {
        let absolute_difference_us = SQL_EPOCH_TIME.difference(&time)?.as_microseconds()?;
        Ok(-i64::try_from(absolute_difference_us)?)
    }
}

impl ToSql for SqlInterval {
    fn to_sql(
        &self,
        _: &postgres_types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        // Convert the interval start and end to SQL timestamps.
        let start_sql_usec = time_to_sql_timestamp(*self.0.start())
            .map_err(|_| "millisecond timestamp of Interval start overflowed")?;
        let end_sql_usec = time_to_sql_timestamp(self.0.end())
            .map_err(|_| "millisecond timestamp of Interval end overflowed")?;

        range_to_sql(
            |out| {
                timestamp_to_sql(start_sql_usec, out);
                Ok(postgres_protocol::types::RangeBound::Inclusive(
                    postgres_protocol::IsNull::No,
                ))
            },
            |out| {
                timestamp_to_sql(end_sql_usec, out);
                Ok(postgres_protocol::types::RangeBound::Exclusive(
                    postgres_protocol::IsNull::No,
                ))
            },
            out,
        )?;

        Ok(postgres_types::IsNull::No)
    }

    accepts!(TS_RANGE);

    to_sql_checked!();
}

/// The state of an HPKE key pair, corresponding to the HPKE_KEY_STATE enum in the schema.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, ToSql, FromSql, Serialize, Deserialize)]
#[postgres(name = "hpke_key_state")]
#[serde(rename_all = "snake_case")]
pub enum HpkeKeyState {
    /// The key should be advertised to DAP clients, and is the preferred key
    /// for new reports to be encrypted with.
    #[postgres(name = "ACTIVE")]
    Active,
    /// The key should not be advertised to DAP clients, but could be used for
    /// decrypting client reports depending on when aggregators pick up the new key.
    /// New keys should be created in this state.
    #[postgres(name = "PENDING")]
    Pending,
    /// The key is pending deletion. It should not be advertised, but could be used
    /// for decrypting client reports depending on the age of those reports or when
    /// clients have refreshed their key caches.
    #[postgres(name = "EXPIRED")]
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalHpkeKeypair {
    hpke_keypair: HpkeKeypair,
    state: HpkeKeyState,
    updated_at: Time,
}

impl GlobalHpkeKeypair {
    pub(super) fn new(hpke_keypair: HpkeKeypair, state: HpkeKeyState, updated_at: Time) -> Self {
        Self {
            hpke_keypair,
            state,
            updated_at,
        }
    }

    pub fn hpke_keypair(&self) -> &HpkeKeypair {
        &self.hpke_keypair
    }

    pub fn state(&self) -> &HpkeKeyState {
        &self.state
    }

    pub fn updated_at(&self) -> &Time {
        &self.updated_at
    }
}
