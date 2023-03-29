use http_api_problem::HttpApiProblem;
use janus_aggregator_core::{datastore, task};
use janus_messages::{
    problem_type::DapProblemType, AggregationJobId, AggregationJobRound, CollectionJobId,
    HpkeConfigId, Interval, PrepareError, ReportId, ReportIdChecksum, Role, TaskId, Time,
};
use opentelemetry::{metrics::Counter, Context, KeyValue};
use prio::{topology::ping_pong::PingPongError, vdaf::VdafError};
use std::{
    fmt::{self, Display, Formatter},
    num::TryFromIntError,
};
use tracing::info;

/// Errors returned by functions and methods in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An invalid configuration was passed.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Error decoding an incoming message.
    #[error("message decoding failed: {0}")]
    MessageDecode(#[from] prio::codec::CodecError),
    /// Error handling a message.
    #[error("invalid message: {0}")]
    Message(#[from] janus_messages::Error),
    /// Corresponds to `reportRejected`, §3.2
    #[error("task {0}: report {1} rejected: {2}")]
    ReportRejected(TaskId, ReportId, Time),
    /// Corresponds to `reportTooEarly`, §3.2. A report was rejected becuase the timestamp is too
    /// far in the future, §4.3.2.
    #[error("task {0}: report {1} too early: {2}")]
    ReportTooEarly(TaskId, ReportId, Time),
    /// Corresponds to `unrecognizedMessage`, §3.2
    #[error("task {0:?}: unrecognized message: {1}")]
    UnrecognizedMessage(Option<TaskId>, &'static str),
    /// Corresponds to `roundMismatch`
    #[error(
        "task {task_id}: unexpected round in aggregation job {aggregation_job_id} (expected \
         {expected_round}, got {got_round})"
    )]
    RoundMismatch {
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        expected_round: AggregationJobRound,
        got_round: AggregationJobRound,
    },
    /// Corresponds to `unrecognizedTask`, §3.2
    #[error("task {0}: unrecognized task")]
    UnrecognizedTask(TaskId),
    /// Corresponds to `missingTaskID`, §3.2
    #[error("no task ID in request")]
    MissingTaskId,
    /// An attempt was made to act on an unknown aggregation job.
    #[error("task {0}: unrecognized aggregation job: {1}")]
    UnrecognizedAggregationJob(TaskId, AggregationJobId),
    /// An attempt was made to act on an unknown collection job.
    #[error("unrecognized collection job: {0}")]
    UnrecognizedCollectionJob(CollectionJobId),
    /// An attempt was made to act on a known but deleted collection job.
    #[error("deleted collection job: {0}")]
    DeletedCollectionJob(CollectionJobId),
    /// Corresponds to `outdatedHpkeConfig`, §3.2
    #[error("task {0}: outdated HPKE config: {1}")]
    OutdatedHpkeConfig(TaskId, HpkeConfigId),
    /// Corresponds to `unauthorizedRequest`, §3.2
    #[error("task {0}: unauthorized request")]
    UnauthorizedRequest(TaskId),
    /// An error from the datastore.
    #[error("datastore error: {0}")]
    Datastore(datastore::Error),
    /// An error from the underlying VDAF library.
    #[error("VDAF error: {0}")]
    Vdaf(#[from] VdafError),
    /// A collect or aggregate share request was rejected because the interval failed boundary
    /// checks (§4.5.6).
    #[error("task {0}: invalid batch interval: {1}")]
    BatchInvalid(TaskId, String),
    /// The number of reports in the batch is invalid for the task's parameters.
    #[error("task {0}: invalid number of reports ({1})")]
    InvalidBatchSize(TaskId, u64),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    /// The checksum or report count in one aggregator's aggregate share does not match the other
    /// aggregator's aggregate share, suggesting different sets of reports were aggregated.
    #[error("{0}")]
    BatchMismatch(Box<BatchMismatch>),
    /// A collect or aggregate share request was rejected because the queries against a single batch
    /// exceed the task's `max_batch_query_count` (§4.5.6).
    #[error("task {0}: batch queried too many times ({1})")]
    BatchQueriedTooManyTimes(TaskId, u64),
    /// A collect or aggregate share request was rejected because the batch overlaps with a
    /// previously collected one.
    #[error("task {0}: queried batch {1} overlaps with previously collected batch(es)")]
    BatchOverlap(TaskId, Interval),
    /// HPKE failure.
    #[error("HPKE error: {0}")]
    Hpke(#[from] janus_core::hpke::Error),
    /// Error handling task parameters.
    #[error("invalid task parameters: {0}")]
    TaskParameters(#[from] task::Error),
    /// Error making an HTTP request.
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    /// HTTP server returned an error status code.
    #[error("HTTP response status {problem_details}")]
    Http {
        problem_details: Box<HttpApiProblem>,
        dap_problem_type: Option<DapProblemType>,
    },
    /// An aggregate share request was rejected.
    #[error("task {0}: {1}")]
    AggregateShareRequestRejected(TaskId, String),
    /// An empty aggregation (no report shares) was attempted.
    #[error("task {0}: empty aggregation")]
    EmptyAggregation(TaskId),
    /// An error representing a generic internal aggregation error; intended for "impossible"
    /// conditions.
    #[error("internal aggregator error: {0}")]
    Internal(String),
    /// A client attempted to mutate an immutable object.
    #[error("forbidden mutation of {resource_type} {identifier}")]
    ForbiddenMutation {
        resource_type: &'static str,
        identifier: String,
    },
    /// A catch-all error representing an issue with a request.
    #[error("request error: {0}")]
    BadRequest(String),
    /// Corresponds to taskprov invalidType (§2)
    #[error("aggregator has opted out of the indicated task: {1}")]
    InvalidTask(TaskId, OptOutReason),
}

/// Errors that cause the aggregator to opt-out of a taskprov task.
#[derive(Debug, thiserror::Error)]
pub enum OptOutReason {
    #[error("this aggregator is not peered with the given {0} aggregator")]
    NoSuchPeer(Role),
    #[error("task has expired")]
    TaskExpired,
    #[error("invalid task: {0}")]
    TaskParameters(#[from] task::Error),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    /// Catch-all error for generally invalid parameters.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

impl Error {
    /// Provides a human-readable error code identifying the error type.
    pub fn error_code(&self) -> &'static str {
        match self {
            Error::InvalidConfiguration(_) => "invalid_configuration",
            Error::MessageDecode(_) => "message_decode",
            Error::Message(_) => "message",
            Error::ReportRejected(_, _, _) => "report_rejected",
            Error::ReportTooEarly(_, _, _) => "report_too_early",
            Error::UnrecognizedMessage(_, _) => "unrecognized_message",
            Error::RoundMismatch { .. } => "round_mismatch",
            Error::UnrecognizedTask(_) => "unrecognized_task",
            Error::MissingTaskId => "missing_task_id",
            Error::UnrecognizedAggregationJob(_, _) => "unrecognized_aggregation_job",
            Error::DeletedCollectionJob(_) => "deleted_collection_job",
            Error::UnrecognizedCollectionJob(_) => "unrecognized_collection_job",
            Error::OutdatedHpkeConfig(_, _) => "outdated_hpke_config",
            Error::UnauthorizedRequest(_) => "unauthorized_request",
            Error::Datastore(_) => "datastore",
            Error::Vdaf(_) => "vdaf",
            Error::BatchInvalid(_, _) => "batch_invalid",
            Error::InvalidBatchSize(_, _) => "invalid_batch_size",
            Error::Url(_) => "url",
            Error::BatchMismatch { .. } => "batch_mismatch",
            Error::BatchQueriedTooManyTimes(_, _) => "batch_queried_too_many_times",
            Error::BatchOverlap(_, _) => "batch_overlap",
            Error::Hpke(_) => "hpke",
            Error::TaskParameters(_) => "task_parameters",
            Error::HttpClient(_) => "http_client",
            Error::Http { .. } => "http",
            Error::AggregateShareRequestRejected(_, _) => "aggregate_share_request_rejected",
            Error::EmptyAggregation(_) => "empty_aggregation",
            Error::Internal(_) => "internal",
            Error::ForbiddenMutation { .. } => "forbidden_mutation",
            Error::BadRequest(_) => "bad_request",
            Error::InvalidTask(_, _) => "invalid_task",
        }
    }
}

// This From implementation ensures that we don't end up with e.g.
// Error::Datastore(datastore::Error::User(Error::...)) by automatically unwrapping to the internal
// aggregator error if converting a datastore::Error::User that contains an Error. Other
// datastore::Error values are wrapped in Error::Datastore unchanged.
impl From<datastore::Error> for Error {
    fn from(err: datastore::Error) -> Self {
        match err {
            datastore::Error::User(err) => match err.downcast::<Error>() {
                Ok(err) => *err,
                Err(err) => Error::Datastore(datastore::Error::User(err)),
            },
            _ => Error::Datastore(err),
        }
    }
}

impl From<TryFromIntError> for Error {
    fn from(err: TryFromIntError) -> Self {
        Error::Internal(format!("couldn't convert numeric type: {err:?}"))
    }
}

/// Details of a [`Error::BatchMismatch`] error.
#[derive(Debug)]
pub struct BatchMismatch {
    pub task_id: TaskId,
    pub own_checksum: ReportIdChecksum,
    pub own_report_count: u64,
    pub peer_checksum: ReportIdChecksum,
    pub peer_report_count: u64,
}

impl Display for BatchMismatch {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "task {0}: batch misalignment (own checksum = {1:?}, own report count = {2}, peer \
             checksum = {3:?}, peer report count = {4})",
            self.task_id,
            self.own_checksum,
            self.own_report_count,
            self.peer_checksum,
            self.peer_report_count
        )
    }
}

/// Inspect the provided `ping_pong_error`, log it, increment the [`Counter`] with appropriate
/// labels, and return a suitable [`PrepareError`].
pub(crate) fn handle_ping_pong_error(
    task_id: &TaskId,
    peer_role: Role,
    report_id: &ReportId,
    ping_pong_error: PingPongError,
    aggregate_step_failure_counter: &Counter<u64>,
) -> PrepareError {
    let (error_desc, value, prepare_error) = match ping_pong_error {
        PingPongError::VdafPrepareInit(_) => (
            "Couldn't helper_initialize report share".to_string(),
            "prepare_init_failure".to_string(),
            PrepareError::VdafPrepError,
        ),
        PingPongError::VdafPreparePreprocess(_) => (
            "Couldn't compute prepare message".to_string(),
            "prepare_message_failure".to_string(),
            PrepareError::VdafPrepError,
        ),
        PingPongError::VdafPrepareStep(_) => (
            "Prepare step failed".to_string(),
            "prepare_step_failure".to_string(),
            PrepareError::VdafPrepError,
        ),
        PingPongError::CodecPrepShare(_) => (
            format!("Couldn't decode {peer_role} prepare share"),
            format!("{peer_role}_prep_share_decode_failure"),
            PrepareError::UnrecognizedMessage,
        ),
        PingPongError::CodecPrepMessage(_) => (
            format!("Couldn't decode {peer_role} prepare message"),
            format!("{peer_role}_prep_message_decode_failure"),
            PrepareError::UnrecognizedMessage,
        ),
        ref error @ PingPongError::StateMismatch(_, _) => (
            format!("{error}"),
            format!("{peer_role}_ping_pong_message_state_mismatch"),
            // TODO(timg): is this the right error if state mismatch?
            PrepareError::VdafPrepError,
        ),
        PingPongError::InternalError(desc) => (
            desc.to_string(),
            "vdaf_ping_pong_internal_error".to_string(),
            PrepareError::VdafPrepError,
        ),
    };

    info!(
        task_id = %task_id,
        report_id = %report_id,
        ?ping_pong_error,
        error_desc,
    );

    aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", value)]);

    prepare_error
}
