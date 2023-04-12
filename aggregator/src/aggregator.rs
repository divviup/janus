//! Common functionality for DAP aggregators.

use crate::aggregator::{
    accumulator::Accumulator,
    aggregate_share::compute_aggregate_share,
    query_type::{CollectableQueryType, UploadableQueryType},
    report_writer::{ReportWriteBatcher, WritableReport},
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{
    types::extra::{U15, U31, U63},
    FixedI16, FixedI32, FixedI64,
};
use http::{header::CONTENT_TYPE, Method};
use http_api_problem::HttpApiProblem;
use janus_aggregator_api::instrumented;
use janus_aggregator_core::{
    datastore::{
        self,
        models::{
            AggregateShareJob, AggregationJob, AggregationJobState, BatchAggregation,
            CollectionJob, CollectionJobState, LeaderStoredReport, PrepareMessageOrShare,
            ReportAggregation, ReportAggregationState,
        },
        Datastore, Transaction,
    },
    query_type::AccumulableQueryType,
    task::{self, Task, VerifyKey},
};
#[cfg(feature = "test-util")]
use janus_core::test_util::dummy_vdaf;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label},
    http::response_to_problem_details,
    task::{AuthenticationToken, VdafInstance, DAP_AUTH_HEADER, PRIO3_VERIFY_KEY_LENGTH},
    time::{Clock, DurationExt, IntervalExt, TimeExt},
};
use janus_messages::{
    problem_type::DapProblemType,
    query_type::{FixedSize, TimeInterval},
    AggregateShare, AggregateShareAad, AggregateShareReq, AggregationJobContinueReq,
    AggregationJobId, AggregationJobInitializeReq, AggregationJobResp, AggregationJobRound,
    BatchSelector, Collection, CollectionJobId, CollectionReq, Duration, HpkeCiphertext,
    HpkeConfigId, HpkeConfigList, InputShareAad, Interval, PartialBatchSelector,
    PlaintextInputShare, PrepareStep, PrepareStepResult, Report, ReportId, ReportIdChecksum,
    ReportShare, ReportShareError, Role, TaskId, Time,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    Context, KeyValue,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded;
#[cfg(feature = "test-util")]
use prio::vdaf::PrepareTransition;
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf::{
        self,
        prio3::{Prio3, Prio3Count, Prio3Histogram, Prio3Sum, Prio3SumVecMultithreaded},
        VdafError,
    },
};
use reqwest::Client;
use ring::digest::{digest, SHA256};
use routefinder::Captures;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    fmt::{self, Debug, Display, Formatter},
    future::Future,
    net::SocketAddr,
    num::TryFromIntError,
    panic,
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};
use tokio::{
    sync::{oneshot, Mutex},
    try_join,
};
use tracing::{debug, error, info, warn};
use trillium::{Conn, Handler, Headers, Info, Init, KnownHeaderName, Status};
use trillium_api::{api, ApiConnExt, State};
use trillium_caching_headers::CacheControlDirective;
use trillium_opentelemetry::metrics;
use trillium_router::{Router, RouterConnExt};
use trillium_tokio::Stopper;
use url::Url;

pub mod accumulator;
#[cfg(test)]
mod aggregate_init_tests;
pub mod aggregate_share;
pub mod aggregation_job_continue;
pub mod aggregation_job_creator;
pub mod aggregation_job_driver;
pub mod collection_job_driver;
#[cfg(test)]
mod collection_job_tests;
pub mod garbage_collector;
pub mod query_type;
pub mod report_writer;

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
}

impl Error {
    /// Provides a human-readable error code identifying the error type.
    fn error_code(&self) -> &'static str {
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
    task_id: TaskId,
    own_checksum: ReportIdChecksum,
    own_report_count: u64,
    peer_checksum: ReportIdChecksum,
    peer_report_count: u64,
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

pub(crate) fn aggregate_step_failure_counter(meter: &Meter) -> Counter<u64> {
    let aggregate_step_failure_counter = meter
        .u64_counter("janus_step_failures")
        .with_description(concat!(
            "Failures while stepping aggregation jobs; these failures are ",
            "related to individual client reports rather than entire aggregation jobs."
        ))
        .init();

    // Initialize counters with desired status labels. This causes Prometheus to see the first
    // non-zero value we record.
    for failure_type in [
        "missing_leader_input_share",
        "missing_helper_input_share",
        "prepare_init_failure",
        "prepare_step_failure",
        "prepare_message_failure",
        "unknown_hpke_config_id",
        "decrypt_failure",
        "input_share_decode_failure",
        "public_share_decode_failure",
        "continue_mismatch",
        "accumulate_failure",
        "finish_mismatch",
        "helper_step_failure",
        "plaintext_input_share_decode_failure",
        "duplicate_extension",
    ] {
        aggregate_step_failure_counter.add(
            &Context::current(),
            0,
            &[KeyValue::new("type", failure_type)],
        );
    }

    aggregate_step_failure_counter
}

/// Aggregator implements a DAP aggregator.
pub struct Aggregator<C: Clock> {
    /// Datastore used for durable storage.
    datastore: Arc<Datastore<C>>,
    /// Clock used to sample time.
    clock: C,
    /// Configuration used for this aggregator.
    cfg: Config,
    /// Report writer, with support for batching.
    report_writer: Arc<ReportWriteBatcher<C>>,
    /// Cache of task aggregators.
    task_aggregators: Mutex<HashMap<TaskId, Arc<TaskAggregator<C>>>>,

    // Metrics.
    /// Counter tracking the number of failed decryptions while handling the /upload endpoint.
    upload_decrypt_failure_counter: Counter<u64>,
    /// Counter tracking the number of failed message decodes while handling the /upload endpoint.
    upload_decode_failure_counter: Counter<u64>,
    /// Counters tracking the number of failures to step client reports through the aggregation
    /// process.
    aggregate_step_failure_counter: Counter<u64>,
}

/// Config represents a configuration for an Aggregator.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// Defines the maximum size of a batch of uploaded reports which will be written in a single
    /// transaction.
    pub max_upload_batch_size: usize,

    /// Defines the maximum delay before writing a batch of uploaded reports, even if it has not yet
    /// reached `max_batch_upload_size`. This is the maximum delay added to the /upload endpoint due
    /// to write-batching.
    pub max_upload_batch_write_delay: StdDuration,

    /// Defines the number of shards to break each batch aggregation into. Increasing this value
    /// will reduce the amount of database contention during helper aggregation, while increasing
    /// the cost of collection.
    pub batch_aggregation_shard_count: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_upload_batch_size: 1,
            max_upload_batch_write_delay: StdDuration::ZERO,
            batch_aggregation_shard_count: 1,
        }
    }
}

impl<C: Clock> Aggregator<C> {
    fn new(datastore: Arc<Datastore<C>>, clock: C, meter: &Meter, cfg: Config) -> Self {
        let report_writer = Arc::new(ReportWriteBatcher::new(
            Arc::clone(&datastore),
            cfg.max_upload_batch_size,
            cfg.max_upload_batch_write_delay,
        ));

        let upload_decrypt_failure_counter = meter
            .u64_counter("janus_upload_decrypt_failures")
            .with_description("Number of decryption failures in the /upload endpoint.")
            .init();
        upload_decrypt_failure_counter.add(&Context::current(), 0, &[]);

        let upload_decode_failure_counter = meter
            .u64_counter("janus_upload_decode_failures")
            .with_description("Number of message decode failures in the /upload endpoint.")
            .init();
        upload_decode_failure_counter.add(&Context::current(), 0, &[]);

        let aggregate_step_failure_counter = aggregate_step_failure_counter(meter);
        aggregate_step_failure_counter.add(&Context::current(), 0, &[]);

        Self {
            datastore,
            clock,
            cfg,
            report_writer,
            task_aggregators: Mutex::new(HashMap::new()),
            upload_decrypt_failure_counter,
            upload_decode_failure_counter,
            aggregate_step_failure_counter,
        }
    }

    async fn handle_hpke_config(
        &self,
        task_id_base64: Option<&[u8]>,
    ) -> Result<HpkeConfigList, Error> {
        // Task ID is optional in an HPKE config request, but Janus requires it.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1
        let task_id_base64 = task_id_base64.ok_or(Error::MissingTaskId)?;

        let task_id_bytes = URL_SAFE_NO_PAD
            .decode(task_id_base64)
            .map_err(|_| Error::UnrecognizedMessage(None, "task_id"))?;
        let task_id = TaskId::get_decoded(&task_id_bytes)
            .map_err(|_| Error::UnrecognizedMessage(None, "task_id"))?;
        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        Ok(task_aggregator.handle_hpke_config())
    }

    async fn handle_upload(&self, task_id: &TaskId, report_bytes: &[u8]) -> Result<(), Arc<Error>> {
        let report = Report::get_decoded(report_bytes).map_err(|err| Arc::new(Error::from(err)))?;

        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Arc::new(Error::UnrecognizedTask(*task_id)));
        }
        task_aggregator
            .handle_upload(
                &self.clock,
                &self.upload_decrypt_failure_counter,
                &self.upload_decode_failure_counter,
                report,
            )
            .await
    }

    async fn handle_aggregate_init(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
    ) -> Result<AggregationJobResp, Error> {
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !auth_token
            .map(|t| task_aggregator.task.check_aggregator_auth_token(&t))
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_aggregate_init(
                &self.datastore,
                &self.aggregate_step_failure_counter,
                self.cfg.batch_aggregation_shard_count,
                aggregation_job_id,
                req_bytes,
            )
            .await
    }

    async fn handle_aggregate_continue(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
    ) -> Result<AggregationJobResp, Error> {
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !auth_token
            .map(|t| task_aggregator.task.check_aggregator_auth_token(&t))
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        let req = AggregationJobContinueReq::get_decoded(req_bytes)?;
        // unwrap safety: SHA-256 computed by ring should always be 32 bytes
        let request_hash = digest(&SHA256, req_bytes).as_ref().try_into().unwrap();

        task_aggregator
            .handle_aggregate_continue(
                &self.datastore,
                &self.aggregate_step_failure_counter,
                self.cfg.batch_aggregation_shard_count,
                aggregation_job_id,
                req,
                request_hash,
            )
            .await
    }

    /// Handle a collection job creation request. Only supported by the leader. `req_bytes` is an
    /// encoded [`CollectionReq`].
    async fn handle_create_collection_job(
        &self,
        task_id: &TaskId,
        collection_job_id: &CollectionJobId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
    ) -> Result<(), Error> {
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !auth_token
            .map(|t| task_aggregator.task.check_collector_auth_token(&t))
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_create_collection_job(&self.datastore, collection_job_id, req_bytes)
            .await
    }

    /// Handle a GET request for a collection job. `collection_job_id` is the unique identifier for the
    /// collection job parsed out of the request URI. Returns an encoded [`Collection`] if the collect
    /// job has been run to completion, `None` if the collection job has not yet run, or an error
    /// otherwise.
    async fn handle_get_collection_job(
        &self,
        task_id: &TaskId,
        collection_job_id: &CollectionJobId,
        auth_token: Option<AuthenticationToken>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !auth_token
            .map(|t| task_aggregator.task.check_collector_auth_token(&t))
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_get_collection_job(&self.datastore, collection_job_id)
            .await
    }

    /// Handle a DELETE request for a collection job.
    async fn handle_delete_collection_job(
        &self,
        task_id: &TaskId,
        collection_job_id: &CollectionJobId,
        auth_token: Option<AuthenticationToken>,
    ) -> Result<(), Error> {
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !auth_token
            .map(|t| task_aggregator.task.check_collector_auth_token(&t))
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_delete_collection_job(&self.datastore, collection_job_id)
            .await?;

        Ok(())
    }

    /// Handle an aggregate share request. Only supported by the helper. `req_bytes` is an encoded
    /// [`AggregateShareReq`]. Returns an [`AggregateShare`].
    async fn handle_aggregate_share(
        &self,
        task_id: &TaskId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
    ) -> Result<AggregateShare, Error> {
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !auth_token
            .map(|t| task_aggregator.task.check_aggregator_auth_token(&t))
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_aggregate_share(&self.datastore, &self.clock, req_bytes)
            .await
    }

    async fn task_aggregator_for(&self, task_id: &TaskId) -> Result<Arc<TaskAggregator<C>>, Error> {
        // TODO(#238): don't cache forever (decide on & implement some cache eviction policy).
        // This is important both to avoid ever-growing resource usage, and to allow aggregators to
        // notice when a task changes (e.g. due to key rotation).

        // Fast path: grab an existing task aggregator if one exists for this task.
        {
            let task_aggs = self.task_aggregators.lock().await;
            if let Some(task_agg) = task_aggs.get(task_id) {
                return Ok(Arc::clone(task_agg));
            }
        }

        // Slow path: retrieve task, create a task aggregator, store it to the cache, then return it.
        let task = self
            .datastore
            .run_tx_with_name("task_aggregator_get_task", |tx| {
                let task_id = *task_id;
                Box::pin(async move { tx.get_task(&task_id).await })
            })
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        let task_agg = Arc::new(TaskAggregator::new(task, Arc::clone(&self.report_writer))?);
        {
            let mut task_aggs = self.task_aggregators.lock().await;
            Ok(Arc::clone(task_aggs.entry(*task_id).or_insert(task_agg)))
        }
    }
}

/// TaskAggregator provides aggregation functionality for a single task.
// TODO(#224): refactor Aggregator to perform indepedent batched operations (e.g. report handling in
// Aggregate requests) using a parallelized library like Rayon.
pub struct TaskAggregator<C: Clock> {
    /// The task being aggregated.
    task: Arc<Task>,
    /// VDAF-specific operations.
    vdaf_ops: VdafOps,
    /// Report writer, with support for batching.
    report_writer: Arc<ReportWriteBatcher<C>>,
}

impl<C: Clock> TaskAggregator<C> {
    /// Create a new aggregator. `report_recipient` is used to decrypt reports received by this
    /// aggregator.
    fn new(task: Task, report_writer: Arc<ReportWriteBatcher<C>>) -> Result<Self, Error> {
        let vdaf_ops = match task.vdaf() {
            VdafInstance::Prio3Count => {
                let vdaf = Prio3::new_count(2)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3Count(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3CountVec { length } => {
                let vdaf = Prio3::new_sum_vec_multithreaded(2, 1, *length)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3CountVec(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3Sum { bits } => {
                let vdaf = Prio3::new_sum(2, *bits)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3Sum(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3SumVec { bits, length } => {
                let vdaf = Prio3::new_sum_vec_multithreaded(2, *bits, *length)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3SumVec(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3Histogram { buckets } => {
                let vdaf = Prio3::new_histogram(2, buckets)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3Histogram(Arc::new(vdaf), verify_key)
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3FixedPoint16BitBoundedL2VecSum(Arc::new(vdaf), verify_key)
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3FixedPoint32BitBoundedL2VecSum(Arc::new(vdaf), verify_key)
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3FixedPoint64BitBoundedL2VecSum(Arc::new(vdaf), verify_key)
            }

            #[cfg(feature = "test-util")]
            VdafInstance::Fake => VdafOps::Fake(Arc::new(dummy_vdaf::Vdaf::new())),

            #[cfg(feature = "test-util")]
            VdafInstance::FakeFailsPrepInit => VdafOps::Fake(Arc::new(
                dummy_vdaf::Vdaf::new().with_prep_init_fn(|_| -> Result<(), VdafError> {
                    Err(VdafError::Uncategorized(
                        "FakeFailsPrepInit failed at prep_init".to_string(),
                    ))
                }),
            )),

            #[cfg(feature = "test-util")]
            VdafInstance::FakeFailsPrepStep => {
                VdafOps::Fake(Arc::new(dummy_vdaf::Vdaf::new().with_prep_step_fn(
                    || -> Result<PrepareTransition<dummy_vdaf::Vdaf, 0, 16>, VdafError> {
                        Err(VdafError::Uncategorized(
                            "FakeFailsPrepStep failed at prep_step".to_string(),
                        ))
                    },
                )))
            }

            _ => panic!("VDAF {:?} is not yet supported", task.vdaf()),
        };

        Ok(Self {
            task: Arc::new(task),
            vdaf_ops,
            report_writer,
        })
    }

    fn handle_hpke_config(&self) -> HpkeConfigList {
        // TODO(#239): consider deciding a better way to determine "primary" (e.g. most-recent) HPKE
        // config/key -- right now it's the one with the maximal config ID, but that will run into
        // trouble if we ever need to wrap-around, which we may since config IDs are effectively a u8.
        HpkeConfigList::new(Vec::from([self
            .task
            .hpke_keys()
            .iter()
            .max_by_key(|(&id, _)| id)
            .unwrap()
            .1
            .config()
            .clone()]))
    }

    async fn handle_upload(
        &self,
        clock: &C,
        upload_decrypt_failure_counter: &Counter<u64>,
        upload_decode_failure_counter: &Counter<u64>,
        report: Report,
    ) -> Result<(), Arc<Error>> {
        self.vdaf_ops
            .handle_upload(
                clock,
                upload_decrypt_failure_counter,
                upload_decode_failure_counter,
                &self.task,
                &self.report_writer,
                report,
            )
            .await
    }

    async fn handle_aggregate_init(
        &self,
        datastore: &Datastore<C>,
        aggregate_step_failure_counter: &Counter<u64>,
        batch_aggregation_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        req_bytes: &[u8],
    ) -> Result<AggregationJobResp, Error> {
        self.vdaf_ops
            .handle_aggregate_init(
                datastore,
                aggregate_step_failure_counter,
                Arc::clone(&self.task),
                batch_aggregation_shard_count,
                aggregation_job_id,
                req_bytes,
            )
            .await
    }

    async fn handle_aggregate_continue(
        &self,
        datastore: &Datastore<C>,
        aggregate_step_failure_counter: &Counter<u64>,
        batch_aggregation_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        req: AggregationJobContinueReq,
        request_hash: [u8; 32],
    ) -> Result<AggregationJobResp, Error> {
        self.vdaf_ops
            .handle_aggregate_continue(
                datastore,
                aggregate_step_failure_counter,
                Arc::clone(&self.task),
                batch_aggregation_shard_count,
                aggregation_job_id,
                Arc::new(req),
                request_hash,
            )
            .await
    }

    async fn handle_create_collection_job(
        &self,
        datastore: &Datastore<C>,
        collection_job_id: &CollectionJobId,
        req_bytes: &[u8],
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_create_collection_job(
                datastore,
                Arc::clone(&self.task),
                collection_job_id,
                req_bytes,
            )
            .await
    }

    async fn handle_get_collection_job(
        &self,
        datastore: &Datastore<C>,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.vdaf_ops
            .handle_get_collection_job(datastore, Arc::clone(&self.task), collection_job_id)
            .await
    }

    async fn handle_delete_collection_job(
        &self,
        datastore: &Datastore<C>,
        collection_job_id: &CollectionJobId,
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_delete_collection_job(datastore, Arc::clone(&self.task), collection_job_id)
            .await
    }

    async fn handle_aggregate_share(
        &self,
        datastore: &Datastore<C>,
        clock: &C,
        req_bytes: &[u8],
    ) -> Result<AggregateShare, Error> {
        self.vdaf_ops
            .handle_aggregate_share(datastore, clock, Arc::clone(&self.task), req_bytes)
            .await
    }
}

/// VdafOps stores VDAF-specific operations for a TaskAggregator in a non-generic way.
#[allow(clippy::enum_variant_names)]
enum VdafOps {
    Prio3Count(Arc<Prio3Count>, VerifyKey<PRIO3_VERIFY_KEY_LENGTH>),
    Prio3CountVec(
        Arc<Prio3SumVecMultithreaded>,
        VerifyKey<PRIO3_VERIFY_KEY_LENGTH>,
    ),
    Prio3Sum(Arc<Prio3Sum>, VerifyKey<PRIO3_VERIFY_KEY_LENGTH>),
    Prio3SumVec(
        Arc<Prio3SumVecMultithreaded>,
        VerifyKey<PRIO3_VERIFY_KEY_LENGTH>,
    ),
    Prio3Histogram(Arc<Prio3Histogram>, VerifyKey<PRIO3_VERIFY_KEY_LENGTH>),
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint16BitBoundedL2VecSum(
        Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>>>,
        VerifyKey<PRIO3_VERIFY_KEY_LENGTH>,
    ),
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint32BitBoundedL2VecSum(
        Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>>>,
        VerifyKey<PRIO3_VERIFY_KEY_LENGTH>,
    ),
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint64BitBoundedL2VecSum(
        Arc<Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>>>,
        VerifyKey<PRIO3_VERIFY_KEY_LENGTH>,
    ),

    #[cfg(feature = "test-util")]
    Fake(Arc<dummy_vdaf::Vdaf>),
}

/// Emits a match block dispatching on a [`VdafOps`] object. Takes a `&VdafOps` as the first
/// argument, followed by a pseudo-pattern and body. The pseudo-pattern takes variable names for the
/// constructed VDAF and the verify key, a type alias name that the block can use to explicitly
/// specify the VDAF's type, and the name of a const that will be set to the VDAF's verify key
/// length, also for explicitly specifying type parameters.
macro_rules! vdaf_ops_dispatch {
    ($vdaf_ops:expr, ($vdaf:pat_param, $verify_key:pat_param, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_ops {
            crate::aggregator::VdafOps::Prio3Count(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Count;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            crate::aggregator::VdafOps::Prio3CountVec(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            crate::aggregator::VdafOps::Prio3Sum(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Sum;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            crate::aggregator::VdafOps::Prio3SumVec(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            crate::aggregator::VdafOps::Prio3Histogram(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Histogram;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            crate::aggregator::VdafOps::Prio3FixedPoint16BitBoundedL2VecSum(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf =
                    ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>>;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            crate::aggregator::VdafOps::Prio3FixedPoint32BitBoundedL2VecSum(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf =
                    ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>>;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            crate::aggregator::VdafOps::Prio3FixedPoint64BitBoundedL2VecSum(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf =
                    ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>>;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            #[cfg(feature = "test-util")]
            crate::aggregator::VdafOps::Fake(vdaf) => {
                let $vdaf = vdaf;
                let $verify_key = &VerifyKey::new([]);
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                $body
            }
        }
    };
}

impl VdafOps {
    async fn handle_upload<C: Clock>(
        &self,
        clock: &C,
        upload_decrypt_failure_counter: &Counter<u64>,
        upload_decode_failure_counter: &Counter<u64>,
        task: &Task,
        report_writer: &ReportWriteBatcher<C>,
        report: Report,
    ) -> Result<(), Arc<Error>> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_upload_generic::<VERIFY_KEY_LENGTH, TimeInterval, VdafType, _>(
                        Arc::clone(vdaf),
                        clock,
                        upload_decrypt_failure_counter,
                        upload_decode_failure_counter,
                        task,
                        report_writer,
                        report,
                    )
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_upload_generic::<VERIFY_KEY_LENGTH, FixedSize, VdafType, _>(
                        Arc::clone(vdaf),
                        clock,
                        upload_decrypt_failure_counter,
                        upload_decode_failure_counter,
                        task,
                        report_writer,
                        report,
                    )
                    .await
                })
            }
        }
    }

    /// Implements the `/aggregate` endpoint for initialization requests for the helper, described
    /// in §4.4.4.1 & §4.4.4.2 of draft-gpew-priv-ppm.
    async fn handle_aggregate_init<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        aggregate_step_failure_counter: &Counter<u64>,
        task: Arc<Task>,
        batch_aggregation_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        req_bytes: &[u8],
    ) -> Result<AggregationJobResp, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, verify_key, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_init_generic::<VERIFY_KEY_LENGTH, TimeInterval, VdafType, _>(
                        datastore,
                        vdaf,
                        aggregate_step_failure_counter,
                        task,
                        batch_aggregation_shard_count,
                        aggregation_job_id,
                        verify_key,
                        req_bytes,
                    )
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, verify_key, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_init_generic::<VERIFY_KEY_LENGTH, FixedSize, VdafType, _>(
                        datastore,
                        vdaf,
                        aggregate_step_failure_counter,
                        task,
                        batch_aggregation_shard_count,
                        aggregation_job_id,
                        verify_key,
                        req_bytes,
                    )
                    .await
                })
            }
        }
    }

    async fn handle_aggregate_continue<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        aggregate_step_failure_counter: &Counter<u64>,
        task: Arc<Task>,
        batch_aggregation_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        req: Arc<AggregationJobContinueReq>,
        request_hash: [u8; 32],
    ) -> Result<AggregationJobResp, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_continue_generic::<VERIFY_KEY_LENGTH, TimeInterval, VdafType, _>(
                        datastore,
                        Arc::clone(vdaf),
                        aggregate_step_failure_counter,
                        task,
                        batch_aggregation_shard_count,
                        aggregation_job_id,
                        req,
                        request_hash,
                    )
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_continue_generic::<VERIFY_KEY_LENGTH, FixedSize, VdafType, _>(
                        datastore,
                        Arc::clone(vdaf),
                        aggregate_step_failure_counter,
                        task,
                        batch_aggregation_shard_count,
                        aggregation_job_id,
                        req,
                        request_hash,
                    )
                    .await
                })
            }
        }
    }

    async fn handle_upload_generic<const SEED_SIZE: usize, Q, A, C>(
        vdaf: Arc<A>,
        clock: &C,
        upload_decrypt_failure_counter: &Counter<u64>,
        upload_decode_failure_counter: &Counter<u64>,
        task: &Task,
        report_writer: &ReportWriteBatcher<C>,
        report: Report,
    ) -> Result<(), Arc<Error>>
    where
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        A::InputShare: PartialEq + Send + Sync,
        A::PublicShare: PartialEq + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        C: Clock,
        Q: UploadableQueryType,
    {
        // The leader's report is the first one.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        if report.encrypted_input_shares().len() != 2 {
            return Err(Arc::new(Error::UnrecognizedMessage(
                Some(*task.id()),
                "unexpected number of encrypted shares in report",
            )));
        }
        let leader_encrypted_input_share =
            &report.encrypted_input_shares()[Role::Leader.index().unwrap()];

        // Verify that the report's HPKE config ID is known.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        let hpke_keypair = task
            .hpke_keys()
            .get(leader_encrypted_input_share.config_id())
            .ok_or_else(|| {
                Error::OutdatedHpkeConfig(*task.id(), *leader_encrypted_input_share.config_id())
            })?;

        let report_deadline = clock
            .now()
            .add(task.tolerable_clock_skew())
            .map_err(|err| Arc::new(Error::from(err)))?;

        // Reject reports from too far in the future.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        if report.metadata().time().is_after(&report_deadline) {
            return Err(Arc::new(Error::ReportTooEarly(
                *task.id(),
                *report.metadata().id(),
                *report.metadata().time(),
            )));
        }

        // Reject reports after a task has expired.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        if report.metadata().time().is_after(task.task_expiration()) {
            return Err(Arc::new(Error::ReportRejected(
                *task.id(),
                *report.metadata().id(),
                *report.metadata().time(),
            )));
        }

        // Reject reports that would be eligible for garbage collection, to prevent replay attacks.
        if let Some(report_expiry_age) = task.report_expiry_age() {
            let report_expiry_time = report
                .metadata()
                .time()
                .add(report_expiry_age)
                .map_err(|err| Arc::new(Error::from(err)))?;
            if clock.now().is_after(&report_expiry_time) {
                return Err(Arc::new(Error::ReportRejected(
                    *task.id(),
                    *report.metadata().id(),
                    *report.metadata().time(),
                )));
            }
        }

        // Decode (and in the case of the leader input share, decrypt) the remaining fields of the
        // report before storing them in the datastore. The spec does not require the /upload
        // handler to do this, but it exercises HPKE decryption, saves us the trouble of storing
        // reports we can't use, and lets the aggregation job handler assume the values it reads
        // from the datastore are valid. We don't inform the client if this fails.
        let public_share =
            match A::PublicShare::get_decoded_with_param(vdaf.as_ref(), report.public_share()) {
                Ok(public_share) => public_share,
                Err(err) => {
                    warn!(
                        report.task_id = %task.id(),
                        report.metadata = ?report.metadata(),
                        ?err,
                        "public share decoding failed",
                    );
                    upload_decode_failure_counter.add(&Context::current(), 1, &[]);
                    return Ok(());
                }
            };

        let encoded_leader_plaintext_input_share = match hpke::open(
            hpke_keypair.config(),
            hpke_keypair.private_key(),
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, task.role()),
            leader_encrypted_input_share,
            &InputShareAad::new(
                *task.id(),
                report.metadata().clone(),
                report.public_share().to_vec(),
            )
            .get_encoded(),
        ) {
            Ok(encoded_leader_plaintext_input_share) => encoded_leader_plaintext_input_share,
            Err(error) => {
                info!(
                    report.task_id = %task.id(),
                    report.metadata = ?report.metadata(),
                    ?error,
                    "Report decryption failed",
                );
                upload_decrypt_failure_counter.add(&Context::current(), 1, &[]);
                return Ok(());
            }
        };

        let leader_plaintext_input_share =
            PlaintextInputShare::get_decoded(&encoded_leader_plaintext_input_share)
                .map_err(|err| Arc::new(Error::from(err)))?;

        let leader_input_share = match A::InputShare::get_decoded_with_param(
            &(&vdaf, Role::Leader.index().unwrap()),
            leader_plaintext_input_share.payload(),
        ) {
            Ok(leader_input_share) => leader_input_share,
            Err(err) => {
                warn!(
                    report.task_id = %task.id(),
                    report.metadata = ?report.metadata(),
                    ?err,
                    "Leader input share decoding failed",
                );
                upload_decode_failure_counter.add(&Context::current(), 1, &[]);
                return Ok(());
            }
        };

        let helper_encrypted_input_share =
            &report.encrypted_input_shares()[Role::Helper.index().unwrap()];

        let report = LeaderStoredReport::new(
            *task.id(),
            report.metadata().clone(),
            public_share,
            Vec::from(leader_plaintext_input_share.extensions()),
            leader_input_share,
            helper_encrypted_input_share.clone(),
        );

        report_writer
            .write_report(WritableReport::<SEED_SIZE, Q, A>::new(vdaf, report))
            .await
    }
}

/// Used by the aggregation job initialization handler to represent initialization of a report
/// share.
#[derive(Clone, Debug)]
struct ReportShareData<const SEED_SIZE: usize, A>
where
    A: vdaf::Aggregator<SEED_SIZE, 16>,
{
    report_share: ReportShare,
    report_aggregation: ReportAggregation<SEED_SIZE, A>,
    prep_result: PrepareStepResult,
    existing_report_aggregation: bool,
    conflicting_aggregate_share: bool,
}

impl<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE, 16>> ReportShareData<SEED_SIZE, A>
where
    A: vdaf::Aggregator<SEED_SIZE, 16>,
{
    fn new(
        report_share: ReportShare,
        report_aggregation: ReportAggregation<SEED_SIZE, A>,
        prep_result: PrepareStepResult,
    ) -> Self {
        Self {
            report_share,
            report_aggregation,
            prep_result,
            existing_report_aggregation: false,
            conflicting_aggregate_share: false,
        }
    }
}

impl VdafOps {
    /// Returns true if the incoming aggregation job matches existing contents of the datastore, in
    /// the sense that no new rows would need to be written to service the job.
    async fn check_aggregation_job_idempotence<'b, const SEED_SIZE: usize, Q, A, C>(
        tx: &Transaction<'b, C>,
        vdaf: &A,
        task: &Task,
        incoming_aggregation_job: &AggregationJob<SEED_SIZE, Q, A>,
        incoming_report_share_data: &[ReportShareData<SEED_SIZE, A>],
    ) -> Result<bool, Error>
    where
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'static + Send + Sync,
        C: Clock,
        A::AggregationParam: Send + Sync + PartialEq,
        A::AggregateShare: Send + Sync,
        A::PrepareMessage: Send + Sync + PartialEq,
        A::PrepareShare: Send + Sync + PartialEq,
        for<'a> A::PrepareState:
            Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)> + PartialEq,
        A::OutputShare: Send + Sync + PartialEq,
    {
        let existing_aggregation_job = tx
            .get_aggregation_job(task.id(), incoming_aggregation_job.id())
            .await?
            .unwrap_or_else(|| {
                panic!(
                    "found no existing aggregation job for task ID {} and aggregation job ID {}",
                    task.id(),
                    incoming_aggregation_job.id()
                )
            });

        if !existing_aggregation_job.eq(incoming_aggregation_job) {
            return Ok(false);
        }

        // Check the existing report aggregations for this job against the ones in the incoming
        // message.
        let existing_report_aggregations = tx
            .get_report_aggregations_for_aggregation_job(
                vdaf,
                &Role::Helper,
                task.id(),
                incoming_aggregation_job.id(),
            )
            .await?;

        // Filter out any report shares in the incoming message that wouldn't get written out: we
        // don't expect to see those in the datastore.
        let incoming_report_share_data: Vec<_> = incoming_report_share_data
            .iter()
            .filter(|report_share_data| {
                !report_share_data.existing_report_aggregation
                    && !report_share_data.conflicting_aggregate_share
            })
            .collect();

        if existing_report_aggregations.len() != incoming_report_share_data.len() {
            return Ok(false);
        }

        // Check each report share in the incoming aggregation job against the already recorded
        // report aggregations. `existing_report_aggregations` preserves the order in which the
        // report shares were seen in the previous `AggregationJobInitReq`, and that order should be
        // preserved in the repeated message, so it's OK to just zip the iterators together.
        if incoming_report_share_data
            .iter()
            .zip(existing_report_aggregations)
            .any(|(incoming_report_share, existing_report_share)| {
                !existing_report_share
                    .report_metadata()
                    .eq(incoming_report_share.report_share.metadata())
                    || !existing_report_share.eq(&incoming_report_share.report_aggregation)
            })
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Implements the aggregate initialization request portion of the `/aggregate` endpoint for the
    /// helper, described in §4.4.4.1 of draft-gpew-priv-ppm.
    async fn handle_aggregate_init_generic<const SEED_SIZE: usize, Q, A, C>(
        datastore: &Datastore<C>,
        vdaf: &A,
        aggregate_step_failure_counter: &Counter<u64>,
        task: Arc<Task>,
        batch_aggregation_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        verify_key: &VerifyKey<SEED_SIZE>,
        req_bytes: &[u8],
    ) -> Result<AggregationJobResp, Error>
    where
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'static + Send + Sync,
        C: Clock,
        A::AggregationParam: Send + Sync + PartialEq,
        A::AggregateShare: Send + Sync,
        A::PrepareMessage: Send + Sync + PartialEq,
        A::PrepareShare: Send + Sync + PartialEq,
        for<'a> A::PrepareState:
            Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)> + PartialEq,
        A::OutputShare: Send + Sync + PartialEq,
    {
        let req = AggregationJobInitializeReq::<Q>::get_decoded(req_bytes)?;

        // If two ReportShare messages have the same report ID, then the helper MUST abort with
        // error "unrecognizedMessage". (§4.4.4.1)
        let mut seen_report_ids = HashSet::with_capacity(req.report_shares().len());
        for share in req.report_shares() {
            if !seen_report_ids.insert(share.metadata().id()) {
                return Err(Error::UnrecognizedMessage(
                    Some(*task.id()),
                    "aggregate request contains duplicate report IDs",
                ));
            }
        }

        // Decrypt shares & prepare initialization states. (§4.4.4.1)
        let mut saw_continue = false;
        let mut report_share_data = Vec::new();
        let agg_param = A::AggregationParam::get_decoded(req.aggregation_parameter())?;
        for (ord, report_share) in req.report_shares().iter().enumerate() {
            let hpke_keypair = task
                .hpke_keys()
                .get(report_share.encrypted_input_share().config_id())
                .ok_or_else(|| {
                    info!(
                        config_id = %report_share.encrypted_input_share().config_id(),
                        "Helper encrypted input share references unknown HPKE config ID"
                    );
                    aggregate_step_failure_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("type", "unknown_hpke_config_id")],
                    );
                    ReportShareError::HpkeUnknownConfigId
                });

            // If decryption fails, then the aggregator MUST fail with error `hpke-decrypt-error`. (§4.4.2.2)
            let plaintext = hpke_keypair.and_then(|hpke_keypair| {
                hpke::open(
                    hpke_keypair.config(),
                    hpke_keypair.private_key(),
                    &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
                    report_share.encrypted_input_share(),
                    &InputShareAad::new(
                        *task.id(),
                        report_share.metadata().clone(),
                        report_share.public_share().to_vec(),
                    )
                    .get_encoded(),
                )
                .map_err(|error| {
                    info!(
                        task_id = %task.id(),
                        metadata = ?report_share.metadata(),
                        ?error,
                        "Couldn't decrypt helper's report share"
                    );
                    aggregate_step_failure_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("type", "decrypt_failure")],
                    );
                    ReportShareError::HpkeDecryptError
                })
            });

            let plaintext_input_share = plaintext.and_then(|plaintext| {
                let plaintext_input_share = PlaintextInputShare::get_decoded(&plaintext).map_err(|error| {
                    info!(task_id = %task.id(), metadata = ?report_share.metadata(), ?error, "Couldn't decode helper's plaintext input share");
                    aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "plaintext_input_share_decode_failure")]);
                    ReportShareError::UnrecognizedMessage
                })?;
                // Check for repeated extensions.
                let mut extension_types = HashSet::new();
                if !plaintext_input_share
                    .extensions()
                    .iter()
                    .all(|extension| extension_types.insert(extension.extension_type())) {
                        info!(task_id = %task.id(), metadata = ?report_share.metadata(), "Received report share with duplicate extensions");
                        aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "duplicate_extension")]);
                        return Err(ReportShareError::UnrecognizedMessage)
                }
                Ok(plaintext_input_share)
            });

            let input_share = plaintext_input_share.and_then(|plaintext_input_share| {
                A::InputShare::get_decoded_with_param(&(vdaf, Role::Helper.index().unwrap()), plaintext_input_share.payload())
                    .map_err(|error| {
                        info!(task_id = %task.id(), metadata = ?report_share.metadata(), ?error, "Couldn't decode helper's input share");
                        aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "input_share_decode_failure")]);
                        ReportShareError::UnrecognizedMessage
                    })
            });

            let public_share = A::PublicShare::get_decoded_with_param(vdaf, report_share.public_share()).map_err(|error|{
                info!(task_id = %task.id(), metadata = ?report_share.metadata(), ?error, "Couldn't decode public share");
                aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "public_share_decode_failure")]);
                ReportShareError::UnrecognizedMessage
            });

            let shares = input_share.and_then(|input_share| Ok((public_share?, input_share)));

            // Next, the aggregator runs the preparation-state initialization algorithm for the VDAF
            // associated with the task and computes the first state transition. [...] If either
            // step fails, then the aggregator MUST fail with error `vdaf-prep-error`. (§4.4.2.2)
            let init_rslt = shares.and_then(|(public_share, input_share)| {
                vdaf
                    .prepare_init(
                        verify_key.as_bytes(),
                        Role::Helper.index().unwrap(),
                        &agg_param,
                        report_share.metadata().id().as_ref(),
                        &public_share,
                        &input_share,
                    )
                    .map_err(|error| {
                        info!(task_id = %task.id(), report_id = %report_share.metadata().id(), ?error, "Couldn't prepare_init report share");
                        aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "prepare_init_failure")]);
                        ReportShareError::VdafPrepError
                    })
            });

            report_share_data.push(match init_rslt {
                Ok((prep_state, prep_share)) => {
                    saw_continue = true;

                    let encoded_prep_share = prep_share.get_encoded();
                    ReportShareData::new(
                        report_share.clone(),
                        ReportAggregation::<SEED_SIZE, A>::new(
                            *task.id(),
                            *aggregation_job_id,
                            *report_share.metadata().id(),
                            *report_share.metadata().time(),
                            ord.try_into()?,
                            ReportAggregationState::<SEED_SIZE, A>::Waiting(
                                prep_state,
                                PrepareMessageOrShare::Helper(prep_share),
                            ),
                        ),
                        PrepareStepResult::Continued(encoded_prep_share),
                    )
                }

                Err(err) => ReportShareData::new(
                    report_share.clone(),
                    ReportAggregation::<SEED_SIZE, A>::new(
                        *task.id(),
                        *aggregation_job_id,
                        *report_share.metadata().id(),
                        *report_share.metadata().time(),
                        ord.try_into()?,
                        ReportAggregationState::<SEED_SIZE, A>::Failed(err),
                    ),
                    PrepareStepResult::Failed(err),
                ),
            });
        }

        // Store data to datastore.
        let req = Arc::new(req);
        let min_client_timestamp = req
            .report_shares()
            .iter()
            .map(|report_share| report_share.metadata().time())
            .min()
            .ok_or_else(|| Error::EmptyAggregation(*task.id()))?;
        let max_client_timestamp = req
            .report_shares()
            .iter()
            .map(|report_share| report_share.metadata().time())
            .max()
            .ok_or_else(|| Error::EmptyAggregation(*task.id()))?;
        let client_timestamp_interval = Interval::new(
            *min_client_timestamp,
            max_client_timestamp
                .difference(min_client_timestamp)?
                .add(&Duration::from_seconds(1))?,
        )?;
        let aggregation_job = Arc::new(AggregationJob::<SEED_SIZE, Q, A>::new(
            *task.id(),
            *aggregation_job_id,
            agg_param,
            req.batch_selector().batch_identifier().clone(),
            client_timestamp_interval,
            if saw_continue {
                AggregationJobState::InProgress
            } else {
                AggregationJobState::Finished
            },
            AggregationJobRound::from(0),
        ));

        let prep_steps = datastore
            .run_tx_with_name("aggregate_init", |tx| {
                let (vdaf, task, req, aggregation_job, mut report_share_data) = (
                    vdaf.clone(),
                    Arc::clone(&task),
                    Arc::clone(&req),
                    Arc::clone(&aggregation_job),
                    report_share_data.clone(),
                );

                Box::pin(async move {
                    for mut share_data in report_share_data.iter_mut() {
                        // Verify that we haven't seen this report ID and aggregation parameter
                        // before in another aggregation job, and that the report isn't for a batch
                        // interval that has already started collection.
                        let (report_aggregation_exists, conflicting_aggregate_share_jobs) = try_join!(
                            tx.check_other_report_aggregation_exists::<SEED_SIZE, A>(
                                task.id(),
                                share_data.report_share.metadata().id(),
                                aggregation_job.aggregation_parameter(),
                                aggregation_job.id(),
                            ),
                            Q::get_conflicting_aggregate_share_jobs::<SEED_SIZE, C, A>(
                                tx,
                                &vdaf,
                                task.id(),
                                req.batch_selector().batch_identifier(),
                                share_data.report_share.metadata()
                            ),
                        )?;

                        share_data.existing_report_aggregation = report_aggregation_exists;
                        share_data.conflicting_aggregate_share = !conflicting_aggregate_share_jobs.is_empty();
                    }

                    // Write aggregation job.
                    let replayed_request = match tx.put_aggregation_job(&aggregation_job).await {
                        Ok(_) => false,
                        Err(datastore::Error::MutationTargetAlreadyExists) => {
                            // Slow path: this request is writing an aggregation job that already
                            // exists in the datastore. PUT to an aggregation job is idempotent, so
                            // that's OK, provided the current request is equivalent to what's in
                            // the datastore, which we must now check.
                            if !Self::check_aggregation_job_idempotence(
                                tx,
                                &vdaf,
                                task.borrow(),
                                aggregation_job.borrow(),
                                &report_share_data,
                            )
                            .await
                            .map_err(|e| datastore::Error::User(e.into()))? {
                                return Err(datastore::Error::User(Error::ForbiddenMutation {
                                    resource_type: "aggregation job",
                                    identifier: aggregation_job.id().to_string(),
                                }.into()));
                            }

                            true
                        }
                        Err(e) => return Err(e),
                    };

                    // Construct a response and write any new report shares and report aggregations
                    // as we go.
                    let mut accumulator = Accumulator::<SEED_SIZE, Q, A>::new(
                        Arc::clone(&task),
                        batch_aggregation_shard_count,
                        aggregation_job.aggregation_parameter().clone(),
                    );

                    let mut prep_steps = Vec::new();
                    for report_share_data in report_share_data
                    {
                        if report_share_data.existing_report_aggregation {
                            prep_steps.push(PrepareStep::new(
                                *report_share_data.report_share.metadata().id(),
                                PrepareStepResult::Failed(ReportShareError::ReportReplayed),
                            ));
                            continue;
                        }
                        if report_share_data.conflicting_aggregate_share {
                            prep_steps.push(PrepareStep::new(
                                *report_share_data.report_share.metadata().id(),
                                PrepareStepResult::Failed(ReportShareError::BatchCollected),
                            ));
                            continue;
                        }

                        if !replayed_request {
                            // Write client report & report aggregation.
                            if let Err(error) = tx.put_report_share(
                                task.id(),
                                &report_share_data.report_share
                            ).await {
                                match error {
                                    datastore::Error::MutationTargetAlreadyExists => {
                                        prep_steps.push(PrepareStep::new(
                                            *report_share_data.report_share.metadata().id(),
                                            PrepareStepResult::Failed(ReportShareError::ReportReplayed),
                                        ));
                                        continue;
                                    }
                                    e => return Err(e),
                                }
                            }
                            tx.put_report_aggregation(&report_share_data.report_aggregation).await?;
                        }

                        if let ReportAggregationState::<SEED_SIZE, A>::Finished(output_share) =
                            report_share_data.report_aggregation.state()
                        {
                            accumulator.update(
                                aggregation_job.partial_batch_identifier(),
                                report_share_data.report_share.metadata().id(),
                                report_share_data.report_share.metadata().time(),
                                output_share,
                            )?;
                        }

                        prep_steps.push(PrepareStep::new(
                            *report_share_data.report_share.metadata().id(),
                            report_share_data.prep_result.clone(),
                        ));
                    }

                    if !replayed_request {
                        accumulator.flush_to_datastore(tx, &vdaf).await?;
                    }
                    Ok(prep_steps)
                })
            })
            .await?;

        // Construct response and return.
        Ok(AggregationJobResp::new(prep_steps))
    }

    async fn handle_aggregate_continue_generic<
        const SEED_SIZE: usize,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16>,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        vdaf: Arc<A>,
        aggregate_step_failure_counter: &Counter<u64>,
        task: Arc<Task>,
        batch_aggregation_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        leader_aggregation_job: Arc<AggregationJobContinueReq>,
        request_hash: [u8; 32],
    ) -> Result<AggregationJobResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PrepareShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::OutputShare: Send + Sync,
    {
        if leader_aggregation_job.round() == AggregationJobRound::from(0) {
            return Err(Error::UnrecognizedMessage(
                Some(*task.id()),
                "aggregation job cannot be advanced to round 0",
            ));
        }

        // TODO(#224): don't hold DB transaction open while computing VDAF updates?
        // TODO(#224): don't do O(n) network round-trips (where n is the number of prepare steps)
        Ok(datastore
            .run_tx_with_name("aggregate_continue", |tx| {
                let (
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    aggregation_job_id,
                    leader_aggregation_job,
                ) = (
                    Arc::clone(&vdaf),
                    aggregate_step_failure_counter.clone(),
                    Arc::clone(&task),
                    *aggregation_job_id,
                    Arc::clone(&leader_aggregation_job),
                );

                Box::pin(async move {
                    // Read existing state.
                    let (helper_aggregation_job, report_aggregations) = try_join!(
                        tx.get_aggregation_job::<SEED_SIZE, Q, A>(task.id(), &aggregation_job_id),
                        tx.get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            &Role::Helper,
                            task.id(),
                            &aggregation_job_id,
                        ),
                    )?;

                    let helper_aggregation_job = helper_aggregation_job.ok_or_else(|| {
                        datastore::Error::User(
                            Error::UnrecognizedAggregationJob(*task.id(), aggregation_job_id)
                                .into(),
                        )
                    })?;

                    // If the leader's request is on the same round as our stored aggregation job,
                    // then we probably have already received this message and computed this round,
                    // but the leader never got our response and so retried stepping the job.
                    // TODO(issue #1087): measure how often this happens with a Prometheus metric
                    if helper_aggregation_job.round() == leader_aggregation_job.round() {
                        match helper_aggregation_job.last_continue_request_hash() {
                            None => {
                                return Err(datastore::Error::User(
                                    Error::Internal(format!(
                                        "aggregation job {aggregation_job_id} is in round {} but \
                                         has no last request hash",
                                        helper_aggregation_job.round(),
                                    ))
                                    .into(),
                                ));
                            }
                            Some(previous_hash) => {
                                if request_hash != previous_hash {
                                    return Err(datastore::Error::User(
                                        Error::ForbiddenMutation {
                                            resource_type: "aggregation job continuation",
                                            identifier: aggregation_job_id.to_string(),
                                        }
                                        .into(),
                                    ));
                                }
                            }
                        }
                        return Self::replay_aggregation_job_round::<C, SEED_SIZE, Q, A>(
                            report_aggregations,
                        );
                    } else if helper_aggregation_job.round().increment()
                        != leader_aggregation_job.round()
                    {
                        // If this is not a replay, the leader should be advancing our state to the next
                        // round and no further.
                        return Err(datastore::Error::User(
                            Error::RoundMismatch {
                                task_id: *task.id(),
                                aggregation_job_id,
                                expected_round: helper_aggregation_job.round().increment(),
                                got_round: leader_aggregation_job.round(),
                            }
                            .into(),
                        ));
                    }

                    // The leader is advancing us to the next round. Step the aggregation job to
                    // compute the next round of prepare messages and state.
                    Self::step_aggregation_job(
                        tx,
                        &task,
                        &vdaf,
                        batch_aggregation_shard_count,
                        helper_aggregation_job,
                        report_aggregations,
                        &leader_aggregation_job,
                        request_hash,
                        &aggregate_step_failure_counter,
                    )
                    .await
                })
            })
            .await?)
    }

    /// Handle requests to the leader to create a collection job.
    async fn handle_create_collection_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<Task>,
        collection_job_id: &CollectionJobId,
        collect_req_bytes: &[u8],
    ) -> Result<(), Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_create_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id, collect_req_bytes)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_create_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id, collect_req_bytes)
                    .await
                })
            }
        }
    }

    #[tracing::instrument(skip(datastore, task, req_bytes), fields(task_id = ?task.id()), err)]
    async fn handle_create_collection_job_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<Task>,
        vdaf: Arc<A>,
        collection_job_id: &CollectionJobId,
        req_bytes: &[u8],
    ) -> Result<(), Error>
    where
        A::AggregationParam: Eq + PartialEq + Send + Sync + 'static,
        A::AggregateShare: Send + Sync,
    {
        let req = Arc::new(CollectionReq::<Q>::get_decoded(req_bytes)?);
        let aggregation_param = Arc::new(A::AggregationParam::get_decoded(
            req.aggregation_parameter(),
        )?);

        Ok(datastore
            .run_tx_with_name("collect", move |tx| {
                let (task, vdaf, collection_job_id, req, aggregation_param) = (
                    Arc::clone(&task),
                    Arc::clone(&vdaf),
                    *collection_job_id,
                    Arc::clone(&req),
                    Arc::clone(&aggregation_param),
                );
                Box::pin(async move {
                    let batch_identifier = Q::batch_identifier_for_query(tx, &task, req.query())
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::BatchInvalid(
                                    *task.id(),
                                    "no batch ready for collection".to_string(),
                                )
                                .into(),
                            )
                        })?;

                    // Check that the batch interval is valid for the task
                    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6.1.1
                    if !Q::validate_collect_identifier(&task, &batch_identifier) {
                        return Err(datastore::Error::User(
                            Error::BatchInvalid(*task.id(), format!("{batch_identifier}")).into(),
                        ));
                    }

                    // Check if this collection job already exists, ensuring that all parameters match.
                    if let Some(collection_job) = tx
                        .get_collection_job::<SEED_SIZE, Q, A>(&vdaf, &collection_job_id)
                        .await?
                    {
                        if collection_job.batch_identifier() == &batch_identifier
                            && collection_job.aggregation_parameter() == aggregation_param.as_ref()
                        {
                            debug!(
                                collection_job_id = %collection_job_id,
                                collect_request = ?req,
                                "collection job already exists"
                            );
                            return Ok(());
                        } else {
                            return Err(datastore::Error::User(
                                Error::ForbiddenMutation {
                                    resource_type: "collection job",
                                    identifier: collection_job_id.to_string(),
                                }
                                .into(),
                            ));
                        }
                    }

                    debug!(collect_request = ?req, "Cache miss, creating new collection job");
                    let (_, report_count) = try_join!(
                        Q::validate_query_count::<SEED_SIZE, C, A>(
                            tx,
                            &vdaf,
                            &task,
                            &batch_identifier
                        ),
                        Q::count_client_reports(tx, &task, &batch_identifier),
                    )?;

                    // Batch size must be validated while handling CollectReq and hence before
                    // creating a collection job.
                    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
                    if !task.validate_batch_size(report_count) {
                        return Err(datastore::Error::User(
                            Error::InvalidBatchSize(*task.id(), report_count).into(),
                        ));
                    }

                    tx.put_collection_job(&CollectionJob::<SEED_SIZE, Q, A>::new(
                        *task.id(),
                        collection_job_id,
                        batch_identifier,
                        aggregation_param.as_ref().clone(),
                        CollectionJobState::<SEED_SIZE, A>::Start,
                    ))
                    .await?;

                    Ok(())
                })
            })
            .await?)
    }

    /// Handle GET requests to a collection job URI obtained from the leader's `/collect` endpoint.
    /// The return value is an encoded `CollectResp<Q>`.
    /// https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.1
    async fn handle_get_collection_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<Task>,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<Vec<u8>>, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_get_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_get_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
        }
    }

    // return value is an encoded CollectResp<Q>
    async fn handle_get_collection_job_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<Task>,
        vdaf: Arc<A>,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<Vec<u8>>, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
    {
        let (collection_job, spanned_interval) = datastore
            .run_tx_with_name("get_collection_job", |tx| {
                let (task, vdaf, collection_job_id) =
                    (Arc::clone(&task), Arc::clone(&vdaf), *collection_job_id);
                Box::pin(async move {
                    let collection_job = tx
                        .get_collection_job::<SEED_SIZE, Q, A>(&vdaf, &collection_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectionJob(collection_job_id).into(),
                            )
                        })?;

                    let (batch_aggregations, _) = try_join!(
                        Q::get_batch_aggregations_for_collect_identifier(
                            tx,
                            &task,
                            vdaf.as_ref(),
                            collection_job.batch_identifier(),
                            collection_job.aggregation_parameter()
                        ),
                        Q::acknowledge_collection(tx, task.id(), collection_job.batch_identifier()),
                    )?;

                    // Merge the intervals spanned by the constituent batch aggregations into the
                    // interval spanned by the collection.
                    let mut spanned_interval: Option<Interval> = None;
                    for interval in batch_aggregations
                        .iter()
                        .map(BatchAggregation::<SEED_SIZE, Q, A>::client_timestamp_interval)
                    {
                        match spanned_interval {
                            Some(m) => spanned_interval = Some(m.merge(interval)?),
                            None => spanned_interval = Some(*interval),
                        }
                    }

                    Ok((collection_job, spanned_interval))
                })
            })
            .await?;

        match collection_job.state() {
            CollectionJobState::Start => {
                debug!(%collection_job_id, task_id = %task.id(), "collection job has not run yet");
                Ok(None)
            }

            CollectionJobState::Finished {
                report_count,
                encrypted_helper_aggregate_share,
                leader_aggregate_share,
            } => {
                let spanned_interval = spanned_interval
                    .ok_or_else(|| {
                        datastore::Error::User(
                            Error::Internal(format!(
                                "collection job {collection_job_id} is finished but spans no time \
                                 interval"
                            ))
                            .into(),
                        )
                    })?
                    .align_to_time_precision(task.time_precision())?;

                // §4.4.4.3: HPKE encrypt aggregate share to the collector. We store the leader
                // aggregate share *unencrypted* in the datastore so that we can encrypt cached
                // results to the collector HPKE config valid when the current collection job request
                // was made, and not whatever was valid at the time the aggregate share was first
                // computed.
                // However we store the helper's *encrypted* share.

                // TODO(#240): consider fetching freshly encrypted helper aggregate share if it has
                // been long enough since the encrypted helper share was cached -- tricky thing is
                // deciding what "long enough" is.
                debug!(
                    %collection_job_id,
                    task_id = %task.id(),
                    "Serving cached collection job response"
                );
                let encrypted_leader_aggregate_share = hpke::seal(
                    task.collector_hpke_config(),
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Leader,
                        &Role::Collector,
                    ),
                    &leader_aggregate_share.get_encoded(),
                    &AggregateShareAad::new(
                        *collection_job.task_id(),
                        BatchSelector::<Q>::new(collection_job.batch_identifier().clone()),
                    )
                    .get_encoded(),
                )?;

                Ok(Some(
                    Collection::<Q>::new(
                        PartialBatchSelector::new(
                            Q::partial_batch_identifier(collection_job.batch_identifier()).clone(),
                        ),
                        *report_count,
                        spanned_interval,
                        Vec::<HpkeCiphertext>::from([
                            encrypted_leader_aggregate_share,
                            encrypted_helper_aggregate_share.clone(),
                        ]),
                    )
                    .get_encoded(),
                ))
            }

            CollectionJobState::Abandoned => {
                // TODO(#248): decide how to respond for abandoned collection jobs.
                warn!(
                    %collection_job_id,
                    task_id = %task.id(),
                    "Attempting to collect abandoned collection job"
                );
                Ok(None)
            }

            CollectionJobState::Deleted => Err(Error::DeletedCollectionJob(*collection_job_id)),
        }
    }

    async fn handle_delete_collection_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<Task>,
        collection_job_id: &CollectionJobId,
    ) -> Result<(), Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_delete_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_delete_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
        }
    }

    async fn handle_delete_collection_job_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<Task>,
        vdaf: Arc<A>,
        collection_job_id: &CollectionJobId,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync + PartialEq + Eq,
    {
        datastore
            .run_tx_with_name("delete_collection_job", move |tx| {
                let (task, vdaf, collection_job_id) =
                    (Arc::clone(&task), Arc::clone(&vdaf), *collection_job_id);
                Box::pin(async move {
                    let collection_job = tx
                        .get_collection_job::<SEED_SIZE, Q, A>(vdaf.as_ref(), &collection_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectionJob(collection_job_id).into(),
                            )
                        })?;
                    Q::acknowledge_collection(tx, task.id(), collection_job.batch_identifier())
                        .await?;
                    if collection_job.state() != &CollectionJobState::Deleted {
                        tx.update_collection_job::<SEED_SIZE, Q, A>(
                            &collection_job.with_state(CollectionJobState::Deleted),
                        )
                        .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    /// Implements the `/aggregate_share` endpoint for the helper, described in §4.4.4.3
    async fn handle_aggregate_share<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        clock: &C,
        task: Arc<Task>,
        req_bytes: &[u8],
    ) -> Result<AggregateShare, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_share_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        VdafType,
                        _,
                    >(datastore, clock, task, Arc::clone(vdaf), req_bytes)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_share_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        VdafType,
                        _,
                    >(datastore, clock, task, Arc::clone(vdaf), req_bytes)
                    .await
                })
            }
        }
    }

    async fn handle_aggregate_share_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        clock: &C,
        task: Arc<Task>,
        vdaf: Arc<A>,
        req_bytes: &[u8],
    ) -> Result<AggregateShare, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
    {
        // Decode request, and verify that it is for the current task. We use an assert to check
        // that the task IDs match as this should be guaranteed by the caller.
        let aggregate_share_req = Arc::new(AggregateShareReq::<Q>::get_decoded(req_bytes)?);

        // §4.4.4.3: check that the batch interval meets the requirements from §4.6
        if !Q::validate_collect_identifier(
            &task,
            aggregate_share_req.batch_selector().batch_identifier(),
        ) {
            return Err(Error::BatchInvalid(
                *task.id(),
                format!(
                    "{}",
                    aggregate_share_req.batch_selector().batch_identifier()
                ),
            ));
        }

        // Reject requests for aggregation shares that are eligible for GC, to prevent replay
        // attacks.
        if let Some(report_expiry_age) = task.report_expiry_age() {
            if let Some(batch_interval) =
                Q::to_batch_interval(aggregate_share_req.batch_selector().batch_identifier())
            {
                let aggregate_share_expiry_time = batch_interval.end().add(report_expiry_age)?;
                if clock.now().is_after(&aggregate_share_expiry_time) {
                    return Err(Error::AggregateShareRequestRejected(
                        *task.id(),
                        "aggregate share request too late".to_string(),
                    ));
                }
            }
        }

        let aggregate_share_job = datastore
            .run_tx_with_name("aggregate_share", |tx| {
                let (task, vdaf, aggregate_share_req) = (
                    Arc::clone(&task),
                    Arc::clone(&vdaf),
                    Arc::clone(&aggregate_share_req),
                );
                Box::pin(async move {
                    // Check if we have already serviced an aggregate share request with these
                    // parameters and serve the cached results if so.
                    let aggregation_param = A::AggregationParam::get_decoded(
                        aggregate_share_req.aggregation_parameter(),
                    )?;
                    let aggregate_share_job = match tx
                        .get_aggregate_share_job(
                            vdaf.as_ref(),
                            task.id(),
                            aggregate_share_req.batch_selector().batch_identifier(),
                            &aggregation_param,
                        )
                        .await?
                    {
                        Some(aggregate_share_job) => {
                            debug!(
                                ?aggregate_share_req,
                                "Serving cached aggregate share job result"
                            );
                            aggregate_share_job
                        }
                        None => {
                            debug!(
                                ?aggregate_share_req,
                                "Cache miss, computing aggregate share job result"
                            );
                            let aggregation_param = A::AggregationParam::get_decoded(
                                aggregate_share_req.aggregation_parameter(),
                            )?;
                            let (batch_aggregations, _) = try_join!(
                                Q::get_batch_aggregations_for_collect_identifier(
                                    tx,
                                    &task,
                                    vdaf.as_ref(),
                                    aggregate_share_req.batch_selector().batch_identifier(),
                                    &aggregation_param
                                ),
                                Q::validate_query_count::<SEED_SIZE, C, A>(
                                    tx,
                                    vdaf.as_ref(),
                                    &task,
                                    aggregate_share_req.batch_selector().batch_identifier(),
                                )
                            )?;

                            let (helper_aggregate_share, report_count, checksum) =
                                compute_aggregate_share::<SEED_SIZE, Q, A>(
                                    &task,
                                    &batch_aggregations,
                                )
                                .await
                                .map_err(|e| datastore::Error::User(e.into()))?;

                            // Now that we are satisfied that the request is serviceable, we consume
                            // a query by recording the aggregate share request parameters and the
                            // result.
                            let aggregate_share_job = AggregateShareJob::<SEED_SIZE, Q, A>::new(
                                *task.id(),
                                aggregate_share_req
                                    .batch_selector()
                                    .batch_identifier()
                                    .clone(),
                                aggregation_param,
                                helper_aggregate_share,
                                report_count,
                                checksum,
                            );
                            tx.put_aggregate_share_job(&aggregate_share_job).await?;
                            aggregate_share_job
                        }
                    };

                    // §4.4.4.3: verify total report count and the checksum we computed against
                    // those reported by the leader.
                    if aggregate_share_job.report_count() != aggregate_share_req.report_count()
                        || aggregate_share_job.checksum() != aggregate_share_req.checksum()
                    {
                        return Err(datastore::Error::User(
                            Error::BatchMismatch(Box::new(BatchMismatch {
                                task_id: *task.id(),
                                own_checksum: *aggregate_share_job.checksum(),
                                own_report_count: aggregate_share_job.report_count(),
                                peer_checksum: *aggregate_share_req.checksum(),
                                peer_report_count: aggregate_share_req.report_count(),
                            }))
                            .into(),
                        ));
                    }

                    Ok(aggregate_share_job)
                })
            })
            .await?;

        // §4.4.4.3: HPKE encrypt aggregate share to the collector. We store *unencrypted* aggregate
        // shares in the datastore so that we can encrypt cached results to the collector HPKE
        // config valid when the current AggregateShareReq was made, and not whatever was valid at
        // the time the aggregate share was first computed.
        let encrypted_aggregate_share = hpke::seal(
            task.collector_hpke_config(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            &aggregate_share_job.helper_aggregate_share().get_encoded(),
            &AggregateShareAad::new(*task.id(), aggregate_share_req.batch_selector().clone())
                .get_encoded(),
        )?;

        Ok(AggregateShare::new(encrypted_aggregate_share))
    }
}

trait DapProblemTypeExt {
    /// Returns the HTTP status code that should be used in responses whose body is a problem
    /// document of this type.
    fn http_status(&self) -> Status;
}

impl DapProblemTypeExt for DapProblemType {
    /// Returns the HTTP status code that should be used in responses whose body is a problem
    /// document of this type.
    fn http_status(&self) -> Status {
        // Per the errors section of the protocol, error responses should use "HTTP status code 400
        // Bad Request unless explicitly specified otherwise."
        // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-03#name-errors
        Status::BadRequest
    }
}

/// The media type for problem details formatted as a JSON document, per RFC 7807.
static PROBLEM_DETAILS_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Serialization helper struct for JSON problem details error responses. See
/// https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-03#section-3.2.
#[derive(Serialize)]
struct ProblemDocument<'a> {
    #[serde(rename = "type")]
    type_: &'static str,
    title: &'static str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    taskid: &'a Option<String>,
}

trait ConnExt {
    /// Send a response containing a JSON-encoded problem details document for the given
    /// DAP-specific problem type, (optionally including the DAP task ID) and set the appropriate
    /// HTTP status code.
    fn with_problem_details(self, error_type: DapProblemType, task_id: Option<&TaskId>) -> Self;
}

impl ConnExt for Conn {
    fn with_problem_details(self, error_type: DapProblemType, task_id: Option<&TaskId>) -> Self {
        let status = error_type.http_status();

        self.with_status(status as u16)
            .with_header(
                KnownHeaderName::ContentType,
                PROBLEM_DETAILS_JSON_MEDIA_TYPE,
            )
            .with_json(&ProblemDocument {
                type_: error_type.type_uri(),
                title: error_type.description(),
                status: status as u16,
                taskid: &task_id.as_ref().map(ToString::to_string),
            })
    }
}

/// Newtype holding a textual error code, to be stored in a Trillium connection's state.
struct ErrorCode(&'static str);

#[async_trait]
impl Handler for Error {
    async fn run(&self, mut conn: Conn) -> Conn {
        let error_code = self.error_code();
        conn.set_state(ErrorCode(error_code));
        warn!(error_code, error=?self, "Error handling endpoint");
        match self {
            Error::InvalidConfiguration(_) => conn.with_status(Status::InternalServerError),
            Error::MessageDecode(_) => {
                conn.with_problem_details(DapProblemType::UnrecognizedMessage, None)
            }
            Error::ReportRejected(task_id, _, _) => {
                conn.with_problem_details(DapProblemType::ReportRejected, Some(task_id))
            }
            Error::UnrecognizedMessage(task_id, _) => {
                conn.with_problem_details(DapProblemType::UnrecognizedMessage, task_id.as_ref())
            }
            Error::RoundMismatch { task_id, .. } => {
                conn.with_problem_details(DapProblemType::RoundMismatch, Some(task_id))
            }
            Error::UnrecognizedTask(task_id) => {
                conn.with_problem_details(DapProblemType::UnrecognizedTask, Some(task_id))
            }
            Error::MissingTaskId => conn.with_problem_details(DapProblemType::MissingTaskId, None),
            Error::UnrecognizedAggregationJob(task_id, _) => {
                conn.with_problem_details(DapProblemType::UnrecognizedAggregationJob, Some(task_id))
            }
            Error::DeletedCollectionJob(_) => conn.with_status(Status::NoContent),
            Error::UnrecognizedCollectionJob(_) => conn.with_status(Status::NotFound),
            Error::OutdatedHpkeConfig(task_id, _) => {
                conn.with_problem_details(DapProblemType::OutdatedConfig, Some(task_id))
            }
            Error::ReportTooEarly(task_id, _, _) => {
                conn.with_problem_details(DapProblemType::ReportTooEarly, Some(task_id))
            }
            Error::UnauthorizedRequest(task_id) => {
                conn.with_problem_details(DapProblemType::UnauthorizedRequest, Some(task_id))
            }
            Error::InvalidBatchSize(task_id, _) => {
                conn.with_problem_details(DapProblemType::InvalidBatchSize, Some(task_id))
            }
            Error::BatchInvalid(task_id, _) => {
                conn.with_problem_details(DapProblemType::BatchInvalid, Some(task_id))
            }
            Error::BatchOverlap(task_id, _) => {
                conn.with_problem_details(DapProblemType::BatchOverlap, Some(task_id))
            }
            Error::BatchMismatch(inner) => {
                conn.with_problem_details(DapProblemType::BatchMismatch, Some(&inner.task_id))
            }
            Error::BatchQueriedTooManyTimes(task_id, _) => {
                conn.with_problem_details(DapProblemType::BatchQueriedTooManyTimes, Some(task_id))
            }
            Error::Hpke(_)
            | Error::Datastore(_)
            | Error::Vdaf(_)
            | Error::Internal(_)
            | Error::Url(_)
            | Error::Message(_)
            | Error::HttpClient(_)
            | Error::Http { .. }
            | Error::TaskParameters(_) => conn.with_status(Status::InternalServerError),
            Error::AggregateShareRequestRejected(_, _) => conn.with_status(Status::BadRequest),
            Error::EmptyAggregation(task_id) => {
                conn.with_problem_details(DapProblemType::UnrecognizedMessage, Some(task_id))
            }
            Error::ForbiddenMutation { .. } => conn.with_status(Status::Conflict),
            Error::BadRequest(_) => conn.with_status(Status::BadRequest),
        }
    }
}

/// The number of seconds we send in the Access-Control-Max-Age header. This determines for how
/// long clients will cache the results of CORS preflight requests. Of popular browsers, Mozilla
/// Firefox has the highest Max-Age cap, at 24 hours, so we use that. Our CORS preflight handlers
/// are tightly scoped to relevant endpoints, and our CORS settings are unlikely to change.
/// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
const CORS_PREFLIGHT_CACHE_AGE: u32 = 24 * 60 * 60;

/// Wrapper around a type that implements [`Encode`]. It acts as a Trillium handler, encoding the
/// inner object and sending it as the response body, setting the Content-Type header to the
/// provided media type, and setting the status to 200.
struct EncodedBody<T> {
    object: T,
    media_type: &'static str,
}

impl<T> EncodedBody<T>
where
    T: Encode,
{
    fn new(object: T, media_type: &'static str) -> Self {
        Self { object, media_type }
    }
}

#[async_trait]
impl<T> Handler for EncodedBody<T>
where
    T: Encode + Sync + Send + 'static,
{
    async fn run(&self, conn: Conn) -> Conn {
        conn.with_header(KnownHeaderName::ContentType, self.media_type)
            .ok(self.object.get_encoded())
    }
}

/// A Trillium handler that checks for state set when sending an error response, and updates an
/// OpenTelemetry counter accordingly.
struct StatusCounter(Counter<u64>);

impl StatusCounter {
    fn new(meter: &Meter) -> Self {
        Self(
            meter
                .u64_counter("janus_aggregator_responses_total")
                .with_description(
                    "Count of requests handled by the aggregator, by method, route, and response status.",
                )
                .init(),
        )
    }
}

#[async_trait]
impl Handler for StatusCounter {
    async fn run(&self, conn: Conn) -> Conn {
        conn
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        // Check for the error code set by the Error handler implementation.
        let error_code_opt = conn.state::<ErrorCode>().map(|error_code| error_code.0);
        let error_code = if let Some(status) = conn.status() {
            if status.is_client_error() || status.is_server_error() {
                error_code_opt.unwrap_or("unknown")
            } else {
                // Set the label to an empty string on success.
                ""
            }
        } else {
            // No status is set, it will fall back to 404.
            error_code_opt.unwrap_or("unknown")
        };
        // Fetch the method.
        let method = conn.method().as_str();
        // Check for the route set by the router.
        let route = conn
            .route()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_owned());
        self.0.add(
            &Context::current(),
            1,
            &[
                KeyValue::new("method", method),
                KeyValue::new("route", route),
                KeyValue::new("error_code", error_code),
            ],
        );
        conn
    }
}

/// Constructs a Trillium handler for the aggregator.
pub fn aggregator_handler<C: Clock>(
    datastore: Arc<Datastore<C>>,
    clock: C,
    cfg: Config,
) -> Result<impl Handler, Error> {
    let meter = opentelemetry::global::meter("janus_aggregator");
    let aggregator = Arc::new(Aggregator::new(datastore, clock, &meter, cfg));

    Ok((
        State(aggregator),
        metrics("janus_aggregator"),
        Router::new()
            .without_options_handling()
            .get("hpke_config", instrumented(api(hpke_config::<C>)))
            .with_route(
                trillium::Method::Options,
                "hpke_config",
                hpke_config_cors_preflight,
            )
            .put("tasks/:task_id/reports", instrumented(api(upload::<C>)))
            .with_route(
                trillium::Method::Options,
                "tasks/:task_id/reports",
                upload_cors_preflight,
            )
            .put(
                "tasks/:task_id/aggregation_jobs/:aggregation_job_id",
                instrumented(api(aggregation_jobs_put::<C>)),
            )
            .post(
                "tasks/:task_id/aggregation_jobs/:aggregation_job_id",
                instrumented(api(aggregation_jobs_post::<C>)),
            )
            .put(
                "tasks/:task_id/collection_jobs/:collection_job_id",
                instrumented(api(collection_jobs_put::<C>)),
            )
            .post(
                "tasks/:task_id/collection_jobs/:collection_job_id",
                instrumented(api(collection_jobs_post::<C>)),
            )
            .delete(
                "tasks/:task_id/collection_jobs/:collection_job_id",
                instrumented(api(collection_jobs_delete::<C>)),
            )
            .post(
                "tasks/:task_id/aggregate_shares",
                instrumented(api(aggregate_shares::<C>)),
            ),
        StatusCounter::new(&meter),
    ))
}

/// Deserialization helper struct to extract a "task_id" parameter from a query string.
#[derive(Deserialize)]
struct HpkeConfigQuery {
    /// The optional "task_id" parameter, in base64url-encoded form.
    #[serde(default)]
    task_id: Option<String>,
}

/// API handler for the "/hpke_config" GET endpoint.
async fn hpke_config<C: Clock>(
    conn: &mut Conn,
    State(aggregator): State<Arc<Aggregator<C>>>,
) -> Result<(CacheControlDirective, EncodedBody<HpkeConfigList>), Error> {
    let query = serde_urlencoded::from_str::<HpkeConfigQuery>(conn.querystring())
        .map_err(|err| Error::BadRequest(format!("couldn't parse query string: {err}")))?;
    let hpke_config_list = aggregator
        .handle_hpke_config(query.task_id.as_ref().map(AsRef::as_ref))
        .await?;

    // Handle CORS, if the request header is present.
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        // Unconditionally allow CORS requests from all origins.
        let origin = origin.clone();
        conn.headers_mut()
            .insert(KnownHeaderName::AccessControlAllowOrigin, origin);
    }

    Ok((
        CacheControlDirective::MaxAge(StdDuration::from_secs(86400)),
        EncodedBody::new(hpke_config_list, HpkeConfigList::MEDIA_TYPE),
    ))
}

/// Handler for CORS preflight requests to "/hpke_config".
async fn hpke_config_cors_preflight(mut conn: Conn) -> Conn {
    conn.headers_mut().insert(KnownHeaderName::Allow, "GET");
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        let origin = origin.clone();
        let request_headers = conn.headers_mut();
        request_headers.insert(KnownHeaderName::AccessControlAllowOrigin, origin);
        request_headers.insert(KnownHeaderName::AccessControlAllowMethods, "GET");
        request_headers.insert(
            KnownHeaderName::AccessControlMaxAge,
            format!("{CORS_PREFLIGHT_CACHE_AGE}"),
        );
    }
    conn.set_status(Status::Ok);
    conn
}

/// API handler for the "/tasks/.../reports" PUT endpoint.
async fn upload<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<Status, Arc<Error>> {
    validate_content_type(conn, Report::MEDIA_TYPE).map_err(Arc::new)?;

    let task_id = parse_task_id(&captures).map_err(Arc::new)?;
    aggregator.handle_upload(&task_id, &body).await?;

    // Handle CORS, if the request header is present.
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        // Unconditionally allow CORS requests from all origins.
        let origin = origin.clone();
        conn.headers_mut()
            .insert(KnownHeaderName::AccessControlAllowOrigin, origin);
    }

    Ok(Status::Ok)
}

/// Handler for CORS preflight requests to "/tasks/.../reports".
async fn upload_cors_preflight(mut conn: Conn) -> Conn {
    conn.headers_mut().insert(KnownHeaderName::Allow, "PUT");
    if let Some(origin) = conn.request_headers().get(KnownHeaderName::Origin) {
        let origin = origin.clone();
        let request_headers = conn.headers_mut();
        request_headers.insert(KnownHeaderName::AccessControlAllowOrigin, origin);
        request_headers.insert(KnownHeaderName::AccessControlAllowMethods, "PUT");
        request_headers.insert(KnownHeaderName::AccessControlAllowHeaders, "content-type");
        request_headers.insert(
            KnownHeaderName::AccessControlMaxAge,
            format!("{CORS_PREFLIGHT_CACHE_AGE}"),
        );
    }
    conn.set_status(Status::Ok);
    conn
}

/// API handler for the "/tasks/.../aggregation_jobs/..." PUT endpoint.
async fn aggregation_jobs_put<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<EncodedBody<AggregationJobResp>, Error> {
    validate_content_type(
        conn,
        AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
    )?;

    let task_id = parse_task_id(&captures)?;
    let aggregation_job_id = parse_aggregation_job_id(&captures)?;
    let auth_token = parse_auth_token(conn);
    let response = aggregator
        .handle_aggregate_init(&task_id, &aggregation_job_id, &body, auth_token)
        .await?;

    Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE))
}

/// API handler for the "/tasks/.../aggregation_jobs/..." POST endpoint.
async fn aggregation_jobs_post<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<EncodedBody<AggregationJobResp>, Error> {
    validate_content_type(conn, AggregationJobContinueReq::MEDIA_TYPE)?;

    let task_id = parse_task_id(&captures)?;
    let aggregation_job_id = parse_aggregation_job_id(&captures)?;
    let auth_token = parse_auth_token(conn);
    let response = aggregator
        .handle_aggregate_continue(&task_id, &aggregation_job_id, &body, auth_token)
        .await?;

    Ok(EncodedBody::new(response, AggregationJobResp::MEDIA_TYPE))
}

/// API handler for the "/tasks/.../collection_jobs/..." PUT endpoint.
async fn collection_jobs_put<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<Status, Error> {
    validate_content_type(conn, CollectionReq::<TimeInterval>::MEDIA_TYPE)?;

    let task_id = parse_task_id(&captures)?;
    let collection_job_id = parse_collection_job_id(&captures)?;
    let auth_token = parse_auth_token(conn);
    aggregator
        .handle_create_collection_job(&task_id, &collection_job_id, &body, auth_token)
        .await?;

    Ok(Status::Created)
}

/// API handler for the "/tasks/.../collection_jobs/..." POST endpoint.
async fn collection_jobs_post<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures)): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
    ),
) -> Result<(), Error> {
    let task_id = parse_task_id(&captures)?;
    let collection_job_id = parse_collection_job_id(&captures)?;
    let auth_token = parse_auth_token(conn);
    let response_opt = aggregator
        .handle_get_collection_job(&task_id, &collection_job_id, auth_token)
        .await?;
    match response_opt {
        Some(response_bytes) => {
            conn.headers_mut().insert(
                KnownHeaderName::ContentType,
                Collection::<TimeInterval>::MEDIA_TYPE,
            );
            conn.set_status(Status::Ok);
            conn.set_body(response_bytes);
        }
        None => conn.set_status(Status::Accepted),
    }
    Ok(())
}

/// API handler for the "/tasks/.../collection_jobs/..." DELETE endpoint.
async fn collection_jobs_delete<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures)): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
    ),
) -> Result<Status, Error> {
    let task_id = parse_task_id(&captures)?;
    let collection_job_id = parse_collection_job_id(&captures)?;
    let auth_token = parse_auth_token(conn);
    aggregator
        .handle_delete_collection_job(&task_id, &collection_job_id, auth_token)
        .await?;
    Ok(Status::NoContent)
}

/// API handler for the "/tasks/.../aggregate_shares" POST endpoint.
async fn aggregate_shares<C: Clock>(
    conn: &mut Conn,
    (State(aggregator), State(captures), body): (
        State<Arc<Aggregator<C>>>,
        State<Captures<'static, 'static>>,
        Vec<u8>,
    ),
) -> Result<EncodedBody<AggregateShare>, Error> {
    validate_content_type(conn, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)?;

    let task_id = parse_task_id(&captures)?;
    let auth_token = parse_auth_token(conn);
    let share = aggregator
        .handle_aggregate_share(&task_id, &body, auth_token)
        .await?;

    Ok(EncodedBody::new(share, AggregateShare::MEDIA_TYPE))
}

/// Check the request's Content-Type header, and return an error if it is missing or not equal to
/// the expected value.
fn validate_content_type(conn: &Conn, expected_media_type: &'static str) -> Result<(), Error> {
    if let Some(content_type) = conn.request_headers().get(KnownHeaderName::ContentType) {
        if content_type != expected_media_type {
            Err(Error::BadRequest(format!(
                "wrong Content-Type header: {content_type}"
            )))
        } else {
            Ok(())
        }
    } else {
        Err(Error::BadRequest("no Content-Type header".to_owned()))
    }
}

/// Parse a [`TaskId`] from the "task_id" parameter in a set of path parameter [`Captures`].
fn parse_task_id(captures: &Captures) -> Result<TaskId, Error> {
    let encoded = captures
        .get("task_id")
        .ok_or_else(|| Error::Internal("task_id parameter is missing from captures".to_string()))?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid TaskId".to_owned()))
}

/// Parse an [`AggregationJobId`] from the "aggregation_job_id" parameter in a set of path parameter
/// [`Captures`].
fn parse_aggregation_job_id(captures: &Captures) -> Result<AggregationJobId, Error> {
    let encoded = captures.get("aggregation_job_id").ok_or_else(|| {
        Error::Internal("aggregation_job_id parameter is missing from captures".to_string())
    })?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid AggregationJobId".to_owned()))
}

/// Parse an [`CollectionJobId`] from the "collection_job_id" parameter in a set of path parameter
/// [`Captures`].
fn parse_collection_job_id(captures: &Captures) -> Result<CollectionJobId, Error> {
    let encoded = captures.get("collection_job_id").ok_or_else(|| {
        Error::Internal("collection_job_id parameter is missing from captures".to_string())
    })?;
    encoded
        .parse()
        .map_err(|_| Error::BadRequest("invalid CollectionJobId".to_owned()))
}

/// Get the value of the DAP-Auth-Token header from the request.
fn parse_auth_token(conn: &Conn) -> Option<AuthenticationToken> {
    conn.request_headers()
        .get(DAP_AUTH_HEADER)
        .map(|value| value.as_ref().to_owned().into())
}

/// Construct a DAP aggregator server, listening on the provided [`SocketAddr`]. If the
/// `SocketAddr`'s `port` is 0, an ephemeral port is used. Returns a `SocketAddr` representing the
/// address and port the server are listening on and a future that can be `await`ed to wait until
/// the server shuts down.
pub async fn aggregator_server<C: Clock>(
    datastore: Arc<Datastore<C>>,
    clock: C,
    cfg: Config,
    listen_address: SocketAddr,
    response_headers: Headers,
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()> + 'static), Error> {
    let stopper = Stopper::new();
    tokio::spawn({
        let stopper = stopper.clone();
        async move {
            shutdown_signal.await;
            stopper.stop();
        }
    });

    let (sender, receiver) = oneshot::channel();
    let init = Init::new(|info: Info| async move {
        // Ignore error if the receiver is dropped.
        let _ = sender.send(info.tcp_socket_addr().copied());
    });

    let server_config = trillium_tokio::config()
        .with_port(listen_address.port())
        .with_host(&listen_address.ip().to_string())
        .with_stopper(stopper)
        .without_signals();
    let handler = (
        init,
        response_headers,
        aggregator_handler(datastore, clock, cfg)?,
    );

    let task_handle = tokio::spawn(server_config.run_async(handler));

    let address = receiver
        .await
        .map_err(|err| Error::Internal(format!("error waiting for socket address: {err}")))?
        .ok_or_else(|| Error::Internal("could not get server's socket address".to_string()))?;

    let future = async {
        if let Err(err) = task_handle.await {
            if let Ok(reason) = err.try_into_panic() {
                panic::resume_unwind(reason);
            }
        }
    };

    Ok((address, future))
}

/// Convenience method to perform an HTTP request to the helper. This includes common
/// metrics and error handling functionality.
#[tracing::instrument(
    skip(
        http_client,
        url,
        request,
        auth_token,
        http_request_duration_histogram,
    ),
    fields(url = %url),
    err,
)]
async fn send_request_to_helper<T: Encode>(
    http_client: &Client,
    method: Method,
    url: Url,
    content_type: &str,
    request: T,
    auth_token: &AuthenticationToken,
    http_request_duration_histogram: &Histogram<f64>,
) -> Result<Bytes, Error> {
    let domain = url.domain().unwrap_or_default().to_string();
    let endpoint = url
        .path_segments()
        .and_then(|mut split| split.next_back())
        .unwrap_or_default()
        .to_string();
    let request_body = request.get_encoded();

    let start = Instant::now();
    let response_result = http_client
        .request(method, url)
        .header(CONTENT_TYPE, content_type)
        .header(DAP_AUTH_HEADER, auth_token.as_ref())
        .body(request_body)
        .send()
        .await;
    let response = match response_result {
        Ok(response) => response,
        Err(error) => {
            http_request_duration_histogram.record(
                &Context::current(),
                start.elapsed().as_secs_f64(),
                &[
                    KeyValue::new("status", "error"),
                    KeyValue::new("domain", domain),
                    KeyValue::new("endpoint", endpoint),
                ],
            );
            return Err(error.into());
        }
    };

    let status = response.status();
    if !status.is_success() {
        http_request_duration_histogram.record(
            &Context::current(),
            start.elapsed().as_secs_f64(),
            &[
                KeyValue::new("status", "error"),
                KeyValue::new("domain", domain),
                KeyValue::new("endpoint", endpoint),
            ],
        );
        let problem_details = response_to_problem_details(response).await;
        let dap_problem_type = problem_details
            .type_url
            .as_ref()
            .and_then(|str| str.parse::<DapProblemType>().ok());
        return Err(Error::Http {
            problem_details: Box::new(problem_details),
            dap_problem_type,
        });
    }

    match response.bytes().await {
        Ok(response_body) => {
            http_request_duration_histogram.record(
                &Context::current(),
                start.elapsed().as_secs_f64(),
                &[
                    KeyValue::new("status", "success"),
                    KeyValue::new("domain", domain),
                    KeyValue::new("endpoint", endpoint),
                ],
            );
            Ok(response_body)
        }
        Err(error) => {
            http_request_duration_histogram.record(
                &Context::current(),
                start.elapsed().as_secs_f64(),
                &[
                    KeyValue::new("status", "error"),
                    KeyValue::new("domain", domain),
                    KeyValue::new("endpoint", endpoint),
                ],
            );
            Err(error.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::{
        aggregate_init_tests::{put_aggregation_job, setup_aggregate_init_test},
        aggregation_job_continue::test_util::{
            post_aggregation_job_and_decode, post_aggregation_job_expecting_error,
        },
        aggregator_handler,
        collection_job_tests::setup_collection_job_test_case,
        send_request_to_helper, Aggregator, BatchMismatch, Config, Error,
    };
    use assert_matches::assert_matches;
    use futures::future::{join_all, try_join_all};
    use http::Method;
    use itertools::Itertools;
    use janus_aggregator_core::{
        datastore::{
            models::{
                AggregateShareJob, AggregationJob, AggregationJobState, BatchAggregation,
                CollectionJob, CollectionJobState, PrepareMessageOrShare, ReportAggregation,
                ReportAggregationState,
            },
            test_util::{ephemeral_datastore, EphemeralDatastore},
            Datastore,
        },
        query_type::CollectableQueryType,
        task::{test_util::TaskBuilder, QueryType, Task, VerifyKey},
    };
    use janus_core::{
        hpke::{
            self, test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo, Label,
        },
        report_id::ReportIdChecksumExt,
        task::{AuthenticationToken, VdafInstance, PRIO3_VERIFY_KEY_LENGTH},
        test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf},
        time::{Clock, DurationExt, IntervalExt, MockClock, RealClock, TimeExt},
    };
    use janus_messages::{
        problem_type::{DapProblemType, DapProblemTypeParseError},
        query_type::TimeInterval,
        AggregateShare as AggregateShareMessage, AggregateShareAad, AggregateShareReq,
        AggregationJobContinueReq, AggregationJobId, AggregationJobInitializeReq,
        AggregationJobResp, AggregationJobRound, BatchSelector, Collection, CollectionJobId,
        CollectionReq, Duration, Extension, ExtensionType, HpkeCiphertext, HpkeConfig,
        HpkeConfigId, HpkeConfigList, InputShareAad, Interval, PartialBatchSelector,
        PlaintextInputShare, PrepareStep, PrepareStepResult, Query, Report, ReportId,
        ReportIdChecksum, ReportMetadata, ReportShare, ReportShareError, Role, TaskId, Time,
    };
    use opentelemetry::global::meter;
    use prio::{
        codec::{Decode, Encode},
        field::Field64,
        vdaf::{
            self,
            prio3::{Prio3, Prio3Count},
            AggregateShare, Aggregator as _, Client as VdafClient, OutputShare,
        },
    };
    use rand::random;
    use reqwest::Client;
    use serde_json::json;
    use std::{
        borrow::Cow, collections::HashSet, io::Cursor, iter, sync::Arc,
        time::Duration as StdDuration,
    };
    use trillium::{KnownHeaderName, Status};
    use trillium_testing::{
        assert_headers,
        prelude::{delete, get, post, put},
        TestConn,
    };

    const DUMMY_VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

    pub(crate) fn default_aggregator_config() -> Config {
        // Enable upload write batching & batch aggregation sharding by default, in hopes that we
        // can shake out any bugs.
        Config {
            max_upload_batch_size: 5,
            max_upload_batch_write_delay: StdDuration::from_millis(100),
            batch_aggregation_shard_count: 32,
        }
    }

    #[tokio::test]
    async fn hpke_config() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .build();
        let unknown_task_id: TaskId = random();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let want_hpke_key = task.current_hpke_key().clone();

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        // No task ID provided
        let mut test_conn = get("/hpke_config").run_async(&handler).await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:missingTaskID",
                "title": "HPKE configuration was requested without specifying a task ID.",
            })
        );

        // Unknown task ID provided
        let mut test_conn = get(&format!("/hpke_config?task_id={unknown_task_id}"))
            .run_async(&handler)
            .await;
        // Expected status and problem type should be per the protocol
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{unknown_task_id}"),
            })
        );

        // Recognized task ID provided
        let mut test_conn = get(&format!("/hpke_config?task_id={}", task.id()))
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "cache-control" => "max-age=86400",
            "content-type" => (HpkeConfigList::MEDIA_TYPE),
        );

        let bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let hpke_config_list = HpkeConfigList::decode(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(
            hpke_config_list.hpke_configs(),
            &[want_hpke_key.config().clone()]
        );

        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
        let message = b"this is a message";
        let associated_data = b"some associated data";

        let ciphertext = hpke::seal(
            &hpke_config_list.hpke_configs()[0],
            &application_info,
            message,
            associated_data,
        )
        .unwrap();
        let plaintext = hpke::open(
            want_hpke_key.config(),
            want_hpke_key.private_key(),
            &application_info,
            &ciphertext,
            associated_data,
        )
        .unwrap();
        assert_eq!(&plaintext, message);
    }

    #[tokio::test]
    async fn hpke_config_cors_headers() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        // Check for appropriate CORS headers in response to a preflight request.
        let test_conn = TestConn::build(
            trillium::Method::Options,
            &format!("/hpke_config?task_id={}", task.id()),
            (),
        )
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .with_request_header(KnownHeaderName::AccessControlRequestMethod, "GET")
        .run_async(&handler)
        .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/",
            "access-control-allow-methods"=> "GET",
            "access-control-max-age"=> "86400",
        );

        // Check for appropriate CORS headers with a simple GET request.
        let test_conn = get(&format!("/hpke_config?task_id={}", task.id()))
            .with_request_header(KnownHeaderName::Origin, "https://example.com/")
            .run_async(&handler)
            .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/",
        );
    }

    fn create_report_with_id(task: &Task, report_timestamp: Time, id: ReportId) -> Report {
        assert_eq!(task.vdaf(), &VdafInstance::Prio3Count);

        let vdaf = Prio3Count::new_count(2).unwrap();
        let hpke_key = task.current_hpke_key();
        let report_metadata = ReportMetadata::new(id, report_timestamp);

        let (public_share, measurements) = vdaf.shard(&1, id.as_ref()).unwrap();

        let associated_data = InputShareAad::new(
            *task.id(),
            report_metadata.clone(),
            public_share.get_encoded(),
        );

        let leader_ciphertext = hpke::seal(
            hpke_key.config(),
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
            &PlaintextInputShare::new(Vec::new(), measurements[0].get_encoded()).get_encoded(),
            &associated_data.get_encoded(),
        )
        .unwrap();
        let helper_ciphertext = hpke::seal(
            hpke_key.config(),
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
            &PlaintextInputShare::new(Vec::new(), measurements[1].get_encoded()).get_encoded(),
            &associated_data.get_encoded(),
        )
        .unwrap();

        Report::new(
            report_metadata,
            public_share.get_encoded(),
            Vec::from([leader_ciphertext, helper_ciphertext]),
        )
    }

    fn create_report(task: &Task, report_timestamp: Time) -> Report {
        create_report_with_id(task, report_timestamp, random())
    }

    #[tokio::test]
    async fn upload_handler() {
        async fn check_response(
            test_conn: &mut TestConn,
            desired_status: Status,
            desired_type: &str,
            desired_title: &str,
            desired_task_id: &TaskId,
        ) {
            assert_eq!(test_conn.status(), Some(desired_status));
            let problem_details: serde_json::Value = serde_json::from_slice(
                &test_conn
                    .take_response_body()
                    .unwrap()
                    .into_bytes()
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                problem_details,
                json!({
                    "status": desired_status as u16,
                    "type": format!("urn:ietf:params:ppm:dap:error:{desired_type}"),
                    "title": desired_title,
                    "taskid": format!("{desired_task_id}"),
                }),
            )
        }

        install_test_trace_subscriber();

        const REPORT_EXPIRY_AGE: u64 = 1_000_000;
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .with_report_expiry_age(Some(Duration::from_seconds(REPORT_EXPIRY_AGE)))
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        datastore.put_task(&task).await.unwrap();
        let report = create_report(&task, clock.now());
        let handler = aggregator_handler(
            Arc::clone(&datastore),
            clock.clone(),
            default_aggregator_config(),
        )
        .unwrap();

        // Upload a report. Do this twice to prove that PUT is idempotent.
        for _ in 0..2 {
            let mut test_conn = put(task.report_upload_uri().unwrap().path())
                .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
                .with_request_body(report.get_encoded())
                .run_async(&handler)
                .await;

            assert_eq!(test_conn.status(), Some(Status::Ok));
            assert!(test_conn.take_response_body().is_none());
        }

        let accepted_report_id = report.metadata().id();

        // Verify that new reports using an existing report ID are rejected with reportRejected
        let duplicate_id_report = create_report_with_id(&task, clock.now(), *accepted_report_id);
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(duplicate_id_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportRejected",
            "Report could not be processed.",
            task.id(),
        )
        .await;

        // Verify that reports older than the report expiry age are rejected with the reportRejected
        // error type.
        let gc_eligible_report = Report::new(
            ReportMetadata::new(
                random(),
                clock
                    .now()
                    .sub(&Duration::from_seconds(REPORT_EXPIRY_AGE + 30000))
                    .unwrap(),
            ),
            report.public_share().to_vec(),
            report.encrypted_input_shares().to_vec(),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(gc_eligible_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportRejected",
            "Report could not be processed.",
            task.id(),
        )
        .await;

        // should reject a report with only one share with the unrecognizedMessage type.
        let bad_report = Report::new(
            report.metadata().clone(),
            report.public_share().to_vec(),
            Vec::from([report.encrypted_input_shares()[0].clone()]),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(bad_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "unrecognizedMessage",
            "The message type for a response was incorrect or the payload was malformed.",
            task.id(),
        )
        .await;

        // should reject a report using the wrong HPKE config for the leader, and reply with
        // the error type outdatedConfig.
        let unused_hpke_config_id = (0..)
            .map(HpkeConfigId::from)
            .find(|id| !task.hpke_keys().contains_key(id))
            .unwrap();
        let bad_report = Report::new(
            report.metadata().clone(),
            report.public_share().to_vec(),
            Vec::from([
                HpkeCiphertext::new(
                    unused_hpke_config_id,
                    report.encrypted_input_shares()[0]
                        .encapsulated_key()
                        .to_vec(),
                    report.encrypted_input_shares()[0].payload().to_vec(),
                ),
                report.encrypted_input_shares()[1].clone(),
            ]),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(bad_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "outdatedConfig",
            "The message was generated using an outdated configuration.",
            task.id(),
        )
        .await;

        // Reports from the future should be rejected.
        let bad_report_time = clock
            .now()
            .add(&Duration::from_minutes(10).unwrap())
            .unwrap()
            .add(&Duration::from_seconds(1))
            .unwrap();
        let bad_report = Report::new(
            ReportMetadata::new(*report.metadata().id(), bad_report_time),
            report.public_share().to_vec(),
            report.encrypted_input_shares().to_vec(),
        );
        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(bad_report.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportTooEarly",
            "Report could not be processed because it arrived too early.",
            task.id(),
        )
        .await;

        // Reports with timestamps past the task's expiration should be rejected.
        let task_expire_soon = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .with_task_expiration(clock.now().add(&Duration::from_seconds(60)).unwrap())
        .build();
        datastore.put_task(&task_expire_soon).await.unwrap();
        let report_2 = create_report(
            &task_expire_soon,
            clock.now().add(&Duration::from_seconds(120)).unwrap(),
        );
        let mut test_conn = put(task_expire_soon.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(report_2.get_encoded())
            .run_async(&handler)
            .await;
        check_response(
            &mut test_conn,
            Status::BadRequest,
            "reportRejected",
            "Report could not be processed.",
            task_expire_soon.id(),
        )
        .await;

        // Check for appropriate CORS headers in response to a preflight request.
        let test_conn = TestConn::build(
            trillium::Method::Options,
            task.report_upload_uri().unwrap().path(),
            (),
        )
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .with_request_header(KnownHeaderName::AccessControlRequestMethod, "PUT")
        .with_request_header(KnownHeaderName::AccessControlRequestHeaders, "content-type")
        .run_async(&handler)
        .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/",
            "access-control-allow-methods"=> "PUT",
            "access-control-allow-headers" => "content-type",
            "access-control-max-age"=> "86400",
        );

        // Check for appropriate CORS headers in response to the main request.
        let test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::Origin, "https://example.com/")
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(
                Report::new(
                    ReportMetadata::new(
                        random(),
                        clock
                            .now()
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                    ),
                    report.public_share().to_vec(),
                    report.encrypted_input_shares().to_vec(),
                )
                .get_encoded(),
            )
            .run_async(&handler)
            .await;
        assert!(test_conn.status().unwrap().is_success());
        assert_headers!(
            &test_conn,
            "access-control-allow-origin" => "https://example.com/"
        );
    }

    // Helper should not expose /upload endpoint
    #[tokio::test]
    async fn upload_handler_helper() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Helper,
        )
        .build();
        datastore.put_task(&task).await.unwrap();
        let report = create_report(&task, clock.now());

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        let mut test_conn = put(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, Report::MEDIA_TYPE)
            .with_request_body(report.get_encoded())
            .run_async(&handler)
            .await;

        assert!(!test_conn.status().unwrap().is_success());
        let bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(
            problem_details
                .as_object()
                .unwrap()
                .get("status")
                .unwrap()
                .as_u64()
                .unwrap(),
            test_conn.status().unwrap() as u16 as u64
        );
    }

    async fn setup_upload_test(
        cfg: Config,
    ) -> (
        Prio3Count,
        Aggregator<MockClock>,
        MockClock,
        Task,
        Arc<Datastore<MockClock>>,
        EphemeralDatastore,
    ) {
        let clock = MockClock::default();
        let vdaf = Prio3Count::new_count(2).unwrap();
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .build();

        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        datastore.put_task(&task).await.unwrap();

        let aggregator = Aggregator::new(
            Arc::clone(&datastore),
            clock.clone(),
            &meter("janus_aggregator"),
            cfg,
        );

        (
            vdaf,
            aggregator,
            clock,
            task,
            datastore,
            ephemeral_datastore,
        )
    }

    #[tokio::test]
    async fn upload() {
        install_test_trace_subscriber();

        let (vdaf, aggregator, clock, task, datastore, _ephemeral_datastore) =
            setup_upload_test(Config {
                max_upload_batch_size: 1000,
                max_upload_batch_write_delay: StdDuration::from_millis(500),
                ..Default::default()
            })
            .await;
        let report = create_report(&task, clock.now());

        aggregator
            .handle_upload(task.id(), &report.get_encoded())
            .await
            .unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                let (vdaf, task_id, report_id) =
                    (vdaf.clone(), *task.id(), *report.metadata().id());
                Box::pin(async move { tx.get_client_report(&vdaf, &task_id, &report_id).await })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(task.id(), got_report.task_id());
        assert_eq!(report.metadata(), got_report.metadata());

        // Report uploads are idempotent
        aggregator
            .handle_upload(task.id(), &report.get_encoded())
            .await
            .unwrap();

        // Reports may not be mutated
        let mutated_report = create_report_with_id(&task, clock.now(), *report.metadata().id());
        let error = aggregator
            .handle_upload(task.id(), &mutated_report.get_encoded())
            .await
            .unwrap_err();
        assert_matches!(error.as_ref(), Error::ReportRejected(task_id, report_id, timestamp) => {
            assert_eq!(task.id(), task_id);
            assert_eq!(mutated_report.metadata().id(), report_id);
            assert_eq!(mutated_report.metadata().time(), timestamp);
        });
    }

    #[tokio::test]
    async fn upload_batch() {
        install_test_trace_subscriber();

        const BATCH_SIZE: usize = 100;
        let (vdaf, aggregator, clock, task, datastore, _ephemeral_datastore) =
            setup_upload_test(Config {
                max_upload_batch_size: BATCH_SIZE,
                max_upload_batch_write_delay: StdDuration::from_secs(86400),
                ..Default::default()
            })
            .await;

        let reports: Vec<_> = iter::repeat_with(|| create_report(&task, clock.now()))
            .take(BATCH_SIZE)
            .collect();
        let want_report_ids: HashSet<_> = reports.iter().map(|r| *r.metadata().id()).collect();

        let aggregator = Arc::new(aggregator);
        try_join_all(reports.iter().map(|r| {
            let aggregator = Arc::clone(&aggregator);
            let enc = r.get_encoded();
            let task_id = task.id();
            async move { aggregator.handle_upload(task_id, &enc).await }
        }))
        .await
        .unwrap();

        let got_report_ids = datastore
            .run_tx(|tx| {
                let vdaf = vdaf.clone();
                let task = task.clone();
                Box::pin(async move { tx.get_client_reports_for_task(&vdaf, task.id()).await })
            })
            .await
            .unwrap()
            .iter()
            .map(|r| *r.metadata().id())
            .collect();

        assert_eq!(want_report_ids, got_report_ids);
    }

    #[tokio::test]
    async fn upload_wrong_number_of_encrypted_shares() {
        install_test_trace_subscriber();

        let (_, aggregator, clock, task, _, _ephemeral_datastore) =
            setup_upload_test(default_aggregator_config()).await;
        let report = create_report(&task, clock.now());
        let report = Report::new(
            report.metadata().clone(),
            report.public_share().to_vec(),
            Vec::from([report.encrypted_input_shares()[0].clone()]),
        );

        assert_matches!(
            aggregator
                .handle_upload(task.id(), &report.get_encoded())
                .await
                .unwrap_err()
                .as_ref(),
            Error::UnrecognizedMessage(_, _)
        );
    }

    #[tokio::test]
    async fn upload_wrong_hpke_config_id() {
        install_test_trace_subscriber();

        let (_, aggregator, clock, task, _, _ephemeral_datastore) =
            setup_upload_test(default_aggregator_config()).await;
        let report = create_report(&task, clock.now());

        let unused_hpke_config_id = (0..)
            .map(HpkeConfigId::from)
            .find(|id| !task.hpke_keys().contains_key(id))
            .unwrap();

        let report = Report::new(
            report.metadata().clone(),
            report.public_share().to_vec(),
            Vec::from([
                HpkeCiphertext::new(
                    unused_hpke_config_id,
                    report.encrypted_input_shares()[0]
                        .encapsulated_key()
                        .to_vec(),
                    report.encrypted_input_shares()[0].payload().to_vec(),
                ),
                report.encrypted_input_shares()[1].clone(),
            ]),
        );

        assert_matches!(aggregator.handle_upload(task.id(), &report.get_encoded()).await.unwrap_err().as_ref(), Error::OutdatedHpkeConfig(task_id, config_id) => {
            assert_eq!(task.id(), task_id);
            assert_eq!(config_id, &unused_hpke_config_id);
        });
    }

    #[tokio::test]
    async fn upload_report_in_the_future_boundary_condition() {
        install_test_trace_subscriber();

        let (vdaf, aggregator, clock, task, datastore, _ephemeral_datastore) =
            setup_upload_test(default_aggregator_config()).await;
        let report = create_report(&task, clock.now().add(task.tolerable_clock_skew()).unwrap());

        aggregator
            .handle_upload(task.id(), &report.get_encoded())
            .await
            .unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                let (vdaf, task_id, report_id) =
                    (vdaf.clone(), *task.id(), *report.metadata().id());
                Box::pin(async move { tx.get_client_report(&vdaf, &task_id, &report_id).await })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(task.id(), got_report.task_id());
        assert_eq!(report.metadata(), got_report.metadata());
    }

    #[tokio::test]
    async fn upload_report_in_the_future_past_clock_skew() {
        install_test_trace_subscriber();

        let (_, aggregator, clock, task, _, _ephemeral_datastore) =
            setup_upload_test(default_aggregator_config()).await;
        let report = create_report(
            &task,
            clock
                .now()
                .add(task.tolerable_clock_skew())
                .unwrap()
                .add(&Duration::from_seconds(1))
                .unwrap(),
        );

        let upload_error = aggregator
            .handle_upload(task.id(), &report.get_encoded())
            .await
            .unwrap_err();

        assert_matches!(upload_error.as_ref(), Error::ReportTooEarly(task_id, report_id, time) => {
            assert_eq!(task.id(), task_id);
            assert_eq!(report.metadata().id(), report_id);
            assert_eq!(report.metadata().time(), time);
        });
    }

    #[tokio::test]
    async fn upload_report_for_collected_batch() {
        install_test_trace_subscriber();

        let (_, aggregator, clock, task, datastore, _ephemeral_datastore) =
            setup_upload_test(default_aggregator_config()).await;
        let report = create_report(&task, clock.now());

        // Insert a collection job for the batch interval including our report.
        let batch_interval = Interval::new(
            report
                .metadata()
                .time()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            *task.time_precision(),
        )
        .unwrap();
        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.put_collection_job(&CollectionJob::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        random(),
                        batch_interval,
                        (),
                        CollectionJobState::Start,
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Try to upload the report, verify that we get the expected error.
        assert_matches!(aggregator.handle_upload(task.id(), &report.get_encoded()).await.unwrap_err().as_ref(), Error::ReportRejected(err_task_id, err_report_id, err_time) => {
            assert_eq!(task.id(), err_task_id);
            assert_eq!(report.metadata().id(), err_report_id);
            assert_eq!(report.metadata().time(), err_time);
        });
    }

    #[tokio::test]
    async fn aggregate_leader() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Leader,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let request = AggregationJobInitializeReq::new(
            Vec::new(),
            PartialBatchSelector::new_time_interval(),
            Vec::new(),
        );

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();
        let aggregation_job_id: AggregationJobId = random();

        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;

        assert!(!test_conn.status().unwrap().is_success());
        let bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(
            problem_details
                .as_object()
                .unwrap()
                .get("status")
                .unwrap()
                .as_u64()
                .unwrap(),
            test_conn.status().unwrap() as u16 as u64
        );

        // Check that CORS headers don't bleed over to other routes.
        assert!(test_conn
            .response_headers()
            .get("access-control-allow-origin")
            .is_none());
        assert!(test_conn
            .response_headers()
            .get("access-control-allow-methods")
            .is_none());
        assert!(test_conn
            .response_headers()
            .get("access-control-max-age")
            .is_none());

        let test_conn = TestConn::build(
            trillium::Method::Options,
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
            (),
        )
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .with_request_header(KnownHeaderName::AccessControlRequestMethod, "PUT")
        .run_async(&handler)
        .await;
        assert!(test_conn
            .response_headers()
            .get(KnownHeaderName::AccessControlAllowMethods)
            .is_none());
    }

    #[tokio::test]
    async fn aggregate_wrong_agg_auth_token() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let request = AggregationJobInitializeReq::new(
            Vec::new(),
            PartialBatchSelector::new_time_interval(),
            Vec::new(),
        );

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();
        let aggregation_job_id: AggregationJobId = random();

        let mut test_conn = put(task
            .aggregation_job_uri(&aggregation_job_id)
            .unwrap()
            .path())
        .with_request_header(
            "DAP-Auth-Token",
            random::<AuthenticationToken>().as_ref().to_owned(),
        )
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(request.get_encoded())
        .run_async(&handler)
        .await;

        let want_status = 400;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap() as u16);

        let mut test_conn = put(task
            .aggregation_job_uri(&aggregation_job_id)
            .unwrap()
            .path())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(request.get_encoded())
        .run_async(&handler)
        .await;

        let want_status = 400;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap() as u16);
    }

    #[tokio::test]
    // Silence the unit_arg lint so that we can work with dummy_vdaf::Vdaf::InputShare values (whose
    // type is ()).
    #[allow(clippy::unit_arg)]
    async fn aggregate_init() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        let vdaf = dummy_vdaf::Vdaf::new();
        let verify_key: VerifyKey<0> = task.primary_vdaf_verify_key().unwrap();
        let hpke_key = task.current_hpke_key();

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_0.id(),
            &(),
        );
        let report_share_0 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_0,
            hpke_key.config(),
            &transcript.public_share,
            Vec::new(),
            &transcript.input_shares[1],
        );

        // report_share_1 fails decryption.
        let report_metadata_1 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_1.id(),
            &(),
        );
        let report_share_1 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_1.clone(),
            hpke_key.config(),
            &transcript.public_share,
            Vec::new(),
            &transcript.input_shares[1],
        );
        let encrypted_input_share = report_share_1.encrypted_input_share();
        let mut corrupted_payload = encrypted_input_share.payload().to_vec();
        corrupted_payload[0] ^= 0xFF;
        let corrupted_input_share = HpkeCiphertext::new(
            *encrypted_input_share.config_id(),
            encrypted_input_share.encapsulated_key().to_vec(),
            corrupted_payload,
        );
        let encoded_public_share = transcript.public_share.get_encoded();
        let report_share_1 = ReportShare::new(
            report_metadata_1,
            encoded_public_share.clone(),
            corrupted_input_share,
        );

        // report_share_2 fails decoding due to an issue with the input share.
        let report_metadata_2 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_2.id(),
            &(),
        );
        let mut input_share_bytes = transcript.input_shares[1].get_encoded();
        input_share_bytes.push(0); // can no longer be decoded.
        let report_share_2 = generate_helper_report_share_for_plaintext(
            report_metadata_2.clone(),
            hpke_key.config(),
            encoded_public_share.clone(),
            &input_share_bytes,
            &InputShareAad::new(*task.id(), report_metadata_2, encoded_public_share).get_encoded(),
        );

        // report_share_3 has an unknown HPKE config ID.
        let report_metadata_3 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_3.id(),
            &(),
        );
        let wrong_hpke_config = loop {
            let hpke_config = generate_test_hpke_config_and_private_key().config().clone();
            if task.hpke_keys().contains_key(hpke_config.id()) {
                continue;
            }
            break hpke_config;
        };
        let report_share_3 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_3,
            &wrong_hpke_config,
            &transcript.public_share,
            Vec::new(),
            &transcript.input_shares[1],
        );

        // report_share_4 has already been aggregated in another aggregation job, with the same
        // aggregation parameter.
        let report_metadata_4 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_4.id(),
            &(),
        );
        let report_share_4 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_4,
            hpke_key.config(),
            &transcript.public_share,
            Vec::new(),
            &transcript.input_shares[1],
        );

        // report_share_5 falls into a batch that has already been collected.
        let past_clock = MockClock::new(Time::from_seconds_since_epoch(
            task.time_precision().as_seconds() / 2,
        ));
        let report_metadata_5 = ReportMetadata::new(
            random(),
            past_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_5.id(),
            &(),
        );
        let report_share_5 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_5,
            hpke_key.config(),
            &transcript.public_share,
            Vec::new(),
            &transcript.input_shares[1],
        );

        // report_share_6 fails decoding due to an issue with the public share.
        let public_share_6 = Vec::from([0]);
        let report_metadata_6 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_6.id(),
            &(),
        );
        let report_share_6 = generate_helper_report_share_for_plaintext(
            report_metadata_6.clone(),
            hpke_key.config(),
            public_share_6.clone(),
            &transcript.input_shares[1].get_encoded(),
            &InputShareAad::new(*task.id(), report_metadata_6, public_share_6).get_encoded(),
        );

        // report_share_7 fails due to having repeated extensions.
        let report_metadata_7 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(0),
            report_metadata_7.id(),
            &(),
        );
        let report_share_7 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_7,
            hpke_key.config(),
            &transcript.public_share,
            Vec::from([
                Extension::new(ExtensionType::Tbd, Vec::new()),
                Extension::new(ExtensionType::Tbd, Vec::new()),
            ]),
            &transcript.input_shares[0],
        );

        // report_share_8 has already been aggregated in another aggregation job, with a different
        // aggregation parameter.
        let report_metadata_8 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &dummy_vdaf::AggregationParam(1),
            report_metadata_8.id(),
            &(),
        );
        let report_share_8 = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            report_metadata_8,
            hpke_key.config(),
            &transcript.public_share,
            Vec::new(),
            &transcript.input_shares[1],
        );

        let (conflicting_aggregation_job, non_conflicting_aggregation_job) = datastore
            .run_tx(|tx| {
                let (task, report_share_4, report_share_8) =
                    (task.clone(), report_share_4.clone(), report_share_8.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    // report_share_4 and report_share_8 are already in the datastore as they were
                    // referenced by existing aggregation jobs.
                    tx.put_report_share(task.id(), &report_share_4).await?;
                    tx.put_report_share(task.id(), &report_share_8).await?;

                    // Put in an aggregation job and report aggregation for report_share_4. It uses
                    // the same aggregation parameter as the aggregation job this test will later
                    // add and so should cause report_share_4 to fail to prepare.
                    let conflicting_aggregation_job = AggregationJob::new(
                        *task.id(),
                        random(),
                        dummy_vdaf::AggregationParam(0),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );
                    tx.put_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &conflicting_aggregation_job,
                    )
                    .await
                    .unwrap();
                    tx.put_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                        *task.id(),
                        *conflicting_aggregation_job.id(),
                        *report_share_4.metadata().id(),
                        *report_share_4.metadata().time(),
                        0,
                        ReportAggregationState::Start,
                    ))
                    .await
                    .unwrap();

                    // Put in an aggregation job and report aggregation for report_share_8, using a
                    // a different aggregation parameter. As the aggregation parameter differs,
                    // report_share_8 should prepare successfully in the aggregation job we'll PUT
                    // later.
                    let non_conflicting_aggregation_job = AggregationJob::new(
                        *task.id(),
                        random(),
                        dummy_vdaf::AggregationParam(1),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    );
                    tx.put_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &non_conflicting_aggregation_job,
                    )
                    .await
                    .unwrap();
                    tx.put_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                        *task.id(),
                        *non_conflicting_aggregation_job.id(),
                        *report_share_8.metadata().id(),
                        *report_share_8.metadata().time(),
                        0,
                        ReportAggregationState::Start,
                    ))
                    .await
                    .unwrap();

                    // Put in an aggregate share job for the interval that report_share_5 falls into
                    // which should cause it to later fail to prepare.
                    tx.put_aggregate_share_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        &AggregateShareJob::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            dummy_vdaf::AggregationParam(0),
                            dummy_vdaf::AggregateShare(0),
                            0,
                            ReportIdChecksum::default(),
                        ),
                    )
                    .await?;

                    Ok((conflicting_aggregation_job, non_conflicting_aggregation_job))
                })
            })
            .await
            .unwrap();

        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([
                report_share_0.clone(),
                report_share_1.clone(),
                report_share_2.clone(),
                report_share_3.clone(),
                report_share_4.clone(),
                report_share_5.clone(),
                report_share_6.clone(),
                report_share_7.clone(),
                report_share_8.clone(),
            ]),
        );

        // Create aggregator filter, send request, and parse response. Do this twice to prove that
        // the request is idempotent.
        let handler =
            aggregator_handler(Arc::clone(&datastore), clock, default_aggregator_config()).unwrap();
        let aggregation_job_id: AggregationJobId = random();

        for _ in 0..2 {
            let mut test_conn =
                put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
            assert_eq!(test_conn.status(), Some(Status::Ok));
            assert_headers!(
                &test_conn,
                "content-type" => (AggregationJobResp::MEDIA_TYPE)
            );
            let body_bytes = test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap();
            let aggregate_resp = AggregationJobResp::get_decoded(&body_bytes).unwrap();

            // Validate response.
            assert_eq!(aggregate_resp.prepare_steps().len(), 9);

            let prepare_step_0 = aggregate_resp.prepare_steps().get(0).unwrap();
            assert_eq!(prepare_step_0.report_id(), report_share_0.metadata().id());
            assert_matches!(prepare_step_0.result(), &PrepareStepResult::Continued(..));

            let prepare_step_1 = aggregate_resp.prepare_steps().get(1).unwrap();
            assert_eq!(prepare_step_1.report_id(), report_share_1.metadata().id());
            assert_matches!(
                prepare_step_1.result(),
                &PrepareStepResult::Failed(ReportShareError::HpkeDecryptError)
            );

            let prepare_step_2 = aggregate_resp.prepare_steps().get(2).unwrap();
            assert_eq!(prepare_step_2.report_id(), report_share_2.metadata().id());
            assert_matches!(
                prepare_step_2.result(),
                &PrepareStepResult::Failed(ReportShareError::UnrecognizedMessage)
            );

            let prepare_step_3 = aggregate_resp.prepare_steps().get(3).unwrap();
            assert_eq!(prepare_step_3.report_id(), report_share_3.metadata().id());
            assert_matches!(
                prepare_step_3.result(),
                &PrepareStepResult::Failed(ReportShareError::HpkeUnknownConfigId)
            );

            let prepare_step_4 = aggregate_resp.prepare_steps().get(4).unwrap();
            assert_eq!(prepare_step_4.report_id(), report_share_4.metadata().id());
            assert_eq!(
                prepare_step_4.result(),
                &PrepareStepResult::Failed(ReportShareError::ReportReplayed)
            );

            let prepare_step_5 = aggregate_resp.prepare_steps().get(5).unwrap();
            assert_eq!(prepare_step_5.report_id(), report_share_5.metadata().id());
            assert_eq!(
                prepare_step_5.result(),
                &PrepareStepResult::Failed(ReportShareError::BatchCollected)
            );

            let prepare_step_6 = aggregate_resp.prepare_steps().get(6).unwrap();
            assert_eq!(prepare_step_6.report_id(), report_share_6.metadata().id());
            assert_eq!(
                prepare_step_6.result(),
                &PrepareStepResult::Failed(ReportShareError::UnrecognizedMessage),
            );

            let prepare_step_7 = aggregate_resp.prepare_steps().get(7).unwrap();
            assert_eq!(prepare_step_7.report_id(), report_share_7.metadata().id());
            assert_eq!(
                prepare_step_7.result(),
                &PrepareStepResult::Failed(ReportShareError::UnrecognizedMessage),
            );

            let prepare_step_8 = aggregate_resp.prepare_steps().get(8).unwrap();
            assert_eq!(prepare_step_8.report_id(), report_share_8.metadata().id());
            assert_matches!(prepare_step_8.result(), &PrepareStepResult::Continued(..));

            // Check aggregation job in datastore.
            let aggregation_jobs = datastore
                .run_tx(|tx| {
                    let task = task.clone();
                    Box::pin(async move {
                        tx.get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            task.id(),
                        )
                        .await
                    })
                })
                .await
                .unwrap();

            assert_eq!(aggregation_jobs.len(), 3);

            let mut saw_conflicting_aggregation_job = false;
            let mut saw_non_conflicting_aggregation_job = false;
            let mut saw_new_aggregation_job = false;
            for aggregation_job in aggregation_jobs {
                if aggregation_job.eq(&conflicting_aggregation_job) {
                    saw_conflicting_aggregation_job = true;
                } else if aggregation_job.eq(&non_conflicting_aggregation_job) {
                    saw_non_conflicting_aggregation_job = true;
                } else if aggregation_job.task_id().eq(task.id())
                    && aggregation_job.id().eq(&aggregation_job_id)
                    && aggregation_job.partial_batch_identifier().eq(&())
                    && aggregation_job.state().eq(&AggregationJobState::InProgress)
                {
                    saw_new_aggregation_job = true;
                }
            }

            assert!(saw_conflicting_aggregation_job);
            assert!(saw_non_conflicting_aggregation_job);
            assert!(saw_new_aggregation_job);
        }
    }

    #[allow(clippy::unit_arg)]
    #[tokio::test]
    async fn aggregate_init_change_report_timestamp() {
        let test_case = setup_aggregate_init_test().await;

        let other_aggregation_parameter = dummy_vdaf::AggregationParam(1);
        assert_ne!(test_case.aggregation_param, other_aggregation_parameter);

        // This report has the same ID as the previous one, but a different timestamp.
        let mutated_timestamp_report_metadata = ReportMetadata::new(
            *test_case.report_shares[0].metadata().id(),
            test_case
                .clock
                .now()
                .add(test_case.task.time_precision())
                .unwrap(),
        );
        let mutated_timestamp_report_share = test_case
            .report_share_generator
            .next_with_metadata(mutated_timestamp_report_metadata)
            .0;

        // Send another aggregate job re-using the same report ID but with a different timestamp. It
        // should be flagged as a replay.
        let request = AggregationJobInitializeReq::new(
            other_aggregation_parameter.get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([mutated_timestamp_report_share.clone()]),
        );

        let mut test_conn =
            put_aggregation_job(&test_case.task, &random(), &request, &test_case.handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        let body_bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let aggregate_resp = AggregationJobResp::get_decoded(&body_bytes).unwrap();

        assert_eq!(aggregate_resp.prepare_steps().len(), 1);

        let prepare_step = aggregate_resp.prepare_steps().get(0).unwrap();
        assert_eq!(
            prepare_step.report_id(),
            mutated_timestamp_report_share.metadata().id()
        );
        assert_matches!(
            prepare_step.result(),
            &PrepareStepResult::Failed(ReportShareError::ReportReplayed)
        );

        // The attempt to mutate the report share timestamp should not cause any change in the
        // datastore.
        let client_reports = test_case
            .datastore
            .run_tx(|tx| {
                let task_id = *test_case.task.id();
                Box::pin(async move {
                    let reports = tx.get_report_metadatas_for_task(&task_id).await.unwrap();

                    Ok(reports)
                })
            })
            .await
            .unwrap();
        assert_eq!(client_reports.len(), 2);
        assert_eq!(&client_reports[0], test_case.report_shares[0].metadata());
        assert_eq!(&client_reports[1], test_case.report_shares[1].metadata());
    }

    #[tokio::test]
    async fn aggregate_init_prep_init_failed() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::FakeFailsPrepInit,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());
        let hpke_key = task.current_hpke_key();

        datastore.put_task(&task).await.unwrap();

        let report_share = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            ReportMetadata::new(
                random(),
                clock
                    .now()
                    .to_batch_interval_start(task.time_precision())
                    .unwrap(),
            ),
            hpke_key.config(),
            &(),
            Vec::new(),
            &dummy_vdaf::InputShare::default(),
        );
        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([report_share.clone()]),
        );

        // Create aggregator filter, send request, and parse response.
        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();
        let aggregation_job_id: AggregationJobId = random();

        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "content-type" => (AggregationJobResp::MEDIA_TYPE)
        );
        let body_bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let aggregate_resp = AggregationJobResp::get_decoded(&body_bytes).unwrap();

        // Validate response.
        assert_eq!(aggregate_resp.prepare_steps().len(), 1);

        let prepare_step = aggregate_resp.prepare_steps().get(0).unwrap();
        assert_eq!(prepare_step.report_id(), report_share.metadata().id());
        assert_matches!(
            prepare_step.result(),
            &PrepareStepResult::Failed(ReportShareError::VdafPrepError)
        );
    }

    #[tokio::test]
    async fn aggregate_init_prep_step_failed() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::FakeFailsPrepInit,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());
        let hpke_key = task.current_hpke_key();

        datastore.put_task(&task).await.unwrap();

        let report_share = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            *task.id(),
            ReportMetadata::new(
                random(),
                clock
                    .now()
                    .to_batch_interval_start(task.time_precision())
                    .unwrap(),
            ),
            hpke_key.config(),
            &(),
            Vec::new(),
            &dummy_vdaf::InputShare::default(),
        );
        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([report_share.clone()]),
        );

        // Create aggregator filter, send request, and parse response.
        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();
        let aggregation_job_id: AggregationJobId = random();

        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "content-type" => (AggregationJobResp::MEDIA_TYPE)
        );
        let body_bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let aggregate_resp = AggregationJobResp::get_decoded(&body_bytes).unwrap();

        // Validate response.
        assert_eq!(aggregate_resp.prepare_steps().len(), 1);

        let prepare_step = aggregate_resp.prepare_steps().get(0).unwrap();
        assert_eq!(prepare_step.report_id(), report_share.metadata().id());
        assert_matches!(
            prepare_step.result(),
            &PrepareStepResult::Failed(ReportShareError::VdafPrepError)
        );
    }

    #[tokio::test]
    async fn aggregate_init_duplicated_report_id() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::FakeFailsPrepInit,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let report_share = ReportShare::new(
            ReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(54321),
            ),
            Vec::from("PUBLIC"),
            HpkeCiphertext::new(
                // bogus, but we never get far enough to notice
                HpkeConfigId::from(42),
                Vec::from("012345"),
                Vec::from("543210"),
            ),
        );

        let request = AggregationJobInitializeReq::new(
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([report_share.clone(), report_share]),
        );

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();
        let aggregation_job_id: AggregationJobId = random();

        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;

        let want_status = 400;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());
    }

    #[tokio::test]
    async fn aggregate_continue() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let aggregation_job_id = random();
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        let vdaf = Arc::new(Prio3::new_count(2).unwrap());
        let verify_key: VerifyKey<PRIO3_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();
        let hpke_key = task.current_hpke_key();

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_0 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata_0.id(),
            &0,
        );
        let (prep_state_0, prep_share_0) = transcript_0.helper_prep_state(0);
        let prep_msg_0 = transcript_0.prepare_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_0.clone(),
            hpke_key.config(),
            &transcript_0.public_share,
            Vec::new(),
            &transcript_0.input_shares[1],
        );

        // report_share_1 is omitted by the leader's request.
        let report_metadata_1 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_1 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata_1.id(),
            &0,
        );

        let (prep_state_1, prep_share_1) = transcript_1.helper_prep_state(0);
        let report_share_1 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_1.clone(),
            hpke_key.config(),
            &transcript_1.public_share,
            Vec::new(),
            &transcript_1.input_shares[1],
        );

        // report_share_2 falls into a batch that has already been collected.
        let past_clock = MockClock::new(Time::from_seconds_since_epoch(
            task.time_precision().as_seconds() / 2,
        ));
        let report_metadata_2 = ReportMetadata::new(
            random(),
            past_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_2 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata_2.id(),
            &0,
        );
        let (prep_state_2, prep_share_2) = transcript_2.helper_prep_state(0);
        let prep_msg_2 = transcript_2.prepare_messages[0].clone();
        let report_share_2 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_2.clone(),
            hpke_key.config(),
            &transcript_2.public_share,
            Vec::new(),
            &transcript_2.input_shares[1],
        );

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                let (report_share_0, report_share_1, report_share_2) = (
                    report_share_0.clone(),
                    report_share_1.clone(),
                    report_share_2.clone(),
                );
                let (prep_share_0, prep_share_1, prep_share_2) = (
                    prep_share_0.clone(),
                    prep_share_1.clone(),
                    prep_share_2.clone(),
                );
                let (prep_state_0, prep_state_1, prep_state_2) = (
                    prep_state_0.clone(),
                    prep_state_1.clone(),
                    prep_state_2.clone(),
                );
                let (report_metadata_0, report_metadata_1, report_metadata_2) = (
                    report_metadata_0.clone(),
                    report_metadata_1.clone(),
                    report_metadata_2.clone(),
                );

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(task.id(), &report_share_0).await?;
                    tx.put_report_share(task.id(), &report_share_1).await?;
                    tx.put_report_share(task.id(), &report_share_2).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation::<PRIO3_VERIFY_KEY_LENGTH, Prio3Count>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_0.id(),
                            *report_metadata_0.time(),
                            0,
                            ReportAggregationState::Waiting(
                                prep_state_0,
                                PrepareMessageOrShare::Helper(prep_share_0),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation::<PRIO3_VERIFY_KEY_LENGTH, Prio3Count>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_1.id(),
                            *report_metadata_1.time(),
                            1,
                            ReportAggregationState::Waiting(
                                prep_state_1,
                                PrepareMessageOrShare::Helper(prep_share_1),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation::<PRIO3_VERIFY_KEY_LENGTH, Prio3Count>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_2.id(),
                            *report_metadata_2.time(),
                            2,
                            ReportAggregationState::Waiting(
                                prep_state_2,
                                PrepareMessageOrShare::Helper(prep_share_2),
                            ),
                        ),
                    )
                    .await?;

                    tx.put_aggregate_share_job::<PRIO3_VERIFY_KEY_LENGTH, TimeInterval, Prio3Count>(
                        &AggregateShareJob::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            (),
                            AggregateShare::from(OutputShare::from(Vec::from([Field64::from(7)]))),
                            0,
                            ReportIdChecksum::default(),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([
                PrepareStep::new(
                    *report_metadata_0.id(),
                    PrepareStepResult::Continued(prep_msg_0.get_encoded()),
                ),
                PrepareStep::new(
                    *report_metadata_2.id(),
                    PrepareStepResult::Continued(prep_msg_2.get_encoded()),
                ),
            ]),
        );

        // Create aggregator handler, send request, and parse response.
        let handler =
            aggregator_handler(Arc::clone(&datastore), clock, default_aggregator_config()).unwrap();

        let aggregate_resp =
            post_aggregation_job_and_decode(&task, &aggregation_job_id, &request, &handler).await;

        // Validate response.
        assert_eq!(
            aggregate_resp,
            AggregationJobResp::new(Vec::from([
                PrepareStep::new(*report_metadata_0.id(), PrepareStepResult::Finished),
                PrepareStep::new(
                    *report_metadata_2.id(),
                    PrepareStepResult::Failed(ReportShareError::BatchCollected),
                )
            ]))
        );

        // Validate datastore.
        let (aggregation_job, report_aggregations) =
            datastore
                .run_tx(|tx| {
                    let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                    Box::pin(async move {
                        let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_VERIFY_KEY_LENGTH, TimeInterval, Prio3Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await.unwrap().unwrap();
                        let report_aggregations = tx
                            .get_report_aggregations_for_aggregation_job(
                                vdaf.as_ref(),
                                &Role::Helper,
                                task.id(),
                                &aggregation_job_id,
                            )
                            .await
                            .unwrap();
                        Ok((aggregation_job, report_aggregations))
                    })
                })
                .await
                .unwrap();

        assert_eq!(
            aggregation_job,
            AggregationJob::new(
                *task.id(),
                aggregation_job_id,
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
                AggregationJobRound::from(1),
            )
            .with_last_continue_request_hash(aggregation_job.last_continue_request_hash().unwrap())
        );
        assert_eq!(
            report_aggregations,
            Vec::from([
                ReportAggregation::new(
                    *task.id(),
                    aggregation_job_id,
                    *report_metadata_0.id(),
                    *report_metadata_0.time(),
                    0,
                    ReportAggregationState::Finished(
                        transcript_0.output_share(Role::Helper).clone()
                    ),
                ),
                ReportAggregation::new(
                    *task.id(),
                    aggregation_job_id,
                    *report_metadata_1.id(),
                    *report_metadata_1.time(),
                    1,
                    ReportAggregationState::Failed(ReportShareError::ReportDropped),
                ),
                ReportAggregation::new(
                    *task.id(),
                    aggregation_job_id,
                    *report_metadata_2.id(),
                    *report_metadata_2.time(),
                    2,
                    ReportAggregationState::Failed(ReportShareError::BatchCollected),
                )
            ])
        );
    }

    #[tokio::test]
    async fn aggregate_continue_accumulate_batch_aggregation() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Count,
            Role::Helper,
        )
        .build();
        let aggregation_job_id_0 = random();
        let aggregation_job_id_1 = random();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(MockClock::default()));
        let first_batch_interval_clock = MockClock::default();
        let second_batch_interval_clock = MockClock::new(
            first_batch_interval_clock
                .now()
                .add(task.time_precision())
                .unwrap(),
        );

        let vdaf = Prio3::new_count(2).unwrap();
        let verify_key: VerifyKey<PRIO3_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();
        let hpke_key = task.current_hpke_key();

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            first_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_0 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_0.id(),
            &0,
        );
        let (prep_state_0, prep_share_0) = transcript_0.helper_prep_state(0);
        let out_share_0 = transcript_0.output_share(Role::Helper);
        let prep_msg_0 = transcript_0.prepare_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_0.clone(),
            hpke_key.config(),
            &transcript_0.public_share,
            Vec::new(),
            &transcript_0.input_shares[1],
        );

        // report_share_1 is another "happy path" report to exercise in-memory accumulation of
        // output shares
        let report_metadata_1 = ReportMetadata::new(
            random(),
            first_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_1 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_1.id(),
            &0,
        );
        let (prep_state_1, prep_share_1) = transcript_1.helper_prep_state(0);
        let out_share_1 = transcript_1.output_share(Role::Helper);
        let prep_msg_1 = transcript_1.prepare_messages[0].clone();
        let report_share_1 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_1.clone(),
            hpke_key.config(),
            &transcript_1.public_share,
            Vec::new(),
            &transcript_1.input_shares[1],
        );

        // report share 2 aggregates successfully, but into a distinct batch aggregation.
        let report_metadata_2 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_2 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_2.id(),
            &0,
        );
        let (prep_state_2, prep_share_2) = transcript_2.helper_prep_state(0);
        let out_share_2 = transcript_2.output_share(Role::Helper);
        let prep_msg_2 = transcript_2.prepare_messages[0].clone();
        let report_share_2 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_2.clone(),
            hpke_key.config(),
            &transcript_2.public_share,
            Vec::new(),
            &transcript_2.input_shares[1],
        );

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                let (report_share_0, report_share_1, report_share_2) = (
                    report_share_0.clone(),
                    report_share_1.clone(),
                    report_share_2.clone(),
                );
                let (prep_share_0, prep_share_1, prep_share_2) = (
                    prep_share_0.clone(),
                    prep_share_1.clone(),
                    prep_share_2.clone(),
                );
                let (prep_state_0, prep_state_1, prep_state_2) = (
                    prep_state_0.clone(),
                    prep_state_1.clone(),
                    prep_state_2.clone(),
                );
                let (report_metadata_0, report_metadata_1, report_metadata_2) = (
                    report_metadata_0.clone(),
                    report_metadata_1.clone(),
                    report_metadata_2.clone(),
                );

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(task.id(), &report_share_0).await?;
                    tx.put_report_share(task.id(), &report_share_1).await?;
                    tx.put_report_share(task.id(), &report_share_2).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_0.id(),
                        *report_metadata_0.time(),
                        0,
                        ReportAggregationState::Waiting(
                            prep_state_0,
                            PrepareMessageOrShare::Helper(prep_share_0),
                        ),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_1.id(),
                        *report_metadata_1.time(),
                        1,
                        ReportAggregationState::Waiting(
                            prep_state_1,
                            PrepareMessageOrShare::Helper(prep_share_1),
                        ),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_2.id(),
                        *report_metadata_2.time(),
                        2,
                        ReportAggregationState::Waiting(
                            prep_state_2,
                            PrepareMessageOrShare::Helper(prep_share_2),
                        ),
                    ))
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([
                PrepareStep::new(
                    *report_metadata_0.id(),
                    PrepareStepResult::Continued(prep_msg_0.get_encoded()),
                ),
                PrepareStep::new(
                    *report_metadata_1.id(),
                    PrepareStepResult::Continued(prep_msg_1.get_encoded()),
                ),
                PrepareStep::new(
                    *report_metadata_2.id(),
                    PrepareStepResult::Continued(prep_msg_2.get_encoded()),
                ),
            ]),
        );

        // Create aggregator handler, send request, and parse response.
        let handler = aggregator_handler(
            Arc::clone(&datastore),
            first_batch_interval_clock.clone(),
            default_aggregator_config(),
        )
        .unwrap();

        let _ =
            post_aggregation_job_and_decode(&task, &aggregation_job_id_0, &request, &handler).await;

        // Map the batch aggregation ordinal value to 0, as it may vary due to sharding.
        let batch_aggregations: Vec<_> = datastore
            .run_tx(|tx| {
                let (task, vdaf, report_metadata_0) =
                    (task.clone(), vdaf.clone(), report_metadata_0.clone());
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                        _,
                    >(
                        tx,
                        &task,
                        &vdaf,
                        &Interval::new(
                            report_metadata_0
                                .time()
                                .to_batch_interval_start(task.time_precision())
                                .unwrap(),
                            // Make interval big enough to capture both batch aggregations
                            Duration::from_seconds(task.time_precision().as_seconds() * 2),
                        )
                        .unwrap(),
                        &(),
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|agg| {
                BatchAggregation::<PRIO3_VERIFY_KEY_LENGTH, TimeInterval, Prio3Count>::new(
                    *agg.task_id(),
                    *agg.batch_identifier(),
                    (),
                    0,
                    agg.aggregate_share().clone(),
                    agg.report_count(),
                    *agg.client_timestamp_interval(),
                    *agg.checksum(),
                )
            })
            .collect();

        let aggregate_share = vdaf
            .aggregate(&(), [out_share_0.clone(), out_share_1.clone()])
            .unwrap();
        let checksum = ReportIdChecksum::for_report_id(report_metadata_0.id())
            .updated_with(report_metadata_1.id());

        assert_eq!(
            batch_aggregations,
            Vec::from([
                BatchAggregation::new(
                    *task.id(),
                    Interval::new(
                        report_metadata_0
                            .time()
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                        *task.time_precision()
                    )
                    .unwrap(),
                    (),
                    0,
                    aggregate_share,
                    2,
                    Interval::from_time(report_metadata_0.time()).unwrap(),
                    checksum,
                ),
                BatchAggregation::new(
                    *task.id(),
                    Interval::new(
                        report_metadata_2
                            .time()
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                        *task.time_precision()
                    )
                    .unwrap(),
                    (),
                    0,
                    AggregateShare::from(out_share_2.clone()),
                    1,
                    Interval::from_time(report_metadata_2.time()).unwrap(),
                    ReportIdChecksum::for_report_id(report_metadata_2.id()),
                ),
            ])
        );

        // Aggregate some more reports, which should get accumulated into the
        // batch_aggregations rows created earlier.
        // report_share_3 gets aggreated into the first batch interval.
        let report_metadata_3 = ReportMetadata::new(
            random(),
            first_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_3 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_3.id(),
            &0,
        );
        let (prep_state_3, prep_share_3) = transcript_3.helper_prep_state(0);
        let out_share_3 = transcript_3.output_share(Role::Helper);
        let prep_msg_3 = transcript_3.prepare_messages[0].clone();
        let report_share_3 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_3.clone(),
            hpke_key.config(),
            &transcript_3.public_share,
            Vec::new(),
            &transcript_3.input_shares[1],
        );

        // report_share_4 gets aggregated into the second batch interval
        let report_metadata_4 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_4 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_4.id(),
            &0,
        );
        let (prep_state_4, prep_share_4) = transcript_4.helper_prep_state(0);
        let out_share_4 = transcript_4.output_share(Role::Helper);
        let prep_msg_4 = transcript_4.prepare_messages[0].clone();
        let report_share_4 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_4.clone(),
            hpke_key.config(),
            &transcript_4.public_share,
            Vec::new(),
            &transcript_4.input_shares[1],
        );

        // report share 5 also gets aggregated into the second batch interval
        let report_metadata_5 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let transcript_5 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_5.id(),
            &0,
        );
        let (prep_state_5, prep_share_5) = transcript_5.helper_prep_state(0);
        let out_share_5 = transcript_5.output_share(Role::Helper);
        let prep_msg_5 = transcript_5.prepare_messages[0].clone();
        let report_share_5 = generate_helper_report_share::<Prio3Count>(
            *task.id(),
            report_metadata_5.clone(),
            hpke_key.config(),
            &transcript_5.public_share,
            Vec::new(),
            &transcript_5.input_shares[1],
        );

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                let (report_share_3, report_share_4, report_share_5) = (
                    report_share_3.clone(),
                    report_share_4.clone(),
                    report_share_5.clone(),
                );
                let (prep_share_3, prep_share_4, prep_share_5) = (
                    prep_share_3.clone(),
                    prep_share_4.clone(),
                    prep_share_5.clone(),
                );
                let (prep_state_3, prep_state_4, prep_state_5) = (
                    prep_state_3.clone(),
                    prep_state_4.clone(),
                    prep_state_5.clone(),
                );
                let (report_metadata_3, report_metadata_4, report_metadata_5) = (
                    report_metadata_3.clone(),
                    report_metadata_4.clone(),
                    report_metadata_5.clone(),
                );

                Box::pin(async move {
                    tx.put_report_share(task.id(), &report_share_3).await?;
                    tx.put_report_share(task.id(), &report_share_4).await?;
                    tx.put_report_share(task.id(), &report_share_5).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_3.id(),
                        *report_metadata_3.time(),
                        3,
                        ReportAggregationState::Waiting(
                            prep_state_3,
                            PrepareMessageOrShare::Helper(prep_share_3),
                        ),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_4.id(),
                        *report_metadata_4.time(),
                        4,
                        ReportAggregationState::Waiting(
                            prep_state_4,
                            PrepareMessageOrShare::Helper(prep_share_4),
                        ),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_5.id(),
                        *report_metadata_5.time(),
                        5,
                        ReportAggregationState::Waiting(
                            prep_state_5,
                            PrepareMessageOrShare::Helper(prep_share_5),
                        ),
                    ))
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([
                PrepareStep::new(
                    *report_metadata_3.id(),
                    PrepareStepResult::Continued(prep_msg_3.get_encoded()),
                ),
                PrepareStep::new(
                    *report_metadata_4.id(),
                    PrepareStepResult::Continued(prep_msg_4.get_encoded()),
                ),
                PrepareStep::new(
                    *report_metadata_5.id(),
                    PrepareStepResult::Continued(prep_msg_5.get_encoded()),
                ),
            ]),
        );

        // Create aggregator handler, send request, and parse response.
        let handler = aggregator_handler(
            Arc::clone(&datastore),
            first_batch_interval_clock,
            default_aggregator_config(),
        )
        .unwrap();

        let _ =
            post_aggregation_job_and_decode(&task, &aggregation_job_id_1, &request, &handler).await;

        // Map the batch aggregation ordinal value to 0, as it may vary due to sharding, and merge
        // batch aggregations over the same interval. (the task & aggregation parameter will always
        // be the same)
        let mut batch_aggregations: Vec<_> = datastore
            .run_tx(|tx| {
                let (task, vdaf, report_metadata_0) =
                    (task.clone(), vdaf.clone(), report_metadata_0.clone());
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        PRIO3_VERIFY_KEY_LENGTH,
                        Prio3Count,
                        _,
                    >(
                        tx,
                        &task,
                        &vdaf,
                        &Interval::new(
                            report_metadata_0
                                .time()
                                .to_batch_interval_start(task.time_precision())
                                .unwrap(),
                            // Make interval big enough to capture both batch aggregations
                            Duration::from_seconds(task.time_precision().as_seconds() * 2),
                        )
                        .unwrap(),
                        &(),
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|agg| {
                BatchAggregation::<PRIO3_VERIFY_KEY_LENGTH, TimeInterval, Prio3Count>::new(
                    *agg.task_id(),
                    *agg.batch_identifier(),
                    (),
                    0,
                    agg.aggregate_share().clone(),
                    agg.report_count(),
                    *agg.client_timestamp_interval(),
                    *agg.checksum(),
                )
            })
            .into_grouping_map_by(|agg| *agg.batch_interval())
            .fold_first(|left, _, right| left.merged_with(&right).unwrap())
            .into_values()
            .collect();
        batch_aggregations.sort_by_key(|agg| *agg.batch_interval().start());

        let first_aggregate_share = vdaf
            .aggregate(
                &(),
                [out_share_0, out_share_1, out_share_3].into_iter().cloned(),
            )
            .unwrap();
        let first_checksum = ReportIdChecksum::for_report_id(report_metadata_0.id())
            .updated_with(report_metadata_1.id())
            .updated_with(report_metadata_3.id());

        let second_aggregate_share = vdaf
            .aggregate(
                &(),
                [out_share_2, out_share_4, out_share_5].into_iter().cloned(),
            )
            .unwrap();
        let second_checksum = ReportIdChecksum::for_report_id(report_metadata_2.id())
            .updated_with(report_metadata_4.id())
            .updated_with(report_metadata_5.id());

        assert_eq!(
            batch_aggregations,
            Vec::from([
                BatchAggregation::new(
                    *task.id(),
                    Interval::new(
                        report_metadata_0
                            .time()
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                        *task.time_precision()
                    )
                    .unwrap(),
                    (),
                    0,
                    first_aggregate_share,
                    3,
                    Interval::from_time(report_metadata_0.time()).unwrap(),
                    first_checksum,
                ),
                BatchAggregation::new(
                    *task.id(),
                    Interval::new(
                        report_metadata_2
                            .time()
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                        *task.time_precision()
                    )
                    .unwrap(),
                    (),
                    0,
                    second_aggregate_share,
                    3,
                    Interval::from_time(report_metadata_2.time()).unwrap(),
                    second_checksum,
                ),
            ])
        );
    }

    #[tokio::test]
    async fn aggregate_continue_leader_sends_non_continue_transition() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(54321),
        );
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let (task, report_metadata) = (task.clone(), report_metadata.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata.clone(),
                            Vec::from("Public Share"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        dummy_vdaf::AggregationParam(0),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata.id(),
                        *report_metadata.time(),
                        0,
                        ReportAggregationState::Waiting(
                            dummy_vdaf::PrepareState::default(),
                            PrepareMessageOrShare::Helper(()),
                        ),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([PrepareStep::new(
                *report_metadata.id(),
                PrepareStepResult::Finished,
            )]),
        );

        let handler =
            aggregator_handler(Arc::clone(&datastore), clock, default_aggregator_config()).unwrap();

        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregate_continue_prep_step_fails() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::FakeFailsPrepStep,
            Role::Helper,
        )
        .build();
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(54321),
        );
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let (task, report_metadata) = (task.clone(), report_metadata.clone());

                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata.clone(),
                            Vec::from("public share"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        dummy_vdaf::AggregationParam(0),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata.id(),
                        *report_metadata.time(),
                        0,
                        ReportAggregationState::Waiting(
                            dummy_vdaf::PrepareState::default(),
                            PrepareMessageOrShare::Helper(()),
                        ),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([PrepareStep::new(
                *report_metadata.id(),
                PrepareStepResult::Continued(Vec::new()),
            )]),
        );

        let handler =
            aggregator_handler(Arc::clone(&datastore), clock, default_aggregator_config()).unwrap();

        let aggregate_resp =
            post_aggregation_job_and_decode(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(
            aggregate_resp,
            AggregationJobResp::new(Vec::from([PrepareStep::new(
                *report_metadata.id(),
                PrepareStepResult::Failed(ReportShareError::VdafPrepError),
            )]),)
        );

        // Check datastore state.
        let (aggregation_job, report_aggregation) = datastore
            .run_tx(|tx| {
                let (task, report_metadata) = (task.clone(), report_metadata.clone());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<DUMMY_VERIFY_KEY_LENGTH, TimeInterval, dummy_vdaf::Vdaf>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await.unwrap().unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            &dummy_vdaf::Vdaf::default(),
                            &Role::Helper,
                            task.id(),
                            &aggregation_job_id,
                            report_metadata.id(),
                        )
                        .await.unwrap().unwrap();
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(
            aggregation_job,
            AggregationJob::new(
                *task.id(),
                aggregation_job_id,
                dummy_vdaf::AggregationParam(0),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
                AggregationJobRound::from(1),
            )
            .with_last_continue_request_hash(aggregation_job.last_continue_request_hash().unwrap())
        );
        assert_eq!(
            report_aggregation,
            ReportAggregation::new(
                *task.id(),
                aggregation_job_id,
                *report_metadata.id(),
                *report_metadata.time(),
                0,
                ReportAggregationState::Failed(ReportShareError::VdafPrepError),
            )
        );
    }

    #[tokio::test]
    async fn aggregate_continue_unexpected_transition() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(54321),
        );
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let (task, report_metadata) = (task.clone(), report_metadata.clone());

                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata.clone(),
                            Vec::from("PUBLIC"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        dummy_vdaf::AggregationParam(0),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata.id(),
                        *report_metadata.time(),
                        0,
                        ReportAggregationState::Waiting(
                            dummy_vdaf::PrepareState::default(),
                            PrepareMessageOrShare::Helper(()),
                        ),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([PrepareStep::new(
                ReportId::from(
                    [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1], // not the same as above
                ),
                PrepareStepResult::Continued(Vec::new()),
            )]),
        );

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregate_continue_out_of_order_transition() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let aggregation_job_id = random();
        let report_metadata_0 = ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(54321),
        );
        let report_metadata_1 = ReportMetadata::new(
            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
            Time::from_seconds_since_epoch(54321),
        );

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let (task, report_metadata_0, report_metadata_1) = (
                    task.clone(),
                    report_metadata_0.clone(),
                    report_metadata_1.clone(),
                );

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata_0.clone(),
                            Vec::from("public"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata_1.clone(),
                            Vec::from("public"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        dummy_vdaf::AggregationParam(0),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata_0.id(),
                        *report_metadata_0.time(),
                        0,
                        ReportAggregationState::Waiting(
                            dummy_vdaf::PrepareState::default(),
                            PrepareMessageOrShare::Helper(()),
                        ),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata_1.id(),
                        *report_metadata_1.time(),
                        1,
                        ReportAggregationState::Waiting(
                            dummy_vdaf::PrepareState::default(),
                            PrepareMessageOrShare::Helper(()),
                        ),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([
                // Report IDs are in opposite order to what was stored in the datastore.
                PrepareStep::new(
                    *report_metadata_1.id(),
                    PrepareStepResult::Continued(Vec::new()),
                ),
                PrepareStep::new(
                    *report_metadata_0.id(),
                    PrepareStepResult::Continued(Vec::new()),
                ),
            ]),
        );

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregate_continue_for_non_waiting_aggregation() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let aggregation_job_id = random();
        let report_metadata = ReportMetadata::new(
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Time::from_seconds_since_epoch(54321),
        );

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let (task, report_metadata) = (task.clone(), report_metadata.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task.id(),
                        &ReportShare::new(
                            report_metadata.clone(),
                            Vec::from("public share"),
                            HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        ),
                    )
                    .await?;
                    tx.put_aggregation_job(&AggregationJob::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        dummy_vdaf::AggregationParam(0),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata.id(),
                        *report_metadata.time(),
                        0,
                        ReportAggregationState::Invalid,
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([PrepareStep::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                PrepareStepResult::Continued(Vec::new()),
            )]),
        );

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn collection_job_put_request_to_helper() {
        let test_case = setup_collection_job_test_case(Role::Helper, QueryType::TimeInterval).await;

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    *test_case.task.time_precision(),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job_with_auth_token(&collection_job_id, &request, Some(&random()))
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_invalid_batch_interval() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    // Collect request will be rejected because batch interval is too small
                    Duration::from_seconds(test_case.task.time_precision().as_seconds() - 1),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch implied by the query is invalid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_invalid_aggregation_parameter() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(test_case.task.time_precision().as_seconds()),
                )
                .unwrap(),
            ),
            // dummy_vdaf::AggregationParam is a tuple struct wrapping a u8, so this is not a valid
            // encoding of an aggregation parameter.
            Vec::from([0u8, 0u8]),
        );

        let mut test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        // Collect request will be rejected because the aggregation parameter can't be decoded
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_invalid_batch_size() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
            .with_min_batch_size(1)
            .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(task.time_precision().as_seconds()),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let mut test_conn = put(task.collection_job_uri(&collection_job_id).unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        // Collect request will be rejected because there are no reports in the batch interval
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_unauthenticated() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();
        let collection_job_id: CollectionJobId = random();
        let req = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        // Incorrect authentication token.
        let mut test_conn = test_case
            .put_collection_job_with_auth_token(&collection_job_id, &req, Some(&random()))
            .await;

        let want_status = Status::BadRequest;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Aggregator authentication token.
        let mut test_conn = test_case
            .put_collection_job_with_auth_token(
                &collection_job_id,
                &req,
                Some(test_case.task.primary_aggregator_auth_token()),
            )
            .await;

        let want_status = Status::BadRequest;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Missing authentication token.
        let mut test_conn = test_case
            .put_collection_job_with_auth_token(&collection_job_id, &req, None)
            .await;

        let want_status = Status::BadRequest;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());
    }

    #[tokio::test]
    async fn collection_job_post_request_unauthenticated_collection_jobs() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        assert_eq!(test_conn.status().unwrap(), Status::Created);

        // Incorrect authentication token.
        let mut test_conn = test_case
            .post_collection_job_with_auth_token(&collection_job_id, Some(&random()))
            .await;

        let want_status = Status::BadRequest;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Aggregator authentication token.
        let mut test_conn = test_case
            .post_collection_job_with_auth_token(
                &collection_job_id,
                Some(test_case.task.primary_aggregator_auth_token()),
            )
            .await;

        let want_status = Status::BadRequest;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());

        // Missing authentication token.
        let mut test_conn = test_case
            .post_collection_job_with_auth_token(&collection_job_id, None)
            .await;

        let want_status = Status::BadRequest;
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status as u16,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap());
    }

    #[tokio::test]
    async fn collection_job_success_time_interval() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        let leader_aggregate_share = dummy_vdaf::AggregateShare(0);
        let helper_aggregate_share = dummy_vdaf::AggregateShare(1);

        let collection_job_id: CollectionJobId = random();
        let request = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        assert_eq!(test_conn.status(), Some(Status::Created));

        let test_conn = test_case.post_collection_job(&collection_job_id).await;
        assert_eq!(test_conn.status(), Some(Status::Accepted));

        // Update the collection job with the aggregate shares and some aggregation jobs. collection
        // job should now be complete.
        test_case
            .datastore
            .run_tx(|tx| {
                let task = test_case.task.clone();
                let helper_aggregate_share_bytes = helper_aggregate_share.get_encoded();
                Box::pin(async move {
                    for (ord, spanned_interval) in [
                        // These intervals fall into the first and second time-precision-length
                        // intervals, so we expect the spanned interval in the collect result to
                        // contain both of them.
                        Interval::new(
                            Time::from_seconds_since_epoch(1000),
                            Duration::from_seconds(1000),
                        )
                        .unwrap(),
                        Interval::new(
                            Time::from_seconds_since_epoch(task.time_precision().as_seconds()),
                            Duration::from_seconds(2000),
                        )
                        .unwrap(),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        tx.put_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &AggregationJob::new(
                                *task.id(),
                                random(),
                                dummy_vdaf::AggregationParam::default(),
                                (),
                                spanned_interval,
                                AggregationJobState::Finished,
                                AggregationJobRound::from(1),
                            ),
                        )
                        .await
                        .unwrap();

                        tx.put_batch_aggregation::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &BatchAggregation::new(
                                *task.id(),
                                batch_interval,
                                dummy_vdaf::AggregationParam::default(),
                                ord as u64,
                                leader_aggregate_share,
                                6,
                                spanned_interval,
                                ReportIdChecksum::default(),
                            ),
                        )
                        .await
                        .unwrap();
                    }

                    let encrypted_helper_aggregate_share = hpke::seal(
                        task.collector_hpke_config(),
                        &HpkeApplicationInfo::new(
                            &Label::AggregateShare,
                            &Role::Helper,
                            &Role::Collector,
                        ),
                        &helper_aggregate_share_bytes,
                        &AggregateShareAad::new(
                            *task.id(),
                            BatchSelector::new_time_interval(batch_interval),
                        )
                        .get_encoded(),
                    )
                    .unwrap();

                    let collection_job = tx
                        .get_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &dummy_vdaf::Vdaf::new(),
                            &collection_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap()
                        .with_state(CollectionJobState::Finished {
                            report_count: 12,
                            encrypted_helper_aggregate_share,
                            leader_aggregate_share,
                        });

                    tx.update_collection_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&collection_job)
                        .await
                        .unwrap();
                    Ok(())
                })
            })
            .await
            .unwrap();

        let mut test_conn = test_case.post_collection_job(&collection_job_id).await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "content-type" => (Collection::<TimeInterval>::MEDIA_TYPE)
        );
        let body_bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        let collect_resp = Collection::<TimeInterval>::get_decoded(body_bytes.as_ref()).unwrap();

        assert_eq!(collect_resp.report_count(), 12);
        assert_eq!(
            collect_resp.interval(),
            &Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(test_case.task.time_precision().as_seconds() * 2),
            )
            .unwrap()
        );
        assert_eq!(collect_resp.encrypted_aggregate_shares().len(), 2);

        let decrypted_leader_aggregate_share = hpke::open(
            test_case.task.collector_hpke_config(),
            test_case.collector_hpke_keypair.private_key(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
            &collect_resp.encrypted_aggregate_shares()[0],
            &AggregateShareAad::new(
                *test_case.task.id(),
                BatchSelector::new_time_interval(batch_interval),
            )
            .get_encoded(),
        )
        .unwrap();
        assert_eq!(
            leader_aggregate_share,
            dummy_vdaf::AggregateShare::get_decoded(decrypted_leader_aggregate_share.as_ref())
                .unwrap()
        );

        let decrypted_helper_aggregate_share = hpke::open(
            test_case.task.collector_hpke_config(),
            test_case.collector_hpke_keypair.private_key(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            &collect_resp.encrypted_aggregate_shares()[1],
            &AggregateShareAad::new(
                *test_case.task.id(),
                BatchSelector::new_time_interval(batch_interval),
            )
            .get_encoded(),
        )
        .unwrap();
        assert_eq!(
            helper_aggregate_share,
            dummy_vdaf::AggregateShare::get_decoded(decrypted_helper_aggregate_share.as_ref())
                .unwrap()
        );
    }

    #[tokio::test]
    async fn collection_job_post_request_no_such_collection_job() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;

        let no_such_collection_job_id: CollectionJobId = random();

        let test_conn = post(&format!(
            "/tasks/{}/collection_jobs/{no_such_collection_job_id}",
            test_case.task.id()
        ))
        .with_request_header(
            "DAP-Auth-Token",
            test_case
                .task
                .primary_collector_auth_token()
                .as_ref()
                .to_owned(),
        )
        .run_async(&test_case.handler)
        .await;
        assert_eq!(test_conn.status(), Some(Status::NotFound));
    }

    #[tokio::test]
    async fn collection_job_put_request_batch_queried_too_many_times() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;
        let interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        test_case
            .datastore
            .run_tx(|tx| {
                let task = test_case.task.clone();
                Box::pin(async move {
                    tx.put_batch_aggregation(&BatchAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision())
                            .unwrap(),
                        dummy_vdaf::AggregationParam(0),
                        0,
                        dummy_vdaf::AggregateShare(0),
                        10,
                        interval,
                        ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Sending this request will consume a query for [0, time_precision).
        let request = CollectionReq::new(
            Query::new_time_interval(interval),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let test_conn = test_case.put_collection_job(&random(), &request).await;

        assert_eq!(test_conn.status(), Some(Status::Created));

        // This request will not be allowed due to the query count already being consumed.
        let invalid_request = CollectionReq::new(
            Query::new_time_interval(interval),
            dummy_vdaf::AggregationParam(1).get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job(&random(), &invalid_request)
            .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes",
                "title": "The batch described by the query has been queried too many times.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collection_job_put_request_batch_overlap() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;
        let interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        test_case
            .datastore
            .run_tx(|tx| {
                let task = test_case.task.clone();
                Box::pin(async move {
                    tx.put_batch_aggregation(&BatchAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        interval,
                        dummy_vdaf::AggregationParam(0),
                        0,
                        dummy_vdaf::AggregateShare(0),
                        10,
                        interval,
                        ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Sending this request will consume a query for [0, 2 * time_precision).
        let request = CollectionReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_microseconds(
                        2 * test_case.task.time_precision().as_microseconds().unwrap(),
                    ),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let test_conn = test_case.put_collection_job(&random(), &request).await;

        assert_eq!(test_conn.status(), Some(Status::Created));

        // This request will not be allowed due to overlapping with the previous request.
        let invalid_request = CollectionReq::new(
            Query::new_time_interval(interval),
            dummy_vdaf::AggregationParam(1).get_encoded(),
        );

        let mut test_conn = test_case
            .put_collection_job(&random(), &invalid_request)
            .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
                "title": "The queried batch overlaps with a previously queried batch.",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }

    #[tokio::test]
    async fn delete_collection_job() {
        let test_case = setup_collection_job_test_case(Role::Leader, QueryType::TimeInterval).await;
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            *test_case.task.time_precision(),
        )
        .unwrap();

        let collection_job_id: CollectionJobId = random();

        // Try to delete a collection job that doesn't exist
        let test_conn = delete(
            test_case
                .task
                .collection_job_uri(&collection_job_id)
                .unwrap()
                .path(),
        )
        .with_request_header(
            "DAP-Auth-Token",
            test_case
                .task
                .primary_collector_auth_token()
                .as_ref()
                .to_owned(),
        )
        .run_async(&test_case.handler)
        .await;
        assert_eq!(test_conn.status(), Some(Status::NotFound));

        // Create a collection job
        let request = CollectionReq::new(
            Query::new_time_interval(batch_interval),
            dummy_vdaf::AggregationParam::default().get_encoded(),
        );

        let test_conn = test_case
            .put_collection_job(&collection_job_id, &request)
            .await;

        assert_eq!(test_conn.status(), Some(Status::Created));

        // Cancel the job
        let test_conn = delete(
            test_case
                .task
                .collection_job_uri(&collection_job_id)
                .unwrap()
                .path(),
        )
        .with_request_header(
            "DAP-Auth-Token",
            test_case
                .task
                .primary_collector_auth_token()
                .as_ref()
                .to_owned(),
        )
        .run_async(&test_case.handler)
        .await;
        assert_eq!(test_conn.status(), Some(Status::NoContent));

        // Get the job again
        let test_conn = test_case.post_collection_job(&collection_job_id).await;
        assert_eq!(test_conn.status(), Some(Status::NoContent));
    }

    #[tokio::test]
    async fn aggregate_share_request_to_leader() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let handler =
            aggregator_handler(Arc::new(datastore), clock, default_aggregator_config()).unwrap();

        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            Vec::new(),
            0,
            ReportIdChecksum::default(),
        );

        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_share_request_invalid_batch_interval() {
        install_test_trace_subscriber();

        // Prepare parameters.
        const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(3600);
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper)
            .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
            .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = ephemeral_datastore.datastore(clock.clone());

        datastore.put_task(&task).await.unwrap();

        let handler = aggregator_handler(
            Arc::new(datastore),
            clock.clone(),
            default_aggregator_config(),
        )
        .unwrap();

        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    clock.now(),
                    // Collect request will be rejected because batch interval is too small
                    Duration::from_seconds(task.time_precision().as_seconds() - 1),
                )
                .unwrap(),
            ),
            Vec::new(),
            0,
            ReportIdChecksum::default(),
        );

        // Test that a request for an invalid batch fails. (Specifically, the batch interval is too
        // small.)
        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch implied by the query is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );

        // Test that a request for a too-old batch fails.
        let test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(
                AggregateShareReq::new(
                    BatchSelector::new_time_interval(
                        Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision())
                            .unwrap(),
                    ),
                    Vec::new(),
                    0,
                    ReportIdChecksum::default(),
                )
                .get_encoded(),
            )
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
    }

    #[tokio::test]
    async fn aggregate_share_request() {
        install_test_trace_subscriber();

        let collector_hpke_keypair = generate_test_hpke_config_and_private_key();
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper)
            .with_max_batch_query_count(1)
            .with_time_precision(Duration::from_seconds(500))
            .with_min_batch_size(10)
            .with_collector_hpke_config(collector_hpke_keypair.config().clone())
            .build();

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        datastore.put_task(&task).await.unwrap();

        let handler =
            aggregator_handler(Arc::clone(&datastore), clock, default_aggregator_config()).unwrap();

        // There are no batch aggregations in the datastore yet
        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            0,
            ReportIdChecksum::default(),
        );

        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );

        // Put some batch aggregations in the DB.
        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    for aggregation_param in [
                        dummy_vdaf::AggregationParam(0),
                        dummy_vdaf::AggregationParam(1),
                    ] {
                        let interval_1 = Interval::new(
                            Time::from_seconds_since_epoch(500),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_1,
                            aggregation_param,
                            0,
                            dummy_vdaf::AggregateShare(64),
                            5,
                            interval_1,
                            ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                        ))
                        .await?;

                        let interval_2 = Interval::new(
                            Time::from_seconds_since_epoch(1500),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_2,
                            aggregation_param,
                            0,
                            dummy_vdaf::AggregateShare(128),
                            5,
                            interval_2,
                            ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                        ))
                        .await?;

                        let interval_3 = Interval::new(
                            Time::from_seconds_since_epoch(2000),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_3,
                            aggregation_param,
                            0,
                            dummy_vdaf::AggregateShare(256),
                            5,
                            interval_3,
                            ReportIdChecksum::get_decoded(&[4; 32]).unwrap(),
                        ))
                        .await?;

                        let interval_4 = Interval::new(
                            Time::from_seconds_since_epoch(2500),
                            *task.time_precision(),
                        )
                        .unwrap();
                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            interval_4,
                            aggregation_param,
                            0,
                            dummy_vdaf::AggregateShare(512),
                            5,
                            interval_4,
                            ReportIdChecksum::get_decoded(&[8; 32]).unwrap(),
                        ))
                        .await?;
                    }

                    Ok(())
                })
            })
            .await
            .unwrap();

        // Specified interval includes too few reports.
        let request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(1000),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            5,
            ReportIdChecksum::default(),
        );
        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "taskid": format!("{}", task.id()),
            })
        );

        // Make requests that will fail because the checksum or report counts don't match.
        for misaligned_request in [
            // Interval is big enough, but checksum doesn't match.
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(0).get_encoded(),
                10,
                ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
            ),
            // Interval is big enough, but report count doesn't match.
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(0).get_encoded(),
                20,
                ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
            ),
        ] {
            let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
                .with_request_header(
                    "DAP-Auth-Token",
                    task.primary_aggregator_auth_token().as_ref().to_owned(),
                )
                .with_request_header(
                    KnownHeaderName::ContentType,
                    AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
                )
                .with_request_body(misaligned_request.get_encoded())
                .run_async(&handler)
                .await;

            assert_eq!(test_conn.status(), Some(Status::BadRequest));
            let problem_details: serde_json::Value = serde_json::from_slice(
                &test_conn
                    .take_response_body()
                    .unwrap()
                    .into_bytes()
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                problem_details,
                json!({
                    "status": Status::BadRequest as u16,
                    "type": "urn:ietf:params:ppm:dap:error:batchMismatch",
                    "title": "Leader and helper disagree on reports aggregated in a batch.",
                    "taskid": format!("{}", task.id()),
                })
            );
        }

        // Valid requests: intervals are big enough, do not overlap, checksum and report count are
        // good.
        for (label, request, expected_result) in [
            (
                "first and second batchess",
                AggregateShareReq::new(
                    BatchSelector::new_time_interval(
                        Interval::new(
                            Time::from_seconds_since_epoch(0),
                            Duration::from_seconds(2000),
                        )
                        .unwrap(),
                    ),
                    dummy_vdaf::AggregationParam(0).get_encoded(),
                    10,
                    ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
                ),
                dummy_vdaf::AggregateShare(64 + 128),
            ),
            (
                "third and fourth batches",
                AggregateShareReq::new(
                    BatchSelector::new_time_interval(
                        Interval::new(
                            Time::from_seconds_since_epoch(2000),
                            Duration::from_seconds(2000),
                        )
                        .unwrap(),
                    ),
                    dummy_vdaf::AggregationParam(0).get_encoded(),
                    10,
                    ReportIdChecksum::get_decoded(&[8 ^ 4; 32]).unwrap(),
                ),
                // Should get sum over the third and fourth batches
                dummy_vdaf::AggregateShare(256 + 512),
            ),
        ] {
            // Request the aggregate share multiple times. If the request parameters don't change,
            // then there is no query count violation and all requests should succeed.
            for iteration in 0..3 {
                let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
                    .with_request_header(
                        "DAP-Auth-Token",
                        task.primary_aggregator_auth_token().as_ref().to_owned(),
                    )
                    .with_request_header(
                        KnownHeaderName::ContentType,
                        AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
                    )
                    .with_request_body(request.get_encoded())
                    .run_async(&handler)
                    .await;

                assert_eq!(
                    test_conn.status(),
                    Some(Status::Ok),
                    "test case: {label:?}, iteration: {iteration}"
                );
                assert_headers!(
                    &test_conn,
                    "content-type" => (AggregateShareMessage::MEDIA_TYPE)
                );
                let body_bytes = test_conn
                    .take_response_body()
                    .unwrap()
                    .into_bytes()
                    .await
                    .unwrap();
                let aggregate_share_resp = AggregateShareMessage::get_decoded(&body_bytes).unwrap();

                let aggregate_share = hpke::open(
                    collector_hpke_keypair.config(),
                    collector_hpke_keypair.private_key(),
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    aggregate_share_resp.encrypted_aggregate_share(),
                    &AggregateShareAad::new(*task.id(), request.batch_selector().clone())
                        .get_encoded(),
                )
                .unwrap();

                // Should get the sum over the first and second aggregate shares
                let decoded_aggregate_share =
                    dummy_vdaf::AggregateShare::get_decoded(aggregate_share.as_ref()).unwrap();
                assert_eq!(
                    decoded_aggregate_share, expected_result,
                    "test case: {label:?}, iteration: {iteration}"
                );
            }
        }

        // Requests for collection intervals that overlap with but are not identical to previous
        // collection intervals fail.
        let all_batch_request = AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(4000),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            20,
            ReportIdChecksum::get_decoded(&[8 ^ 4 ^ 3 ^ 2; 32]).unwrap(),
        );
        let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_request_body(all_batch_request.get_encoded())
            .run_async(&handler)
            .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        let problem_details: serde_json::Value = serde_json::from_slice(
            &test_conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
                "title": "The queried batch overlaps with a previously queried batch.",
                "taskid": format!("{}", task.id()),
            }),
        );

        // Previous sequence of aggregate share requests should have consumed the available queries
        // for all the batches. Further requests for any batches will cause query count violations.
        for query_count_violation_request in [
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(1).get_encoded(),
                10,
                ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
            ),
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                ),
                dummy_vdaf::AggregationParam(1).get_encoded(),
                10,
                ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
            ),
        ] {
            let mut test_conn = post(task.aggregate_shares_uri().unwrap().path())
                .with_request_header(
                    "DAP-Auth-Token",
                    task.primary_aggregator_auth_token().as_ref().to_owned(),
                )
                .with_request_header(
                    KnownHeaderName::ContentType,
                    AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
                )
                .with_request_body(query_count_violation_request.get_encoded())
                .run_async(&handler)
                .await;
            assert_eq!(test_conn.status(), Some(Status::BadRequest));
            let problem_details: serde_json::Value = serde_json::from_slice(
                &test_conn
                    .take_response_body()
                    .unwrap()
                    .into_bytes()
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                problem_details,
                json!({
                    "status": Status::BadRequest as u16,
                    "type": "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes",
                    "title": "The batch described by the query has been queried too many times.",
                    "taskid": format!("{}", task.id()),
                })
            );
        }
    }

    pub(crate) fn generate_helper_report_share<V: vdaf::Client<16>>(
        task_id: TaskId,
        report_metadata: ReportMetadata,
        cfg: &HpkeConfig,
        public_share: &V::PublicShare,
        extensions: Vec<Extension>,
        input_share: &V::InputShare,
    ) -> ReportShare {
        generate_helper_report_share_for_plaintext(
            report_metadata.clone(),
            cfg,
            public_share.get_encoded(),
            &PlaintextInputShare::new(extensions, input_share.get_encoded()).get_encoded(),
            &InputShareAad::new(task_id, report_metadata, public_share.get_encoded()).get_encoded(),
        )
    }

    fn generate_helper_report_share_for_plaintext(
        metadata: ReportMetadata,
        cfg: &HpkeConfig,
        encoded_public_share: Vec<u8>,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> ReportShare {
        ReportShare::new(
            metadata,
            encoded_public_share,
            hpke::seal(
                cfg,
                &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
                plaintext,
                associated_data,
            )
            .unwrap(),
        )
    }

    #[test]
    fn dap_problem_type_round_trip() {
        for problem_type in [
            DapProblemType::UnrecognizedMessage,
            DapProblemType::UnrecognizedTask,
            DapProblemType::MissingTaskId,
            DapProblemType::UnrecognizedAggregationJob,
            DapProblemType::OutdatedConfig,
            DapProblemType::ReportRejected,
            DapProblemType::ReportTooEarly,
            DapProblemType::BatchInvalid,
            DapProblemType::InvalidBatchSize,
            DapProblemType::BatchQueriedTooManyTimes,
            DapProblemType::BatchMismatch,
            DapProblemType::UnauthorizedRequest,
            DapProblemType::BatchOverlap,
        ] {
            let uri = problem_type.type_uri();
            assert_eq!(uri.parse::<DapProblemType>().unwrap(), problem_type);
        }
        assert_matches!("".parse::<DapProblemType>(), Err(DapProblemTypeParseError));
    }

    #[tokio::test]
    async fn problem_details_round_trip() {
        let meter = opentelemetry::global::meter("");
        let request_histogram = meter
            .f64_histogram("janus_http_request_duration_seconds")
            .init();

        struct TestCase {
            error_factory: Box<dyn Fn() -> Error + Send + Sync>,
            expected_problem_type: Option<DapProblemType>,
        }

        impl TestCase {
            fn new(
                error_factory: Box<dyn Fn() -> Error + Send + Sync>,
                expected_problem_type: Option<DapProblemType>,
            ) -> TestCase {
                TestCase {
                    error_factory,
                    expected_problem_type,
                }
            }
        }

        join_all(
            [
                TestCase::new(Box::new(|| Error::InvalidConfiguration("test")), None),
                TestCase::new(
                    Box::new(|| {
                        Error::ReportRejected(random(), random(), RealClock::default().now())
                    }),
                    Some(DapProblemType::ReportRejected),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedMessage(Some(random()), "test")),
                    Some(DapProblemType::UnrecognizedMessage),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedTask(random())),
                    Some(DapProblemType::UnrecognizedTask),
                ),
                TestCase::new(
                    Box::new(|| Error::MissingTaskId),
                    Some(DapProblemType::MissingTaskId),
                ),
                TestCase::new(
                    Box::new(|| Error::UnrecognizedAggregationJob(random(), random())),
                    Some(DapProblemType::UnrecognizedAggregationJob),
                ),
                TestCase::new(
                    Box::new(|| Error::OutdatedHpkeConfig(random(), HpkeConfigId::from(0))),
                    Some(DapProblemType::OutdatedConfig),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::ReportTooEarly(random(), random(), RealClock::default().now())
                    }),
                    Some(DapProblemType::ReportTooEarly),
                ),
                TestCase::new(
                    Box::new(|| Error::UnauthorizedRequest(random())),
                    Some(DapProblemType::UnauthorizedRequest),
                ),
                TestCase::new(
                    Box::new(|| Error::InvalidBatchSize(random(), 8)),
                    Some(DapProblemType::InvalidBatchSize),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::BatchInvalid(
                            random(),
                            format!(
                                "{}",
                                Interval::new(
                                    RealClock::default().now(),
                                    Duration::from_seconds(3600)
                                )
                                .unwrap()
                            ),
                        )
                    }),
                    Some(DapProblemType::BatchInvalid),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::BatchOverlap(
                            random(),
                            Interval::new(RealClock::default().now(), Duration::from_seconds(3600))
                                .unwrap(),
                        )
                    }),
                    Some(DapProblemType::BatchOverlap),
                ),
                TestCase::new(
                    Box::new(|| {
                        Error::BatchMismatch(Box::new(BatchMismatch {
                            task_id: random(),
                            own_checksum: ReportIdChecksum::from([0; 32]),
                            own_report_count: 100,
                            peer_checksum: ReportIdChecksum::from([1; 32]),
                            peer_report_count: 99,
                        }))
                    }),
                    Some(DapProblemType::BatchMismatch),
                ),
                TestCase::new(
                    Box::new(|| Error::BatchQueriedTooManyTimes(random(), 99)),
                    Some(DapProblemType::BatchQueriedTooManyTimes),
                ),
            ]
            .into_iter()
            .map(|test_case| {
                let request_histogram = request_histogram.clone();
                async move {
                    // Run the handler implementation of the given error, and capture its response.
                    let error_factory = Arc::new(test_case.error_factory);
                    let error = error_factory();
                    let mut test_conn = post("/").run_async(&error).await;
                    let body = if let Some(body) = test_conn.take_response_body() {
                        body.into_bytes().await.unwrap()
                    } else {
                        Cow::from([].as_slice())
                    };

                    // Serve the response via mockito, and run it through post_to_helper's error handling.
                    let mut server = mockito::Server::new_async().await;
                    let error_mock = server
                        .mock("POST", "/")
                        .with_status(test_conn.status().unwrap() as u16 as usize)
                        .with_header("Content-Type", "application/problem+json")
                        .with_body(body)
                        .create_async()
                        .await;
                    let actual_error = send_request_to_helper(
                        &Client::new(),
                        Method::POST,
                        server.url().parse().unwrap(),
                        "text/plain",
                        (),
                        &AuthenticationToken::from("auth".as_bytes().to_vec()),
                        &request_histogram,
                    )
                    .await
                    .unwrap_err();
                    error_mock.assert_async().await;

                    // Confirm that post_to_helper() correctly parsed the error type from error_handler().
                    assert_matches!(
                        actual_error,
                        Error::Http { dap_problem_type: problem_type, .. } => {
                            assert_eq!(problem_type, test_case.expected_problem_type);
                        }
                    );
                }
            }),
        )
        .await;
    }
}
