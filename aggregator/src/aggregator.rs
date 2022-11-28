//! Common functionality for DAP aggregators.

pub mod accumulator;
pub mod aggregate_share;
pub mod aggregation_job_creator;
pub mod aggregation_job_driver;
pub mod collect_job_driver;
pub mod query_type;

use crate::{
    aggregator::{
        accumulator::Accumulator, aggregate_share::compute_aggregate_share,
        query_type::CollectableQueryType,
    },
    datastore::{
        self,
        models::{
            AggregateShareJob, AggregationJob, AggregationJobState, CollectJob, CollectJobState,
            LeaderStoredReport, ReportAggregation, ReportAggregationState,
        },
        Datastore,
    },
    messages::TimeExt,
    task::{self, Task, VerifyKey, PRIO3_AES128_VERIFY_KEY_LENGTH},
    try_join,
};
use bytes::Bytes;
use http::{
    header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION},
    HeaderMap, StatusCode,
};
use http_api_problem::HttpApiProblem;
use janus_core::{
    hpke::{
        self, associated_data_for_aggregate_share, associated_data_for_report_share,
        HpkeApplicationInfo, Label,
    },
    http::response_to_problem_details,
    task::{AuthenticationToken, VdafInstance, DAP_AUTH_HEADER},
    time::Clock,
};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq, AggregateInitializeResp,
    AggregateShareReq, AggregateShareResp, AggregationJobId, CollectReq, CollectResp,
    DapProblemType, HpkeCiphertext, HpkeConfig, HpkeConfigId, Interval, PartialBatchSelector,
    PrepareStep, PrepareStepResult, Report, ReportId, ReportIdChecksum, ReportShare,
    ReportShareError, Role, TaskId, Time,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter, Unit},
    Context, KeyValue,
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf::{
        self,
        prio3::{
            Prio3, Prio3Aes128Count, Prio3Aes128CountVecMultithreaded, Prio3Aes128Histogram,
            Prio3Aes128Sum,
        },
        PrepareTransition,
    },
};
use reqwest::Client;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt::{self, Display, Formatter},
    future::Future,
    io::Cursor,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use url::Url;
use uuid::Uuid;
use warp::{
    cors::Cors,
    filters::BoxedFilter,
    reply::{self, Response},
    trace, Filter, Rejection, Reply,
};

#[cfg(feature = "test-util")]
use janus_core::test_util::dummy_vdaf;
#[cfg(feature = "test-util")]
use prio::vdaf::VdafError;

use self::query_type::AccumulableQueryType;

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
    /// Corresponds to `reportTooLate`, §3.2
    #[error("task {0}: report {1} too late: {2}")]
    ReportTooLate(TaskId, ReportId, Time),
    /// Corresponds to `reportTooEarly`, §3.2. A report was rejected becuase the timestamp is too
    /// far in the future, §4.3.2.
    #[error("task {0}: report {1} too early: {2}")]
    ReportTooEarly(TaskId, ReportId, Time),
    /// Corresponds to `unrecognizedMessage`, §3.2
    #[error("task {0:?}: unrecognized message: {1}")]
    UnrecognizedMessage(Option<TaskId>, &'static str),
    /// Corresponds to `unrecognizedTask`, §3.2
    #[error("task {0}: unrecognized task")]
    UnrecognizedTask(TaskId),
    /// Corresponds to `missingTaskID`, §3.2
    #[error("no task ID in request")]
    MissingTaskId,
    /// An attempt was made to act on an unknown aggregation job.
    #[error("task {0}: unrecognized aggregation job: {1}")]
    UnrecognizedAggregationJob(TaskId, AggregationJobId),
    /// An attempt was made to act on an unknown collect job.
    #[error("unrecognized collect job: {0}")]
    UnrecognizedCollectJob(Uuid),
    /// An attempt was made to act on a known but deleted collect job.
    #[error("deleted collect job: {0}")]
    DeletedCollectJob(Uuid),
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
    Vdaf(#[from] vdaf::VdafError),
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
    TaskParameters(#[from] crate::task::Error),
    /// Error making an HTTP request.
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    /// HTTP server returned an error status code.
    #[error("HTTP response status {problem_details}")]
    Http {
        problem_details: Box<HttpApiProblem>,
        dap_problem_type: Option<DapProblemType>,
    },
    /// An error representing a generic internal aggregation error; intended for "impossible"
    /// conditions.
    #[error("internal aggregator error: {0}")]
    Internal(String),
}

impl Error {
    /// Provides a human-readable error code identifying the error type.
    fn error_code(&self) -> &'static str {
        match self {
            Error::InvalidConfiguration(_) => "invalid_configuration",
            Error::MessageDecode(_) => "message_decode",
            Error::Message(_) => "message",
            Error::ReportTooLate(_, _, _) => "report_too_late",
            Error::ReportTooEarly(_, _, _) => "report_too_early",
            Error::UnrecognizedMessage(_, _) => "unrecognized_message",
            Error::UnrecognizedTask(_) => "unrecognized_task",
            Error::MissingTaskId => "missing_task_id",
            Error::UnrecognizedAggregationJob(_, _) => "unrecognized_aggregation_job",
            Error::DeletedCollectJob(_) => "deleted_collect_job",
            Error::UnrecognizedCollectJob(_) => "unrecognized_collect_job",
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
            Error::Internal(_) => "internal",
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
            "task {0}: batch misalignment (own checksum = {1:?}, own report count = \
{2}, peer checksum = {3:?}, peer report count = {4})",
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
    /// Cache of task aggregators.
    task_aggregators: Mutex<HashMap<TaskId, Arc<TaskAggregator>>>,

    // Metrics.
    /// Counter tracking the number of failed decryptions while handling the /upload endpoint.
    upload_decrypt_failure_counter: Counter<u64>,
    /// Counter tracking the number of failed message decodes while handling the /upload endpoint.
    upload_decode_failure_counter: Counter<u64>,
    /// Counters tracking the number of failures to step client reports through the aggregation
    /// process.
    aggregate_step_failure_counter: Counter<u64>,
}

impl<C: Clock> Aggregator<C> {
    fn new(datastore: Arc<Datastore<C>>, clock: C, meter: Meter) -> Self {
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

        let aggregate_step_failure_counter = aggregate_step_failure_counter(&meter);
        aggregate_step_failure_counter.add(&Context::current(), 0, &[]);

        Self {
            datastore,
            clock,
            task_aggregators: Mutex::new(HashMap::new()),
            upload_decrypt_failure_counter,
            upload_decode_failure_counter,
            aggregate_step_failure_counter,
        }
    }

    async fn handle_hpke_config(&self, task_id_base64: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        // Task ID is optional in an HPKE config request, but Janus requires it.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1
        let task_id_base64 = task_id_base64.ok_or(Error::MissingTaskId)?;

        let task_id_bytes = base64::decode_config(task_id_base64, base64::URL_SAFE_NO_PAD)
            .map_err(|_| Error::UnrecognizedMessage(None, "task_id"))?;
        let task_id = TaskId::get_decoded(&task_id_bytes)
            .map_err(|_| Error::UnrecognizedMessage(None, "task_id"))?;
        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        Ok(task_aggregator.handle_hpke_config().get_encoded())
    }

    async fn handle_upload(&self, report_bytes: &[u8]) -> Result<(), Error> {
        let report = Report::get_decoded(report_bytes)?;

        let task_aggregator = self.task_aggregator_for(report.task_id()).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(*report.task_id()));
        }
        task_aggregator
            .handle_upload(
                &self.datastore,
                &self.clock,
                &self.upload_decrypt_failure_counter,
                &self.upload_decode_failure_counter,
                report,
            )
            .await
    }

    async fn handle_aggregate_init(
        &self,
        req_bytes: &[u8],
        auth_token: Option<String>,
    ) -> Result<Vec<u8>, Error> {
        // Parse task ID early to avoid parsing the entire message before performing authentication.
        // This assumes that the task ID is at the start of the message content.
        let task_id = TaskId::decode(&mut Cursor::new(req_bytes))?;
        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(task_id));
        }
        if !auth_token
            .map(|t| {
                task_aggregator
                    .task
                    .check_aggregator_auth_token(&t.into_bytes().into())
            })
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(task_id));
        }

        Ok(task_aggregator
            .handle_aggregate_init(
                &self.datastore,
                &self.aggregate_step_failure_counter,
                req_bytes,
            )
            .await?
            .get_encoded())
    }

    async fn handle_aggregate_continue(
        &self,
        req_bytes: &[u8],
        auth_token: Option<String>,
    ) -> Result<Vec<u8>, Error> {
        // Parse task ID early to avoid parsing the entire message before performing authentication.
        // This assumes that the task ID is at the start of the message content.
        let task_id = TaskId::decode(&mut Cursor::new(req_bytes))?;
        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(task_id));
        }
        if !auth_token
            .map(|t| {
                task_aggregator
                    .task
                    .check_aggregator_auth_token(&t.into_bytes().into())
            })
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(task_id));
        }

        let req = AggregateContinueReq::get_decoded(req_bytes)?;
        assert_eq!(req.task_id(), &task_id);

        Ok(task_aggregator
            .handle_aggregate_continue(&self.datastore, &self.aggregate_step_failure_counter, req)
            .await?
            .get_encoded())
    }

    /// Handle a collect request. Only supported by the leader. `req_bytes` is an encoded
    /// [`CollectReq`]. Returns the URL at which a collector may poll for status of the collect job
    /// corresponding to the `CollectReq`.
    async fn handle_collect(
        &self,
        req_bytes: &[u8],
        auth_token: Option<String>,
    ) -> Result<Url, Error> {
        // Parse task ID early to avoid parsing the entire message before performing authentication.
        // This assumes that the task ID is at the start of the message content.
        let task_id = TaskId::decode(&mut Cursor::new(req_bytes))?;
        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(task_id));
        }
        if !auth_token
            .map(|t| {
                task_aggregator
                    .task
                    .check_collector_auth_token(&t.into_bytes().into())
            })
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(task_id));
        }

        task_aggregator
            .handle_collect(&self.datastore, req_bytes)
            .await
    }

    /// Handle a GET request for a collect job. `collect_job_id` is the unique identifier for the
    /// collect job parsed out of the request URI. Returns an encoded [`CollectResp`] if the collect
    /// job has been run to completion, `None` if the collect job has not yet run, or an error
    /// otherwise.
    async fn handle_get_collect_job(
        &self,
        collect_job_id: Uuid,
        auth_token: Option<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let task_id = self
            .datastore
            .run_tx(|tx| Box::pin(async move { tx.get_collect_job_task_id(&collect_job_id).await }))
            .await?
            .ok_or(Error::UnrecognizedCollectJob(collect_job_id))?;

        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(task_id));
        }
        if !auth_token
            .map(|t| {
                task_aggregator
                    .task
                    .check_collector_auth_token(&t.into_bytes().into())
            })
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(task_id));
        }

        task_aggregator
            .handle_get_collect_job(&self.datastore, collect_job_id)
            .await
    }

    /// Handle a DELETE request for a collect job.
    async fn handle_delete_collect_job(
        &self,
        collect_job_id: Uuid,
        auth_token: Option<String>,
    ) -> Result<Response, Error> {
        let task_id = self
            .datastore
            .run_tx(|tx| Box::pin(async move { tx.get_collect_job_task_id(&collect_job_id).await }))
            .await?
            .ok_or(Error::UnrecognizedCollectJob(collect_job_id))?;

        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(task_id));
        }
        if !auth_token
            .map(|t| {
                task_aggregator
                    .task
                    .check_collector_auth_token(&t.into_bytes().into())
            })
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(task_id));
        }

        task_aggregator
            .handle_delete_collect_job(&self.datastore, collect_job_id)
            .await?;

        Ok(StatusCode::NO_CONTENT.into_response())
    }

    /// Handle an aggregate share request. Only supported by the helper. `req_bytes` is an encoded,
    /// authenticated [`AggregateShareReq`]. Returns an encoded, authenticated
    /// [`AggregateShareResp`].
    async fn handle_aggregate_share(
        &self,
        req_bytes: &[u8],
        auth_token: Option<String>,
    ) -> Result<Vec<u8>, Error> {
        // Parse task ID early to avoid parsing the entire message before performing authentication.
        // This assumes that the task ID is at the start of the message content.
        let task_id = TaskId::decode(&mut Cursor::new(req_bytes))?;
        let task_aggregator = self.task_aggregator_for(&task_id).await?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(task_id));
        }
        if !auth_token
            .map(|t| {
                task_aggregator
                    .task
                    .check_aggregator_auth_token(&t.into_bytes().into())
            })
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(task_id));
        }

        let resp = task_aggregator
            .handle_aggregate_share(&self.datastore, req_bytes)
            .await?;
        Ok(resp.get_encoded())
    }

    async fn task_aggregator_for(&self, task_id: &TaskId) -> Result<Arc<TaskAggregator>, Error> {
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
            .run_tx(|tx| {
                let task_id = *task_id;
                Box::pin(async move { tx.get_task(&task_id).await })
            })
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        let task_agg = Arc::new(TaskAggregator::new(task)?);
        {
            let mut task_aggs = self.task_aggregators.lock().await;
            Ok(Arc::clone(task_aggs.entry(*task_id).or_insert(task_agg)))
        }
    }
}

/// TaskAggregator provides aggregation functionality for a single task.
// TODO(#224): refactor Aggregator to perform indepedent batched operations (e.g. report handling in
// Aggregate requests) using a parallelized library like Rayon.
pub struct TaskAggregator {
    /// The task being aggregated.
    task: Arc<Task>,
    /// VDAF-specific operations.
    vdaf_ops: VdafOps,
}

impl TaskAggregator {
    /// Create a new aggregator. `report_recipient` is used to decrypt reports received by this
    /// aggregator.
    fn new(task: Task) -> Result<Self, Error> {
        let vdaf_ops = match task.vdaf() {
            VdafInstance::Prio3Aes128Count => {
                let vdaf = Prio3::new_aes128_count(2)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3Aes128Count(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3Aes128CountVec { length } => {
                let vdaf = Prio3::new_aes128_count_vec_multithreaded(2, *length)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3Aes128CountVec(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3Aes128Sum { bits } => {
                let vdaf = Prio3::new_aes128_sum(2, *bits)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3Aes128Sum(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3Aes128Histogram { buckets } => {
                let vdaf = Prio3::new_aes128_histogram(2, buckets)?;
                let verify_key = task.primary_vdaf_verify_key()?;
                VdafOps::Prio3Aes128Histogram(Arc::new(vdaf), verify_key)
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
                    || -> Result<PrepareTransition<dummy_vdaf::Vdaf, 0>, VdafError> {
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
        })
    }

    fn handle_hpke_config(&self) -> HpkeConfig {
        // TODO(#239): consider deciding a better way to determine "primary" (e.g. most-recent) HPKE
        // config/key -- right now it's the one with the maximal config ID, but that will run into
        // trouble if we ever need to wrap-around, which we may since config IDs are effectively a u8.
        self.task
            .hpke_keys()
            .iter()
            .max_by_key(|(&id, _)| id)
            .unwrap()
            .1
             .0
            .clone()
    }

    async fn handle_upload<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        clock: &C,
        upload_decrypt_failure_counter: &Counter<u64>,
        upload_decode_failure_counter: &Counter<u64>,
        report: Report,
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_upload(
                datastore,
                clock,
                upload_decrypt_failure_counter,
                upload_decode_failure_counter,
                &self.task,
                report,
            )
            .await
    }

    async fn handle_aggregate_init<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        aggregate_step_failure_counter: &Counter<u64>,
        req_bytes: &[u8],
    ) -> Result<AggregateInitializeResp, Error> {
        self.vdaf_ops
            .handle_aggregate_init(
                datastore,
                aggregate_step_failure_counter,
                Arc::clone(&self.task),
                req_bytes,
            )
            .await
    }

    async fn handle_aggregate_continue<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        aggregate_step_failure_counter: &Counter<u64>,
        req: AggregateContinueReq,
    ) -> Result<AggregateContinueResp, Error> {
        self.vdaf_ops
            .handle_aggregate_continue(
                datastore,
                aggregate_step_failure_counter,
                Arc::clone(&self.task),
                Arc::new(req),
            )
            .await
    }

    async fn handle_collect<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        req_bytes: &[u8],
    ) -> Result<Url, Error> {
        let collect_job_id = self
            .vdaf_ops
            .handle_collect(datastore, Arc::clone(&self.task), req_bytes)
            .await?;

        Ok(self
            .task
            .aggregator_url(&Role::Leader)?
            .join("collect_jobs/")?
            .join(&collect_job_id.to_string())?)
    }

    async fn handle_get_collect_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        collect_job_id: Uuid,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.vdaf_ops
            .handle_get_collect_job(datastore, &self.task, Arc::new(collect_job_id))
            .await
    }

    async fn handle_delete_collect_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        collect_job_id: Uuid,
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_delete_collect_job(datastore, &self.task, collect_job_id)
            .await
    }

    async fn handle_aggregate_share<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        req_bytes: &[u8],
    ) -> Result<AggregateShareResp, Error> {
        self.vdaf_ops
            .handle_aggregate_share(datastore, Arc::clone(&self.task), req_bytes)
            .await
    }
}

/// VdafOps stores VDAF-specific operations for a TaskAggregator in a non-generic way.
#[allow(clippy::enum_variant_names)]
enum VdafOps {
    // For the Prio3 VdafOps, the second parameter is the verify_key.
    Prio3Aes128Count(
        Arc<Prio3Aes128Count>,
        VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH>,
    ),
    Prio3Aes128CountVec(
        Arc<Prio3Aes128CountVecMultithreaded>,
        VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH>,
    ),
    Prio3Aes128Sum(
        Arc<Prio3Aes128Sum>,
        VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH>,
    ),
    Prio3Aes128Histogram(
        Arc<Prio3Aes128Histogram>,
        VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH>,
    ),

    #[cfg(feature = "test-util")]
    Fake(Arc<dummy_vdaf::Vdaf>),
}

impl VdafOps {
    async fn handle_upload<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        clock: &C,
        upload_decrypt_failure_counter: &Counter<u64>,
        upload_decode_failure_counter: &Counter<u64>,
        task: &Task,
        report: Report,
    ) -> Result<(), Error> {
        match self {
            VdafOps::Prio3Aes128Count(vdaf, _) => {
                Self::handle_upload_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count, _>(
                    datastore,
                    vdaf,
                    clock,
                    upload_decrypt_failure_counter,
                    upload_decode_failure_counter,
                    task,
                    report,
                )
                .await
            }
            VdafOps::Prio3Aes128CountVec(vdaf, _) => {
                Self::handle_upload_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(
                    datastore,
                    vdaf,
                    clock,
                    upload_decrypt_failure_counter,
                    upload_decode_failure_counter,
                    task,
                    report,
                )
                .await
            }
            VdafOps::Prio3Aes128Sum(vdaf, _) => {
                Self::handle_upload_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Sum, _>(
                    datastore,
                    vdaf,
                    clock,
                    upload_decrypt_failure_counter,
                    upload_decode_failure_counter,
                    task,
                    report,
                )
                .await
            }
            VdafOps::Prio3Aes128Histogram(vdaf, _) => Self::handle_upload_generic::<
                PRIO3_AES128_VERIFY_KEY_LENGTH,
                Prio3Aes128Histogram,
                _,
            >(
                datastore,
                vdaf,
                clock,
                upload_decrypt_failure_counter,
                upload_decode_failure_counter,
                task,
                report,
            )
            .await,

            #[cfg(feature = "test-util")]
            VdafOps::Fake(vdaf) => {
                Self::handle_upload_generic::<0, dummy_vdaf::Vdaf, _>(
                    datastore,
                    vdaf,
                    clock,
                    upload_decrypt_failure_counter,
                    upload_decode_failure_counter,
                    task,
                    report,
                )
                .await
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
        req_bytes: &[u8],
    ) -> Result<AggregateInitializeResp, Error> {
        match (task.query_type(), self) {
            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Count(vdaf, verify_key)) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128CountVec(vdaf, verify_key)) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Sum(vdaf, verify_key)) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Sum,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Histogram(vdaf, verify_key)) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Histogram,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafOps::Fake(vdaf)) => {
                Self::handle_aggregate_init_generic::<0, TimeInterval, dummy_vdaf::Vdaf, _>(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    &VerifyKey::new([]),
                    req_bytes,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Count(vdaf, verify_key)) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Count,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128CountVec(vdaf, verify_key)) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Sum(vdaf, verify_key)) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Sum,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            (
                task::QueryType::FixedSize { .. },
                VdafOps::Prio3Aes128Histogram(vdaf, verify_key),
            ) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Histogram,
                    _,
                >(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    verify_key,
                    req_bytes,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize { .. }, VdafOps::Fake(vdaf)) => {
                Self::handle_aggregate_init_generic::<0, TimeInterval, dummy_vdaf::Vdaf, _>(
                    datastore,
                    vdaf,
                    aggregate_step_failure_counter,
                    task,
                    &VerifyKey::new([]),
                    req_bytes,
                )
                .await
            }
        }
    }

    async fn handle_aggregate_continue<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        aggregate_step_failure_counter: &Counter<u64>,
        task: Arc<Task>,
        req: Arc<AggregateContinueReq>,
    ) -> Result<AggregateContinueResp, Error> {
        match (task.query_type(), self) {
            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Count(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128CountVec(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Sum(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Sum,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Histogram(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Histogram,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafOps::Fake(vdaf)) => {
                Self::handle_aggregate_continue_generic::<0, TimeInterval, dummy_vdaf::Vdaf, _>(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Count(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Count,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128CountVec(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Sum(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Sum,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Histogram(vdaf, _)) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Histogram,
                    _,
                >(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize { .. }, VdafOps::Fake(vdaf)) => {
                Self::handle_aggregate_continue_generic::<0, FixedSize, dummy_vdaf::Vdaf, _>(
                    datastore,
                    Arc::clone(vdaf),
                    aggregate_step_failure_counter,
                    task,
                    req,
                )
                .await
            }
        }
    }

    async fn handle_upload_generic<const L: usize, A, C>(
        datastore: &Datastore<C>,
        vdaf: &A,
        clock: &C,
        upload_decrypt_failure_counter: &Counter<u64>,
        upload_decode_failure_counter: &Counter<u64>,
        task: &Task,
        report: Report,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<L> + Send + Sync + 'static,
        A::InputShare: PartialEq + Send + Sync,
        A::PublicShare: PartialEq + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        C: Clock,
    {
        // The leader's report is the first one.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        if report.encrypted_input_shares().len() != 2 {
            return Err(Error::UnrecognizedMessage(
                Some(*report.task_id()),
                "unexpected number of encrypted shares in report",
            ));
        }
        let leader_encrypted_input_share =
            &report.encrypted_input_shares()[Role::Leader.index().unwrap()];

        // Verify that the report's HPKE config ID is known.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        let (hpke_config, hpke_private_key) = task
            .hpke_keys()
            .get(leader_encrypted_input_share.config_id())
            .ok_or_else(|| {
                Error::OutdatedHpkeConfig(
                    *report.task_id(),
                    *leader_encrypted_input_share.config_id(),
                )
            })?;

        let report_deadline = clock.now().add(task.tolerable_clock_skew())?;

        // Reject reports from too far in the future.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        if report.metadata().time().is_after(&report_deadline) {
            return Err(Error::ReportTooEarly(
                *report.task_id(),
                *report.metadata().id(),
                *report.metadata().time(),
            ));
        }

        // Reject reports after a task has expired.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
        if report.metadata().time().is_after(task.task_expiration()) {
            return Err(Error::ReportTooLate(
                *report.task_id(),
                *report.metadata().id(),
                *report.metadata().time(),
            ));
        }

        // Decode (and in the case of the leader input share, decrypt) the remaining fields of the
        // report before storing them in the datastore. The spec does not require the /upload
        // handler to do this, but it exercises HPKE decryption, saves us the trouble of storing
        // reports we can't use, and lets the aggregation job handler assume the values it reads
        // from the datastore are valid. We don't inform the client if this fails.
        let public_share =
            match A::PublicShare::get_decoded_with_param(&vdaf, report.public_share()) {
                Ok(public_share) => public_share,
                Err(err) => {
                    warn!(
                        report.task_id = %report.task_id(),
                        report.metadata = ?report.metadata(),
                        ?err,
                        "public share decoding failed",
                    );
                    upload_decode_failure_counter.add(&Context::current(), 1, &[]);
                    return Ok(());
                }
            };

        let leader_decrypted_input_share = match hpke::open(
            hpke_config,
            hpke_private_key,
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, task.role()),
            leader_encrypted_input_share,
            &associated_data_for_report_share(
                report.task_id(),
                report.metadata(),
                report.public_share(),
            ),
        ) {
            Ok(leader_decrypted_input_share) => leader_decrypted_input_share,
            Err(error) => {
                info!(
                    report.task_id = %report.task_id(),
                    report.metadata = ?report.metadata(),
                    ?error,
                    "Report decryption failed",
                );
                upload_decrypt_failure_counter.add(&Context::current(), 1, &[]);
                return Ok(());
            }
        };

        let leader_input_share = match A::InputShare::get_decoded_with_param(
            &(vdaf, Role::Leader.index().unwrap()),
            &leader_decrypted_input_share,
        ) {
            Ok(leader_input_share) => leader_input_share,
            Err(err) => {
                warn!(
                    report.task_id = %report.task_id(),
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

        let stored_report = LeaderStoredReport::new(
            *report.task_id(),
            report.metadata().clone(),
            public_share,
            leader_input_share,
            helper_encrypted_input_share.clone(),
        );

        datastore
            .run_tx(|tx| {
                let (vdaf, stored_report) = (vdaf.clone(), stored_report.clone());
                Box::pin(async move {
                    let (existing_client_report, conflicting_collect_jobs) = try_join!(
                        tx.get_client_report(
                            &vdaf,
                            stored_report.task_id(),
                            stored_report.metadata().id()
                        ),
                        tx.get_collect_jobs_including_time::<L, A>(
                            stored_report.task_id(),
                            stored_report.metadata().time()
                        ),
                    )?;

                    // Reject reports whose report IDs have been seen before.
                    if existing_client_report.is_some() {
                        // TODO(#34): change this error type.
                        return Err(datastore::Error::User(
                            Error::ReportTooLate(
                                *stored_report.task_id(),
                                *stored_report.metadata().id(),
                                *stored_report.metadata().time(),
                            )
                            .into(),
                        ));
                    }

                    // Reject reports whose timestamps fall into a batch interval that has already
                    // been collected.
                    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.2
                    if !conflicting_collect_jobs.is_empty() {
                        return Err(datastore::Error::User(
                            Error::ReportTooLate(
                                *stored_report.task_id(),
                                *stored_report.metadata().id(),
                                *stored_report.metadata().time(),
                            )
                            .into(),
                        ));
                    }

                    // Store the report.
                    tx.put_client_report::<L, A>(&stored_report).await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    /// Implements the aggregate initialization request portion of the `/aggregate` endpoint for the
    /// helper, described in §4.4.4.1 of draft-gpew-priv-ppm.
    async fn handle_aggregate_init_generic<
        const L: usize,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        vdaf: &A,
        aggregate_step_failure_counter: &Counter<u64>,
        task: Arc<Task>,
        verify_key: &VerifyKey<L>,
        req_bytes: &[u8],
    ) -> Result<AggregateInitializeResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        // Decode request, and verify that it is for the current task. We use an assert to check
        // that the task IDs match as this should be guaranteed by the caller.
        let req = AggregateInitializeReq::<Q>::get_decoded(req_bytes)?;
        assert_eq!(req.task_id(), task.id());

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
        struct ReportShareData<const L: usize, A: vdaf::Aggregator<L>>
        where
            for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        {
            report_share: ReportShare,
            prep_result: PrepareStepResult,
            agg_state: ReportAggregationState<L, A>,
        }
        let mut saw_continue = false;
        let mut report_share_data = Vec::new();
        let agg_param = A::AggregationParam::get_decoded(req.aggregation_parameter())?;
        for report_share in req.report_shares() {
            let hpke_key = task
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
            let plaintext = hpke_key.and_then(|(hpke_config, hpke_private_key)| {
                hpke::open(
                    hpke_config,
                    hpke_private_key,
                    &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
                    report_share.encrypted_input_share(),
                    &associated_data_for_report_share(
                        task.id(),
                        report_share.metadata(),
                        report_share.public_share(),
                    ),
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

            // `vdaf-prep-error` probably isn't the right code, but there is no better one & we
            // don't want to fail the entire aggregation job with an UnrecognizedMessage error
            // because a single client sent bad data.
            // TODO(https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/255): agree on/standardize
            // an error code for "client report data can't be decoded" & use it here.
            let input_share = plaintext.and_then(|plaintext| {
                A::InputShare::get_decoded_with_param(&(vdaf, Role::Helper.index().unwrap()), &plaintext)
                    .map_err(|error| {
                        info!(task_id = %task.id(), metadata = ?report_share.metadata(), ?error, "Couldn't decode helper's input share");
                        aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "input_share_decode_failure")]);
                        ReportShareError::VdafPrepError
                    })
            });

            let public_share = A::PublicShare::get_decoded_with_param(&vdaf, report_share.public_share()).map_err(|error|{
                info!(task_id = %task.id(), metadata = ?report_share.metadata(), ?error, "Couldn't decode public share");
                aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "public_share_decode_failure")]);
                ReportShareError::VdafPrepError
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
                        &report_share.metadata().id().get_encoded(),
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
                    ReportShareData {
                        report_share: report_share.clone(),
                        prep_result: PrepareStepResult::Continued(prep_share.get_encoded()),
                        agg_state: ReportAggregationState::<L, A>::Waiting(prep_state, None),
                    }
                }

                Err(err) => ReportShareData {
                    report_share: report_share.clone(),
                    prep_result: PrepareStepResult::Failed(err),
                    agg_state: ReportAggregationState::<L, A>::Failed(err),
                },
            });
        }

        // Store data to datastore.
        let batch_identifier_opt =
            Q::upgrade_partial_batch_identifier(req.batch_selector().batch_identifier()).cloned();
        let req = Arc::new(req);
        let aggregation_job = Arc::new(AggregationJob::<L, Q, A>::new(
            *task.id(),
            *req.job_id(),
            batch_identifier_opt,
            agg_param,
            if saw_continue {
                AggregationJobState::InProgress
            } else {
                AggregationJobState::Finished
            },
        ));
        let report_share_data = Arc::new(report_share_data);
        let prep_steps = datastore
            .run_tx(|tx| {
                let (task, req, aggregation_job, report_share_data) = (
                    Arc::clone(&task),
                    Arc::clone(&req),
                    Arc::clone(&aggregation_job),
                    Arc::clone(&report_share_data),
                );

                Box::pin(async move {
                    // Write aggregation job.
                    tx.put_aggregation_job(&aggregation_job).await?;

                    let mut accumulator = Accumulator::<L, Q, A>::new(
                        Arc::clone(&task),
                        aggregation_job.aggregation_parameter().clone(),
                    );

                    let mut prep_steps = Vec::new();
                    for (ord, share_data) in report_share_data.iter().enumerate() {
                        // Verify that we haven't seen this report ID before, and that the report
                        // isn't for a batch interval that has already started collection.
                        let (report_share_exists, conflicting_aggregate_share_jobs) = try_join!(
                            tx.check_report_share_exists(
                                task.id(),
                                share_data.report_share.metadata().id()
                            ),
                            Q::get_conflicting_aggregate_share_jobs::<L, C, A>(
                                tx,
                                task.id(),
                                req.batch_selector().batch_identifier(),
                                share_data.report_share.metadata()
                            ),
                        )?;
                        if report_share_exists {
                            prep_steps.push(PrepareStep::new(
                                *share_data.report_share.metadata().id(),
                                PrepareStepResult::Failed(ReportShareError::ReportReplayed),
                            ));
                            continue;
                        }
                        if !conflicting_aggregate_share_jobs.is_empty() {
                            prep_steps.push(PrepareStep::new(
                                *share_data.report_share.metadata().id(),
                                PrepareStepResult::Failed(ReportShareError::BatchCollected),
                            ));
                            continue;
                        }

                        // Write client report & report aggregation.
                        tx.put_report_share(task.id(), &share_data.report_share)
                            .await?;
                        tx.put_report_aggregation(&ReportAggregation::<L, A>::new(
                            *task.id(),
                            *req.job_id(),
                            *share_data.report_share.metadata().id(),
                            *share_data.report_share.metadata().time(),
                            ord as i64,
                            share_data.agg_state.clone(),
                        ))
                        .await?;

                        if let ReportAggregationState::<L, A>::Finished(ref output_share) =
                            share_data.agg_state
                        {
                            accumulator.update(
                                aggregation_job.partial_batch_identifier()?,
                                share_data.report_share.metadata().id(),
                                share_data.report_share.metadata().time(),
                                output_share,
                            )?;
                        }

                        prep_steps.push(PrepareStep::new(
                            *share_data.report_share.metadata().id(),
                            share_data.prep_result.clone(),
                        ));
                    }

                    accumulator.flush_to_datastore(tx).await?;
                    Ok(prep_steps)
                })
            })
            .await?;

        // Construct response and return.
        Ok(AggregateInitializeResp::new(prep_steps))
    }

    async fn handle_aggregate_continue_generic<
        const L: usize,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        vdaf: Arc<A>,
        aggregate_step_failure_counter: &Counter<u64>,
        task: Arc<Task>,
        req: Arc<AggregateContinueReq>,
    ) -> Result<AggregateContinueResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Debug,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PrepareShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::OutputShare: Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        // TODO(#224): don't hold DB transaction open while computing VDAF updates?
        // TODO(#224): don't do O(n) network round-trips (where n is the number of prepare steps)
        Ok(datastore
            .run_tx(|tx| {
                let (vdaf, aggregate_step_failure_counter, task, req) =
                    (Arc::clone(&vdaf), aggregate_step_failure_counter.clone(), Arc::clone(&task), Arc::clone(&req));

                Box::pin(async move {
                    // Read existing state.
                    let (aggregation_job, report_aggregations) = try_join!(
                        tx.get_aggregation_job::<L, Q, A>(task.id(), req.job_id()),
                        tx.get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            &Role::Helper,
                            task.id(),
                            req.job_id(),
                        ),
                    )?;
                    let aggregation_job = aggregation_job.ok_or_else(|| datastore::Error::User(Error::UnrecognizedAggregationJob(*task.id(), *req.job_id()).into()))?;

                    // Handle each transition in the request.
                    let mut report_aggregations = report_aggregations.into_iter();
                    let (mut saw_continue, mut saw_finish) = (false, false);
                    let mut response_prep_steps = Vec::new();
                    let mut accumulator = Accumulator::<L, Q, A>::new(Arc::clone(&task), aggregation_job.aggregation_parameter().clone());

                    for prep_step in req.prepare_steps().iter() {
                        // Match preparation step received from leader to stored report aggregation,
                        // and extract the stored preparation step.
                        let report_aggregation = loop {
                            let report_agg = report_aggregations.next().ok_or_else(|| {
                                datastore::Error::User(Error::UnrecognizedMessage(
                                    Some(*task.id()),
                                    "leader sent unexpected, duplicate, or out-of-order prepare steps",
                                ).into())
                            })?;
                            if report_agg.report_id() != prep_step.report_id() {
                                // This report was omitted by the leader because of a prior failure.
                                // Note that the report was dropped (if it's not already in an error
                                // state) and continue.
                                if matches!(report_agg.state(), ReportAggregationState::Waiting(_, _)) {
                                    tx.update_report_aggregation(&report_agg.with_state(ReportAggregationState::Failed(ReportShareError::ReportDropped))).await?;
                                }
                                continue;
                            }
                            break report_agg;
                        };

                        // Make sure this report isn't in an interval that has already started
                        // collection.
                        let conflicting_aggregate_share_jobs = tx.get_aggregate_share_jobs_including_time::<L, A>(task.id(), report_aggregation.time()).await?;
                        if !conflicting_aggregate_share_jobs.is_empty() {
                            response_prep_steps.push(PrepareStep::new(
                                *prep_step.report_id(),
                                PrepareStepResult::Failed(ReportShareError::BatchCollected),
                            ));
                            tx.update_report_aggregation(&report_aggregation.with_state(ReportAggregationState::Failed(ReportShareError::BatchCollected))).await?;
                            continue;
                        }

                        let prep_state =
                            match report_aggregation.state() {
                                ReportAggregationState::Waiting(prep_state, _) => prep_state,
                                _ => {
                                    return Err(datastore::Error::User(
                                        Error::UnrecognizedMessage(
                                            Some(*task.id()),
                                            "leader sent prepare step for non-WAITING report aggregation",
                                        ).into()
                                    ));
                                },
                            };

                        // Parse preparation message out of prepare step received from leader.
                        let prep_msg = match prep_step.result() {
                            PrepareStepResult::Continued(payload) => {
                                A::PrepareMessage::decode_with_param(
                                    prep_state,
                                    &mut Cursor::new(payload.as_ref()),
                                )?
                            }
                            _ => {
                                return Err(datastore::Error::User(
                                    Error::UnrecognizedMessage(
                                        Some(*task.id()),
                                        "leader sent non-Continued prepare step",
                                    ).into()
                                ));
                            }
                        };

                        // Compute the next transition, prepare to respond & update DB.
                        let next_state = match vdaf.prepare_step(prep_state.clone(), prep_msg) {
                            Ok(PrepareTransition::Continue(prep_state, prep_share))=> {
                                saw_continue = true;
                                response_prep_steps.push(PrepareStep::new(
                                    *prep_step.report_id(),
                                    PrepareStepResult::Continued(prep_share.get_encoded()),
                                ));
                                ReportAggregationState::Waiting(prep_state, None)
                            }

                            Ok(PrepareTransition::Finish(output_share)) => {
                                saw_finish = true;
                                accumulator.update(
                                    aggregation_job.partial_batch_identifier()?,
                                    prep_step.report_id(),
                                    report_aggregation.time(),
                                    &output_share,
                                )?;
                                response_prep_steps.push(PrepareStep::new(
                                    *prep_step.report_id(),
                                    PrepareStepResult::Finished,
                                ));
                                ReportAggregationState::Finished(output_share)
                            }

                            Err(error) => {
                                info!(task_id = %task.id(), job_id = %req.job_id(), report_id = %prep_step.report_id(), ?error, "Prepare step failed");
                                aggregate_step_failure_counter.add(&Context::current(), 1, &[KeyValue::new("type", "prepare_step_failure")]);
                                response_prep_steps.push(PrepareStep::new(
                                    *prep_step.report_id(),
                                    PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                                ));
                                ReportAggregationState::Failed(ReportShareError::VdafPrepError)
                            }
                        };

                        tx.update_report_aggregation(&report_aggregation.with_state(next_state)).await?;
                    }

                    for report_agg in report_aggregations {
                        // This report was omitted by the leader because of a prior failure.
                        // Note that the report was dropped (if it's not already in an error state)
                        // and continue.
                        if matches!(report_agg.state(), ReportAggregationState::Waiting(_, _)) {
                            tx.update_report_aggregation(&report_agg.with_state(ReportAggregationState::Failed(ReportShareError::ReportDropped))).await?;
                        }
                    }

                    let aggregation_job = aggregation_job.with_state(match (saw_continue, saw_finish) {
                        (false, false) => AggregationJobState::Finished, // everything failed, or there were no reports
                        (true, false) => AggregationJobState::InProgress,
                        (false, true) => AggregationJobState::Finished,
                        (true, true) => {
                            return Err(datastore::Error::User(Error::Internal(
                                "VDAF took an inconsistent number of rounds to reach Finish state"
                                    .to_string(),
                            ).into()))
                        }
                    });
                    tx.update_aggregation_job(&aggregation_job).await?;

                    accumulator.flush_to_datastore(tx).await?;

                    Ok(AggregateContinueResp::new(response_prep_steps))
                })
            })
            .await?)
    }

    /// Handle requests to the leader `/collect` endpoint (§4.5).
    async fn handle_collect<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<Task>,
        collect_req_bytes: &[u8],
    ) -> Result<Uuid, Error> {
        match (task.query_type(), self) {
            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Sum,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafOps::Fake(_)) => {
                Self::handle_collect_generic::<0, TimeInterval, dummy_vdaf::Vdaf, _>(
                    datastore,
                    task,
                    collect_req_bytes,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Sum,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, collect_req_bytes)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize { .. }, VdafOps::Fake(_)) => {
                Self::handle_collect_generic::<0, FixedSize, dummy_vdaf::Vdaf, _>(
                    datastore,
                    task,
                    collect_req_bytes,
                )
                .await
            }
        }
    }

    #[tracing::instrument(skip(datastore), err)]
    async fn handle_collect_generic<
        const L: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<L>,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<Task>,
        req_bytes: &[u8],
    ) -> Result<Uuid, Error>
    where
        A::AggregationParam: Send + Sync + 'static,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        // Decode request, and verify that it is for the current task. We use an assert to check
        // that the task IDs match as this should be guaranteed by the caller.
        let req = Arc::new(CollectReq::<Q>::get_decoded(req_bytes)?);
        assert_eq!(req.task_id(), task.id());

        let aggregation_param =
            A::AggregationParam::get_decoded(req.as_ref().aggregation_parameter())?;

        // Check that the batch interval is valid for the task
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6.1.1
        if !Q::validate_collect_identifier(&task, req.query().batch_identifier()) {
            return Err(Error::BatchInvalid(
                *task.id(),
                format!("{}", req.query().batch_identifier()),
            ));
        }

        Ok(datastore
            .run_tx(move |tx| {
                let aggregation_param = aggregation_param.clone();
                let task = task.clone();
                let req = req.clone();
                Box::pin(async move {
                    if let Some(collect_job_id) = tx
                        .get_collect_job_id::<L, Q, A>(
                            task.id(),
                            req.query().batch_identifier(),
                            &aggregation_param,
                        )
                        .await?
                    {
                        debug!(collect_request = ?req, "Serving existing collect job UUID");
                        return Ok(collect_job_id);
                    }

                    debug!(collect_request = ?req, "Cache miss, creating new collect job UUID");
                    let (_, report_count) = try_join!(
                        Q::validate_query_count::<L, C, A>(
                            tx,
                            &task,
                            req.query().batch_identifier(),
                        ),
                        Q::count_client_reports(tx, &task, req.query().batch_identifier()),
                    )?;

                    // Batch size must be validated while handling CollectReq and hence before
                    // creating a collect job.
                    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
                    if !task.validate_batch_size(report_count) {
                        return Err(datastore::Error::User(
                            Error::InvalidBatchSize(*task.id(), report_count).into(),
                        ));
                    }

                    let collect_job_id = Uuid::new_v4();
                    tx.put_collect_job(&CollectJob::<L, Q, A>::new(
                        *req.task_id(),
                        collect_job_id,
                        req.query().batch_identifier().clone(),
                        aggregation_param,
                        CollectJobState::<L, A>::Start,
                    ))
                    .await?;
                    Ok(collect_job_id)
                })
            })
            .await?)
    }

    /// Handle GET requests to a collect job URI obtained from the leader's `/collect` endpoint.
    /// The return value is an encoded `CollectResp<Q>`.
    /// https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.1
    async fn handle_get_collect_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: &Task,
        collect_job_id: Arc<Uuid>,
    ) -> Result<Option<Vec<u8>>, Error> {
        match (task.query_type(), self) {
            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Sum,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafOps::Fake(_)) => {
                Self::handle_get_collect_job_generic::<0, TimeInterval, dummy_vdaf::Vdaf, _>(
                    datastore,
                    task,
                    collect_job_id,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Sum,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_get_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize { .. }, VdafOps::Fake(_)) => {
                Self::handle_get_collect_job_generic::<0, FixedSize, dummy_vdaf::Vdaf, _>(
                    datastore,
                    task,
                    collect_job_id,
                )
                .await
            }
        }
    }

    // return value is an encoded CollectResp<Q>
    async fn handle_get_collect_job_generic<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: &Task,
        collect_job_id: Arc<Uuid>,
    ) -> Result<Option<Vec<u8>>, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        let collect_job = datastore
            .run_tx(|tx| {
                let collect_job_id = Arc::clone(&collect_job_id);
                Box::pin(async move {
                    tx.get_collect_job::<L, Q, A>(&collect_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(*collect_job_id).into(),
                            )
                        })
                })
            })
            .await?;

        match collect_job.state() {
            CollectJobState::Start => {
                debug!(%collect_job_id, task_id = %task.id(), "Collect job has not run yet");
                Ok(None)
            }

            CollectJobState::Finished {
                report_count,
                encrypted_helper_aggregate_share,
                leader_aggregate_share,
            } => {
                // §4.4.4.3: HPKE encrypt aggregate share to the collector. We store the leader
                // aggregate share *unencrypted* in the datastore so that we can encrypt cached
                // results to the collector HPKE config valid when the current collect job request
                // was made, and not whatever was valid at the time the aggregate share was first
                // computed.
                // However we store the helper's *encrypted* share.

                // TODO(#240): consider fetching freshly encrypted helper aggregate share if it has
                // been long enough since the encrypted helper share was cached -- tricky thing is
                // deciding what "long enough" is.
                debug!(
                    %collect_job_id,
                    task_id = %task.id(),
                    "Serving cached collect job response"
                );
                let associated_data = associated_data_for_aggregate_share::<Q>(
                    collect_job.task_id(),
                    collect_job.batch_identifier(),
                );
                let encrypted_leader_aggregate_share = hpke::seal(
                    task.collector_hpke_config(),
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Leader,
                        &Role::Collector,
                    ),
                    &<Vec<u8>>::from(leader_aggregate_share),
                    &associated_data,
                )?;

                Ok(Some(
                    CollectResp::<Q>::new(
                        PartialBatchSelector::new(
                            Q::partial_batch_identifier(collect_job.batch_identifier()).clone(),
                        ),
                        *report_count,
                        Vec::<HpkeCiphertext>::from([
                            encrypted_leader_aggregate_share,
                            encrypted_helper_aggregate_share.clone(),
                        ]),
                    )
                    .get_encoded(),
                ))
            }

            CollectJobState::Abandoned => {
                // TODO(#248): decide how to respond for abandoned collect jobs.
                warn!(
                    %collect_job_id,
                    task_id = %task.id(),
                    "Attempting to collect abandoned collect job"
                );
                Ok(None)
            }

            CollectJobState::Deleted => Err(Error::DeletedCollectJob(*collect_job_id)),
        }
    }

    async fn handle_delete_collect_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: &Task,
        collect_job_id: Uuid,
    ) -> Result<(), Error> {
        match (task.query_type(), self) {
            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Sum,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafOps::Fake(_)) => {
                Self::handle_delete_collect_job_generic::<0, TimeInterval, dummy_vdaf::Vdaf, _>(
                    datastore,
                    collect_job_id,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Count,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Sum,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_delete_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, collect_job_id)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize { .. }, VdafOps::Fake(_)) => {
                Self::handle_delete_collect_job_generic::<0, FixedSize, dummy_vdaf::Vdaf, _>(
                    datastore,
                    collect_job_id,
                )
                .await
            }
        }
    }

    async fn handle_delete_collect_job_generic<
        const L: usize,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        collect_job_id: Uuid,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync + PartialEq + Eq,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        datastore
            .run_tx(move |tx| {
                Box::pin(async move {
                    let collect_job = tx
                        .get_collect_job::<L, Q, A>(&collect_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(collect_job_id).into(),
                            )
                        })?;

                    if collect_job.state() != &CollectJobState::Deleted {
                        tx.update_collect_job::<L, Q, A>(
                            &collect_job.with_state(CollectJobState::Deleted),
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
        task: Arc<Task>,
        req_bytes: &[u8],
    ) -> Result<AggregateShareResp, Error> {
        match (task.query_type(), self) {
            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Sum,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            (task::QueryType::TimeInterval, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafOps::Fake(_)) => {
                Self::handle_aggregate_share_generic::<0, TimeInterval, dummy_vdaf::Vdaf, _>(
                    datastore, task, req_bytes,
                )
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Count(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128CountVec(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128CountVecMultithreaded,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Sum(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Sum,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            (task::QueryType::FixedSize { .. }, VdafOps::Prio3Aes128Histogram(_, _)) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    FixedSize,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, req_bytes)
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize { .. }, VdafOps::Fake(_)) => {
                Self::handle_aggregate_share_generic::<0, FixedSize, dummy_vdaf::Vdaf, _>(
                    datastore, task, req_bytes,
                )
                .await
            }
        }
    }

    async fn handle_aggregate_share_generic<
        const L: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<L>,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<Task>,
        req_bytes: &[u8],
    ) -> Result<AggregateShareResp, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        // Decode request, and verify that it is for the current task. We use an assert to check
        // that the task IDs match as this should be guaranteed by the caller.
        let aggregate_share_req = Arc::new(AggregateShareReq::<Q>::get_decoded(req_bytes)?);
        assert_eq!(aggregate_share_req.task_id(), task.id());

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

        let aggregate_share_job = datastore
            .run_tx(|tx| {
                let (task, aggregate_share_req) =
                    (Arc::clone(&task), Arc::clone(&aggregate_share_req));
                Box::pin(async move {
                    // Check if we have already serviced an aggregate share request with these
                    // parameters and serve the cached results if so.
                    let aggregation_param = A::AggregationParam::get_decoded(
                        aggregate_share_req.aggregation_parameter(),
                    )?;
                    let aggregate_share_job = match tx
                        .get_aggregate_share_job(
                            aggregate_share_req.task_id(),
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
                                    aggregate_share_req.batch_selector().batch_identifier(),
                                    &aggregation_param
                                ),
                                Q::validate_query_count::<L, C, A>(
                                    tx,
                                    &task,
                                    aggregate_share_req.batch_selector().batch_identifier(),
                                )
                            )?;

                            let (helper_aggregate_share, report_count, checksum) =
                                compute_aggregate_share::<L, Q, A>(&task, &batch_aggregations)
                                    .await
                                    .map_err(|e| datastore::Error::User(e.into()))?;

                            // Now that we are satisfied that the request is serviceable, we consume
                            // a query by recording the aggregate share request parameters and the
                            // result.
                            let aggregate_share_job = AggregateShareJob::<L, Q, A>::new(
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
                                task_id: *aggregate_share_req.task_id(),
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
            &<Vec<u8>>::from(aggregate_share_job.helper_aggregate_share()),
            &associated_data_for_aggregate_share::<Q>(
                aggregate_share_req.task_id(),
                aggregate_share_req.batch_selector().batch_identifier(),
            ),
        )?;

        Ok(AggregateShareResp::new(encrypted_aggregate_share))
    }
}

/// Injects a clone of the provided value into the warp filter, making it
/// available to the filter's map() or and_then() handler.
fn with_cloned_value<T>(value: T) -> impl Filter<Extract = (T,), Error = Infallible> + Clone
where
    T: Clone + Sync + Send,
{
    warp::any().map(move || value.clone())
}

trait DapProblemTypeExt {
    /// Returns the HTTP status code that should be used in responses whose body is a problem
    /// document of this type.
    fn http_status(&self) -> StatusCode;
}

impl DapProblemTypeExt for DapProblemType {
    /// Returns the HTTP status code that should be used in responses whose body is a problem
    /// document of this type.
    fn http_status(&self) -> StatusCode {
        match self {
            // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1
            Self::UnrecognizedTask => StatusCode::NOT_FOUND,
            // So far, 400 Bad Request seems to be the appropriate choice for most problem types.
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// The media type for problem details formatted as a JSON document, per RFC 7807.
static PROBLEM_DETAILS_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Construct an error response in accordance with §3.2.
// TODO(https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/209): The handling of the instance,
// title, detail, and taskid fields are subject to change.
fn build_problem_details_response(error_type: DapProblemType, task_id: Option<TaskId>) -> Response {
    let status = error_type.http_status();

    warp::reply::with_status(
        warp::reply::with_header(
            warp::reply::json(&json!({
                "type": error_type.type_uri(),
                "title": error_type.description(),
                "status": status.as_u16(),
                "detail": error_type.description(),
                // The base URI is either "[leader]/upload", "[aggregator]/aggregate",
                // "[helper]/aggregate_share", or "[leader]/collect". Relative URLs are allowed in
                // the instance member, thus ".." will always refer to the aggregator's endpoint,
                // as required by §3.2.
                "instance": "..",
                "taskid": task_id.map(|tid| format!("{}", tid)),
            })),
            http::header::CONTENT_TYPE,
            PROBLEM_DETAILS_JSON_MEDIA_TYPE,
        ),
        status,
    )
    .into_response()
}

/// Produces a closure that will transform applicable errors into a problem details JSON object
/// (see RFC 7807) and update a metrics counter tracking the error status of the result as well as
/// timing information. The returned closure is meant to be used in a warp `with` filter.
fn error_handler<F, T>(
    response_time_histogram: Histogram<f64>,
    name: &'static str,
) -> impl Fn(F) -> BoxedFilter<(Response,)>
where
    F: Filter<Extract = (Result<T, Error>,), Error = Rejection> + Clone + Send + Sync + 'static,
    T: Reply,
{
    move |filter| {
        let response_time_histogram = response_time_histogram.clone();
        warp::any()
            .map(Instant::now)
            .and(filter)
            .map(move |start: Instant, result: Result<T, Error>| {
                let error_code = if let Err(error) = &result {
                    warn!(?error, endpoint = name, "Error handling endpoint");
                    error.error_code()
                } else {
                    ""
                };
                response_time_histogram.record(
                    &Context::current(),
                    start.elapsed().as_secs_f64(),
                    &[
                        KeyValue::new("endpoint", name),
                        KeyValue::new("error_code", error_code),
                    ],
                );

                match result {
                    Ok(reply) => reply.into_response(),
                    Err(Error::InvalidConfiguration(_)) => {
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                    Err(Error::MessageDecode(_)) => {
                        build_problem_details_response(DapProblemType::UnrecognizedMessage, None)
                    }
                    Err(Error::ReportTooLate(task_id, _, _)) => {
                        build_problem_details_response(DapProblemType::ReportTooLate, Some(task_id))
                    }
                    Err(Error::UnrecognizedMessage(task_id, _)) => {
                        build_problem_details_response(DapProblemType::UnrecognizedMessage, task_id)
                    }
                    Err(Error::UnrecognizedTask(task_id)) => {
                        // TODO(#237): ensure that a helper returns HTTP 404 or 403 when this happens.
                        build_problem_details_response(
                            DapProblemType::UnrecognizedTask,
                            Some(task_id),
                        )
                    }
                    Err(Error::MissingTaskId) => {
                        build_problem_details_response(DapProblemType::MissingTaskId, None)
                    }
                    Err(Error::UnrecognizedAggregationJob(task_id, _)) => {
                        build_problem_details_response(
                            DapProblemType::UnrecognizedAggregationJob,
                            Some(task_id),
                        )
                    }
                    Err(Error::DeletedCollectJob(_)) => StatusCode::NO_CONTENT.into_response(),
                    Err(Error::UnrecognizedCollectJob(_)) => StatusCode::NOT_FOUND.into_response(),
                    Err(Error::OutdatedHpkeConfig(task_id, _)) => build_problem_details_response(
                        DapProblemType::OutdatedConfig,
                        Some(task_id),
                    ),
                    Err(Error::ReportTooEarly(task_id, _, _)) => build_problem_details_response(
                        DapProblemType::ReportTooEarly,
                        Some(task_id),
                    ),
                    Err(Error::UnauthorizedRequest(task_id)) => build_problem_details_response(
                        DapProblemType::UnauthorizedRequest,
                        Some(task_id),
                    ),
                    Err(Error::InvalidBatchSize(task_id, _)) => build_problem_details_response(
                        DapProblemType::InvalidBatchSize,
                        Some(task_id),
                    ),
                    Err(Error::BatchInvalid(task_id, _)) => {
                        build_problem_details_response(DapProblemType::BatchInvalid, Some(task_id))
                    }
                    Err(Error::BatchOverlap(task_id, _)) => {
                        build_problem_details_response(DapProblemType::BatchOverlap, Some(task_id))
                    }
                    Err(Error::BatchMismatch(inner)) => build_problem_details_response(
                        DapProblemType::BatchMismatch,
                        Some(inner.task_id),
                    ),
                    Err(Error::BatchQueriedTooManyTimes(task_id, ..)) => {
                        build_problem_details_response(
                            DapProblemType::BatchQueriedTooManyTimes,
                            Some(task_id),
                        )
                    }
                    Err(Error::Hpke(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::Datastore(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::Vdaf(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::Internal(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::Url(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::Message(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::HttpClient(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::Http { .. }) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    Err(Error::TaskParameters(_)) => {
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            })
            .boxed()
    }
}

/// Convenience function to perform common composition of Warp filters for a single endpoint. A
/// combined filter is returned, with a CORS handler, instrumented to measure both request
/// processing time and successes or failures for metrics, and with per-route named tracing spans.
///
/// `route_filter` should be a filter that determines whether the incoming request matches a
/// given route or not. It should inspect the ambient request, and either extract the empty tuple
/// or reject.
///
/// `response_filter` should be a filter that performs all response handling for this route, after
/// the above `route_filter` has already determined the request is applicable to this route. It
/// should only reject in response to malformed requests, not requests that may yet be served by a
/// different route. This will ensure that a single request doesn't pass through multiple wrapping
/// filters, skewing the low end of unrelated requests' timing histograms. The filter's return type
/// should be `Result<impl Reply, Error>`, and errors will be transformed into responses with
/// problem details documents as appropriate.
///
/// `cors` is a configuration object describing CORS policies for this route.
///
/// `response_time_histogram` is a `Histogram` that will be used to record request handling timings.
///
/// `name` is a unique name for this route. This will be used as a metrics label, and will be added
/// to the tracing span's values as its message.
fn compose_common_wrappers<F1, F2, T>(
    route_filter: F1,
    response_filter: F2,
    cors: Cors,
    response_time_histogram: Histogram<f64>,
    name: &'static str,
) -> BoxedFilter<(impl Reply,)>
where
    F1: Filter<Extract = (), Error = Rejection> + Send + Sync + 'static,
    F2: Filter<Extract = (Result<T, Error>,), Error = Rejection> + Clone + Send + Sync + 'static,
    T: Reply + 'static,
{
    route_filter
        .and(
            response_filter
                .with(warp::wrap_fn(error_handler(response_time_histogram, name)))
                .with(cors)
                .with(trace::named(name)),
        )
        .boxed()
}

/// The number of seconds we send in the Access-Control-Max-Age header. This determines for how
/// long clients will cache the results of CORS preflight requests. Of popular browsers, Mozilla
/// Firefox has the highest Max-Age cap, at 24 hours, so we use that. Our CORS preflight handlers
/// are tightly scoped to relevant endpoints, and our CORS settings are unlikely to change.
/// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
const CORS_PREFLIGHT_CACHE_AGE: u32 = 24 * 60 * 60;

/// Constructs a Warp filter with endpoints common to all aggregators.
pub fn aggregator_filter<C: Clock>(
    datastore: Arc<Datastore<C>>,
    clock: C,
) -> Result<BoxedFilter<(impl Reply,)>, Error> {
    let meter = opentelemetry::global::meter("janus_aggregator");
    let response_time_histogram = meter
        .f64_histogram("janus_aggregator_response_time")
        .with_description("Elapsed time handling incoming requests, by endpoint & status.")
        .with_unit(Unit::new("seconds"))
        .init();

    let aggregator = Arc::new(Aggregator::new(datastore, clock, meter));

    let hpke_config_routing = warp::path("hpke_config");
    let hpke_config_responding = warp::get()
        .and(with_cloned_value(Arc::clone(&aggregator)))
        .and(warp::query::<HashMap<String, String>>())
        .then(
            |aggregator: Arc<Aggregator<C>>, query_params: HashMap<String, String>| async move {
                let hpke_config_bytes = aggregator
                    .handle_hpke_config(query_params.get("task_id").map(String::as_ref))
                    .await?;
                http::Response::builder()
                    .header(CACHE_CONTROL, "max-age=86400")
                    .header(CONTENT_TYPE, HpkeConfig::MEDIA_TYPE)
                    .body(hpke_config_bytes)
                    .map_err(|err| Error::Internal(format!("couldn't produce response: {}", err)))
            },
        );
    let hpke_config_endpoint = compose_common_wrappers(
        hpke_config_routing,
        hpke_config_responding,
        warp::cors()
            .allow_any_origin()
            .allow_method("GET")
            .max_age(CORS_PREFLIGHT_CACHE_AGE)
            .build(),
        response_time_histogram.clone(),
        "hpke_config",
    );

    let upload_routing = warp::path("upload");
    let upload_responding = warp::post()
        .and(warp::header::exact(
            CONTENT_TYPE.as_str(),
            Report::MEDIA_TYPE,
        ))
        .and(with_cloned_value(Arc::clone(&aggregator)))
        .and(warp::body::bytes())
        .then(|aggregator: Arc<Aggregator<C>>, body: Bytes| async move {
            aggregator.handle_upload(&body).await?;
            Ok(StatusCode::OK)
        });
    let upload_endpoint = compose_common_wrappers(
        upload_routing,
        upload_responding,
        warp::cors()
            .allow_any_origin()
            .allow_method("POST")
            .allow_header("content-type")
            .max_age(CORS_PREFLIGHT_CACHE_AGE)
            .build(),
        response_time_histogram.clone(),
        "upload",
    );

    let aggregate_routing = warp::path("aggregate");
    let aggregate_responding = warp::post()
        .and(with_cloned_value(Arc::clone(&aggregator)))
        .and(warp::body::bytes())
        .and(warp::header(CONTENT_TYPE.as_str()))
        .and(warp::header::optional::<String>(DAP_AUTH_HEADER))
        .then(
            |aggregator: Arc<Aggregator<C>>,
             body: Bytes,
             content_type: String,
             auth_token: Option<String>| async move {
                match content_type.as_str() {
                    AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE => http::Response::builder()
                        .header(CONTENT_TYPE, AggregateInitializeResp::MEDIA_TYPE)
                        .body(aggregator.handle_aggregate_init(&body, auth_token).await?),
                    AggregateContinueReq::MEDIA_TYPE => http::Response::builder()
                        .header(CONTENT_TYPE, AggregateContinueResp::MEDIA_TYPE)
                        .body(
                            aggregator
                                .handle_aggregate_continue(&body, auth_token)
                                .await?,
                        ),
                    _ => http::Response::builder()
                        .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                        .body(Vec::new()),
                }
                .map_err(|err| Error::Internal(format!("couldn't produce response: {}", err)))
            },
        );
    let aggregate_endpoint = compose_common_wrappers(
        aggregate_routing,
        aggregate_responding,
        warp::cors().build(),
        response_time_histogram.clone(),
        "aggregate",
    );

    let collect_routing = warp::path("collect");
    let collect_responding = warp::post()
        .and(warp::header::exact(
            CONTENT_TYPE.as_str(),
            CollectReq::<TimeInterval>::MEDIA_TYPE,
        ))
        .and(with_cloned_value(Arc::clone(&aggregator)))
        .and(warp::body::bytes())
        .and(warp::header::optional::<String>(DAP_AUTH_HEADER))
        .then(
            |aggregator: Arc<Aggregator<C>>, body: Bytes, auth_token: Option<String>| async move {
                let collect_uri = aggregator.handle_collect(&body, auth_token).await?;
                // §4.5: Response is an HTTP 303 with the collect URI in a Location header.
                Ok(reply::with_status(
                    reply::with_header(reply::reply(), LOCATION, collect_uri.as_str()),
                    StatusCode::SEE_OTHER,
                ))
            },
        );
    let collect_endpoint = compose_common_wrappers(
        collect_routing,
        collect_responding,
        warp::cors().build(),
        response_time_histogram.clone(),
        "collect",
    );

    let collect_jobs_get_routing = warp::path("collect_jobs").and(warp::get());
    let collect_jobs_get =
        with_cloned_value(Arc::clone(&aggregator))
            .and(warp::path::param())
            .and(warp::header::optional::<String>(DAP_AUTH_HEADER))
            .then(
                |aggregator: Arc<Aggregator<C>>,
                 collect_job_id: Uuid,
                 auth_token: Option<String>| async move {
                    let resp_bytes = aggregator
                        .handle_get_collect_job(collect_job_id, auth_token)
                        .await?;
                    match resp_bytes {
                        Some(resp_bytes) => http::Response::builder()
                            .header(CONTENT_TYPE, CollectResp::<TimeInterval>::MEDIA_TYPE)
                            .body(resp_bytes),
                        None => http::Response::builder()
                            .status(StatusCode::ACCEPTED)
                            .body(Vec::new()),
                    }
                    .map_err(|err| Error::Internal(format!("couldn't produce response: {}", err)))
                },
            );
    let collect_jobs_get_endpoint = compose_common_wrappers(
        collect_jobs_get_routing,
        collect_jobs_get,
        warp::cors().build(),
        response_time_histogram.clone(),
        "collect_jobs_get",
    );

    let collect_jobs_delete_routing = warp::path("collect_jobs").and(warp::delete());
    let collect_jobs_delete =
        with_cloned_value(Arc::clone(&aggregator))
            .and(warp::path::param())
            .and(warp::header::optional::<String>(DAP_AUTH_HEADER))
            .then(
                |aggregator: Arc<Aggregator<C>>,
                 collect_job_id: Uuid,
                 auth_token: Option<String>| async move {
                    aggregator
                        .handle_delete_collect_job(collect_job_id, auth_token)
                        .await
                },
            );
    let collect_jobs_delete_endpoint = compose_common_wrappers(
        collect_jobs_delete_routing,
        collect_jobs_delete,
        warp::cors().build(),
        response_time_histogram.clone(),
        "collect_jobs_delete",
    );

    let aggregate_share_routing = warp::path("aggregate_share");
    let aggregate_share_responding = warp::post()
        .and(warp::header::exact(
            CONTENT_TYPE.as_str(),
            AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
        ))
        .and(with_cloned_value(Arc::clone(&aggregator)))
        .and(warp::body::bytes())
        .and(warp::header::optional::<String>(DAP_AUTH_HEADER))
        .then(
            |aggregator: Arc<Aggregator<C>>, body: Bytes, auth_token: Option<String>| async move {
                let resp_bytes = aggregator.handle_aggregate_share(&body, auth_token).await?;

                http::Response::builder()
                    .header(CONTENT_TYPE, AggregateShareResp::MEDIA_TYPE)
                    .body(resp_bytes)
                    .map_err(|err| Error::Internal(format!("couldn't produce response: {}", err)))
            },
        );
    let aggregate_share_endpoint = compose_common_wrappers(
        aggregate_share_routing,
        aggregate_share_responding,
        warp::cors().build(),
        response_time_histogram,
        "aggregate_share",
    );

    Ok(hpke_config_endpoint
        .or(upload_endpoint)
        .or(aggregate_endpoint)
        .or(collect_endpoint)
        .or(collect_jobs_get_endpoint)
        .or(collect_jobs_delete_endpoint)
        .or(aggregate_share_endpoint)
        .boxed())
}

/// Construct a DAP aggregator server, listening on the provided [`SocketAddr`].
/// If the `SocketAddr`'s `port` is 0, an ephemeral port is used. Returns a
/// `SocketAddr` representing the address and port the server are listening on
/// and a future that can be `await`ed to begin serving requests.
pub fn aggregator_server<C: Clock>(
    datastore: Arc<Datastore<C>>,
    clock: C,
    listen_address: SocketAddr,
    response_headers: HeaderMap,
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()> + 'static), Error> {
    let filter = aggregator_filter(datastore, clock)?;
    let wrapped_filter = filter.with(warp::filters::reply::headers(response_headers));
    let server = warp::serve(wrapped_filter);
    Ok(server.bind_with_graceful_shutdown(listen_address, shutdown_signal))
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
async fn post_to_helper<T: Encode>(
    http_client: &Client,
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
        .post(url)
        .header(CONTENT_TYPE, content_type)
        .header(DAP_AUTH_HEADER, auth_token.as_bytes())
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
    use crate::{
        aggregator::{
            aggregator_filter, error_handler, post_to_helper, Aggregator, BatchMismatch,
            CollectableQueryType, Error,
        },
        datastore::{
            models::{
                AggregateShareJob, AggregationJob, AggregationJobState, BatchAggregation,
                CollectJob, CollectJobState, ReportAggregation, ReportAggregationState,
            },
            test_util::{ephemeral_datastore, DbHandle},
            Datastore,
        },
        messages::{DurationExt, TimeExt},
        task::{
            test_util::{generate_auth_token, TaskBuilder},
            QueryType, Task, VerifyKey, PRIO3_AES128_VERIFY_KEY_LENGTH,
        },
    };
    use assert_matches::assert_matches;
    use http::{
        header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION},
        Method, StatusCode,
    };
    use hyper::body;
    use janus_core::{
        hpke::associated_data_for_report_share,
        hpke::{
            self, associated_data_for_aggregate_share,
            test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo,
            HpkePrivateKey, Label,
        },
        report_id::ReportIdChecksumExt,
        task::{AuthenticationToken, VdafInstance},
        test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf},
        time::{Clock, MockClock, RealClock, TimeExt as _},
    };
    use janus_messages::{
        query_type::TimeInterval, AggregateContinueReq, AggregateContinueResp,
        AggregateInitializeReq, AggregateInitializeResp, AggregateShareReq, AggregateShareResp,
        BatchSelector, CollectReq, CollectResp, DapProblemType, DapProblemTypeParseError, Duration,
        HpkeCiphertext, HpkeConfig, HpkeConfigId, Interval, PartialBatchSelector, PrepareStep,
        PrepareStepResult, Query, Report, ReportId, ReportIdChecksum, ReportMetadata, ReportShare,
        ReportShareError, Role, TaskId, Time,
    };
    use mockito::mock;
    use opentelemetry::global::meter;
    use prio::{
        codec::{Decode, Encode},
        field::Field64,
        vdaf::{
            self,
            prio3::{Prio3, Prio3Aes128Count},
            AggregateShare, Aggregator as _, Client as VdafClient, PrepareTransition,
        },
    };
    use rand::random;
    use reqwest::Client;
    use serde_json::json;
    use std::{collections::HashMap, io::Cursor, sync::Arc};
    use url::Url;
    use uuid::Uuid;
    use warp::{
        cors::CorsForbidden,
        filters::BoxedFilter,
        reply::{Reply, Response},
        Filter, Rejection,
    };

    const DUMMY_VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

    #[tokio::test]
    async fn hpke_config() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let unknown_task_id: TaskId = random();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let want_hpke_key = current_hpke_key(task.hpke_keys()).clone();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        // No task ID provided
        let mut response = warp::test::request()
            .path("/hpke_config")
            .method("GET")
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        // The protocol mandates problem type but not HTTP status
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:missingTaskID",
                "title": "HPKE configuration was requested without specifying a task ID.",
                "detail": "HPKE configuration was requested without specifying a task ID.",
                "instance": "..",
                // TODO(#545) problem document shouldn't include taskid key
                "taskid": serde_json::Value::Null,
            })
        );

        // Unknown task ID provided
        let mut response = warp::test::request()
            .path(&format!("/hpke_config?task_id={unknown_task_id}"))
            .method("GET")
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        // Expected status and problem type should be per the protocol
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 404u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
                "taskid": format!("{unknown_task_id}"),
            })
        );

        // Recognized task ID provided
        let response = warp::test::request()
            .path(&format!("/hpke_config?task_id={}", task.id()))
            .method("GET")
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "max-age=86400"
        );
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            HpkeConfig::MEDIA_TYPE
        );

        let bytes = body::to_bytes(response.into_body()).await.unwrap();
        let hpke_config = HpkeConfig::decode(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(hpke_config, want_hpke_key.0);

        let application_info =
            HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
        let message = b"this is a message";
        let associated_data = b"some associated data";

        let ciphertext =
            hpke::seal(&hpke_config, &application_info, message, associated_data).unwrap();
        let plaintext = hpke::open(
            &want_hpke_key.0,
            &want_hpke_key.1,
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
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        // Check for appropriate CORS headers in response to a preflight request.
        let response = warp::test::request()
            .method("OPTIONS")
            .path(&format!("/hpke_config?task_id={}", task.id()))
            .header("origin", "https://example.com/")
            .header("access-control-request-method", "GET")
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert!(response.status().is_success());
        let headers = response.headers();
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://example.com/"
        );
        assert_eq!(headers.get("access-control-allow-methods").unwrap(), "GET");
        assert_eq!(headers.get("access-control-max-age").unwrap(), "86400");

        // Check for appropriate CORS headers with a simple GET request.
        let response = warp::test::request()
            .method("GET")
            .path(&format!("/hpke_config?task_id={}", task.id()))
            .header("origin", "https://example.com/")
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert!(response.status().is_success());
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://example.com/"
        );
    }

    async fn setup_report(
        task: &Task,
        datastore: &Datastore<MockClock>,
        report_timestamp: Time,
    ) -> Report {
        assert_eq!(task.vdaf(), &VdafInstance::Prio3Aes128Count);
        datastore.put_task(task).await.unwrap();

        let vdaf = Prio3Aes128Count::new_aes128_count(2).unwrap();
        let hpke_key = current_hpke_key(task.hpke_keys());
        let report_metadata = ReportMetadata::new(random(), report_timestamp, Vec::new());

        let (public_share, measurements) = vdaf.shard(&1).unwrap();

        let associated_data = associated_data_for_report_share(
            task.id(),
            &report_metadata,
            &public_share.get_encoded(),
        );

        let leader_ciphertext = hpke::seal(
            &hpke_key.0,
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
            &measurements[0].get_encoded(),
            &associated_data,
        )
        .unwrap();
        let helper_ciphertext = hpke::seal(
            &hpke_key.0,
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
            &measurements[1].get_encoded(),
            &associated_data,
        )
        .unwrap();

        Report::new(
            *task.id(),
            report_metadata,
            public_share.get_encoded(),
            Vec::from([leader_ciphertext, helper_ciphertext]),
        )
    }

    /// Convenience method to handle interaction with `warp::test` for typical DAP requests.
    async fn drive_filter(
        method: Method,
        path: &str,
        body: &[u8],
        filter: &BoxedFilter<(impl Reply + 'static,)>,
    ) -> Result<Response, Rejection> {
        warp::test::request()
            .method(method.as_str())
            .path(path)
            .header(CONTENT_TYPE, Report::MEDIA_TYPE)
            .body(body)
            .filter(filter)
            .await
            .map(|reply| reply.into_response())
    }

    #[tokio::test]
    async fn upload_filter() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        let report = setup_report(&task, &datastore, clock.now()).await;
        let filter = aggregator_filter(Arc::clone(&datastore), clock.clone()).unwrap();

        let response = drive_filter(Method::POST, "/upload", &report.get_encoded(), &filter)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body::to_bytes(response.into_body())
            .await
            .unwrap()
            .is_empty());

        // Verify that we reject duplicate reports with the reportTooLate type.
        // TODO(#34): change this error type.
        let mut response = drive_filter(Method::POST, "/upload", &report.get_encoded(), &filter)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:reportTooLate",
                "title": "Report could not be processed because it arrived too late.",
                "detail": "Report could not be processed because it arrived too late.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
            })
        );

        // should reject a report with only one share with the unrecognizedMessage type.
        let bad_report = Report::new(
            *report.task_id(),
            report.metadata().clone(),
            report.public_share().to_vec(),
            Vec::from([report.encrypted_input_shares()[0].clone()]),
        );
        let mut response =
            drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
            })
        );

        // should reject a report using the wrong HPKE config for the leader, and reply with
        // the error type outdatedConfig.
        let unused_hpke_config_id = (0..)
            .map(HpkeConfigId::from)
            .find(|id| !task.hpke_keys().contains_key(id))
            .unwrap();
        let bad_report = Report::new(
            *report.task_id(),
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
        let mut response =
            drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:outdatedConfig",
                "title": "The message was generated using an outdated configuration.",
                "detail": "The message was generated using an outdated configuration.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
            })
        );

        // Reports from the future should be rejected.
        let bad_report_time = clock
            .now()
            .add(&Duration::from_minutes(10).unwrap())
            .unwrap()
            .add(&Duration::from_seconds(1))
            .unwrap();
        let bad_report = Report::new(
            *report.task_id(),
            ReportMetadata::new(
                *report.metadata().id(),
                bad_report_time,
                report.metadata().extensions().to_vec(),
            ),
            report.public_share().to_vec(),
            report.encrypted_input_shares().to_vec(),
        );
        let mut response =
            drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:reportTooEarly",
                "title": "Report could not be processed because it arrived too early.",
                "detail": "Report could not be processed because it arrived too early.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
            })
        );

        // Reports with timestamps past the task's expiration should be rejected.
        let task_expire_soon = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_task_expiration(clock.now().add(&Duration::from_seconds(60)).unwrap())
        .build();
        let report_2 = setup_report(
            &task_expire_soon,
            &datastore,
            clock.now().add(&Duration::from_seconds(120)).unwrap(),
        )
        .await;
        let mut response = drive_filter(Method::POST, "/upload", &report_2.get_encoded(), &filter)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:reportTooLate",
                "title": "Report could not be processed because it arrived too late.",
                "detail": "Report could not be processed because it arrived too late.",
                "instance": "..",
                "taskid": format!("{}", report_2.task_id()),
            })
        );

        // Check for appropriate CORS headers in response to a preflight request.
        let response = warp::test::request()
            .method("OPTIONS")
            .path("/upload")
            .header("origin", "https://example.com/")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert!(response.status().is_success());
        let headers = response.headers();
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://example.com/"
        );
        assert_eq!(headers.get("access-control-allow-methods").unwrap(), "POST");
        assert_eq!(
            headers.get("access-control-allow-headers").unwrap(),
            "content-type"
        );
        assert_eq!(headers.get("access-control-max-age").unwrap(), "86400");

        // Check for appropriate CORS headers in response to the main request.
        let response = warp::test::request()
            .method("POST")
            .path("/upload")
            .header("origin", "https://example.com/")
            .header(CONTENT_TYPE, Report::MEDIA_TYPE)
            .body(
                Report::new(
                    *report.task_id(),
                    ReportMetadata::new(
                        random(),
                        clock
                            .now()
                            .to_batch_interval_start(task.time_precision())
                            .unwrap(),
                        Vec::new(),
                    ),
                    report.public_share().to_vec(),
                    report.encrypted_input_shares().to_vec(),
                )
                .get_encoded(),
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert!(response.status().is_success());
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://example.com/"
        );
    }

    // Helper should not expose /upload endpoint
    #[tokio::test]
    async fn upload_filter_helper() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let report = setup_report(&task, &datastore, clock.now()).await;

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (part, body) = warp::test::request()
            .method("POST")
            .path("/upload")
            .header(CONTENT_TYPE, Report::MEDIA_TYPE)
            .body(report.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert!(!part.status.is_success());
        let bytes = body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 404,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
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
            part.status.as_u16() as u64
        );
    }

    enum UploadTestCaseReportTimestamp {
        OnClockSkewBoundary,
        WithinTolerableClockSkew,
        PastTolerableClockSkew,
    }

    async fn setup_upload_test(
        report_timestamp_duration: UploadTestCaseReportTimestamp,
    ) -> (
        Prio3Aes128Count,
        Aggregator<MockClock>,
        Task,
        Report,
        Arc<Datastore<MockClock>>,
        DbHandle,
    ) {
        let clock = MockClock::default();
        let vdaf = Prio3Aes128Count::new_aes128_count(2).unwrap();
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();

        let (datastore, db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        let report_timestamp = match report_timestamp_duration {
            UploadTestCaseReportTimestamp::OnClockSkewBoundary => {
                clock.now().add(task.tolerable_clock_skew()).unwrap()
            }
            UploadTestCaseReportTimestamp::WithinTolerableClockSkew => clock.now(),
            UploadTestCaseReportTimestamp::PastTolerableClockSkew => clock
                .now()
                .add(task.tolerable_clock_skew())
                .unwrap()
                .add(&Duration::from_seconds(1))
                .unwrap(),
        };
        let report = setup_report(&task, &datastore, report_timestamp).await;

        let aggregator = Aggregator::new(
            Arc::clone(&datastore),
            clock.clone(),
            meter("janus_aggregator"),
        );

        (vdaf, aggregator, task, report, datastore, db_handle)
    }

    #[tokio::test]
    async fn upload() {
        install_test_trace_subscriber();

        let (vdaf, aggregator, _, report, datastore, _db_handle) =
            setup_upload_test(UploadTestCaseReportTimestamp::WithinTolerableClockSkew).await;

        aggregator
            .handle_upload(&report.get_encoded())
            .await
            .unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                let (vdaf, task_id, report_id) =
                    (vdaf.clone(), *report.task_id(), *report.metadata().id());
                Box::pin(async move { tx.get_client_report(&vdaf, &task_id, &report_id).await })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.task_id(), got_report.task_id());
        assert_eq!(report.metadata(), got_report.metadata());

        // should reject duplicate reports.
        // TODO(#34): change this error type.
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::ReportTooLate(task_id, stale_report_id, stale_time)) => {
            assert_eq!(&task_id, report.task_id());
            assert_eq!(report.metadata().id(), &stale_report_id);
            assert_eq!(report.metadata().time(), &stale_time);
        });
    }

    #[tokio::test]
    async fn upload_wrong_number_of_encrypted_shares() {
        install_test_trace_subscriber();

        let (_, aggregator, _, report, _, _db_handle) =
            setup_upload_test(UploadTestCaseReportTimestamp::WithinTolerableClockSkew).await;

        let report = Report::new(
            *report.task_id(),
            report.metadata().clone(),
            report.public_share().to_vec(),
            Vec::from([report.encrypted_input_shares()[0].clone()]),
        );

        assert_matches!(
            aggregator.handle_upload(&report.get_encoded()).await,
            Err(Error::UnrecognizedMessage(_, _))
        );
    }

    #[tokio::test]
    async fn upload_wrong_hpke_config_id() {
        install_test_trace_subscriber();

        let (_, aggregator, task, report, _, _db_handle) =
            setup_upload_test(UploadTestCaseReportTimestamp::WithinTolerableClockSkew).await;

        let unused_hpke_config_id = (0..)
            .map(HpkeConfigId::from)
            .find(|id| !task.hpke_keys().contains_key(id))
            .unwrap();

        let report = Report::new(
            *report.task_id(),
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

        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::OutdatedHpkeConfig(task_id, config_id)) => {
            assert_eq!(&task_id, report.task_id());
            assert_eq!(config_id, unused_hpke_config_id);
        });
    }

    #[tokio::test]
    async fn upload_report_in_the_future_boundary_condition() {
        install_test_trace_subscriber();

        let (vdaf, aggregator, _, report, datastore, _db_handle) =
            setup_upload_test(UploadTestCaseReportTimestamp::OnClockSkewBoundary).await;

        aggregator
            .handle_upload(&report.get_encoded())
            .await
            .unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                let (vdaf, task_id, report_id) =
                    (vdaf.clone(), *report.task_id(), *report.metadata().id());
                Box::pin(async move { tx.get_client_report(&vdaf, &task_id, &report_id).await })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.task_id(), got_report.task_id());
        assert_eq!(report.metadata(), got_report.metadata());
    }

    #[tokio::test]
    async fn upload_report_in_the_future_past_clock_skew() {
        install_test_trace_subscriber();

        let (_, aggregator, _, report, _, _db_handle) =
            setup_upload_test(UploadTestCaseReportTimestamp::PastTolerableClockSkew).await;

        let upload_error = aggregator
            .handle_upload(&report.get_encoded())
            .await
            .unwrap_err();

        assert_matches!(upload_error, Error::ReportTooEarly(task_id, report_id, time) => {
            assert_eq!(&task_id, report.task_id());
            assert_eq!(report.metadata().id(), &report_id);
            assert_eq!(report.metadata().time(), &time);
        });
    }

    #[tokio::test]
    async fn upload_report_for_collected_batch() {
        install_test_trace_subscriber();

        let (_, aggregator, task, report, datastore, _db_handle) =
            setup_upload_test(UploadTestCaseReportTimestamp::WithinTolerableClockSkew).await;

        // Insert a collect job for the batch interval including our report.
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
                    tx.put_collect_job(&CollectJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        Uuid::new_v4(),
                        batch_interval,
                        (),
                        CollectJobState::Start,
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Try to upload the report, verify that we get the expected error.
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await.unwrap_err(), Error::ReportTooLate(err_task_id, err_report_id, err_time) => {
            assert_eq!(report.task_id(), &err_task_id);
            assert_eq!(report.metadata().id(), &err_report_id);
            assert_eq!(report.metadata().time(), &err_time);
        });
    }

    #[tokio::test]
    async fn aggregate_leader() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let request = AggregateInitializeReq::new(
            *task.id(),
            random(),
            Vec::new(),
            PartialBatchSelector::new_time_interval(),
            Vec::new(),
        );

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (part, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(
                CONTENT_TYPE,
                AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert!(!part.status.is_success());
        let bytes = body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": 404,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
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
            part.status.as_u16() as u64
        );

        // Check that CORS headers don't bleed over to other routes.
        assert!(part.headers.get("access-control-allow-origin").is_none());
        assert!(part.headers.get("access-control-allow-methods").is_none());
        assert!(part.headers.get("access-control-max-age").is_none());

        let result = warp::test::request()
            .method("OPTIONS")
            .path("/aggregate")
            .header("origin", "https://example.com/")
            .header("access-control-request-method", "POST")
            .filter(&filter)
            .await
            .map(Reply::into_response);
        assert_matches!(result, Err(rejection) => rejection.find::<CorsForbidden>().unwrap());
    }

    #[tokio::test]
    async fn aggregate_wrong_agg_auth_token() {
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let request = AggregateInitializeReq::new(
            *task.id(),
            random(),
            Vec::new(),
            PartialBatchSelector::new_time_interval(),
            Vec::new(),
        );

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header("DAP-Auth-Token", generate_auth_token().as_bytes())
            .header(
                CONTENT_TYPE,
                AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        let want_status = 400;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, parts.status.as_u16());

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                CONTENT_TYPE,
                AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        let want_status = 400;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, parts.status.as_u16());
    }

    #[tokio::test]
    async fn aggregate_init() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();
        let hpke_key = current_hpke_key(task.hpke_keys());

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_0.id(),
            &0,
        );
        let input_share = transcript.input_shares[1].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_0,
            &hpke_key.0,
            &transcript.public_share,
            &input_share,
        );

        // report_share_1 fails decryption.
        let report_metadata_1 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let encrypted_input_share = report_share_0.encrypted_input_share();
        let mut corrupted_payload = encrypted_input_share.payload().to_vec();
        corrupted_payload[0] ^= 0xFF;
        let corrupted_input_share = HpkeCiphertext::new(
            *encrypted_input_share.config_id(),
            encrypted_input_share.encapsulated_key().to_vec(),
            corrupted_payload,
        );
        #[allow(clippy::unit_arg)]
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
            Vec::new(),
        );
        let mut input_share_bytes = input_share.get_encoded();
        input_share_bytes.push(0); // can no longer be decoded.
        let aad =
            associated_data_for_report_share(task.id(), &report_metadata_2, &encoded_public_share);
        let report_share_2 = generate_helper_report_share_for_plaintext(
            report_metadata_2,
            &hpke_key.0,
            encoded_public_share,
            &input_share_bytes,
            &aad,
        );

        // report_share_3 has an unknown HPKE config ID.
        let report_metadata_3 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let wrong_hpke_config = loop {
            let hpke_config = generate_test_hpke_config_and_private_key().0;
            if task.hpke_keys().contains_key(hpke_config.id()) {
                continue;
            }
            break hpke_config;
        };
        let report_share_3 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_3,
            &wrong_hpke_config,
            &transcript.public_share,
            &input_share,
        );

        // report_share_4 has already been aggregated.
        let report_metadata_4 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_4.id(),
            &0,
        );
        let input_share = transcript.input_shares[1].clone();
        let report_share_4 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_4,
            &hpke_key.0,
            &transcript.public_share,
            &input_share,
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
            Vec::new(),
        );
        let transcript = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_5.id(),
            &0,
        );
        let input_share = transcript.input_shares[1].clone();
        let report_share_5 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_5,
            &hpke_key.0,
            &transcript.public_share,
            &input_share,
        );

        // report_share_6 fails decoding due to an issue with the public share.
        let public_share_6 = Vec::from([0]);
        let report_metadata_6 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let aad = associated_data_for_report_share(task.id(), &report_metadata_6, &public_share_6);
        let report_share_6 = generate_helper_report_share_for_plaintext(
            report_metadata_6,
            &hpke_key.0,
            public_share_6,
            &input_share.get_encoded(),
            &aad,
        );

        datastore
            .run_tx(|tx| {
                let (task, report_share_4) = (task.clone(), report_share_4.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(task.id(), &report_share_4).await?;
                    tx.put_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        &AggregateShareJob::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            (),
                            AggregateShare::from(Vec::from([Field64::from(7)])),
                            0,
                            ReportIdChecksum::default(),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        let request = AggregateInitializeReq::new(
            *task.id(),
            random(),
            Vec::new(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([
                report_share_0.clone(),
                report_share_1.clone(),
                report_share_2.clone(),
                report_share_3.clone(),
                report_share_4.clone(),
                report_share_5.clone(),
                report_share_6.clone(),
            ]),
        );

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::clone(&datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(
                CONTENT_TYPE,
                AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregateInitializeResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp = AggregateInitializeResp::get_decoded(&body_bytes).unwrap();

        // Validate response.
        assert_eq!(aggregate_resp.prepare_steps().len(), 7);

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
            &PrepareStepResult::Failed(ReportShareError::VdafPrepError)
        );

        let prepare_step_6 = aggregate_resp.prepare_steps().get(6).unwrap();
        assert_eq!(prepare_step_6.report_id(), report_share_6.metadata().id());
        assert_matches!(
            prepare_step_6.result(),
            &PrepareStepResult::Failed(ReportShareError::VdafPrepError)
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

        // Check aggregation job in datastore.
        let aggregation_jobs = datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_aggregation_jobs_for_task_id::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >(task.id())
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(aggregation_jobs.len(), 1);
        assert_eq!(aggregation_jobs[0].task_id(), task.id());
        assert_eq!(aggregation_jobs[0].id(), request.job_id());
        assert!(aggregation_jobs[0].batch_identifier().is_none());
        assert_eq!(
            aggregation_jobs[0].state(),
            &AggregationJobState::InProgress
        );
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
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let hpke_key = current_hpke_key(task.hpke_keys());

        datastore.put_task(&task).await.unwrap();

        let report_share = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            task.id(),
            &ReportMetadata::new(
                random(),
                clock
                    .now()
                    .to_batch_interval_start(task.time_precision())
                    .unwrap(),
                Vec::new(),
            ),
            &hpke_key.0,
            &(),
            &(),
        );
        let request = AggregateInitializeReq::new(
            *task.id(),
            random(),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([report_share.clone()]),
        );

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(
                CONTENT_TYPE,
                AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregateInitializeResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp = AggregateInitializeResp::get_decoded(&body_bytes).unwrap();

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
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let hpke_key = current_hpke_key(task.hpke_keys());

        datastore.put_task(&task).await.unwrap();

        let report_share = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            task.id(),
            &ReportMetadata::new(
                random(),
                clock
                    .now()
                    .to_batch_interval_start(task.time_precision())
                    .unwrap(),
                Vec::new(),
            ),
            &hpke_key.0,
            &(),
            &(),
        );
        let request = AggregateInitializeReq::new(
            *task.id(),
            random(),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([report_share.clone()]),
        );

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(
                CONTENT_TYPE,
                AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregateInitializeResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp = AggregateInitializeResp::get_decoded(&body_bytes).unwrap();

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
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let report_share = ReportShare::new(
            ReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(54321),
                Vec::new(),
            ),
            Vec::from("PUBLIC"),
            HpkeCiphertext::new(
                // bogus, but we never get far enough to notice
                HpkeConfigId::from(42),
                Vec::from("012345"),
                Vec::from("543210"),
            ),
        );

        let request = AggregateInitializeReq::new(
            *task.id(),
            random(),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([report_share.clone(), report_share]),
        );

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(
                CONTENT_TYPE,
                AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
            )
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        let want_status = 400;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, parts.status.as_u16());
    }

    #[tokio::test]
    async fn aggregate_continue() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let aggregation_job_id = random();
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();
        let hpke_key = current_hpke_key(task.hpke_keys());

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript_0 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata_0.id(),
            &0,
        );
        let prep_state_0 = assert_matches!(
            &transcript_0.prepare_transitions[1][0],
            PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _)
            => prep_state.clone()
        );
        let out_share_0 = assert_matches!(
            &transcript_0.prepare_transitions[1][1],
            PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share)
            => out_share.clone()
        );
        let prep_msg_0 = transcript_0.prepare_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_0,
            &hpke_key.0,
            &transcript_0.public_share,
            &transcript_0.input_shares[1],
        );

        // report_share_1 is omitted by the leader's request.
        let report_metadata_1 = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript_1 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata_1.id(),
            &0,
        );
        let prep_state_1 = assert_matches!(&transcript_1.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let report_share_1 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_1,
            &hpke_key.0,
            &transcript_1.public_share,
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
            Vec::new(),
        );
        let transcript_2 = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata_2.id(),
            &0,
        );
        let prep_state_2 = assert_matches!(&transcript_2.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let prep_msg_2 = transcript_2.prepare_messages[0].clone();
        let report_share_2 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_2,
            &hpke_key.0,
            &transcript_2.public_share,
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
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        None,
                        (),
                        AggregationJobState::InProgress,
                    ))
                    .await?;

                    tx.put_report_aggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_0.id(),
                            *report_metadata_0.time(),
                            0,
                            ReportAggregationState::Waiting(prep_state_0, None),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_1.id(),
                            *report_metadata_1.time(),
                            1,
                            ReportAggregationState::Waiting(prep_state_1, None),
                        ),
                    )
                    .await?;
                    tx.put_report_aggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_metadata_2.id(),
                            *report_metadata_2.time(),
                            2,
                            ReportAggregationState::Waiting(prep_state_2, None),
                        ),
                    )
                    .await?;

                    tx.put_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        &AggregateShareJob::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(0),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            (),
                            AggregateShare::from(Vec::from([Field64::from(7)])),
                            0,
                            ReportIdChecksum::default(),
                        ),
                    )
                    .await
                })
            })
            .await
            .unwrap();

        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id,
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

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregateContinueResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp = AggregateContinueResp::get_decoded(&body_bytes).unwrap();

        // Validate response.
        assert_eq!(
            aggregate_resp,
            AggregateContinueResp::new(Vec::from([
                PrepareStep::new(*report_metadata_0.id(), PrepareStepResult::Finished),
                PrepareStep::new(
                    *report_metadata_2.id(),
                    PrepareStepResult::Failed(ReportShareError::BatchCollected),
                )
            ]))
        );

        // Validate datastore.
        let (aggregation_job, report_aggregations) = datastore
            .run_tx(|tx| {
                let (vdaf, task) = (Arc::clone(&vdaf), task.clone());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            &Role::Helper,
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?;
                    Ok((aggregation_job, report_aggregations))
                })
            })
            .await
            .unwrap();

        assert_eq!(
            aggregation_job,
            Some(AggregationJob::new(
                *task.id(),
                aggregation_job_id,
                None,
                (),
                AggregationJobState::Finished,
            ))
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
                    ReportAggregationState::Finished(out_share_0.clone()),
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
            VdafInstance::Prio3Aes128Count,
            Role::Helper,
        )
        .build();
        let aggregation_job_id_0 = random();
        let aggregation_job_id_1 = random();
        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;
        let datastore = Arc::new(datastore);
        let first_batch_interval_clock = MockClock::default();
        let second_batch_interval_clock = MockClock::new(
            first_batch_interval_clock
                .now()
                .add(task.time_precision())
                .unwrap(),
        );

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();
        let hpke_key = current_hpke_key(task.hpke_keys());

        // report_share_0 is a "happy path" report.
        let report_metadata_0 = ReportMetadata::new(
            random(),
            first_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript_0 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_0.id(),
            &0,
        );
        let prep_state_0 = assert_matches!(&transcript_0.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_0 = assert_matches!(&transcript_0.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_0 = transcript_0.prepare_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_0,
            &hpke_key.0,
            &transcript_0.public_share,
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
            Vec::new(),
        );
        let transcript_1 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_1.id(),
            &0,
        );
        let prep_state_1 = assert_matches!(&transcript_1.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_1 = assert_matches!(&transcript_1.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_1 = transcript_1.prepare_messages[0].clone();
        let report_share_1 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_1,
            &hpke_key.0,
            &transcript_1.public_share,
            &transcript_1.input_shares[1],
        );

        // report share 2 aggregates successfully, but into a distinct batch aggregation.
        let report_metadata_2 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript_2 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_2.id(),
            &0,
        );
        let prep_state_2 = assert_matches!(&transcript_2.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_2 = assert_matches!(&transcript_2.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_2 = transcript_2.prepare_messages[0].clone();
        let report_share_2 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_2,
            &hpke_key.0,
            &transcript_2.public_share,
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
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        None,
                        (),
                        AggregationJobState::InProgress,
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_0.id(),
                        *report_metadata_0.time(),
                        0,
                        ReportAggregationState::Waiting(prep_state_0, None),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_1.id(),
                        *report_metadata_1.time(),
                        1,
                        ReportAggregationState::Waiting(prep_state_1, None),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_0,
                        *report_metadata_2.id(),
                        *report_metadata_2.time(),
                        2,
                        ReportAggregationState::Waiting(prep_state_2, None),
                    ))
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id_0,
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

        // Create aggregator filter, send request, and parse response.
        let filter =
            aggregator_filter(datastore.clone(), first_batch_interval_clock.clone()).unwrap();

        let response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregateContinueResp::MEDIA_TYPE
        );

        let batch_aggregations = datastore
            .run_tx(|tx| {
                let (task, report_metadata_0) = (task.clone(), report_metadata_0.clone());
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                        _,
                    >(
                        tx,
                        &task,
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
            .unwrap();

        let aggregate_share = vdaf
            .aggregate(&(), [out_share_0.clone(), out_share_1.clone()])
            .unwrap();
        let checksum = ReportIdChecksum::for_report_id(report_metadata_0.id())
            .updated_with(report_metadata_1.id());

        assert_eq!(
            batch_aggregations,
            Vec::from(
                [
                    BatchAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
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
                        aggregate_share,
                        2,
                        checksum,
                    ),
                    BatchAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
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
                        AggregateShare::from(out_share_2.clone()),
                        1,
                        ReportIdChecksum::for_report_id(report_metadata_2.id()),
                    ),
                ]
            )
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
            Vec::new(),
        );
        let transcript_3 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_3.id(),
            &0,
        );
        let prep_state_3 = assert_matches!(&transcript_3.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_3 = assert_matches!(&transcript_3.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_3 = transcript_3.prepare_messages[0].clone();
        let report_share_3 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_3,
            &hpke_key.0,
            &transcript_3.public_share,
            &transcript_3.input_shares[1],
        );

        // report_share_4 gets aggregated into the second batch interval
        let report_metadata_4 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript_4 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_4.id(),
            &0,
        );
        let prep_state_4 = assert_matches!(&transcript_4.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_4 = assert_matches!(&transcript_4.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_4 = transcript_4.prepare_messages[0].clone();
        let report_share_4 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_4,
            &hpke_key.0,
            &transcript_4.public_share,
            &transcript_4.input_shares[1],
        );

        // report share 5 also gets aggregated into the second batch interval
        let report_metadata_5 = ReportMetadata::new(
            random(),
            second_batch_interval_clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
            Vec::new(),
        );
        let transcript_5 = run_vdaf(
            &vdaf,
            verify_key.as_bytes(),
            &(),
            report_metadata_5.id(),
            &0,
        );
        let prep_state_5 = assert_matches!(&transcript_5.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_5 = assert_matches!(&transcript_5.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_5 = transcript_5.prepare_messages[0].clone();
        let report_share_5 = generate_helper_report_share::<Prio3Aes128Count>(
            task.id(),
            &report_metadata_5,
            &hpke_key.0,
            &transcript_5.public_share,
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
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        None,
                        (),
                        AggregationJobState::InProgress,
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_3.id(),
                        *report_metadata_3.time(),
                        3,
                        ReportAggregationState::Waiting(prep_state_3, None),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_4.id(),
                        *report_metadata_4.time(),
                        4,
                        ReportAggregationState::Waiting(prep_state_4, None),
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id_1,
                        *report_metadata_5.id(),
                        *report_metadata_5.time(),
                        5,
                        ReportAggregationState::Waiting(prep_state_5, None),
                    ))
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id_1,
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

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(datastore.clone(), first_batch_interval_clock).unwrap();

        let response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregateContinueResp::MEDIA_TYPE
        );

        let batch_aggregations = datastore
            .run_tx(|tx| {
                let (task, report_metadata_0) = (task.clone(), report_metadata_0.clone());
                Box::pin(async move {
                    TimeInterval::get_batch_aggregations_for_collect_identifier::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                        _,
                    >(
                        tx,
                        &task,
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
            .unwrap();

        let first_aggregate_share = vdaf
            .aggregate(&(), [out_share_0, out_share_1, out_share_3])
            .unwrap();
        let first_checksum = ReportIdChecksum::for_report_id(report_metadata_0.id())
            .updated_with(report_metadata_1.id())
            .updated_with(report_metadata_3.id());

        let second_aggregate_share = vdaf
            .aggregate(&(), [out_share_2, out_share_4, out_share_5])
            .unwrap();
        let second_checksum = ReportIdChecksum::for_report_id(report_metadata_2.id())
            .updated_with(report_metadata_4.id())
            .updated_with(report_metadata_5.id());

        assert_eq!(
            batch_aggregations,
            Vec::from(
                [
                    BatchAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
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
                        first_aggregate_share,
                        3,
                        first_checksum,
                    ),
                    BatchAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
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
                        second_aggregate_share,
                        3,
                        second_checksum,
                    ),
                ]
            )
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
            Vec::new(),
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

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
                        None,
                        dummy_vdaf::AggregationParam(0),
                        AggregationJobState::InProgress,
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
                        ReportAggregationState::Waiting((), None),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id,
            Vec::from([PrepareStep::new(
                *report_metadata.id(),
                PrepareStepResult::Finished,
            )]),
        );

        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
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
            Vec::new(),
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

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
                        None,
                        dummy_vdaf::AggregationParam(0),
                        AggregationJobState::InProgress,
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
                        ReportAggregationState::Waiting((), None),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id,
            Vec::from([PrepareStep::new(
                *report_metadata.id(),
                PrepareStepResult::Continued(Vec::new()),
            )]),
        );

        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(
            parts.headers.get(CONTENT_TYPE).unwrap(),
            AggregateContinueResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(body).await.unwrap();
        let aggregate_resp = AggregateContinueResp::get_decoded(&body_bytes).unwrap();
        assert_eq!(
            aggregate_resp,
            AggregateContinueResp::new(Vec::from([PrepareStep::new(
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
                        .await?;
                    let report_aggregation = tx
                        .get_report_aggregation(
                            &dummy_vdaf::Vdaf::default(),
                            &Role::Helper,
                            task.id(),
                            &aggregation_job_id,
                            report_metadata.id(),
                        )
                        .await?;
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(
            aggregation_job,
            Some(AggregationJob::new(
                *task.id(),
                aggregation_job_id,
                None,
                dummy_vdaf::AggregationParam(0),
                AggregationJobState::Finished,
            ))
        );
        assert_eq!(
            report_aggregation,
            Some(ReportAggregation::new(
                *task.id(),
                aggregation_job_id,
                *report_metadata.id(),
                *report_metadata.time(),
                0,
                ReportAggregationState::Failed(ReportShareError::VdafPrepError),
            ))
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
            Vec::new(),
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

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
                        None,
                        dummy_vdaf::AggregationParam(0),
                        AggregationJobState::InProgress,
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
                        ReportAggregationState::Waiting((), None),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id,
            Vec::from([PrepareStep::new(
                ReportId::from(
                    [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1], // not the same as above
                ),
                PrepareStepResult::Continued(Vec::new()),
            )]),
        );

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
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
            Vec::new(),
        );
        let report_metadata_1 = ReportMetadata::new(
            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
            Time::from_seconds_since_epoch(54321),
            Vec::new(),
        );

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

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
                        None,
                        dummy_vdaf::AggregationParam(0),
                        AggregationJobState::InProgress,
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
                        ReportAggregationState::Waiting((), None),
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
                        ReportAggregationState::Waiting((), None),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id,
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

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
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
            Vec::new(),
        );

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

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
                        None,
                        dummy_vdaf::AggregationParam(0),
                        AggregationJobState::InProgress,
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
        let request = AggregateContinueReq::new(
            *task.id(),
            aggregation_job_id,
            Vec::from([PrepareStep::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                PrepareStepResult::Continued(Vec::new()),
            )]),
        );

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collect_request_to_helper() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            Vec::new(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header("DAP-Auth-Token", generate_auth_token().as_bytes())
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::NOT_FOUND);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::NOT_FOUND.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collect_request_invalid_batch_interval() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    // Collect request will be rejected because batch interval is too small
                    Duration::from_seconds(task.time_precision().as_seconds() - 1),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch implied by the query is invalid.",
                "detail": "The batch implied by the query is invalid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collect_request_invalid_aggregation_parameter() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(task.time_precision().as_seconds()),
                )
                .unwrap(),
            ),
            // dummy_vdaf::AggregationParam is a tuple struct wrapping a u8, so this is not a valid
            // encoding of an aggregation parameter.
            Vec::new(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Collect request will be rejected because the aggregation parameter can't be decoded
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": serde_json::Value::Null,
            })
        );
    }

    #[tokio::test]
    async fn collect_request_invalid_batch_size() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
            .with_min_batch_size(1)
            .build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(task.time_precision().as_seconds()),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Collect request will be rejected because there are no reports in the batch interval
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "detail": "The number of reports included in the batch is invalid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collect_request_unauthenticated() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let batch_interval =
            Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap();

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::clone(&datastore), clock).unwrap();

        let req = CollectReq::new(
            *task.id(),
            Query::new_time_interval(batch_interval),
            Vec::new(),
        );

        // Incorrect authentication token.
        let mut response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header("DAP-Auth-Token", generate_auth_token().as_bytes())
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(req.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        let want_status = StatusCode::BAD_REQUEST;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, response.status());

        // Aggregator authentication token.
        let mut response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(req.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        let want_status = StatusCode::BAD_REQUEST;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, response.status());

        // Missing authentication token.
        let mut response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(req.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        let want_status = StatusCode::BAD_REQUEST;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, response.status());
    }

    #[tokio::test]
    async fn collect_request_unauthenticated_collect_jobs() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let batch_interval =
            Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap();

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::clone(&datastore), clock).unwrap();

        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(batch_interval),
            Vec::new(),
        );

        let response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let collect_uri =
            Url::parse(response.headers().get(LOCATION).unwrap().to_str().unwrap()).unwrap();
        assert_eq!(collect_uri.scheme(), "https");
        assert_eq!(collect_uri.host_str().unwrap(), "leader.endpoint");
        let mut path_segments = collect_uri.path_segments().unwrap();
        assert_eq!(path_segments.next(), Some("collect_jobs"));
        let collect_job_id = Uuid::parse_str(path_segments.next().unwrap()).unwrap();
        assert!(path_segments.next().is_none());

        // Incorrect authentication token.
        let mut response = warp::test::request()
            .method("GET")
            .path(&format!("/collect_jobs/{}", collect_job_id))
            .header("DAP-Auth-Token", generate_auth_token().as_bytes())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        let want_status = StatusCode::BAD_REQUEST;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, response.status());

        // Aggregator authentication token.
        let mut response = warp::test::request()
            .method("GET")
            .path(&format!("/collect_jobs/{}", collect_job_id))
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        let want_status = StatusCode::BAD_REQUEST;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, response.status());

        // Missing authentication token.
        let mut response = warp::test::request()
            .method("GET")
            .path(&format!("/collect_jobs/{}", collect_job_id))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        let want_status = StatusCode::BAD_REQUEST;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, response.status());
    }

    #[tokio::test]
    async fn collect_request() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let (collector_hpke_config, collector_hpke_recipient) =
            generate_test_hpke_config_and_private_key();
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_collector_hpke_config(collector_hpke_config)
        .build();
        let batch_interval =
            Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap();

        let leader_aggregate_share = AggregateShare::from(Vec::from([Field64::from(64)]));
        let helper_aggregate_share = AggregateShare::from(Vec::from([Field64::from(32)]));

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::clone(&datastore), clock).unwrap();

        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(batch_interval),
            Vec::new(),
        );

        let response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let collect_uri =
            Url::parse(response.headers().get(LOCATION).unwrap().to_str().unwrap()).unwrap();
        assert_eq!(collect_uri.scheme(), "https");
        assert_eq!(collect_uri.host_str().unwrap(), "leader.endpoint");
        let mut path_segments = collect_uri.path_segments().unwrap();
        assert_eq!(path_segments.next(), Some("collect_jobs"));
        let collect_job_id = Uuid::parse_str(path_segments.next().unwrap()).unwrap();
        assert!(path_segments.next().is_none());

        let collect_job_response = warp::test::request()
            .method("GET")
            .path(&format!("/collect_jobs/{}", collect_job_id))
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(collect_job_response.status(), StatusCode::ACCEPTED);

        // Update the collect job with the aggregate shares. Collect job should now be complete.
        datastore
            .run_tx(|tx| {
                let task = task.clone();
                let helper_aggregate_share_bytes: Vec<u8> = (&helper_aggregate_share).into();
                let leader_aggregate_share = leader_aggregate_share.clone();
                Box::pin(async move {
                    let encrypted_helper_aggregate_share = hpke::seal(
                        task.collector_hpke_config(),
                        &HpkeApplicationInfo::new(
                            &Label::AggregateShare,
                            &Role::Helper,
                            &Role::Collector,
                        ),
                        &helper_aggregate_share_bytes,
                        &associated_data_for_aggregate_share::<TimeInterval>(
                            task.id(),
                            &batch_interval,
                        ),
                    )
                    .unwrap();

                    let collect_job = tx
                        .get_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                            &collect_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap()
                        .with_state(CollectJobState::Finished {
                            report_count: 12,
                            encrypted_helper_aggregate_share,
                            leader_aggregate_share,
                        });

                    tx.update_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        &collect_job,
                    )
                    .await
                    .unwrap();
                    Ok(())
                })
            })
            .await
            .unwrap();

        let (parts, body) = warp::test::request()
            .method("GET")
            .path(&format!("/collect_jobs/{}", collect_job_id))
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(
            parts.headers.get(CONTENT_TYPE).unwrap(),
            CollectResp::<TimeInterval>::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(body).await.unwrap();
        let collect_resp = CollectResp::<TimeInterval>::get_decoded(body_bytes.as_ref()).unwrap();
        assert_eq!(collect_resp.encrypted_aggregate_shares().len(), 2);

        let decrypted_leader_aggregate_share = hpke::open(
            task.collector_hpke_config(),
            &collector_hpke_recipient,
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
            &collect_resp.encrypted_aggregate_shares()[0],
            &associated_data_for_aggregate_share::<TimeInterval>(task.id(), &batch_interval),
        )
        .unwrap();
        assert_eq!(
            leader_aggregate_share,
            AggregateShare::try_from(decrypted_leader_aggregate_share.as_ref()).unwrap()
        );

        let decrypted_helper_aggregate_share = hpke::open(
            task.collector_hpke_config(),
            &collector_hpke_recipient,
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            &collect_resp.encrypted_aggregate_shares()[1],
            &associated_data_for_aggregate_share::<TimeInterval>(task.id(), &batch_interval),
        )
        .unwrap();
        assert_eq!(
            helper_aggregate_share,
            AggregateShare::try_from(decrypted_helper_aggregate_share.as_ref()).unwrap()
        );
    }

    #[tokio::test]
    async fn no_such_collect_job() {
        install_test_trace_subscriber();
        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;
        let filter = aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap();

        let no_such_collect_job_id = Uuid::new_v4();

        let response = warp::test::request()
            .method("GET")
            .path(&format!("/collect_jobs/{no_such_collect_job_id}"))
            .header(
                "DAP-Auth-Token",
                "this is a fake authentication token since there are no tasks",
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn collect_request_batch_queried_too_many_times() {
        install_test_trace_subscriber();

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();

        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_batch_aggregation(&BatchAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision())
                            .unwrap(),
                        dummy_vdaf::AggregationParam(0),
                        dummy_vdaf::AggregateShare(0),
                        10,
                        ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap();

        // Sending this request will consume a query for [0, time_precision).
        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // This request will not be allowed due to the query count already being consumed.
        let invalid_request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            dummy_vdaf::AggregationParam(1).get_encoded(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(invalid_request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes",
                "title": "The batch described by the query has been queried too many times.",
                "detail": "The batch described by the query has been queried too many times.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn collect_request_batch_overlap() {
        install_test_trace_subscriber();

        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();

        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_batch_aggregation(&BatchAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        dummy_vdaf::Vdaf,
                    >::new(
                        *task.id(),
                        Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision())
                            .unwrap(),
                        dummy_vdaf::AggregationParam(0),
                        dummy_vdaf::AggregateShare(0),
                        10,
                        ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                    ))
                    .await
                })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap();

        // Sending this request will consume a query for [0, 2 * time_precision).
        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_microseconds(
                        2 * task.time_precision().as_microseconds().unwrap(),
                    ),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
        );

        let response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // This request will not be allowed due to overlapping with the previous request.
        let invalid_request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0)
                        .add(task.time_precision())
                        .unwrap(),
                    *task.time_precision(),
                )
                .unwrap(),
            ),
            dummy_vdaf::AggregationParam(1).get_encoded(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(invalid_request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
                "title": "The queried batch overlaps with a previously queried batch.",
                "detail": "The queried batch overlaps with a previously queried batch.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn delete_collect_job() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .build();
        let batch_interval =
            Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap();

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::clone(&datastore), clock).unwrap();

        // Try to delete a collect job that doesn't exist
        let delete_job_response = warp::test::request()
            .method("DELETE")
            .path(&format!("/collect_jobs/{}", Uuid::new_v4()))
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(delete_job_response.status(), StatusCode::NOT_FOUND);

        // Create a collect job
        let request = CollectReq::new(
            *task.id(),
            Query::new_time_interval(batch_interval),
            Vec::new(),
        );

        let collect_response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(collect_response.status(), StatusCode::SEE_OTHER);
        let collect_uri = Url::parse(
            collect_response
                .headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();

        // Cancel the job
        let delete_job_response = warp::test::request()
            .method("DELETE")
            .path(collect_uri.path())
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(delete_job_response.status(), StatusCode::NO_CONTENT);

        // Get the job again
        let get_response = warp::test::request()
            .method("GET")
            .path(collect_uri.path())
            .header(
                "DAP-Auth-Token",
                task.primary_collector_auth_token().as_bytes(),
            )
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(get_response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn aggregate_share_request_to_leader() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = AggregateShareReq::new(
            *task.id(),
            BatchSelector::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            Vec::new(),
            0,
            ReportIdChecksum::default(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::NOT_FOUND);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::NOT_FOUND.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_share_request_invalid_batch_interval() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = AggregateShareReq::new(
            *task.id(),
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(0),
                    // Collect request will be rejected because batch interval is too small
                    Duration::from_seconds(task.time_precision().as_seconds() - 1),
                )
                .unwrap(),
            ),
            Vec::new(),
            0,
            ReportIdChecksum::default(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
            .path("/aggregate_share")
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch implied by the query is invalid.",
                "detail": "The batch implied by the query is invalid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_share_request() {
        install_test_trace_subscriber();

        let (collector_hpke_config, collector_hpke_recipient) =
            generate_test_hpke_config_and_private_key();
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper)
            .with_max_batch_query_count(1)
            .with_time_precision(Duration::from_seconds(500))
            .with_min_batch_size(10)
            .with_collector_hpke_config(collector_hpke_config.clone())
            .build();

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        datastore.put_task(&task).await.unwrap();

        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        // There are no batch aggregations in the datastore yet
        let request = AggregateShareReq::new(
            *task.id(),
            BatchSelector::new_time_interval(
                Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision()).unwrap(),
            ),
            dummy_vdaf::AggregationParam(0).get_encoded(),
            0,
            ReportIdChecksum::default(),
        );

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "detail": "The number of reports included in the batch is invalid.",
                "instance": "..",
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
                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(500),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            aggregation_param,
                            dummy_vdaf::AggregateShare(64),
                            5,
                            ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                        ))
                        .await?;

                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(1500),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            aggregation_param,
                            dummy_vdaf::AggregateShare(128),
                            5,
                            ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                        ))
                        .await?;

                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(2000),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            aggregation_param,
                            dummy_vdaf::AggregateShare(256),
                            5,
                            ReportIdChecksum::get_decoded(&[4; 32]).unwrap(),
                        ))
                        .await?;

                        tx.put_batch_aggregation(&BatchAggregation::<
                            DUMMY_VERIFY_KEY_LENGTH,
                            TimeInterval,
                            dummy_vdaf::Vdaf,
                        >::new(
                            *task.id(),
                            Interval::new(
                                Time::from_seconds_since_epoch(2500),
                                *task.time_precision(),
                            )
                            .unwrap(),
                            aggregation_param,
                            dummy_vdaf::AggregateShare(512),
                            5,
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
            *task.id(),
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
        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "detail": "The number of reports included in the batch is invalid.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            })
        );

        // Make requests that will fail because the checksum or report counts don't match.
        for misaligned_request in [
            // Interval is big enough, but checksum doesn't match.
            AggregateShareReq::new(
                *task.id(),
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
                *task.id(),
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
            let (parts, body) = warp::test::request()
                .method("POST")
                .path("/aggregate_share")
                .header(
                    "DAP-Auth-Token",
                    task.primary_aggregator_auth_token().as_bytes(),
                )
                .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
                .body(misaligned_request.get_encoded())
                .filter(&filter)
                .await
                .unwrap()
                .into_response()
                .into_parts();

            assert_eq!(parts.status, StatusCode::BAD_REQUEST);
            let problem_details: serde_json::Value =
                serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
            assert_eq!(
                problem_details,
                json!({
                    "status": StatusCode::BAD_REQUEST.as_u16(),
                    "type": "urn:ietf:params:ppm:dap:error:batchMismatch",
                    "title": "Leader and helper disagree on reports aggregated in a batch.",
                    "detail": "Leader and helper disagree on reports aggregated in a batch.",
                    "instance": "..",
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
                    *task.id(),
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
                    *task.id(),
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
                let (parts, body) = warp::test::request()
                    .method("POST")
                    .path("/aggregate_share")
                    .header(
                        "DAP-Auth-Token",
                        task.primary_aggregator_auth_token().as_bytes(),
                    )
                    .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
                    .body(request.get_encoded())
                    .filter(&filter)
                    .await
                    .unwrap()
                    .into_response()
                    .into_parts();

                assert_eq!(
                    parts.status,
                    StatusCode::OK,
                    "test case: {:?}, iteration: {}",
                    label,
                    iteration
                );
                assert_eq!(
                    parts.headers.get(CONTENT_TYPE).unwrap(),
                    AggregateShareResp::MEDIA_TYPE,
                    "test case: {:?}, iteration: {}",
                    label,
                    iteration
                );
                let body_bytes = body::to_bytes(body).await.unwrap();
                let aggregate_share_resp = AggregateShareResp::get_decoded(&body_bytes).unwrap();

                let aggregate_share = hpke::open(
                    &collector_hpke_config,
                    &collector_hpke_recipient,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    aggregate_share_resp.encrypted_aggregate_share(),
                    &associated_data_for_aggregate_share::<TimeInterval>(
                        request.task_id(),
                        request.batch_selector().batch_identifier(),
                    ),
                )
                .unwrap();

                // Should get the sum over the first and second aggregate shares
                let decoded_aggregate_share =
                    dummy_vdaf::AggregateShare::try_from(aggregate_share.as_ref()).unwrap();
                assert_eq!(
                    decoded_aggregate_share, expected_result,
                    "test case: {:?}, iteration: {}",
                    label, iteration
                );
            }
        }

        // Requests for collection intervals that overlap with but are not identical to previous
        // collection intervals fail.
        let all_batch_request = AggregateShareReq::new(
            *task.id(),
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
        let mut resp = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
            .body(all_batch_request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(resp.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
                "title": "The queried batch overlaps with a previously queried batch.",
                "detail": "The queried batch overlaps with a previously queried batch.",
                "instance": "..",
                "taskid": format!("{}", task.id()),
            }),
        );

        // Previous sequence of aggregate share requests should have consumed the available queries
        // for all the batches. Further requests for any batches will cause query count violations.
        for query_count_violation_request in [
            AggregateShareReq::new(
                *task.id(),
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
                *task.id(),
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
            let mut resp = warp::test::request()
                .method("POST")
                .path("/aggregate_share")
                .header(
                    "DAP-Auth-Token",
                    task.primary_aggregator_auth_token().as_bytes(),
                )
                .header(CONTENT_TYPE, AggregateShareReq::<TimeInterval>::MEDIA_TYPE)
                .body(query_count_violation_request.get_encoded())
                .filter(&filter)
                .await
                .unwrap()
                .into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let problem_details: serde_json::Value =
                serde_json::from_slice(&body::to_bytes(resp.body_mut()).await.unwrap()).unwrap();
            assert_eq!(
                problem_details,
                json!({
                    "status": StatusCode::BAD_REQUEST.as_u16(),
                    "type": "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes",
                    "title": "The batch described by the query has been queried too many times.",
                    "detail": "The batch described by the query has been queried too many times.",
                    "instance": "..",
                    "taskid": format!("{}", task.id()),
                })
            );
        }
    }

    fn current_hpke_key(
        hpke_keys: &HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
    ) -> &(HpkeConfig, HpkePrivateKey) {
        hpke_keys
            .values()
            .max_by_key(|(cfg, _)| u8::from(*cfg.id()))
            .unwrap()
    }

    fn generate_helper_report_share<V: vdaf::Client>(
        task_id: &TaskId,
        report_metadata: &ReportMetadata,
        cfg: &HpkeConfig,
        public_share: &V::PublicShare,
        input_share: &V::InputShare,
    ) -> ReportShare
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let encoded_public_share = public_share.get_encoded();
        let associated_data =
            associated_data_for_report_share(task_id, report_metadata, &encoded_public_share);
        generate_helper_report_share_for_plaintext(
            report_metadata.clone(),
            cfg,
            encoded_public_share,
            &input_share.get_encoded(),
            &associated_data,
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
            DapProblemType::ReportTooLate,
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
        let response_histogram = meter.f64_histogram("janus_aggregator_response_time").init();
        let request_histogram = meter
            .f64_histogram("janus_http_request_duration_seconds")
            .init();
        let server_url: Url = mockito::server_url().parse().unwrap();
        let auth_token = AuthenticationToken::from("auth".as_bytes().to_vec());
        let http_client = Client::new();

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

        let test_cases = [
            TestCase::new(Box::new(|| Error::InvalidConfiguration("test")), None),
            TestCase::new(
                Box::new(|| Error::ReportTooLate(random(), random(), RealClock::default().now())),
                Some(DapProblemType::ReportTooLate),
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
                Box::new(|| Error::ReportTooEarly(random(), random(), RealClock::default().now())),
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
                            Interval::new(RealClock::default().now(), Duration::from_seconds(3600))
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
        ];

        for TestCase {
            error_factory,
            expected_problem_type,
        } in test_cases
        {
            // Run error_handler() on the given error, and capture its response.
            let error_factory = Arc::new(error_factory);
            let base_filter = warp::post().map({
                let error_factory = Arc::clone(&error_factory);
                move || -> Result<Response, Error> { Err(error_factory()) }
            });
            let wrapped_filter = base_filter.with(warp::wrap_fn(error_handler(
                response_histogram.clone(),
                "test",
            )));
            let response = warp::test::request()
                .method("POST")
                .reply(&wrapped_filter)
                .await;

            // Serve the response via mockito, and run it through post_to_helper's error handling.
            let error_mock = mock("POST", "/")
                .with_status(response.status().as_u16().into())
                .with_header("Content-Type", "application/problem+json")
                .with_body(response.body())
                .create();
            let actual_error = post_to_helper(
                &http_client,
                server_url.clone(),
                "text/plain",
                (),
                &auth_token,
                &request_histogram,
            )
            .await
            .unwrap_err();
            error_mock.assert();

            // Confirm that post_to_helper() correctly parsed the error type from error_handler().
            assert_matches!(
                actual_error,
                Error::Http { dap_problem_type: problem_type, .. } => {
                    assert_eq!(problem_type, expected_problem_type);
                }
            );
        }
    }
}
