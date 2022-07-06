//! Common functionality for PPM aggregators

mod accumulator;
pub mod aggregate_share;
pub mod aggregation_job_creator;
pub mod aggregation_job_driver;

use crate::{
    aggregator::{
        accumulator::Accumulator,
        aggregate_share::{compute_aggregate_share, validate_batch_lifetime_for_unit_aggregations},
    },
    datastore::{
        self,
        models::{
            AggregateShareJob, AggregationJob, AggregationJobState, CollectJobState,
            ReportAggregation, ReportAggregationState,
        },
        Datastore,
    },
    message::{
        AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq,
        AggregateInitializeResp, AggregateShareReq, AggregateShareResp, AggregationJobId,
        CollectReq, CollectResp, PrepareStep, PrepareStepResult, ReportShare, ReportShareError,
    },
    task::{self, Task, VdafInstance, DAP_AUTH_HEADER, PRIO3_AES128_VERIFY_KEY_LENGTH},
};
use bytes::Bytes;
use futures::try_join;
use http::{
    header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION},
    StatusCode,
};
use janus_core::{
    hpke::{self, associated_data_for_aggregate_share, HpkeApplicationInfo, Label},
    message::{HpkeConfig, HpkeConfigId, Interval, Nonce, NonceChecksum, Report, Role, TaskId},
    time::Clock,
};
use opentelemetry::{
    metrics::{Counter, Unit, ValueRecorder},
    KeyValue,
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf::{
        self,
        prio3::{Prio3, Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        PrepareTransition,
    },
};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt,
    future::Future,
    io::Cursor,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use tokio::sync::Mutex;
use tracing::{debug, error, warn};
use url::Url;
use uuid::Uuid;
use warp::{
    cors::Cors,
    filters::BoxedFilter,
    reply::{self, Response},
    trace, Filter, Rejection, Reply,
};

#[cfg(test)]
use janus_test_util::dummy_vdaf;
#[cfg(test)]
use prio::vdaf::VdafError;

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
    Message(#[from] janus_core::message::Error),
    /// Corresponds to `reportTooLate`, §3.1
    #[error("stale report: {0} {1:?}")]
    ReportTooLate(Nonce, TaskId),
    /// Corresponds to `reportTooEarly`, §3.1. A report was rejected becuase the timestamp is too far in the future, §4.3.4.
    #[error("report from the future: {0} {1:?}")]
    ReportTooEarly(Nonce, TaskId),
    /// Corresponds to `unrecognizedMessage`, §3.1
    #[error("unrecognized message: {0} {1:?}")]
    UnrecognizedMessage(&'static str, Option<TaskId>),
    /// Corresponds to `unrecognizedTask`, §3.1
    #[error("unrecognized task: {0:?}")]
    UnrecognizedTask(TaskId),
    /// An attempt was made to act on an unknown aggregation job.
    #[error("unrecognized aggregation job: {0:?}")]
    UnrecognizedAggregationJob(AggregationJobId, TaskId),
    /// An attempt was made to act on an unknown collect job.
    #[error("unrecognized collect job: {0}")]
    UnrecognizedCollectJob(Uuid),
    /// Corresponds to `outdatedHpkeConfig`, §3.1
    #[error("outdated HPKE config: {0} {1:?}")]
    OutdatedHpkeConfig(HpkeConfigId, TaskId),
    /// Corresponds to `unauthorizedRequest`, §3.1
    #[error("unauthorized request: {0:?}")]
    UnauthorizedRequest(TaskId),
    /// An error from the datastore.
    #[error("datastore error: {0}")]
    Datastore(datastore::Error),
    /// An error from the underlying VDAF library.
    #[error("VDAF error: {0}")]
    Vdaf(#[from] vdaf::VdafError),
    /// A collect or aggregate share request was rejected because the interval is valid, per §4.6
    #[error("invalid batch interval: {0} {1:?}")]
    BatchInvalid(Interval, TaskId),
    /// There are not enough reports in the batch interval to meet the task's minimum batch size.
    #[error("insufficient number of reports ({0}) for task {1:?}")]
    InsufficientBatchSize(u64, TaskId),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    /// The checksum or report count in one aggregator's aggregate share does not match the other
    /// aggregator's aggregate share, suggesting different sets of reports were aggregated.
    #[error(
        "batch misalignment: own checksum: {own_checksum:?} own report count: {own_report_count} \
peer checksum: {peer_checksum:?} peer report count: {peer_report_count}"
    )]
    BatchMismatch {
        task_id: TaskId,
        own_checksum: NonceChecksum,
        own_report_count: u64,
        peer_checksum: NonceChecksum,
        peer_report_count: u64,
    },
    /// Too many queries against a single batch.
    #[error("maxiumum batch lifetime for task {0:?} exceeded")]
    BatchLifetimeExceeded(TaskId),
    /// HPKE failure.
    #[error("HPKE error: {0}")]
    Hpke(#[from] janus_core::hpke::Error),
    /// Error handling task parameters
    #[error("invalid task parameters: {0}")]
    TaskParameters(#[from] crate::task::Error),
    /// Error making an HTTP request
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    /// An error representing a generic internal aggregation error; intended for "impossible"
    /// conditions.
    #[error("internal aggregator error: {0}")]
    Internal(String),
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

/// Aggregator implements a PPM aggregator.
pub struct Aggregator<C: Clock> {
    /// Datastore used for durable storage.
    datastore: Arc<Datastore<C>>,
    /// Clock used to sample time.
    clock: C,
    /// Cache of task aggregators.
    task_aggregators: Mutex<HashMap<TaskId, Arc<TaskAggregator>>>,
}

impl<C: Clock> Aggregator<C> {
    fn new(datastore: Arc<Datastore<C>>, clock: C) -> Self {
        Self {
            datastore,
            clock,
            task_aggregators: Mutex::new(HashMap::new()),
        }
    }

    async fn handle_hpke_config(&self, task_id_base64: &[u8]) -> Result<Vec<u8>, Error> {
        let task_id_bytes = base64::decode_config(task_id_base64, base64::URL_SAFE_NO_PAD)
            .map_err(|_| Error::UnrecognizedMessage("task_id", None))?;
        let task_id = TaskId::get_decoded(&task_id_bytes)
            .map_err(|_| Error::UnrecognizedMessage("task_id", None))?;
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        Ok(task_aggregator.handle_hpke_config().get_encoded())
    }

    async fn handle_upload(&self, report_bytes: &[u8]) -> Result<(), Error> {
        let report = Report::get_decoded(report_bytes)?;

        let task_aggregator = self.task_aggregator_for(report.task_id()).await?;
        // Only the leader supports upload.
        if task_aggregator.task.role != Role::Leader {
            return Err(Error::UnrecognizedTask(report.task_id()));
        }
        task_aggregator
            .handle_upload(&self.datastore, &self.clock, report)
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
        let task_aggregator = self.task_aggregator_for(task_id).await?;
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

        let req = AggregateInitializeReq::get_decoded(req_bytes)?;
        assert_eq!(req.task_id, task_id);

        if task_aggregator.task.role != Role::Helper {
            return Err(Error::UnrecognizedTask(task_id));
        }
        Ok(task_aggregator
            .handle_aggregate_init(&self.datastore, req)
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
        let task_aggregator = self.task_aggregator_for(task_id).await?;
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
        assert_eq!(req.task_id, task_id);

        if task_aggregator.task.role != Role::Helper {
            return Err(Error::UnrecognizedTask(task_id));
        }
        Ok(task_aggregator
            .handle_aggregate_continue(&self.datastore, req)
            .await?
            .get_encoded())
    }

    /// Handle a collect request. Only supported by the leader. `req_bytes` is an encoded
    /// [`CollectReq`]. Returns the URL at which a collector may poll for status of the collect job
    /// corresponding to the `CollectReq`.
    async fn handle_collect(&self, req_bytes: &[u8]) -> Result<Url, Error> {
        let collect_req = CollectReq::get_decoded(req_bytes)?;

        let task_aggregator = self.task_aggregator_for(collect_req.task_id).await?;

        // Only the leader supports /collect.
        if task_aggregator.task.role != Role::Leader {
            return Err(Error::UnrecognizedTask(collect_req.task_id));
        }

        task_aggregator
            .handle_collect(&self.datastore, collect_req)
            .await
    }

    /// Handle a request for a collect job. `collect_job_id` is the unique identifier for the
    /// collect job parsed out of the request URI. Returns an encoded [`CollectResp`] if the collect
    /// job has been run to completion, `None` if the collect job has not yet run, or an error
    /// otherwise.
    async fn handle_collect_job(&self, collect_job_id: Uuid) -> Result<Option<Vec<u8>>, Error> {
        let task_id = self
            .datastore
            .run_tx(|tx| Box::pin(async move { tx.get_collect_job_task_id(collect_job_id).await }))
            .await?
            .ok_or(Error::UnrecognizedCollectJob(collect_job_id))?;

        let task_aggregator = self.task_aggregator_for(task_id).await?;

        // Only the leader handles collect jobs.
        if task_aggregator.task.role != Role::Leader {
            return Err(Error::UnrecognizedTask(task_id));
        }

        Ok(task_aggregator
            .handle_collect_job(&self.datastore, collect_job_id)
            .await?
            .map(|resp| resp.get_encoded()))
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
        let task_aggregator = self.task_aggregator_for(task_id).await?;
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

        let req = AggregateShareReq::get_decoded(req_bytes)?;
        assert_eq!(req.task_id, task_id);

        // Only the helper supports /aggregate_share.
        if task_aggregator.task.role != Role::Helper {
            return Err(Error::UnrecognizedTask(req.task_id));
        }

        let resp = task_aggregator
            .handle_aggregate_share(&self.datastore, &req)
            .await?;
        Ok(resp.get_encoded())
    }

    async fn task_aggregator_for(&self, task_id: TaskId) -> Result<Arc<TaskAggregator>, Error> {
        // TODO(#238): don't cache forever (decide on & implement some cache eviction policy).
        // This is important both to avoid ever-growing resource usage, and to allow aggregators to
        // notice when a task changes (e.g. due to key rotation).

        // Fast path: grab an existing task aggregator if one exists for this task.
        {
            let task_aggs = self.task_aggregators.lock().await;
            if let Some(task_agg) = task_aggs.get(&task_id) {
                return Ok(task_agg.clone());
            }
        }

        // Slow path: retrieve task, create a task aggregator, store it to the cache, then return it.
        let task = self
            .datastore
            .run_tx(|tx| Box::pin(async move { tx.get_task(task_id).await }))
            .await?
            .ok_or(Error::UnrecognizedTask(task_id))?;
        let task_agg = Arc::new(TaskAggregator::new(task)?);
        {
            let mut task_aggs = self.task_aggregators.lock().await;
            Ok(task_aggs.entry(task_id).or_insert(task_agg).clone())
        }
    }
}

/// TaskAggregator provides aggregation functionality for a single task.
// TODO(#224): refactor Aggregator to perform indepedent batched operations (e.g. report handling in
// Aggregate requests) using a parallelized library like Rayon.
pub struct TaskAggregator {
    /// The task being aggregated.
    task: Task,
    /// VDAF-specific operations.
    vdaf_ops: VdafOps,
}

impl TaskAggregator {
    /// Create a new aggregator. `report_recipient` is used to decrypt reports received by this
    /// aggregator.
    fn new(task: Task) -> Result<Self, Error> {
        let current_vdaf_verify_key = task.vdaf_verify_keys.last().unwrap();
        let vdaf_ops = match &task.vdaf {
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
                let vdaf = Prio3::new_aes128_count(2)?;
                let verify_key = current_vdaf_verify_key
                    .clone()
                    .try_into()
                    .map_err(|_| Error::TaskParameters(task::Error::AggregatorAuthKeySize))?;
                VdafOps::Prio3Aes128Count(vdaf, verify_key)
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { bits }) => {
                let vdaf = Prio3::new_aes128_sum(2, *bits)?;
                let verify_key = current_vdaf_verify_key
                    .clone()
                    .try_into()
                    .map_err(|_| Error::TaskParameters(task::Error::AggregatorAuthKeySize))?;
                VdafOps::Prio3Aes128Sum(vdaf, verify_key)
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram {
                buckets,
            }) => {
                let vdaf = Prio3::new_aes128_histogram(2, &*buckets)?;
                let verify_key = current_vdaf_verify_key
                    .clone()
                    .try_into()
                    .map_err(|_| Error::TaskParameters(task::Error::AggregatorAuthKeySize))?;
                VdafOps::Prio3Aes128Histogram(vdaf, verify_key)
            }

            #[cfg(test)]
            VdafInstance::Fake => VdafOps::Fake(dummy_vdaf::Vdaf::new()),

            #[cfg(test)]
            VdafInstance::FakeFailsPrepInit => VdafOps::Fake(
                dummy_vdaf::Vdaf::new().with_prep_init_fn(|_| -> Result<(), VdafError> {
                    Err(VdafError::Uncategorized(
                        "FakeFailsPrepInit failed at prep_init".to_string(),
                    ))
                }),
            ),

            #[cfg(test)]
            VdafInstance::FakeFailsPrepStep => {
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                VdafOps::Fake(dummy_vdaf::Vdaf::new().with_prep_step_fn(
                    || -> Result<PrepareTransition<dummy_vdaf::Vdaf, VERIFY_KEY_LENGTH>, VdafError> {
                        Err(VdafError::Uncategorized(
                            "FakeFailsPrepStep failed at prep_step".to_string(),
                        ))
                    },
                ))
            }

            _ => panic!("VDAF {:?} is not yet supported", task.vdaf),
        };

        Ok(Self { task, vdaf_ops })
    }

    fn handle_hpke_config(&self) -> HpkeConfig {
        // TODO(#239): consider deciding a better way to determine "primary" (e.g. most-recent) HPKE
        // config/key -- right now it's the one with the maximal config ID, but that will run into
        // trouble if we ever need to wrap-around, which we may since config IDs are effectively a u8.
        self.task
            .hpke_keys
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
        report: Report,
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_upload(datastore, clock, &self.task, report)
            .await
    }

    async fn handle_aggregate_init<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        req: AggregateInitializeReq,
    ) -> Result<AggregateInitializeResp, Error> {
        self.vdaf_ops
            .handle_aggregate_init(datastore, &self.task, req)
            .await
    }

    async fn handle_aggregate_continue<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        req: AggregateContinueReq,
    ) -> Result<AggregateContinueResp, Error> {
        self.vdaf_ops
            .handle_aggregate_continue(datastore, &self.task, req)
            .await
    }

    async fn handle_collect<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        req: CollectReq,
    ) -> Result<Url, Error> {
        let collect_job_id = self
            .vdaf_ops
            .handle_collect(datastore, &self.task, &req)
            .await?;

        Ok(self
            .task
            .aggregator_url(Role::Leader)?
            .join("collect_jobs/")?
            .join(&collect_job_id.to_string())?)
    }

    async fn handle_collect_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        collect_job_id: Uuid,
    ) -> Result<Option<CollectResp>, Error> {
        self.vdaf_ops
            .handle_collect_job(datastore, &self.task, collect_job_id)
            .await
    }

    async fn handle_aggregate_share<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        req: &AggregateShareReq,
    ) -> Result<AggregateShareResp, Error> {
        // §4.4.4.3: check that the batch interval meets the requirements from §4.6
        if !self.task.validate_batch_interval(req.batch_interval) {
            return Err(Error::BatchInvalid(req.batch_interval, self.task.id));
        }

        self.vdaf_ops
            .handle_aggregate_share(datastore, &self.task, req)
            .await
    }
}

/// VdafOps stores VDAF-specific operations for a TaskAggregator in a non-generic way.
#[allow(clippy::enum_variant_names)]
enum VdafOps {
    // For the Prio3 VdafOps, the second parameter is the verify_key.
    Prio3Aes128Count(Prio3Aes128Count, [u8; PRIO3_AES128_VERIFY_KEY_LENGTH]),
    Prio3Aes128Sum(Prio3Aes128Sum, [u8; PRIO3_AES128_VERIFY_KEY_LENGTH]),
    Prio3Aes128Histogram(Prio3Aes128Histogram, [u8; PRIO3_AES128_VERIFY_KEY_LENGTH]),

    #[cfg(test)]
    Fake(dummy_vdaf::Vdaf),
}

impl VdafOps {
    async fn handle_upload<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        clock: &C,
        task: &Task,
        report: Report,
    ) -> Result<(), Error> {
        match self {
            VdafOps::Prio3Aes128Count(_, _) => {
                Self::handle_upload_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count, _>(
                    datastore, clock, task, report,
                )
                .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => {
                Self::handle_upload_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Sum, _>(
                    datastore, clock, task, report,
                )
                .await
            }
            VdafOps::Prio3Aes128Histogram(_, _) => Self::handle_upload_generic::<
                PRIO3_AES128_VERIFY_KEY_LENGTH,
                Prio3Aes128Histogram,
                _,
            >(datastore, clock, task, report)
            .await,

            #[cfg(test)]
            VdafOps::Fake(_) => {
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                Self::handle_upload_generic::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf, _>(
                    datastore, clock, task, report,
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
        task: &Task,
        req: AggregateInitializeReq,
    ) -> Result<AggregateInitializeResp, Error> {
        match self {
            VdafOps::Prio3Aes128Count(vdaf, verify_key) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                    _,
                >(datastore, vdaf, task, verify_key, req)
                .await
            }
            VdafOps::Prio3Aes128Sum(vdaf, verify_key) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Sum,
                    _,
                >(datastore, vdaf, task, verify_key, req)
                .await
            }
            VdafOps::Prio3Aes128Histogram(vdaf, verify_key) => {
                Self::handle_aggregate_init_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, vdaf, task, verify_key, req)
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(vdaf) => {
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                Self::handle_aggregate_init_generic::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf, _>(
                    datastore,
                    vdaf,
                    task,
                    &[],
                    req,
                )
                .await
            }
        }
    }

    async fn handle_aggregate_continue<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: &Task,
        req: AggregateContinueReq,
    ) -> Result<AggregateContinueResp, Error> {
        match self {
            VdafOps::Prio3Aes128Count(vdaf, _) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                    _,
                >(datastore, vdaf, task, req)
                .await
            }
            VdafOps::Prio3Aes128Sum(vdaf, _) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Sum,
                    _,
                >(datastore, vdaf, task, req)
                .await
            }
            VdafOps::Prio3Aes128Histogram(vdaf, _) => {
                Self::handle_aggregate_continue_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, vdaf, task, req)
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(vdaf) => {
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                Self::handle_aggregate_continue_generic::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf, _>(
                    datastore, vdaf, task, req,
                )
                .await
            }
        }
    }

    async fn handle_upload_generic<const L: usize, A: vdaf::Aggregator<L>, C: Clock>(
        datastore: &Datastore<C>,
        clock: &C,
        task: &Task,
        report: Report,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        // §4.2.2 The leader's report is the first one
        if report.encrypted_input_shares().len() != 2 {
            warn!(
                share_count = report.encrypted_input_shares().len(),
                "Unexpected number of encrypted shares in report"
            );
            return Err(Error::UnrecognizedMessage(
                "unexpected number of encrypted shares in report",
                Some(report.task_id()),
            ));
        }
        let leader_report = &report.encrypted_input_shares()[0];

        // §4.2.2: verify that the report's HPKE config ID is known
        let (hpke_config, hpke_private_key) = task
            .hpke_keys
            .get(&leader_report.config_id())
            .ok_or_else(|| {
                warn!(
                    config_id = ?leader_report.config_id(),
                    "Unknown HPKE config ID"
                );
                Error::OutdatedHpkeConfig(leader_report.config_id(), report.task_id())
            })?;

        let report_deadline = clock.now().add(task.tolerable_clock_skew)?;

        // §4.2.4: reject reports from too far in the future
        if report.nonce().time().is_after(report_deadline) {
            warn!(report.task_id = ?report.task_id(), report.nonce = ?report.nonce(), "Report timestamp exceeds tolerable clock skew");
            return Err(Error::ReportTooEarly(report.nonce(), report.task_id()));
        }

        // Check that we can decrypt the report. This isn't required by the spec
        // but this exercises HPKE decryption and saves us the trouble of
        // storing reports we can't use. We don't inform the client if this
        // fails.
        if let Err(err) = hpke::open(
            hpke_config,
            hpke_private_key,
            &HpkeApplicationInfo::new(Label::InputShare, Role::Client, task.role),
            leader_report,
            &report.associated_data(),
        ) {
            warn!(report.task_id = ?report.task_id(), report.nonce = ?report.nonce(), ?err, "Report decryption failed");
            return Ok(());
        }

        datastore
                    .run_tx(|tx| {
                        let report = report.clone();
                        Box::pin(async move {
                            let (existing_client_report, conflicting_collect_jobs) = try_join!(
                                tx.get_client_report(report.task_id(), report.nonce()),
                                tx.find_collect_jobs_including_time::<L, A>(report.task_id(), report.nonce().time()),
                            )?;

                            // §4.2.2 and 4.3.2.2: reject reports whose nonce has been seen before.
                            if existing_client_report.is_some() {
                                warn!(report.task_id = ?report.task_id(), report.nonce = ?report.nonce(), "Report replayed");
                                // TODO(#34): change this error type.
                                return Err(datastore::Error::User(
                                    Error::ReportTooLate(report.nonce(), report.task_id()).into(),
                                ));
                            }

                            // §4.3.2: reject reports whose timestamps fall into a batch interval
                            // that has already been collected.
                            if !conflicting_collect_jobs.is_empty() {
                                return Err(datastore::Error::User(
                                    Error::ReportTooLate(report.nonce(), report.task_id()).into(),
                                ));
                            }

                            // Store the report.
                            tx.put_client_report(&report).await?;
                            Ok(())
                        })
                    })
                    .await?;
        Ok(())
    }

    /// Implements the aggregate initialization request portion of the `/aggregate` endpoint for the
    /// helper, described in §4.4.4.1 of draft-gpew-priv-ppm.
    async fn handle_aggregate_init_generic<const L: usize, A: vdaf::Aggregator<L>, C: Clock>(
        datastore: &Datastore<C>,
        vdaf: &A,
        task: &Task,
        verify_key: &[u8; L],
        req: AggregateInitializeReq,
    ) -> Result<AggregateInitializeResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let task_id = task.id;
        let min_batch_duration = task.min_batch_duration;

        // If two ReportShare messages have the same nonce, then the helper MUST abort with
        // error "unrecognizedMessage". (§4.4.4.1)
        let mut seen_nonces = HashSet::with_capacity(req.report_shares.len());
        for share in &req.report_shares {
            if !seen_nonces.insert(share.nonce) {
                return Err(Error::UnrecognizedMessage(
                    "aggregate request contains duplicate nonce",
                    Some(task_id),
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
        let agg_param = A::AggregationParam::get_decoded(&req.agg_param)?;
        for report_share in req.report_shares {
            let hpke_key = task
                .hpke_keys
                .get(&report_share.encrypted_input_share.config_id())
                .ok_or_else(|| {
                    warn!(
                        config_id = ?report_share.encrypted_input_share.config_id(),
                        "Unknown HPKE config ID"
                    );
                    ReportShareError::HpkeUnknownConfigId
                });

            // If decryption fails, then the aggregator MUST fail with error `hpke-decrypt-error`. (§4.4.2.2)
            let plaintext = hpke_key.and_then(|(hpke_config, hpke_private_key)| {
                hpke::open(
                    hpke_config,
                    hpke_private_key,
                    &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Helper),
                    &report_share.encrypted_input_share,
                    &report_share.associated_data(task_id),
                )
                .map_err(|err| {
                    warn!(
                        ?task_id,
                        nonce = %report_share.nonce,
                        %err,
                        "Couldn't decrypt report share"
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
                    .map_err(|err| {
                        warn!(?task_id, nonce = %report_share.nonce, %err, "Couldn't decode input share from report share");
                        ReportShareError::VdafPrepError
                    })
            });

            // Next, the aggregator runs the preparation-state initialization algorithm for the VDAF
            // associated with the task and computes the first state transition. [...] If either
            // step fails, then the aggregator MUST fail with error `vdaf-prep-error`. (§4.4.2.2)
            let init_rslt = input_share.and_then(|input_share| {
                vdaf
                    .prepare_init(
                        verify_key,
                        Role::Helper.index().unwrap(),
                        &agg_param,
                        &report_share.nonce.get_encoded(),
                        &input_share,
                    )
                    .map_err(|err| {
                        warn!(?task_id, nonce = %report_share.nonce, %err, "Couldn't prepare_init report share");
                        ReportShareError::VdafPrepError
                    })
            });

            report_share_data.push(match init_rslt {
                Ok((prep_state, prep_share)) => {
                    saw_continue = true;
                    ReportShareData {
                        report_share,
                        prep_result: PrepareStepResult::Continued(prep_share.get_encoded()),
                        agg_state: ReportAggregationState::<L, A>::Waiting(prep_state, None),
                    }
                }

                Err(err) => ReportShareData {
                    report_share,
                    prep_result: PrepareStepResult::Failed(err),
                    agg_state: ReportAggregationState::<L, A>::Failed(err),
                },
            });
        }

        // Store data to datastore.
        let aggregation_job_state = if saw_continue {
            AggregationJobState::InProgress
        } else {
            AggregationJobState::Finished
        };
        let aggregation_job = Arc::new(AggregationJob::<L, A> {
            aggregation_job_id: req.job_id,
            task_id,
            aggregation_param: agg_param,
            state: aggregation_job_state,
        });
        let report_share_data = Arc::new(report_share_data);
        let prep_steps = datastore
            .run_tx(|tx| {
                let aggregation_job = aggregation_job.clone();
                let report_share_data = report_share_data.clone();

                Box::pin(async move {
                    // Write aggregation job.
                    tx.put_aggregation_job(&aggregation_job).await?;

                    let mut accumulator = Accumulator::<L, A>::new(
                        task_id,
                        min_batch_duration,
                        &aggregation_job.aggregation_param,
                    );

                    let mut prep_steps = Vec::new();
                    for (ord, share_data) in report_share_data.iter().enumerate() {
                        // Verify that we haven't seen this nonce before, and that the report isn't
                        // for a batch interval that has already started collection.
                        let (report_share_exists, conflicting_aggregate_share_jobs) = try_join!(
                            tx.check_report_share_exists(task_id, share_data.report_share.nonce),
                            tx.find_aggregate_share_jobs_including_time::<L, A>(
                                task_id,
                                share_data.report_share.nonce.time()
                            ),
                        )?;
                        if report_share_exists {
                            prep_steps.push(PrepareStep {
                                nonce: share_data.report_share.nonce,
                                result: PrepareStepResult::Failed(ReportShareError::ReportReplayed),
                            });
                            continue;
                        }
                        if !conflicting_aggregate_share_jobs.is_empty() {
                            prep_steps.push(PrepareStep {
                                nonce: share_data.report_share.nonce,
                                result: PrepareStepResult::Failed(ReportShareError::BatchCollected),
                            });
                            continue;
                        }

                        // Write client report & report aggregation.
                        tx.put_report_share(task_id, &share_data.report_share)
                            .await?;
                        tx.put_report_aggregation(&ReportAggregation::<L, A> {
                            aggregation_job_id: req.job_id,
                            task_id,
                            nonce: share_data.report_share.nonce,
                            ord: ord as i64,
                            state: share_data.agg_state.clone(),
                        })
                        .await?;

                        if let ReportAggregationState::<L, A>::Finished(ref output_share) =
                            share_data.agg_state
                        {
                            accumulator.update(output_share, share_data.report_share.nonce)?;
                        }

                        prep_steps.push(PrepareStep {
                            nonce: share_data.report_share.nonce,
                            result: share_data.prep_result.clone(),
                        })
                    }

                    accumulator.flush_to_datastore(tx).await?;
                    Ok(prep_steps)
                })
            })
            .await?;

        // Construct response and return.
        Ok(AggregateInitializeResp {
            prepare_steps: prep_steps,
        })
    }

    async fn handle_aggregate_continue_generic<const L: usize, A: vdaf::Aggregator<L>, C: Clock>(
        datastore: &Datastore<C>,
        vdaf: &A,
        task: &Task,
        req: AggregateContinueReq,
    ) -> Result<AggregateContinueResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PrepareShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::OutputShare: Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let task_id = task.id;
        let min_batch_duration = task.min_batch_duration;
        let vdaf = Arc::new(vdaf.clone());
        let prep_steps = Arc::new(req.prepare_steps);

        // TODO(#224): don't hold DB transaction open while computing VDAF updates?
        // TODO(#224): don't do O(n) network round-trips (where n is the number of prepare steps)
        Ok(datastore
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);
                let prep_steps = Arc::clone(&prep_steps);

                Box::pin(async move {
                    // Read existing state.
                    let (aggregation_job, report_aggregations) = try_join!(
                        tx.get_aggregation_job::<L, A>(task_id, req.job_id),
                        tx.get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            Role::Helper,
                            task_id,
                            req.job_id,
                        ),
                    )?;
                    let mut aggregation_job = aggregation_job.ok_or_else(|| datastore::Error::User(Error::UnrecognizedAggregationJob(req.job_id, task_id).into()))?;

                    // Handle each transition in the request.
                    let mut report_aggregations = report_aggregations.into_iter();
                    let (mut saw_continue, mut saw_finish) = (false, false);
                    let mut response_prep_steps = Vec::new();
                    let mut accumulator = Accumulator::<L, A>::new(task_id, min_batch_duration, &aggregation_job.aggregation_param);

                    for prep_step in prep_steps.iter() {
                        // Match preparation step received from leader to stored report aggregation,
                        // and extract the stored preparation step.
                        let mut report_aggregation = loop {
                            let mut report_agg = report_aggregations.next().ok_or_else(|| {
                                warn!(?task_id, job_id = ?req.job_id, nonce = %prep_step.nonce, "Leader sent unexpected, duplicate, or out-of-order prepare steps");
                                datastore::Error::User(Error::UnrecognizedMessage(
                                    "leader sent unexpected, duplicate, or out-of-order prepare steps",
                                    Some(task_id),
                                ).into())
                            })?;
                            if report_agg.nonce != prep_step.nonce {
                                // This report was omitted by the leader because of a prior failure.
                                // Note that the report was dropped (if it's not already in an error
                                // state) and continue.
                                if matches!(report_agg.state, ReportAggregationState::Waiting(_, _)) {
                                    report_agg.state = ReportAggregationState::Failed(ReportShareError::ReportDropped);
                                    tx.update_report_aggregation(&report_agg).await?;
                                }
                                continue;
                            }
                            break report_agg;
                        };

                        // Make sure this report isn't in an interval that has already started
                        // collection.
                        let conflicting_aggregate_share_jobs = tx.find_aggregate_share_jobs_including_time::<L, A>(task_id, prep_step.nonce.time()).await?;
                        if !conflicting_aggregate_share_jobs.is_empty() {
                            report_aggregation.state = ReportAggregationState::Failed(ReportShareError::BatchCollected);
                            response_prep_steps.push(PrepareStep {
                                nonce: prep_step.nonce,
                                result: PrepareStepResult::Failed(ReportShareError::BatchCollected),
                            });
                            tx.update_report_aggregation(&report_aggregation).await?;
                            continue;
                        }

                        let prep_state =
                            match report_aggregation.state {
                                ReportAggregationState::Waiting(prep_state, _) => prep_state,
                                _ => {
                                    warn!(?task_id, job_id = ?req.job_id, nonce = %prep_step.nonce, "Leader sent prepare step for non-WAITING report aggregation");
                                    return Err(datastore::Error::User(
                                        Error::UnrecognizedMessage(
                                            "leader sent prepare step for non-WAITING report aggregation",
                                            Some(task_id),
                                        ).into()
                                    ));
                                },
                            };

                        // Parse preparation message out of prepare step received from leader.
                        let prep_msg = match &prep_step.result {
                            PrepareStepResult::Continued(payload) => {
                                A::PrepareMessage::decode_with_param(
                                    &prep_state,
                                    &mut Cursor::new(payload.as_ref()),
                                )?
                            }
                            _ => {
                                warn!(?task_id, job_id = ?req.job_id, nonce = %prep_step.nonce, "Leader sent non-Continued prepare step");
                                return Err(datastore::Error::User(
                                    Error::UnrecognizedMessage(
                                        "leader sent non-Continued prepare step",
                                        Some(task_id),
                                    ).into()
                                ));
                            }
                        };

                        // Compute the next transition, prepare to respond & update DB.
                        match vdaf.prepare_step(prep_state, prep_msg) {
                            Ok(PrepareTransition::Continue(prep_state, prep_share))=> {
                                saw_continue = true;
                                report_aggregation.state =
                                    ReportAggregationState::Waiting(prep_state, None);
                                response_prep_steps.push(PrepareStep {
                                    nonce: prep_step.nonce,
                                    result: PrepareStepResult::Continued(prep_share.get_encoded()),
                                })
                            }

                            Ok(PrepareTransition::Finish(output_share)) => {
                                saw_finish = true;
                                accumulator.update(&output_share, prep_step.nonce)?;
                                report_aggregation.state =
                                    ReportAggregationState::Finished(output_share);
                                response_prep_steps.push(PrepareStep {
                                    nonce: prep_step.nonce,
                                    result: PrepareStepResult::Finished,
                                });
                            }

                            Err(err) => {
                                warn!(?task_id, job_id = ?req.job_id, nonce = %prep_step.nonce, %err, "Prepare step failed");
                                report_aggregation.state =
                                    ReportAggregationState::Failed(ReportShareError::VdafPrepError);
                                response_prep_steps.push(PrepareStep {
                                    nonce: prep_step.nonce,
                                    result: PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                                })
                            }
                        }

                        tx.update_report_aggregation(&report_aggregation).await?;
                    }

                    for mut report_agg in report_aggregations {
                        // This report was omitted by the leader because of a prior failure.
                        // Note that the report was dropped (if it's not already in an error state)
                        // and continue.
                        if matches!(report_agg.state, ReportAggregationState::Waiting(_, _)) {
                            report_agg.state = ReportAggregationState::Failed(ReportShareError::ReportDropped);
                            tx.update_report_aggregation(&report_agg).await?;
                        }
                    }

                    aggregation_job.state = match (saw_continue, saw_finish) {
                        (false, false) => AggregationJobState::Finished, // everything failed, or there were no reports
                        (true, false) => AggregationJobState::InProgress,
                        (false, true) => AggregationJobState::Finished,
                        (true, true) => {
                            return Err(datastore::Error::User(Error::Internal(
                                "VDAF took an inconsistent number of rounds to reach Finish state"
                                    .to_string(),
                            ).into()))
                        }
                    };
                    tx.update_aggregation_job(&aggregation_job).await?;

                    accumulator.flush_to_datastore(tx).await?;

                    Ok(AggregateContinueResp {
                        prepare_steps: response_prep_steps,
                    })
                })
            })
            .await?)
    }

    /// Handle requests to the leader `/collect` endpoint (§4.5).
    async fn handle_collect<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: &Task,
        collect_req: &CollectReq,
    ) -> Result<Uuid, Error> {
        match self {
            VdafOps::Prio3Aes128Count(_, _) => {
                Self::handle_collect_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count, _>(
                    datastore,
                    task,
                    collect_req,
                )
                .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => {
                Self::handle_collect_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Sum, _>(
                    datastore,
                    task,
                    collect_req,
                )
                .await
            }
            VdafOps::Prio3Aes128Histogram(_, _) => {
                Self::handle_collect_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, collect_req)
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(_) => {
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                Self::handle_collect_generic::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf, _>(
                    datastore,
                    task,
                    collect_req,
                )
                .await
            }
        }
    }

    #[tracing::instrument(skip(datastore), err)]
    async fn handle_collect_generic<const L: usize, A: vdaf::Aggregator<L>, C: Clock>(
        datastore: &Datastore<C>,
        task: &Task,
        req: &CollectReq,
    ) -> Result<Uuid, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
    {
        // §4.5: check that the batch interval meets the requirements from §4.6
        if !task.validate_batch_interval(req.batch_interval) {
            return Err(Error::BatchInvalid(req.batch_interval, task.id));
        }

        Ok(datastore
            .run_tx(move |tx| {
                let task = task.clone();
                let req = req.clone();
                Box::pin(async move {
                    if let Some(collect_job_id) = tx
                        .get_collect_job_id(task.id, req.batch_interval, &req.agg_param)
                        .await?
                    {
                        debug!(collect_request = ?req, "Serving existing collect job UUID");
                        return Ok(collect_job_id);
                    }

                    debug!(collect_request = ?req, "Cache miss, creating new collect job UUID");
                    let aggregation_param = A::AggregationParam::get_decoded(&req.agg_param)?;
                    let batch_unit_aggregations = tx
                        .get_batch_unit_aggregations_for_task_in_interval::<L, A>(
                            task.id,
                            req.batch_interval,
                            &aggregation_param,
                        )
                        .await?;
                    validate_batch_lifetime_for_unit_aggregations(
                        tx,
                        &task,
                        &batch_unit_aggregations,
                    )
                    .await?;

                    tx.put_collect_job(req.task_id, req.batch_interval, &req.agg_param)
                        .await
                })
            })
            .await?)
    }

    /// Handle requests to a collect job URI obtained from the leader's `/collect` endpoint (§4.5).
    async fn handle_collect_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: &Task,
        collect_job_id: Uuid,
    ) -> Result<Option<CollectResp>, Error> {
        match self {
            VdafOps::Prio3Aes128Count(_, _) => {
                Self::handle_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => Self::handle_collect_job_generic::<
                PRIO3_AES128_VERIFY_KEY_LENGTH,
                Prio3Aes128Sum,
                _,
            >(datastore, task, collect_job_id)
            .await,
            VdafOps::Prio3Aes128Histogram(_, _) => {
                Self::handle_collect_job_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, collect_job_id)
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(_) => {
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                Self::handle_collect_job_generic::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf, _>(
                    datastore,
                    task,
                    collect_job_id,
                )
                .await
            }
        }
    }

    async fn handle_collect_job_generic<const L: usize, A: vdaf::Aggregator<L>, C: Clock>(
        datastore: &Datastore<C>,
        task: &Task,
        collect_job_id: Uuid,
    ) -> Result<Option<CollectResp>, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
    {
        let task_id = task.id;
        let collect_job = datastore
            .run_tx(move |tx| {
                Box::pin(async move {
                    tx.get_collect_job::<L, A>(collect_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(collect_job_id).into(),
                            )
                        })
                })
            })
            .await?;

        match collect_job.state {
            CollectJobState::Start => {
                debug!(?collect_job_id, ?task_id, "Collect job has not run yet");
                Ok(None)
            }

            CollectJobState::Finished {
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
                    ?collect_job_id,
                    ?task_id,
                    "Serving cached collect job response"
                );
                let associated_data = associated_data_for_aggregate_share(
                    collect_job.task_id,
                    collect_job.batch_interval,
                );
                let encrypted_leader_aggregate_share = hpke::seal(
                    &task.collector_hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Leader, Role::Collector),
                    &<Vec<u8>>::from(&leader_aggregate_share),
                    &associated_data,
                )?;

                Ok(Some(CollectResp {
                    encrypted_agg_shares: vec![
                        encrypted_leader_aggregate_share,
                        encrypted_helper_aggregate_share,
                    ],
                }))
            }

            CollectJobState::Abandoned => {
                // TODO(#248): decide how to respond for abandoned collect jobs.
                warn!(
                    ?collect_job_id,
                    ?task_id,
                    "Attempting to collect abandoned collect job"
                );
                Ok(None)
            }
        }
    }

    /// Implements the `/aggregate_share` endpoint for the helper, described in §4.4.4.3
    async fn handle_aggregate_share<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: &Task,
        aggregate_share_req: &AggregateShareReq,
    ) -> Result<AggregateShareResp, Error> {
        match self {
            VdafOps::Prio3Aes128Count(_, _) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                    _,
                >(datastore, task, aggregate_share_req)
                .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Sum,
                    _,
                >(datastore, task, aggregate_share_req)
                .await
            }
            VdafOps::Prio3Aes128Histogram(_, _) => {
                Self::handle_aggregate_share_generic::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Histogram,
                    _,
                >(datastore, task, aggregate_share_req)
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(_) => {
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                Self::handle_aggregate_share_generic::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf, _>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }
        }
    }

    async fn handle_aggregate_share_generic<const L: usize, A: vdaf::Aggregator<L>, C: Clock>(
        datastore: &Datastore<C>,
        task: &Task,
        aggregate_share_req: &AggregateShareReq,
    ) -> Result<AggregateShareResp, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
    {
        let aggregate_share_job = datastore
            .run_tx(move |tx| {
                let task = task.clone();
                let aggregate_share_req = aggregate_share_req.clone();
                Box::pin(async move {
                    // Check if we have already serviced an aggregate share request with these
                    // parameters and serve the cached results if so.
                    let aggregate_share_job = match tx
                        .get_aggregate_share_job_by_request(&aggregate_share_req)
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
                                &aggregate_share_req.aggregation_param,
                            )?;
                            let batch_unit_aggregations = tx
                                .get_batch_unit_aggregations_for_task_in_interval::<L, A>(
                                    task.id,
                                    aggregate_share_req.batch_interval,
                                    &aggregation_param,
                                )
                                .await?;

                            validate_batch_lifetime_for_unit_aggregations(
                                tx,
                                &task,
                                &batch_unit_aggregations,
                            )
                            .await?;

                            let (helper_aggregate_share, report_count, checksum) =
                                compute_aggregate_share::<L, A>(&task, &batch_unit_aggregations)
                                    .await
                                    .map_err(|e| datastore::Error::User(e.into()))?;

                            // Now that we are satisfied that the request is serviceable, we consume batch lifetime by
                            // recording the aggregate share request parameters and the result.
                            let aggregate_share_job = AggregateShareJob::<L, A> {
                                task_id: task.id,
                                batch_interval: aggregate_share_req.batch_interval,
                                aggregation_param,
                                helper_aggregate_share,
                                report_count,
                                checksum,
                            };

                            tx.put_aggregate_share_job(&aggregate_share_job).await?;

                            aggregate_share_job
                        }
                    };

                    Ok(aggregate_share_job)
                })
            })
            .await?;

        // §4.4.4.3: verify total report count and the checksum we computed against those reported
        // by the leader.
        //
        // We check these *after* consuming batch lifetime by recording the aggregate share jobs
        // because the leader could retry the AggregateShareReq with corrected report count and
        // checksum, in which case we want to service that new request from cache. It may also be
        // helpful to have a record in the helper's datastore of failed requests for debugging. But
        // we may only wish to consider batch lifetime to be consumed once the an aggregate share
        // leaves the helper.
        if aggregate_share_job.report_count != aggregate_share_req.report_count
            || aggregate_share_job.checksum != aggregate_share_req.checksum
        {
            return Err(Error::BatchMismatch {
                task_id: aggregate_share_req.task_id,
                own_checksum: aggregate_share_job.checksum,
                own_report_count: aggregate_share_job.report_count,
                peer_checksum: aggregate_share_req.checksum,
                peer_report_count: aggregate_share_req.report_count,
            });
        }

        // §4.4.4.3: HPKE encrypt aggregate share to the collector. We store *unencrypted* aggregate
        // shares in the datastore so that we can encrypt cached results to the  collector HPKE
        // config valid when the current AggregateShareReq was made, and not whatever was valid at
        // the time the aggregate share was first computed.
        let encrypted_aggregate_share = hpke::seal(
            &task.collector_hpke_config,
            &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
            &<Vec<u8>>::from(&aggregate_share_job.helper_aggregate_share),
            &aggregate_share_req.associated_data_for_aggregate_share(),
        )?;

        Ok(AggregateShareResp {
            encrypted_aggregate_share,
        })
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

/// Representation of the different problem types defined in Table 1 in §3.1.
enum DapProblemType {
    UnrecognizedMessage,
    UnrecognizedTask,
    UnrecognizedAggregationJob, // TODO(https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/270): standardize this value
    OutdatedConfig,
    ReportTooLate,
    ReportTooEarly,
    BatchInvalid,
    InsufficientBatchSize,
    BatchLifetimeExceeded,
    BatchMismatch,
    UnauthorizedRequest,
}

impl DapProblemType {
    /// Returns the problem type URI for a particular kind of error.
    fn type_uri(&self) -> &'static str {
        match self {
            DapProblemType::UnrecognizedMessage => {
                "urn:ietf:params:ppm:dap:error:unrecognizedMessage"
            }
            DapProblemType::UnrecognizedTask => "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            DapProblemType::UnrecognizedAggregationJob => {
                "urn:ietf:params:ppm:dap:error:unrecognizedAggregationJob"
            }
            DapProblemType::OutdatedConfig => "urn:ietf:params:ppm:dap:error:outdatedConfig",
            DapProblemType::ReportTooLate => "urn:ietf:params:ppm:dap:error:reportTooLate",
            DapProblemType::ReportTooEarly => "urn:ietf:params:ppm:dap:error:reportTooEarly",
            DapProblemType::BatchInvalid => "urn:ietf:params:ppm:dap:error:batchInvalid",
            DapProblemType::InsufficientBatchSize => {
                "urn:ietf:params:ppm:dap:error:insufficientBatchSize"
            }
            DapProblemType::BatchLifetimeExceeded => {
                "urn:ietf:params:ppm:dap:error:batchLifetimeExceeded"
            }
            DapProblemType::BatchMismatch => "urn:ietf:params:ppm:dap:error:batchMismatch",
            DapProblemType::UnauthorizedRequest => {
                "urn:ietf:params:ppm:dap:error:unauthorizedRequest"
            }
        }
    }

    /// Returns a human-readable summary of a problem type.
    fn description(&self) -> &'static str {
        match self {
            DapProblemType::UnrecognizedMessage => {
                "The message type for a response was incorrect or the payload was malformed."
            }
            DapProblemType::UnrecognizedTask => {
                "An endpoint received a message with an unknown task ID."
            }
            DapProblemType::UnrecognizedAggregationJob => {
                "An endpoint received a message with an unknown aggregation job ID."
            }
            DapProblemType::OutdatedConfig => {
                "The message was generated using an outdated configuration."
            }
            DapProblemType::ReportTooLate => {
                "Report could not be processed because it arrived too late."
            }
            DapProblemType::ReportTooEarly => "Report could not be processed because it arrived too early.",
            DapProblemType::BatchInvalid => "The batch interval in the collect or aggregate share request is not valid for the task.",
            DapProblemType::InsufficientBatchSize => "There are not enough reports in the batch interval.",
            DapProblemType::BatchLifetimeExceeded => {
                "The batch lifetime has been exceeded for one or more reports included in the batch interval."
            }
            DapProblemType::BatchMismatch => {
                "Leader and helper disagree on reports aggregated in a batch."
            }
            DapProblemType::UnauthorizedRequest => "The request's authorization is not valid.",
        }
    }
}

/// The media type for problem details formatted as a JSON document, per RFC 7807.
static PROBLEM_DETAILS_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Construct an error response in accordance with §3.1.
// TODO(https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/209): The handling of the instance,
// title, detail, and taskid fields are subject to change.
fn build_problem_details_response(error_type: DapProblemType, task_id: Option<TaskId>) -> Response {
    // So far, 400 Bad Request seems to be the appropriate choice for each defined problem type.
    let status = StatusCode::BAD_REQUEST;
    warp::reply::with_status(
        warp::reply::with_header(
            warp::reply::json(&serde_json::json!({
                "type": error_type.type_uri(),
                "title": error_type.description(),
                "status": status.as_u16(),
                "detail": error_type.description(),
                // The base URI is either "[leader]/upload", "[aggregator]/aggregate",
                // "[helper]/aggregate_share", or "[leader]/collect". Relative URLs are allowed in
                // the instance member, thus ".." will always refer to the aggregator's endpoint,
                // as required by §3.1.
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
/// (See RFC 7807) and update a metrics counter. The returned closure is meant to be used in a warp
/// `map` filter.
fn error_handler<R: Reply>(
    request_status_counter: &Counter<u64>,
    name: &'static str,
) -> impl Fn(Result<R, Error>) -> warp::reply::Response + Clone {
    let bound_counter_success = request_status_counter.bind(&[
        KeyValue::new("endpoint", name),
        KeyValue::new("status", "success"),
    ]);
    let bound_counter_error = request_status_counter.bind(&[
        KeyValue::new("endpoint", name),
        KeyValue::new("status", "error"),
    ]);

    move |result| {
        if let Err(error) = &result {
            error!(%error);
            bound_counter_error.add(1);
        } else {
            bound_counter_success.add(1);
        }
        match result {
            Ok(reply) => reply.into_response(),
            Err(Error::InvalidConfiguration(_)) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            Err(Error::MessageDecode(_)) => StatusCode::BAD_REQUEST.into_response(),
            Err(Error::ReportTooLate(_, task_id)) => {
                build_problem_details_response(DapProblemType::ReportTooLate, Some(task_id))
            }
            Err(Error::UnrecognizedMessage(_, task_id)) => {
                build_problem_details_response(DapProblemType::UnrecognizedMessage, task_id)
            }
            Err(Error::UnrecognizedTask(task_id)) => {
                // TODO(#237): ensure that a helper returns HTTP 404 or 403 when this happens.
                build_problem_details_response(DapProblemType::UnrecognizedTask, Some(task_id))
            }
            Err(Error::UnrecognizedAggregationJob(_, task_id)) => build_problem_details_response(
                DapProblemType::UnrecognizedAggregationJob,
                Some(task_id),
            ),
            Err(Error::UnrecognizedCollectJob(_)) => StatusCode::NOT_FOUND.into_response(),
            Err(Error::OutdatedHpkeConfig(_, task_id)) => {
                build_problem_details_response(DapProblemType::OutdatedConfig, Some(task_id))
            }
            Err(Error::ReportTooEarly(_, task_id)) => {
                build_problem_details_response(DapProblemType::ReportTooEarly, Some(task_id))
            }
            Err(Error::UnauthorizedRequest(task_id)) => {
                build_problem_details_response(DapProblemType::UnauthorizedRequest, Some(task_id))
            }
            Err(Error::BatchInvalid(_, task_id)) => {
                build_problem_details_response(DapProblemType::BatchInvalid, Some(task_id))
            }
            Err(Error::InsufficientBatchSize(_, task_id)) => {
                build_problem_details_response(DapProblemType::InsufficientBatchSize, Some(task_id))
            }
            Err(Error::BatchMismatch { task_id, .. }) => {
                build_problem_details_response(DapProblemType::BatchMismatch, Some(task_id))
            }
            Err(Error::BatchLifetimeExceeded(task_id)) => {
                build_problem_details_response(DapProblemType::BatchLifetimeExceeded, Some(task_id))
            }
            Err(Error::Hpke(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Datastore(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Vdaf(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Internal(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Url(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Message(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::HttpClient(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::TaskParameters(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

/// Factory that produces a closure that will wrap a `warp::Filter`, measuring the time that it
/// takes to run, and recording it in metrics.
fn timing_wrapper<F, T>(
    value_recorder: &ValueRecorder<f64>,
    name: &'static str,
) -> impl Fn(F) -> BoxedFilter<(T,)>
where
    F: Filter<Extract = (T,), Error = Rejection> + Clone + Send + Sync + 'static,
    T: Reply,
{
    let bound_value_recorder = value_recorder.bind(&[KeyValue::new("endpoint", name)]);
    move |filter| {
        warp::any()
            .map(Instant::now)
            .and(filter)
            .map({
                let bound_value_recorder = bound_value_recorder.clone();
                move |start: Instant, reply| {
                    let elapsed = start.elapsed().as_secs_f64();
                    bound_value_recorder.record(elapsed);
                    reply
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
/// `response_counter` is a `Counter` that will be used to record successes and failures.
///
/// `timing_value_recorder` is a `ValueRecorder` that will be used to record request handling
/// timings. It is expected the value recorder will be backed by a histogram.
///
/// `name` is a unique name for this route. This will be used as a metrics label, and will be added
/// to the tracing span's values as its message.
fn compose_common_wrappers<F1, F2, T>(
    route_filter: F1,
    response_filter: F2,
    cors: Cors,
    response_counter: &Counter<u64>,
    timing_value_recorder: &ValueRecorder<f64>,
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
                .map(error_handler(response_counter, name))
                .with(cors)
                .with(warp::wrap_fn(timing_wrapper(timing_value_recorder, name)))
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
fn aggregator_filter<C: Clock>(
    datastore: Arc<Datastore<C>>,
    clock: C,
) -> Result<BoxedFilter<(impl Reply,)>, Error> {
    let aggregator = Arc::new(Aggregator::new(datastore, clock));

    let meter = opentelemetry::global::meter("janus_server");
    let response_counter = meter
        .u64_counter("aggregator_response")
        .with_description("Success and failure responses to incoming requests.")
        .init();
    let time_value_recorder = meter
        .f64_value_recorder("aggregator_response_time")
        .with_description("Elapsed time handling incoming requests.")
        .with_unit(Unit::new("seconds"))
        .init();

    let hpke_config_routing = warp::path("hpke_config");
    let hpke_config_responding = warp::get()
        .and(with_cloned_value(aggregator.clone()))
        .and(warp::query::<HashMap<String, String>>())
        .then(
            |aggregator: Arc<Aggregator<C>>, query_params: HashMap<String, String>| async move {
                let task_id_b64 = query_params
                    .get("task_id")
                    .ok_or(Error::UnrecognizedMessage("task_id", None))?;
                let hpke_config_bytes = aggregator.handle_hpke_config(task_id_b64.as_ref()).await?;
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
        &response_counter,
        &time_value_recorder,
        "hpke_config",
    );

    let upload_routing = warp::path("upload");
    let upload_responding = warp::post()
        .and(warp::header::exact(
            CONTENT_TYPE.as_str(),
            Report::MEDIA_TYPE,
        ))
        .and(with_cloned_value(aggregator.clone()))
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
        &response_counter,
        &time_value_recorder,
        "upload",
    );

    let aggregate_routing = warp::path("aggregate");
    let aggregate_responding = warp::post()
        .and(with_cloned_value(aggregator.clone()))
        .and(warp::body::bytes())
        .and(warp::header(CONTENT_TYPE.as_str()))
        .and(warp::header::optional::<String>(DAP_AUTH_HEADER))
        .then(
            |aggregator: Arc<Aggregator<C>>,
             body: Bytes,
             content_type: String,
             auth_token: Option<String>| async move {
                match content_type.as_str() {
                    AggregateInitializeReq::MEDIA_TYPE => http::Response::builder()
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
        &response_counter,
        &time_value_recorder,
        "aggregate",
    );

    let collect_routing = warp::path("collect");
    let collect_responding = warp::post()
        .and(warp::header::exact(
            CONTENT_TYPE.as_str(),
            CollectReq::MEDIA_TYPE,
        ))
        .and(with_cloned_value(aggregator.clone()))
        .and(warp::body::bytes())
        .then(|aggregator: Arc<Aggregator<C>>, body: Bytes| async move {
            let collect_uri = aggregator.handle_collect(&body).await?;
            // §4.5: Response is an HTTP 303 with the collect URI in a Location header.
            Ok(reply::with_status(
                reply::with_header(reply::reply(), LOCATION, collect_uri.as_str()),
                StatusCode::SEE_OTHER,
            ))
        });
    let collect_endpoint = compose_common_wrappers(
        collect_routing,
        collect_responding,
        warp::cors().build(),
        &response_counter,
        &time_value_recorder,
        "collect",
    );

    let collect_jobs_routing = warp::path("collect_jobs");
    let collect_jobs_responding = warp::get()
        .and(warp::path::param())
        .and(with_cloned_value(aggregator.clone()))
        .then(
            |collect_job_id: Uuid, aggregator: Arc<Aggregator<C>>| async move {
                let resp_bytes = aggregator.handle_collect_job(collect_job_id).await?;
                match resp_bytes {
                    Some(resp_bytes) => http::Response::builder()
                        .header(CONTENT_TYPE, CollectResp::MEDIA_TYPE)
                        .body(resp_bytes),
                    None => http::Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(Vec::new()),
                }
                .map_err(|err| Error::Internal(format!("couldn't produce response: {}", err)))
            },
        );
    let collect_jobs_endpoint = compose_common_wrappers(
        collect_jobs_routing,
        collect_jobs_responding,
        warp::cors().build(),
        &response_counter,
        &time_value_recorder,
        "collect_jobs",
    );

    let aggregate_share_routing = warp::path("aggregate_share");
    let aggregate_share_responding = warp::post()
        .and(warp::header::exact(
            CONTENT_TYPE.as_str(),
            AggregateShareReq::MEDIA_TYPE,
        ))
        .and(with_cloned_value(aggregator))
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
        &response_counter,
        &time_value_recorder,
        "aggregate_share",
    );

    Ok(hpke_config_endpoint
        .or(upload_endpoint)
        .or(aggregate_endpoint)
        .or(collect_endpoint)
        .or(collect_jobs_endpoint)
        .or(aggregate_share_endpoint)
        .boxed())
}

/// Construct a PPM aggregator server, listening on the provided [`SocketAddr`].
/// If the `SocketAddr`'s `port` is 0, an ephemeral port is used. Returns a
/// `SocketAddr` representing the address and port the server are listening on
/// and a future that can be `await`ed to begin serving requests.
pub fn aggregator_server<C: Clock>(
    datastore: Arc<Datastore<C>>,
    clock: C,
    listen_address: SocketAddr,
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()> + 'static), Error> {
    Ok(warp::serve(aggregator_filter(datastore, clock)?)
        .bind_with_graceful_shutdown(listen_address, shutdown_signal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastore::{
            models::BatchUnitAggregation,
            test_util::{ephemeral_datastore, DbHandle},
        },
        task::{
            test_util::{generate_aggregator_auth_token, new_dummy_task},
            VdafInstance,
        },
    };
    use assert_matches::assert_matches;
    use http::Method;
    use hyper::body;
    use janus_core::{
        hpke::associated_data_for_report_share,
        hpke::{
            associated_data_for_aggregate_share, test_util::generate_hpke_config_and_private_key,
            HpkePrivateKey, Label,
        },
        message::{Duration, HpkeCiphertext, HpkeConfig, TaskId, Time},
    };
    use janus_test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf, MockClock};
    use prio::{
        codec::Decode,
        field::Field64,
        vdaf::{prio3::Prio3Aes128Count, AggregateShare, Aggregator as _},
    };
    use rand::{thread_rng, Rng};
    use std::{collections::HashMap, io::Cursor};
    use uuid::Uuid;
    use warp::{cors::CorsForbidden, reply::Reply, Rejection};

    #[tokio::test]
    async fn hpke_config() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Leader,
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let want_hpke_key = current_hpke_key(&task.hpke_keys).clone();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let response = warp::test::request()
            .path(&format!("/hpke_config?task_id={}", task_id))
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
            HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader);
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

        // Check for appropriate CORS headers in response to a preflight request.
        let response = warp::test::request()
            .method("OPTIONS")
            .path(&format!("/hpke_config?task_id={}", task_id))
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
            .path(&format!("/hpke_config?task_id={}", task_id))
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
        clock: &MockClock,
    ) -> Report {
        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let hpke_key = current_hpke_key(&task.hpke_keys);
        let nonce = Nonce::new(
            clock.now().sub(task.tolerable_clock_skew).unwrap(),
            thread_rng().gen(),
        );
        let extensions = vec![];
        let message = b"this is a message";
        let associated_data = associated_data_for_report_share(task.id, nonce, &extensions);

        let leader_ciphertext = hpke::seal(
            &hpke_key.0,
            &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader),
            message,
            &associated_data,
        )
        .unwrap();
        let helper_ciphertext = hpke::seal(
            &hpke_key.0,
            &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader),
            message,
            &associated_data,
        )
        .unwrap();

        Report::new(
            task.id,
            nonce,
            extensions,
            vec![leader_ciphertext, helper_ciphertext],
        )
    }

    /// Convenience method to handle interaction with `warp::test` for typical PPM requests.
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

        let task = new_dummy_task(
            TaskId::random(),
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Leader,
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let report = setup_report(&task, &datastore, &clock).await;
        let filter = aggregator_filter(Arc::new(datastore), clock.clone()).unwrap();

        let response = drive_filter(Method::POST, "/upload", &report.get_encoded(), &filter)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body::to_bytes(response.into_body())
            .await
            .unwrap()
            .is_empty());

        // Verify that we reject duplicate reports with the staleReport type.
        // TODO(#34): change this error type.
        let mut response = drive_filter(Method::POST, "/upload", &report.get_encoded(), &filter)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(response.body_mut()).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
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
            report.task_id(),
            report.nonce(),
            report.extensions().to_vec(),
            vec![report.encrypted_input_shares()[0].clone()],
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
            serde_json::json!({
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
        let bad_report = Report::new(
            report.task_id(),
            report.nonce(),
            report.extensions().to_vec(),
            vec![
                HpkeCiphertext::new(
                    HpkeConfigId::from(101),
                    report.encrypted_input_shares()[0]
                        .encapsulated_context()
                        .to_vec(),
                    report.encrypted_input_shares()[0].payload().to_vec(),
                ),
                report.encrypted_input_shares()[1].clone(),
            ],
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
            serde_json::json!({
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
            .add(Duration::from_minutes(10).unwrap())
            .unwrap()
            .add(Duration::from_seconds(1))
            .unwrap();
        let bad_report = Report::new(
            report.task_id(),
            Nonce::new(bad_report_time, report.nonce().rand()),
            report.extensions().to_vec(),
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
            serde_json::json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:dap:error:reportTooEarly",
                "title": "Report could not be processed because it arrived too early.",
                "detail": "Report could not be processed because it arrived too early.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
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
                    report.task_id(),
                    Nonce::generate(&clock),
                    vec![],
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

        let task_id = TaskId::random();
        let task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let report = setup_report(&task, &datastore, &clock).await;

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
            serde_json::json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
                "taskid": format!("{}", task_id),
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

    async fn setup_upload_test() -> (
        Aggregator<MockClock>,
        Task,
        Report,
        Arc<Datastore<MockClock>>,
        DbHandle,
    ) {
        let task = new_dummy_task(
            TaskId::random(),
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Leader,
        );
        let clock = MockClock::default();
        let (datastore, db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);
        let report = setup_report(&task, &datastore, &clock).await;

        let aggregator = Aggregator::new(datastore.clone(), clock);

        (aggregator, task, report, datastore, db_handle)
    }

    #[tokio::test]
    async fn upload() {
        install_test_trace_subscriber();

        let (aggregator, _, report, datastore, _db_handle) = setup_upload_test().await;

        aggregator
            .handle_upload(&report.get_encoded())
            .await
            .unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                let task_id = report.task_id();
                let nonce = report.nonce();
                Box::pin(async move { tx.get_client_report(task_id, nonce).await })
            })
            .await
            .unwrap();
        assert_eq!(Some(&report), got_report.as_ref());

        // should reject duplicate reports.
        // TODO(#34): change this error type.
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::ReportTooLate(stale_nonce, task_id)) => {
            assert_eq!(task_id, report.task_id());
            assert_eq!(report.nonce(), stale_nonce);
        });
    }

    #[tokio::test]
    async fn upload_wrong_number_of_encrypted_shares() {
        install_test_trace_subscriber();

        let (aggregator, _, mut report, _, _db_handle) = setup_upload_test().await;

        report = Report::new(
            report.task_id(),
            report.nonce(),
            report.extensions().to_vec(),
            vec![report.encrypted_input_shares()[0].clone()],
        );

        assert_matches!(
            aggregator.handle_upload(&report.get_encoded()).await,
            Err(Error::UnrecognizedMessage(_, _))
        );
    }

    #[tokio::test]
    async fn upload_wrong_hpke_config_id() {
        install_test_trace_subscriber();

        let (aggregator, _, mut report, _, _db_handle) = setup_upload_test().await;

        report = Report::new(
            report.task_id(),
            report.nonce(),
            report.extensions().to_vec(),
            vec![
                HpkeCiphertext::new(
                    HpkeConfigId::from(101),
                    report.encrypted_input_shares()[0]
                        .encapsulated_context()
                        .to_vec(),
                    report.encrypted_input_shares()[0].payload().to_vec(),
                ),
                report.encrypted_input_shares()[1].clone(),
            ],
        );

        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::OutdatedHpkeConfig(config_id, task_id)) => {
            assert_eq!(task_id, report.task_id());
            assert_eq!(config_id, HpkeConfigId::from(101));
        });
    }

    fn reencrypt_report(report: Report, hpke_config: &HpkeConfig) -> Report {
        let message = b"this is a message";
        let associated_data = report.associated_data();

        let leader_ciphertext = hpke::seal(
            hpke_config,
            &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader),
            message,
            &associated_data,
        )
        .unwrap();

        let helper_ciphertext = hpke::seal(
            hpke_config,
            &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Helper),
            message,
            &associated_data,
        )
        .unwrap();

        Report::new(
            report.task_id(),
            report.nonce(),
            report.extensions().to_vec(),
            vec![leader_ciphertext, helper_ciphertext],
        )
    }

    #[tokio::test]
    async fn upload_report_in_the_future() {
        install_test_trace_subscriber();

        let (aggregator, task, report, datastore, _db_handle) = setup_upload_test().await;

        // Boundary condition
        let future_nonce = Nonce::new(
            aggregator
                .clock
                .now()
                .add(task.tolerable_clock_skew)
                .unwrap(),
            report.nonce().rand(),
        );
        let report = reencrypt_report(
            Report::new(
                report.task_id(),
                future_nonce,
                report.extensions().to_vec(),
                report.encrypted_input_shares().to_vec(),
            ),
            &task.hpke_keys.values().next().unwrap().0,
        );
        aggregator
            .handle_upload(&report.get_encoded())
            .await
            .unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                let task_id = report.task_id();
                let nonce = report.nonce();
                Box::pin(async move { tx.get_client_report(task_id, nonce).await })
            })
            .await
            .unwrap();
        assert_eq!(Some(&report), got_report.as_ref());

        // Just past the clock skew
        let future_nonce = Nonce::new(
            aggregator
                .clock
                .now()
                .add(task.tolerable_clock_skew)
                .unwrap()
                .add(Duration::from_seconds(1))
                .unwrap(),
            report.nonce().rand(),
        );
        let report = reencrypt_report(
            Report::new(
                report.task_id(),
                future_nonce,
                report.extensions().to_vec(),
                report.encrypted_input_shares().to_vec(),
            ),
            &task.hpke_keys.values().next().unwrap().0,
        );
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::ReportTooEarly(nonce, task_id)) => {
            assert_eq!(task_id, report.task_id());
            assert_eq!(report.nonce(), nonce);
        });
    }

    #[tokio::test]
    async fn upload_report_for_collected_batch() {
        install_test_trace_subscriber();

        let (aggregator, task, report, datastore, _db_handle) = setup_upload_test().await;
        let (task_id, nonce) = (task.id, report.nonce());

        // Insert a collect job for the batch interval including our report.
        let batch_interval = Interval::new(
            nonce
                .time()
                .to_batch_unit_interval_start(task.min_batch_duration)
                .unwrap(),
            task.min_batch_duration,
        )
        .unwrap();
        datastore
            .run_tx(|tx| {
                Box::pin(async move { tx.put_collect_job(task_id, batch_interval, &[]).await })
            })
            .await
            .unwrap();

        // Try to upload the report, verify that we get the expected error.
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await.unwrap_err(), Error::ReportTooLate(err_nonce, err_task_id) => {
            assert_eq!(nonce, err_nonce);
            assert_eq!(task_id, err_task_id);
        });
    }

    #[tokio::test]
    async fn aggregate_leader() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Leader,
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let request = AggregateInitializeReq {
            task_id,
            job_id: AggregationJobId::random(),
            agg_param: Vec::new(),
            report_shares: Vec::new(),
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (part, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
                "taskid": format!("{}", task_id),
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

        let task_id = TaskId::random();
        let task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let request = AggregateInitializeReq {
            task_id,
            job_id: AggregationJobId::random(),
            agg_param: Vec::new(),
            report_shares: Vec::new(),
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                generate_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
        assert_eq!(want_status, parts.status.as_u16());

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "detail": "The request's authorization is not valid.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
        assert_eq!(want_status, parts.status.as_u16());
    }

    #[tokio::test]
    async fn aggregate_init() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let verify_key = task
            .vdaf_verify_keys
            .get(0)
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let hpke_key = current_hpke_key(&task.hpke_keys);

        // report_share_0 is a "happy path" report.
        let nonce_0 = Nonce::generate(&clock);
        let input_share = run_vdaf(&vdaf, &verify_key, &(), nonce_0, &0)
            .input_shares
            .remove(1);
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_0,
            &hpke_key.0,
            &input_share,
        );

        // report_share_1 fails decryption.
        let mut report_share_1 = report_share_0.clone();
        report_share_1.nonce = Nonce::generate(&clock);
        let mut corrupted_payload = report_share_1.encrypted_input_share.payload().to_vec();
        corrupted_payload[0] ^= 0xFF;
        report_share_1.encrypted_input_share = HpkeCiphertext::new(
            report_share_1.encrypted_input_share.config_id(),
            report_share_1
                .encrypted_input_share
                .encapsulated_context()
                .to_vec(),
            corrupted_payload,
        );

        // report_share_2 fails decoding.
        let nonce_2 = Nonce::generate(&clock);
        let mut input_share_bytes = input_share.get_encoded();
        input_share_bytes.push(0); // can no longer be decoded.
        let report_share_2 = generate_helper_report_share_for_plaintext(
            nonce_2,
            &hpke_key.0,
            &input_share_bytes,
            &associated_data_for_report_share(task_id, nonce_2, &[]),
        );

        // report_share_3 has an unknown HPKE config ID.
        let nonce_3 = Nonce::generate(&clock);
        let wrong_hpke_config = loop {
            let hpke_config = generate_hpke_config_and_private_key().0;
            if task.hpke_keys.contains_key(&hpke_config.id()) {
                continue;
            }
            break hpke_config;
        };
        let report_share_3 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_3,
            &wrong_hpke_config,
            &input_share,
        );

        // report_share_4 has already been aggregated.
        let nonce_4 = Nonce::generate(&clock);
        let input_share = run_vdaf(&vdaf, &verify_key, &(), nonce_4, &0)
            .input_shares
            .remove(1);
        let report_share_4 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_4,
            &hpke_key.0,
            &input_share,
        );

        // report_share_5 falls into a batch unit that has already been collected.
        let past_clock = MockClock::new(Time::from_seconds_since_epoch(
            task.min_batch_duration.as_seconds() / 2,
        ));
        let nonce_5 = Nonce::generate(&past_clock);
        let input_share = run_vdaf(&vdaf, &verify_key, &(), nonce_5, &0)
            .input_shares
            .remove(1);
        let report_share_5 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_5,
            &hpke_key.0,
            &input_share,
        );

        datastore
            .run_tx(|tx| {
                let (task, report_share_4) = (task.clone(), report_share_4.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(task_id, &report_share_4).await?;
                    tx.put_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &AggregateShareJob {
                            task_id,
                            batch_interval: Interval::new(
                                Time::from_seconds_since_epoch(0),
                                task.min_batch_duration,
                            )
                            .unwrap(),
                            aggregation_param: (),
                            helper_aggregate_share: AggregateShare::from(Vec::from([
                                Field64::from(7),
                            ])),
                            report_count: 0,
                            checksum: NonceChecksum::default(),
                        },
                    )
                    .await
                })
            })
            .await
            .unwrap();

        let request = AggregateInitializeReq {
            task_id,
            job_id: AggregationJobId::random(),
            agg_param: Vec::new(),
            report_shares: vec![
                report_share_0.clone(),
                report_share_1.clone(),
                report_share_2.clone(),
                report_share_3.clone(),
                report_share_4.clone(),
                report_share_5.clone(),
            ],
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
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
        assert_eq!(aggregate_resp.prepare_steps.len(), 6);

        let prepare_step_0 = aggregate_resp.prepare_steps.get(0).unwrap();
        assert_eq!(prepare_step_0.nonce, report_share_0.nonce);
        assert_matches!(prepare_step_0.result, PrepareStepResult::Continued(..));

        let prepare_step_1 = aggregate_resp.prepare_steps.get(1).unwrap();
        assert_eq!(prepare_step_1.nonce, report_share_1.nonce);
        assert_matches!(
            prepare_step_1.result,
            PrepareStepResult::Failed(ReportShareError::HpkeDecryptError)
        );

        let prepare_step_2 = aggregate_resp.prepare_steps.get(2).unwrap();
        assert_eq!(prepare_step_2.nonce, report_share_2.nonce);
        assert_matches!(
            prepare_step_2.result,
            PrepareStepResult::Failed(ReportShareError::VdafPrepError)
        );

        let prepare_step_3 = aggregate_resp.prepare_steps.get(3).unwrap();
        assert_eq!(prepare_step_3.nonce, report_share_3.nonce);
        assert_matches!(
            prepare_step_3.result,
            PrepareStepResult::Failed(ReportShareError::HpkeUnknownConfigId)
        );

        let prepare_step_4 = aggregate_resp.prepare_steps.get(4).unwrap();
        assert_eq!(prepare_step_4.nonce, report_share_4.nonce);
        assert_eq!(
            prepare_step_4.result,
            PrepareStepResult::Failed(ReportShareError::ReportReplayed)
        );

        let prepare_step_5 = aggregate_resp.prepare_steps.get(5).unwrap();
        assert_eq!(prepare_step_5.nonce, report_share_5.nonce);
        assert_eq!(
            prepare_step_5.result,
            PrepareStepResult::Failed(ReportShareError::BatchCollected)
        );
    }

    #[tokio::test]
    async fn aggregate_init_prep_init_failed() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::FakeFailsPrepInit, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let hpke_key = current_hpke_key(&task.hpke_keys);

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let report_share = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            task_id,
            Nonce::generate(&clock),
            &hpke_key.0,
            &(),
        );
        let request = AggregateInitializeReq {
            task_id,
            job_id: AggregationJobId::random(),
            agg_param: Vec::new(),
            report_shares: vec![report_share.clone()],
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
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
        assert_eq!(aggregate_resp.prepare_steps.len(), 1);

        let prepare_step = aggregate_resp.prepare_steps.get(0).unwrap();
        assert_eq!(prepare_step.nonce, report_share.nonce);
        assert_matches!(
            prepare_step.result,
            PrepareStepResult::Failed(ReportShareError::VdafPrepError)
        );
    }

    #[tokio::test]
    async fn aggregate_init_prep_step_failed() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::FakeFailsPrepInit, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let hpke_key = current_hpke_key(&task.hpke_keys);

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let report_share = generate_helper_report_share::<dummy_vdaf::Vdaf>(
            task_id,
            Nonce::generate(&clock),
            &hpke_key.0,
            &(),
        );
        let request = AggregateInitializeReq {
            task_id,
            job_id: AggregationJobId::random(),
            agg_param: Vec::new(),
            report_shares: vec![report_share.clone()],
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
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
        assert_eq!(aggregate_resp.prepare_steps.len(), 1);

        let prepare_step = aggregate_resp.prepare_steps.get(0).unwrap();
        assert_eq!(prepare_step.nonce, report_share.nonce);
        assert_matches!(
            prepare_step.result,
            PrepareStepResult::Failed(ReportShareError::VdafPrepError)
        );
    }

    #[tokio::test]
    async fn aggregate_init_duplicated_nonce() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::FakeFailsPrepInit, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let report_share = ReportShare {
            nonce: Nonce::new(
                Time::from_seconds_since_epoch(54321),
                [1, 2, 3, 4, 5, 6, 7, 8],
            ),
            extensions: Vec::new(),
            encrypted_input_share: HpkeCiphertext::new(
                // bogus, but we never get far enough to notice
                HpkeConfigId::from(42),
                Vec::from("012345"),
                Vec::from("543210"),
            ),
        };

        let request = AggregateInitializeReq {
            task_id,
            job_id: AggregationJobId::random(),
            agg_param: Vec::new(),
            report_shares: vec![report_share.clone(), report_share],
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
        assert_eq!(want_status, parts.status.as_u16());
    }

    #[tokio::test]
    async fn aggregate_continue() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let aggregation_job_id = AggregationJobId::random();
        let task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
        );
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let verify_key = task
            .vdaf_verify_keys
            .get(0)
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let hpke_key = current_hpke_key(&task.hpke_keys);

        // report_share_0 is a "happy path" report.
        let nonce_0 = Nonce::generate(&clock);
        let transcript_0 = run_vdaf(vdaf.as_ref(), &verify_key, &(), nonce_0, &0);
        let prep_state_0 = assert_matches!(&transcript_0.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_0 = assert_matches!(&transcript_0.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_0 = transcript_0.prepare_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_0,
            &hpke_key.0,
            &transcript_0.input_shares[1],
        );

        // report_share_1 is omitted by the leader's request.
        let nonce_1 = Nonce::generate(&clock);
        let transcript_1 = run_vdaf(vdaf.as_ref(), &verify_key, &(), nonce_1, &0);
        let prep_state_1 = assert_matches!(&transcript_1.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let report_share_1 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_1,
            &hpke_key.0,
            &transcript_1.input_shares[1],
        );

        // report_share_2 falls into a batch unit that has already been collected.
        let past_clock = MockClock::new(Time::from_seconds_since_epoch(
            task.min_batch_duration.as_seconds() / 2,
        ));
        let nonce_2 = Nonce::generate(&past_clock);
        let transcript_2 = run_vdaf(vdaf.as_ref(), &verify_key, &(), nonce_2, &0);
        let prep_state_2 = assert_matches!(&transcript_2.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let prep_msg_2 = transcript_2.prepare_messages[0].clone();
        let report_share_2 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_2,
            &hpke_key.0,
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

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(task_id, &report_share_0).await?;
                    tx.put_report_share(task_id, &report_share_1).await?;
                    tx.put_report_share(task_id, &report_share_2).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    tx.put_report_aggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &ReportAggregation {
                            aggregation_job_id,
                            task_id,
                            nonce: nonce_0,
                            ord: 0,
                            state: ReportAggregationState::Waiting(prep_state_0, None),
                        },
                    )
                    .await?;
                    tx.put_report_aggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &ReportAggregation {
                            aggregation_job_id,
                            task_id,
                            nonce: nonce_1,
                            ord: 1,
                            state: ReportAggregationState::Waiting(prep_state_1, None),
                        },
                    )
                    .await?;
                    tx.put_report_aggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &ReportAggregation {
                            aggregation_job_id,
                            task_id,
                            nonce: nonce_2,
                            ord: 2,
                            state: ReportAggregationState::Waiting(prep_state_2, None),
                        },
                    )
                    .await?;

                    tx.put_aggregate_share_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        &AggregateShareJob {
                            task_id,
                            batch_interval: Interval::new(
                                Time::from_seconds_since_epoch(0),
                                task.min_batch_duration,
                            )
                            .unwrap(),
                            aggregation_param: (),
                            helper_aggregate_share: AggregateShare::from(Vec::from([
                                Field64::from(7),
                            ])),
                            report_count: 0,
                            checksum: NonceChecksum::default(),
                        },
                    )
                    .await
                })
            })
            .await
            .unwrap();

        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id,
            prepare_steps: Vec::from([
                PrepareStep {
                    nonce: nonce_0,
                    result: PrepareStepResult::Continued(prep_msg_0.get_encoded()),
                },
                PrepareStep {
                    nonce: nonce_2,
                    result: PrepareStepResult::Continued(prep_msg_2.get_encoded()),
                },
            ]),
        };

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
            AggregateContinueResp {
                prepare_steps: Vec::from([
                    PrepareStep {
                        nonce: nonce_0,
                        result: PrepareStepResult::Finished,
                    },
                    PrepareStep {
                        nonce: nonce_2,
                        result: PrepareStepResult::Failed(ReportShareError::BatchCollected),
                    }
                ])
            }
        );

        // Validate datastore.
        let (aggregation_job, report_aggregations) = datastore
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);

                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                            task_id,
                            aggregation_job_id,
                        )
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            Role::Helper,
                            task_id,
                            aggregation_job_id,
                        )
                        .await?;
                    Ok((aggregation_job, report_aggregations))
                })
            })
            .await
            .unwrap();

        assert_eq!(
            aggregation_job,
            Some(AggregationJob {
                aggregation_job_id,
                task_id,
                aggregation_param: (),
                state: AggregationJobState::Finished,
            })
        );
        assert_eq!(
            report_aggregations,
            vec![
                ReportAggregation {
                    aggregation_job_id,
                    task_id,
                    nonce: nonce_0,
                    ord: 0,
                    state: ReportAggregationState::Finished(out_share_0.clone()),
                },
                ReportAggregation {
                    aggregation_job_id,
                    task_id,
                    nonce: nonce_1,
                    ord: 1,
                    state: ReportAggregationState::Failed(ReportShareError::ReportDropped),
                },
                ReportAggregation {
                    aggregation_job_id,
                    task_id,
                    nonce: nonce_2,
                    ord: 2,
                    state: ReportAggregationState::Failed(ReportShareError::BatchCollected),
                }
            ]
        );
    }

    #[tokio::test]
    async fn aggregate_continue_accumulate_batch_unit_aggregation() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let aggregation_job_id_0 = AggregationJobId::random();
        let aggregation_job_id_1 = AggregationJobId::random();
        let task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
        );
        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;
        let datastore = Arc::new(datastore);
        let first_batch_unit_interval_clock = MockClock::default();
        let second_batch_unit_interval_clock = MockClock::new(
            first_batch_unit_interval_clock
                .now()
                .add(task.min_batch_duration)
                .unwrap(),
        );

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let verify_key = task
            .vdaf_verify_keys
            .get(0)
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let hpke_key = current_hpke_key(&task.hpke_keys);

        // report_share_0 is a "happy path" report.
        let nonce_0 = Nonce::generate(&first_batch_unit_interval_clock);
        let transcript_0 = run_vdaf(&vdaf, &verify_key, &(), nonce_0, &0);
        let prep_state_0 = assert_matches!(&transcript_0.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_0 = assert_matches!(&transcript_0.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_0 = transcript_0.prepare_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_0,
            &hpke_key.0,
            &transcript_0.input_shares[1],
        );

        // report_share_1 is another "happy path" report to exercise in-memory accumulation of
        // output shares
        let nonce_1 = Nonce::generate(&first_batch_unit_interval_clock);
        let transcript_1 = run_vdaf(&vdaf, &verify_key, &(), nonce_1, &0);
        let prep_state_1 = assert_matches!(&transcript_1.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_1 = assert_matches!(&transcript_1.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_1 = transcript_1.prepare_messages[0].clone();
        let report_share_1 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_1,
            &hpke_key.0,
            &transcript_1.input_shares[1],
        );

        // report share 2 aggregates successfully, but into a distinct batch unit aggregation.
        let nonce_2 = Nonce::generate(&second_batch_unit_interval_clock);
        let transcript_2 = run_vdaf(&vdaf, &verify_key, &(), nonce_2, &0);
        let prep_state_2 = assert_matches!(&transcript_2.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_2 = assert_matches!(&transcript_2.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_2 = transcript_2.prepare_messages[0].clone();
        let report_share_2 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_2,
            &hpke_key.0,
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

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(task_id, &report_share_0).await?;
                    tx.put_report_share(task_id, &report_share_1).await?;
                    tx.put_report_share(task_id, &report_share_2).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        nonce: nonce_0,
                        ord: 0,
                        state: ReportAggregationState::Waiting(prep_state_0, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        nonce: nonce_1,
                        ord: 1,
                        state: ReportAggregationState::Waiting(prep_state_1, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        nonce: nonce_2,
                        ord: 2,
                        state: ReportAggregationState::Waiting(prep_state_2, None),
                    })
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id_0,
            prepare_steps: vec![
                PrepareStep {
                    nonce: nonce_0,
                    result: PrepareStepResult::Continued(prep_msg_0.get_encoded()),
                },
                PrepareStep {
                    nonce: nonce_1,
                    result: PrepareStepResult::Continued(prep_msg_1.get_encoded()),
                },
                PrepareStep {
                    nonce: nonce_2,
                    result: PrepareStepResult::Continued(prep_msg_2.get_encoded()),
                },
            ],
        };

        // Create aggregator filter, send request, and parse response.
        let filter =
            aggregator_filter(datastore.clone(), first_batch_unit_interval_clock.clone()).unwrap();

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

        let batch_unit_aggregations = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_batch_unit_aggregations_for_task_in_interval::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task_id,
                        Interval::new(
                            nonce_0
                                .time()
                                .to_batch_unit_interval_start(task.min_batch_duration)
                                .unwrap(),
                            // Make interval big enough to capture both batch unit aggregations
                            Duration::from_seconds(task.min_batch_duration.as_seconds() * 2),
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
        let mut checksum = NonceChecksum::from_nonce(nonce_0);
        checksum.update(nonce_1);

        assert_eq!(
            batch_unit_aggregations,
            vec![
                BatchUnitAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count> {
                    task_id,
                    unit_interval_start: nonce_0
                        .time()
                        .to_batch_unit_interval_start(task.min_batch_duration)
                        .unwrap(),
                    aggregation_param: (),
                    aggregate_share,
                    report_count: 2,
                    checksum,
                },
                BatchUnitAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count> {
                    task_id,
                    unit_interval_start: nonce_2
                        .time()
                        .to_batch_unit_interval_start(task.min_batch_duration)
                        .unwrap(),
                    aggregation_param: (),
                    aggregate_share: AggregateShare::from(out_share_2.clone()),
                    report_count: 1,
                    checksum: NonceChecksum::from_nonce(nonce_2),
                }
            ]
        );

        // Aggregate some more reports, which should get accumulated into the
        // batch_unit_aggregations rows created earlier.
        // report_share_3 gets aggreated into the first batch unit interval.
        let nonce_3 = Nonce::generate(&first_batch_unit_interval_clock);
        let transcript_3 = run_vdaf(&vdaf, &verify_key, &(), nonce_3, &0);
        let prep_state_3 = assert_matches!(&transcript_3.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_3 = assert_matches!(&transcript_3.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_3 = transcript_3.prepare_messages[0].clone();
        let report_share_3 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_3,
            &hpke_key.0,
            &transcript_3.input_shares[1],
        );

        // report_share_4 gets aggregated into the second batch unit interval
        let nonce_4 = Nonce::generate(&second_batch_unit_interval_clock);
        let transcript_4 = run_vdaf(&vdaf, &verify_key, &(), nonce_4, &0);
        let prep_state_4 = assert_matches!(&transcript_4.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_4 = assert_matches!(&transcript_4.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_4 = transcript_4.prepare_messages[0].clone();
        let report_share_4 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_4,
            &hpke_key.0,
            &transcript_4.input_shares[1],
        );

        // report share 5 also gets aggregated into the second batch unit interval
        let nonce_5 = Nonce::generate(&second_batch_unit_interval_clock);
        let transcript_5 = run_vdaf(&vdaf, &verify_key, &(), nonce_5, &0);
        let prep_state_5 = assert_matches!(&transcript_5.prepare_transitions[1][0], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Continue(prep_state, _) => prep_state.clone());
        let out_share_5 = assert_matches!(&transcript_5.prepare_transitions[1][1], PrepareTransition::<Prio3Aes128Count, PRIO3_AES128_VERIFY_KEY_LENGTH>::Finish(out_share) => out_share.clone());
        let prep_msg_5 = transcript_5.prepare_messages[0].clone();
        let report_share_5 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_5,
            &hpke_key.0,
            &transcript_5.input_shares[1],
        );

        datastore
            .run_tx(|tx| {
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

                Box::pin(async move {
                    tx.put_report_share(task_id, &report_share_3).await?;
                    tx.put_report_share(task_id, &report_share_4).await?;
                    tx.put_report_share(task_id, &report_share_5).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        nonce: nonce_3,
                        ord: 3,
                        state: ReportAggregationState::Waiting(prep_state_3, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        nonce: nonce_4,
                        ord: 4,
                        state: ReportAggregationState::Waiting(prep_state_4, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        nonce: nonce_5,
                        ord: 5,
                        state: ReportAggregationState::Waiting(prep_state_5, None),
                    })
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id_1,
            prepare_steps: vec![
                PrepareStep {
                    nonce: nonce_3,
                    result: PrepareStepResult::Continued(prep_msg_3.get_encoded()),
                },
                PrepareStep {
                    nonce: nonce_4,
                    result: PrepareStepResult::Continued(prep_msg_4.get_encoded()),
                },
                PrepareStep {
                    nonce: nonce_5,
                    result: PrepareStepResult::Continued(prep_msg_5.get_encoded()),
                },
            ],
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(datastore.clone(), first_batch_unit_interval_clock).unwrap();

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

        let batch_unit_aggregations = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_batch_unit_aggregations_for_task_in_interval::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        task_id,
                        Interval::new(
                            nonce_0
                                .time()
                                .to_batch_unit_interval_start(task.min_batch_duration)
                                .unwrap(),
                            // Make interval big enough to capture both batch unit aggregations
                            Duration::from_seconds(task.min_batch_duration.as_seconds() * 2),
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
        let mut first_checksum = NonceChecksum::from_nonce(nonce_0);
        first_checksum.update(nonce_1);
        first_checksum.update(nonce_3);

        let second_aggregate_share = vdaf
            .aggregate(&(), [out_share_2, out_share_4, out_share_5])
            .unwrap();
        let mut second_checksum = NonceChecksum::from_nonce(nonce_2);
        second_checksum.update(nonce_4);
        second_checksum.update(nonce_5);

        assert_eq!(
            batch_unit_aggregations,
            vec![
                BatchUnitAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count> {
                    task_id,
                    unit_interval_start: nonce_0
                        .time()
                        .to_batch_unit_interval_start(task.min_batch_duration)
                        .unwrap(),
                    aggregation_param: (),
                    aggregate_share: first_aggregate_share,
                    report_count: 3,
                    checksum: first_checksum,
                },
                BatchUnitAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count> {
                    task_id,
                    unit_interval_start: nonce_2
                        .time()
                        .to_batch_unit_interval_start(task.min_batch_duration)
                        .unwrap(),
                    aggregation_param: (),
                    aggregate_share: second_aggregate_share,
                    report_count: 3,
                    checksum: second_checksum,
                }
            ]
        );
    }

    #[tokio::test]
    async fn aggregate_continue_leader_sends_non_continue_transition() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let aggregation_job_id = AggregationJobId::random();
        let nonce = Nonce::new(
            Time::from_seconds_since_epoch(54321),
            [1, 2, 3, 4, 5, 6, 7, 8],
        );
        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task_id,
                        &ReportShare {
                            nonce,
                            extensions: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                    )
                    .await?;
                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        },
                    )
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce,
                        ord: 0,
                        state: ReportAggregationState::Waiting((), None),
                    })
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id,
            prepare_steps: vec![PrepareStep {
                nonce,
                result: PrepareStepResult::Finished,
            }],
        };

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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_continue_prep_step_fails() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let aggregation_job_id = AggregationJobId::random();
        let nonce = Nonce::new(
            Time::from_seconds_since_epoch(54321),
            [1, 2, 3, 4, 5, 6, 7, 8],
        );
        let task = new_dummy_task(task_id, VdafInstance::FakeFailsPrepStep, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task_id,
                        &ReportShare {
                            nonce,
                            extensions: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                    )
                    .await?;
                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        },
                    )
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce,
                        ord: 0,
                        state: ReportAggregationState::Waiting((), None),
                    })
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id,
            prepare_steps: vec![PrepareStep {
                nonce,
                result: PrepareStepResult::Continued(Vec::new()),
            }],
        };

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
            AggregateContinueResp {
                prepare_steps: vec![PrepareStep {
                    nonce,
                    result: PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                }],
            }
        );

        // Check datastore state.
        let (aggregation_job, report_aggregation) = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(
                            task_id,
                            aggregation_job_id,
                        )
                        .await?;
                    let report_aggregation = tx
                        .get_report_aggregation(
                            &dummy_vdaf::Vdaf::default(),
                            Role::Helper,
                            task_id,
                            aggregation_job_id,
                            nonce,
                        )
                        .await?;
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(
            aggregation_job,
            Some(AggregationJob {
                aggregation_job_id,
                task_id,
                aggregation_param: (),
                state: AggregationJobState::Finished,
            })
        );
        assert_eq!(
            report_aggregation,
            Some(ReportAggregation {
                aggregation_job_id,
                task_id,
                nonce,
                ord: 0,
                state: ReportAggregationState::Failed(ReportShareError::VdafPrepError),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_continue_unexpected_transition() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let aggregation_job_id = AggregationJobId::random();
        let nonce = Nonce::new(
            Time::from_seconds_since_epoch(54321),
            [1, 2, 3, 4, 5, 6, 7, 8],
        );
        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task_id,
                        &ReportShare {
                            nonce,
                            extensions: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                    )
                    .await?;
                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        },
                    )
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce,
                        ord: 0,
                        state: ReportAggregationState::Waiting((), None),
                    })
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id,
            prepare_steps: vec![PrepareStep {
                nonce: Nonce::new(
                    Time::from_seconds_since_epoch(54321),
                    [8, 7, 6, 5, 4, 3, 2, 1], // not the same as above
                ),
                result: PrepareStepResult::Continued(Vec::new()),
            }],
        };

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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_continue_out_of_order_transition() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let aggregation_job_id = AggregationJobId::random();
        let nonce_0 = Nonce::new(
            Time::from_seconds_since_epoch(54321),
            [1, 2, 3, 4, 5, 6, 7, 8],
        );
        let nonce_1 = Nonce::new(
            Time::from_seconds_since_epoch(54321),
            [8, 7, 6, 5, 4, 3, 2, 1],
        );

        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(
                        task_id,
                        &ReportShare {
                            nonce: nonce_0,
                            extensions: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                    )
                    .await?;
                    tx.put_report_share(
                        task_id,
                        &ReportShare {
                            nonce: nonce_1,
                            extensions: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                    )
                    .await?;

                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        },
                    )
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce: nonce_0,
                        ord: 0,
                        state: ReportAggregationState::Waiting((), None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce: nonce_1,
                        ord: 1,
                        state: ReportAggregationState::Waiting((), None),
                    })
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id,
            prepare_steps: vec![
                // nonces are in opposite order to what was stored in the datastore.
                PrepareStep {
                    nonce: nonce_1,
                    result: PrepareStepResult::Continued(Vec::new()),
                },
                PrepareStep {
                    nonce: nonce_0,
                    result: PrepareStepResult::Continued(Vec::new()),
                },
            ],
        };

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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_continue_for_non_waiting_aggregation() {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let aggregation_job_id = AggregationJobId::random();
        let nonce = Nonce::new(
            Time::from_seconds_since_epoch(54321),
            [1, 2, 3, 4, 5, 6, 7, 8],
        );

        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        // Setup datastore.
        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_report_share(
                        task_id,
                        &ReportShare {
                            nonce,
                            extensions: Vec::new(),
                            encrypted_input_share: HpkeCiphertext::new(
                                HpkeConfigId::from(42),
                                Vec::from("012345"),
                                Vec::from("543210"),
                            ),
                        },
                    )
                    .await?;
                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: (),
                            state: AggregationJobState::InProgress,
                        },
                    )
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce,
                        ord: 0,
                        state: ReportAggregationState::Invalid,
                    })
                    .await
                })
            })
            .await
            .unwrap();

        // Make request.
        let request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id,
            prepare_steps: vec![PrepareStep {
                nonce: Nonce::new(
                    Time::from_seconds_since_epoch(54321),
                    [1, 2, 3, 4, 5, 6, 7, 8],
                ),
                result: PrepareStepResult::Continued(Vec::new()),
            }],
        };

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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn collect_request_to_helper() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();

        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = CollectReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                task.min_batch_duration,
            )
            .unwrap(),
            agg_param: vec![],
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn collect_request_invalid_batch_interval() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();

        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Leader);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = CollectReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                // Collect request will be rejected because batch interval is too small
                Duration::from_seconds(task.min_batch_duration.as_seconds() - 1),
            )
            .unwrap(),
            agg_param: vec![],
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch interval in the collect or aggregate share request is not valid for the task.",
                "detail": "The batch interval in the collect or aggregate share request is not valid for the task.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn collect_request() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let mut task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Leader,
        );
        task.aggregator_endpoints = vec![
            "https://leader.endpoint".parse().unwrap(),
            "https://helper.endpoint".parse().unwrap(),
        ];
        task.max_batch_lifetime = 1;
        let batch_interval =
            Interval::new(Time::from_seconds_since_epoch(0), task.min_batch_duration).unwrap();
        let (collector_hpke_config, collector_hpke_recipient) =
            generate_hpke_config_and_private_key();
        task.collector_hpke_config = collector_hpke_config;

        let leader_aggregate_share = AggregateShare::from(vec![Field64::from(64)]);
        let helper_aggregate_share = AggregateShare::from(vec![Field64::from(32)]);

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::clone(&datastore), clock).unwrap();

        let request = CollectReq {
            task_id,
            batch_interval,
            agg_param: vec![],
        };

        let response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
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
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(collect_job_response.status(), StatusCode::ACCEPTED);

        // Update the collect job with the aggregate shares. Collect job should now be complete.
        datastore
            .run_tx(|tx| {
                let collector_hpke_config = task.collector_hpke_config.clone();
                let helper_aggregate_share_bytes: Vec<u8> = (&helper_aggregate_share).into();
                let leader_aggregate_share = leader_aggregate_share.clone();
                Box::pin(async move {
                    let encrypted_helper_aggregate_share = hpke::seal(
                        &collector_hpke_config,
                        &HpkeApplicationInfo::new(
                            Label::AggregateShare,
                            Role::Helper,
                            Role::Collector,
                        ),
                        &helper_aggregate_share_bytes,
                        &associated_data_for_aggregate_share(task.id, batch_interval),
                    )
                    .unwrap();

                    tx.update_collect_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                        collect_job_id,
                        &leader_aggregate_share,
                        &encrypted_helper_aggregate_share,
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
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(
            parts.headers.get(CONTENT_TYPE).unwrap(),
            CollectResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(body).await.unwrap();
        let collect_resp = CollectResp::get_decoded(body_bytes.as_ref()).unwrap();
        assert_eq!(collect_resp.encrypted_agg_shares.len(), 2);

        let decrypted_leader_aggregate_share = hpke::open(
            &task.collector_hpke_config,
            &collector_hpke_recipient,
            &HpkeApplicationInfo::new(Label::AggregateShare, Role::Leader, Role::Collector),
            &collect_resp.encrypted_agg_shares[0],
            &associated_data_for_aggregate_share(task_id, batch_interval),
        )
        .unwrap();
        assert_eq!(
            leader_aggregate_share,
            AggregateShare::try_from(decrypted_leader_aggregate_share.as_ref()).unwrap()
        );

        let decrypted_helper_aggregate_share = hpke::open(
            &task.collector_hpke_config,
            &collector_hpke_recipient,
            &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
            &collect_resp.encrypted_agg_shares[1],
            &associated_data_for_aggregate_share(task_id, batch_interval),
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
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn collect_request_batch_lifetime_violation() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Fake, Role::Leader);
        task.max_batch_lifetime = 1;

        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        task_id: task.id,
                        unit_interval_start: Time::from_seconds_since_epoch(0),
                        aggregation_param: (),
                        aggregate_share: dummy_vdaf::AggregateShare(),
                        report_count: 10,
                        checksum: NonceChecksum::get_decoded(&[2; 32]).unwrap(),
                    })
                    .await
                })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap();

        // Sending this request will consume the lifetime for [0, min_batch_duration).
        let request = CollectReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                task.min_batch_duration,
            )
            .unwrap(),
            agg_param: vec![],
        };

        let response = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let invalid_request = CollectReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(task.min_batch_duration.as_seconds() * 2),
            )
            .unwrap(),
            agg_param: vec![],
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/collect")
            .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchLifetimeExceeded",
                "title": "The batch lifetime has been exceeded for one or more reports included in the batch interval.",
                "detail": "The batch lifetime has been exceeded for one or more reports included in the batch interval.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_share_request_to_leader() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Leader);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                task.min_batch_duration,
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 0,
            checksum: NonceChecksum::default(),
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "detail": "An endpoint received a message with an unknown task ID.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_share_request_invalid_batch_interval() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Fake, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                // Collect request will be rejected because batch interval is too small
                Duration::from_seconds(task.min_batch_duration.as_seconds() - 1),
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 0,
            checksum: NonceChecksum::default(),
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch interval in the collect or aggregate share request is not valid for the task.",
                "detail": "The batch interval in the collect or aggregate share request is not valid for the task.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    #[tokio::test]
    async fn aggregate_share_request() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let (collector_hpke_config, collector_hpke_recipient) =
            generate_hpke_config_and_private_key();

        let mut task = new_dummy_task(
            task_id,
            janus_core::task::VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
        );
        task.max_batch_lifetime = 3;
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        task.collector_hpke_config = collector_hpke_config.clone();

        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        // There are no batch unit_aggregations in the datastore yet
        let request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                task.min_batch_duration,
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 0,
            checksum: NonceChecksum::default(),
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:insufficientBatchSize",
                "title": "There are not enough reports in the batch interval.",
                "detail": "There are not enough reports in the batch interval.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );

        // Put some batch unit aggregations in the DB
        datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(500),
                        aggregation_param: (),
                        aggregate_share: AggregateShare::from(vec![Field64::from(64)]),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[3; 32]).unwrap(),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(1500),
                        aggregation_param: (),
                        aggregate_share: AggregateShare::from(vec![Field64::from(128)]),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[2; 32]).unwrap(),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(2000),
                        aggregation_param: (),
                        aggregate_share: AggregateShare::from(vec![Field64::from(256)]),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[4; 32]).unwrap(),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    > {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(2500),
                        aggregation_param: (),
                        aggregate_share: AggregateShare::from(vec![Field64::from(512)]),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[8; 32]).unwrap(),
                    })
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        // Specified interval includes too few reports
        let request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(1000),
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 5,
            checksum: NonceChecksum::default(),
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:insufficientBatchSize",
                "title": "There are not enough reports in the batch interval.",
                "detail": "There are not enough reports in the batch interval.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );

        // Make requests that will fail because the checksum or report counts don't match. Note that
        // while these requests fail, they *do* consume batch lifetime.
        let misaligned_requests = [
            // Interval is big enough, but checksum doesn't match
            AggregateShareReq {
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(2500),
                )
                .unwrap(),
                aggregation_param: vec![],
                report_count: 10,
                checksum: NonceChecksum::get_decoded(&[3; 32]).unwrap(),
            }, // Interval is big enough, but report count doesn't match
            AggregateShareReq {
                task_id,
                batch_interval: Interval::new(
                    Time::from_seconds_since_epoch(0),
                    Duration::from_seconds(2500),
                )
                .unwrap(),
                aggregation_param: vec![],
                report_count: 20,
                checksum: NonceChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
            },
        ];

        for misaligned_request in misaligned_requests {
            let (parts, body) = warp::test::request()
                .method("POST")
                .path("/aggregate_share")
                .header(
                    "DAP-Auth-Token",
                    task.primary_aggregator_auth_token().as_bytes(),
                )
                .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
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
                serde_json::json!({
                    "status": StatusCode::BAD_REQUEST.as_u16(),
                    "type": "urn:ietf:params:ppm:dap:error:batchMismatch",
                    "title": "Leader and helper disagree on reports aggregated in a batch.",
                    "detail": "Leader and helper disagree on reports aggregated in a batch.",
                    "instance": "..",
                    "taskid": format!("{}", task_id),
                })
            );
        }

        // Intervals are big enough, do not overlap, checksum and report count are good
        let valid_requests = [
            (
                "first and second batch units",
                AggregateShareReq {
                    task_id,
                    batch_interval: Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                    aggregation_param: vec![],
                    report_count: 10,
                    checksum: NonceChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
                },
                Field64::from(64 + 128),
            ),
            (
                "third and fourth batch units",
                AggregateShareReq {
                    task_id,
                    batch_interval: Interval::new(
                        Time::from_seconds_since_epoch(2000),
                        Duration::from_seconds(2000),
                    )
                    .unwrap(),
                    aggregation_param: vec![],
                    report_count: 10,
                    checksum: NonceChecksum::get_decoded(&[8 ^ 4; 32]).unwrap(),
                },
                // Should get sum over the third and fourth batch units
                Field64::from(256 + 512),
            ),
            (
                "first, second, third, fourth batch units",
                AggregateShareReq {
                    task_id,
                    batch_interval: Interval::new(
                        Time::from_seconds_since_epoch(0),
                        Duration::from_seconds(4000),
                    )
                    .unwrap(),
                    aggregation_param: vec![],
                    report_count: 20,
                    checksum: NonceChecksum::get_decoded(&[8 ^ 4 ^ 3 ^ 2; 32]).unwrap(),
                },
                // Should get sum over the third and fourth batch units
                Field64::from(64 + 128 + 256 + 512),
            ),
        ];

        for (label, request, expected_result) in valid_requests {
            // Request the aggregate share multiple times. If the request parameters don't change,
            // then there is no batch lifetime violation and all requests should succeed, being
            // served from cache after the first time.
            for iteration in 0..3 {
                let (parts, body) = warp::test::request()
                    .method("POST")
                    .path("/aggregate_share")
                    .header(
                        "DAP-Auth-Token",
                        task.primary_aggregator_auth_token().as_bytes(),
                    )
                    .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
                    .body(request.get_encoded())
                    .filter(&filter)
                    .await
                    .unwrap()
                    .into_response()
                    .into_parts();

                assert_eq!(
                    parts.status,
                    StatusCode::OK,
                    "test case: {} iteration: {}",
                    label,
                    iteration
                );
                assert_eq!(
                    parts.headers.get(CONTENT_TYPE).unwrap(),
                    AggregateShareResp::MEDIA_TYPE,
                    "test case: {} iteration: {}",
                    label,
                    iteration
                );
                let body_bytes = body::to_bytes(body).await.unwrap();
                let aggregate_share_resp = AggregateShareResp::get_decoded(&body_bytes).unwrap();

                let aggregate_share = hpke::open(
                    &collector_hpke_config,
                    &collector_hpke_recipient,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
                    &aggregate_share_resp.encrypted_aggregate_share,
                    &request.associated_data_for_aggregate_share(),
                )
                .unwrap();

                // Should get the sum over the first and second aggregate shares
                let decoded_aggregate_share =
                    <AggregateShare<Field64>>::try_from(aggregate_share.as_ref()).unwrap();
                assert_eq!(
                    decoded_aggregate_share,
                    AggregateShare::from(vec![expected_result]),
                    "test case: {} iteration: {}",
                    label,
                    iteration
                );
            }
        }

        // Previous sequence of aggregate share requests should have consumed the batch lifetime for
        // all the batch units. Further requests for any batch units will cause batch lifetime
        // violations.
        let batch_lifetime_violation_request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(3000),
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 10,
            checksum: NonceChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
        };
        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
            .body(batch_lifetime_violation_request.get_encoded())
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
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchLifetimeExceeded",
                "title": "The batch lifetime has been exceeded for one or more reports included in the batch interval.",
                "detail": "The batch lifetime has been exceeded for one or more reports included in the batch interval.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );
    }

    fn current_hpke_key(
        hpke_keys: &HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
    ) -> &(HpkeConfig, HpkePrivateKey) {
        hpke_keys
            .values()
            .max_by_key(|(cfg, _)| u8::from(cfg.id()))
            .unwrap()
    }

    fn generate_helper_report_share<V: vdaf::Client>(
        task_id: TaskId,
        nonce: Nonce,
        cfg: &HpkeConfig,
        input_share: &V::InputShare,
    ) -> ReportShare
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let associated_data = associated_data_for_report_share(task_id, nonce, &[]);
        generate_helper_report_share_for_plaintext(
            nonce,
            cfg,
            &input_share.get_encoded(),
            &associated_data,
        )
    }

    fn generate_helper_report_share_for_plaintext(
        nonce: Nonce,
        cfg: &HpkeConfig,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> ReportShare {
        ReportShare {
            nonce,
            extensions: Vec::new(),
            encrypted_input_share: hpke::seal(
                cfg,
                &HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Helper),
                plaintext,
                associated_data,
            )
            .unwrap(),
        }
    }
}
