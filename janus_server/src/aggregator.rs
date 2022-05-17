//! Common functionality for PPM aggregators

mod accumulator;

use crate::{
    aggregator::accumulator::Accumulator,
    datastore::{
        self,
        models::{
            AggregateShareJob, AggregationJob, AggregationJobState, BatchUnitAggregation,
            ReportAggregation, ReportAggregationState,
        },
        Datastore, Transaction,
    },
    message::{
        AggregateReq,
        AggregateReqBody::{AggregateContinueReq, AggregateInitReq},
        AggregateResp, AggregateShareReq, AggregateShareResp, AggregationJobId,
        AuthenticatedDecodeError, AuthenticatedEncoder, AuthenticatedRequestDecoder, CollectReq,
        CollectResp, Interval, ReportShare, Transition, TransitionError,
        TransitionTypeSpecificData,
    },
    task::{Task, VdafInstance},
};
use bytes::Bytes;
use futures::try_join;
use http::{
    header::{CACHE_CONTROL, LOCATION},
    StatusCode,
};
use janus::{
    hpke::{self, HpkeApplicationInfo, Label},
    message::{HpkeConfig, HpkeConfigId, Nonce, NonceChecksum, Report, Role, TaskId},
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
        prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        Aggregatable, PrepareTransition, Vdaf,
    },
};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
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
    filters::BoxedFilter,
    reply::{self, Response},
    trace, Filter, Rejection, Reply,
};

#[cfg(test)]
use self::test_util::fake;
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
    Message(#[from] janus::message::Error),
    /// Corresponds to `staleReport`, §3.1
    #[error("stale report: {0} {1:?}")]
    StaleReport(Nonce, TaskId),
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
    /// A report was rejected becuase the timestamp is too far in the future,
    /// §4.3.4.
    // TODO(timg): define an error type in §3.1 and clarify language on
    // rejecting future reports
    #[error("report from the future: {0} {1:?}")]
    ReportFromTheFuture(Nonce, TaskId),
    /// Corresponds to `invalidHmac`, §3.1
    #[error("invalid HMAC tag: {0:?}")]
    InvalidHmac(TaskId),
    /// An error from the datastore.
    #[error("datastore error: {0}")]
    Datastore(datastore::Error),
    /// An error from the underlying VDAF library.
    #[error("VDAF error: {0}")]
    Vdaf(#[from] vdaf::VdafError),
    /// A collect or aggregate share request was rejected because the interval is valid, per §4.6
    #[error("Invalid batch interval: {0} {1:?}")]
    InvalidBatchInterval(Interval, TaskId),
    /// There are not enough reports in the batch interval to meet the task's minimum batch size.
    #[error("Insufficient number of reports ({0}) for task {1:?}")]
    InsufficientBatchSize(u64, TaskId),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    /// The checksum or report count in one aggregator's aggregate share does not match the other
    /// aggregator's aggregate share, suggesting different sets of reports were aggregated.
    #[error(
        "Batch misalignment: own checksum: {own_checksum:?} own report count: {own_report_count} \
peer checksum: {peer_checksum:?} peer report count: {peer_report_count}"
    )]
    BatchMisalignment {
        task_id: TaskId,
        own_checksum: NonceChecksum,
        own_report_count: u64,
        peer_checksum: NonceChecksum,
        peer_report_count: u64,
    },
    /// Too many queries against a single batch.
    #[error("Maxiumum batch lifetime for task {0:?} exceeded")]
    BatchLifetimeExceeded(TaskId),
    /// HPKE failure.
    #[error("HPKE error: {0}")]
    Hpke(#[from] janus::hpke::Error),
    /// Error handling task parameters
    #[error("Invalid task parameters: {0}")]
    TaskParameters(#[from] crate::task::Error),
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

    async fn handle_aggregate(&self, req_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let (task_aggregator, req) = self
            .authenticated_decode(req_bytes, Some(Role::Helper))
            .await?;
        let resp = task_aggregator
            .handle_aggregate(&self.datastore, req)
            .await?;
        let key = task_aggregator
            .task
            .primary_aggregator_auth_key()
            .ok_or_else(|| {
                Error::Internal("task has no aggregator auth keys configured".to_string())
            })?;
        Ok(AuthenticatedEncoder::new(resp).encode(key.as_ref()))
    }

    async fn authenticated_decode<T: Decode>(
        &self,
        buf: &[u8],
        required_role: Option<Role>,
    ) -> Result<(Arc<TaskAggregator>, T), Error> {
        let decoder = AuthenticatedRequestDecoder::new(buf).map_err(Error::from)?;
        let task_id = decoder.task_id();
        let task_aggregator = self.task_aggregator_for(task_id).await?;
        if required_role.is_some() && required_role.unwrap() != task_aggregator.task.role {
            return Err(Error::UnrecognizedTask(task_id));
        }
        match decoder.decode(
            task_aggregator
                .task
                .agg_auth_keys
                .iter()
                .map(|k| k.as_ref())
                .rev(),
        ) {
            Ok(decoded_body) => Ok((task_aggregator, decoded_body)),
            Err(AuthenticatedDecodeError::InvalidHmac) => Err(Error::InvalidHmac(task_id)),
            Err(AuthenticatedDecodeError::Codec(err)) => Err(Error::MessageDecode(err)),
        }
    }

    /// Handle a collect request. Only supported by the leader. `req_bytes` is an encoded
    /// [`CollectReq`]. Returns the URL at which a collector may poll for status of the collect job
    /// corresponding to the `CollectReq`.
    async fn handle_collect(&self, req_bytes: &[u8]) -> Result<Url, Error> {
        let collect_req = CollectReq::get_decoded(req_bytes)?;

        let task_aggregator = self.task_aggregator_for(collect_req.task_id).await?;

        // Only the leader supports /collect.
        if task_aggregator.task.role != Role::Leader {
            // TODO (timg): We should make sure that a helper returns HTTP 404 or 403 when this
            // happens
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
    async fn handle_aggregate_share(&self, req_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let (task_aggregator, req): (_, AggregateShareReq) = self
            .authenticated_decode(req_bytes, Some(Role::Helper))
            .await?;

        // Only the helper supports /aggregate_share.
        if task_aggregator.task.role != Role::Helper {
            // TODO (timg): We should make sure that a leader returns HTTP 404 or 403 when this
            // happens
            return Err(Error::UnrecognizedTask(req.task_id));
        }

        let resp = task_aggregator
            .handle_aggregate_share(&self.datastore, &req)
            .await?;
        let key = task_aggregator
            .task
            .primary_aggregator_auth_key()
            .ok_or_else(|| {
                Error::Internal("task has no aggregator auth keys configured".to_string())
            })?;
        Ok(AuthenticatedEncoder::new(resp).encode(key.as_ref()))
    }

    async fn task_aggregator_for(&self, task_id: TaskId) -> Result<Arc<TaskAggregator>, Error> {
        // TODO(brandon): don't cache forever (decide on & implement some cache eviction policy).
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
// TODO: refactor Aggregator to perform indepedent batched operations (e.g. report handling in
//       Aggregate requests) using a parallelized library like Rayon.
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
        let current_vdaf_verify_parameter = task.vdaf_verify_parameters.last().unwrap();
        let vdaf_ops = match &task.vdaf {
            VdafInstance::Prio3Aes128Count => {
                let vdaf = Prio3Aes128Count::new(2)?;
                let verify_param = <Prio3Aes128Count as Vdaf>::VerifyParam::get_decoded_with_param(
                    &vdaf,
                    current_vdaf_verify_parameter,
                )?;
                VdafOps::Prio3Aes128Count(vdaf, verify_param)
            }

            VdafInstance::Prio3Aes128Sum { bits } => {
                let vdaf = Prio3Aes128Sum::new(2, *bits)?;
                let verify_param = <Prio3Aes128Sum as Vdaf>::VerifyParam::get_decoded_with_param(
                    &vdaf,
                    current_vdaf_verify_parameter,
                )?;
                VdafOps::Prio3Aes128Sum(vdaf, verify_param)
            }

            VdafInstance::Prio3Aes128Histogram { buckets } => {
                let vdaf = Prio3Aes128Histogram::new(2, &*buckets)?;
                let verify_param =
                    <Prio3Aes128Histogram as Vdaf>::VerifyParam::get_decoded_with_param(
                        &vdaf,
                        current_vdaf_verify_parameter,
                    )?;
                VdafOps::Prio3Aes128Histogram(vdaf, verify_param)
            }

            #[cfg(test)]
            VdafInstance::Fake => VdafOps::Fake(fake::Vdaf::new()),

            #[cfg(test)]
            VdafInstance::FakeFailsPrepInit => VdafOps::Fake(fake::Vdaf::new().with_prep_init_fn(
                || -> Result<(), VdafError> {
                    Err(VdafError::Uncategorized(
                        "FakeFailsPrepInit failed at prep_init".to_string(),
                    ))
                },
            )),

            #[cfg(test)]
            VdafInstance::FakeFailsPrepStep => VdafOps::Fake(fake::Vdaf::new().with_prep_step_fn(
                || -> PrepareTransition<(), (), fake::OutputShare> {
                    PrepareTransition::Fail(VdafError::Uncategorized(
                        "FakeFailsPrepStep failed at prep_step".to_string(),
                    ))
                },
            )),

            _ => panic!("VDAF {:?} is not yet supported", task.vdaf),
        };

        Ok(Self { task, vdaf_ops })
    }

    fn handle_hpke_config(&self) -> HpkeConfig {
        // TODO(brandon): consider deciding a better way to determine "primary" (e.g. most-recent) HPKE
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
        let (hpke_config, hpke_private_key) = self
            .task
            .hpke_keys
            .get(&leader_report.config_id())
            .ok_or_else(|| {
            warn!(
                config_id = ?leader_report.config_id(),
                "Unknown HPKE config ID"
            );
            Error::OutdatedHpkeConfig(leader_report.config_id(), report.task_id())
        })?;

        let report_deadline = clock.now().add(self.task.tolerable_clock_skew)?;

        // §4.2.4: reject reports from too far in the future
        if report.nonce().time().is_after(report_deadline) {
            warn!(report.task_id = ?report.task_id(), report.nonce = ?report.nonce(), "Report timestamp exceeds tolerable clock skew");
            return Err(Error::ReportFromTheFuture(report.nonce(), report.task_id()));
        }

        // Check that we can decrypt the report. This isn't required by the spec
        // but this exercises HPKE decryption and saves us the trouble of
        // storing reports we can't use. We don't inform the client if this
        // fails.
        if let Err(err) = hpke::open(
            hpke_config,
            hpke_private_key,
            &HpkeApplicationInfo::new(
                report.task_id(),
                Label::InputShare,
                Role::Client,
                self.task.role,
            ),
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
                    // §4.2.2 and 4.3.2.2: reject reports whose nonce has been seen before.
                    if tx
                        .get_client_report(report.task_id(), report.nonce())
                        .await?
                        .is_some()
                    {
                        warn!(report.task_id = ?report.task_id(), report.nonce = ?report.nonce(), "Report replayed");
                        // TODO (issue #34): change this error type.
                        return Err(datastore::Error::User(
                            Error::StaleReport(report.nonce(), report.task_id()).into(),
                        ));
                    }

                    // TODO: reject with `staleReport` reports whose timestamps fall in a
                    // batch interval that has already been collected (§4.3.2). We don't
                    // support collection so we can't implement this requirement yet.

                    // Store the report.
                    tx.put_client_report(&report).await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    async fn handle_aggregate<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        req: AggregateReq,
    ) -> Result<AggregateResp, Error> {
        self.vdaf_ops
            .handle_aggregate(datastore, &self.task, req)
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
            return Err(Error::InvalidBatchInterval(
                req.batch_interval,
                self.task.id,
            ));
        }

        self.vdaf_ops
            .handle_aggregate_share(datastore, &self.task, req)
            .await
    }
}

/// VdafOps stores VDAF-specific operations for a TaskAggregator in a non-generic way.
#[allow(clippy::enum_variant_names)]
enum VdafOps {
    Prio3Aes128Count(Prio3Aes128Count, <Prio3Aes128Count as Vdaf>::VerifyParam),
    Prio3Aes128Sum(Prio3Aes128Sum, <Prio3Aes128Sum as Vdaf>::VerifyParam),
    Prio3Aes128Histogram(
        Prio3Aes128Histogram,
        <Prio3Aes128Histogram as Vdaf>::VerifyParam,
    ),

    #[cfg(test)]
    Fake(fake::Vdaf),
}

impl VdafOps {
    /// Implements the `/aggregate` endpoint for the helper, described in §4.4.4.1 & §4.4.4.2 of
    /// draft-gpew-priv-ppm.
    async fn handle_aggregate<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: &Task,
        req: AggregateReq,
    ) -> Result<AggregateResp, Error> {
        match self {
            VdafOps::Prio3Aes128Count(vdaf, verify_param) => {
                Self::handle_aggregate_generic::<Prio3Aes128Count, _>(
                    datastore,
                    vdaf,
                    task,
                    verify_param,
                    req,
                )
                .await
            }
            VdafOps::Prio3Aes128Sum(vdaf, verify_param) => {
                Self::handle_aggregate_generic::<Prio3Aes128Sum, _>(
                    datastore,
                    vdaf,
                    task,
                    verify_param,
                    req,
                )
                .await
            }
            VdafOps::Prio3Aes128Histogram(vdaf, verify_param) => {
                Self::handle_aggregate_generic::<Prio3Aes128Histogram, _>(
                    datastore,
                    vdaf,
                    task,
                    verify_param,
                    req,
                )
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(vdaf) => {
                Self::handle_aggregate_generic::<fake::Vdaf, _>(datastore, vdaf, task, &(), req)
                    .await
            }
        }
    }

    async fn handle_aggregate_generic<A: vdaf::Aggregator, C: Clock>(
        datastore: &Datastore<C>,
        vdaf: &A,
        task: &Task,
        verify_param: &A::VerifyParam,
        req: AggregateReq,
    ) -> Result<AggregateResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareStep: Send + Sync + Encode + ParameterizedDecode<A::VerifyParam>,
        A::PrepareMessage: Send + Sync,
        A::OutputShare: Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::VerifyParam: Send + Sync,
    {
        match req.body {
            AggregateInitReq { agg_param, seq } => {
                Self::handle_aggregate_init_generic(
                    datastore,
                    vdaf,
                    task,
                    verify_param,
                    req.job_id,
                    agg_param,
                    seq,
                )
                .await
            }
            AggregateContinueReq { seq } => {
                Self::handle_aggregate_continue_generic(
                    datastore,
                    vdaf,
                    task,
                    verify_param,
                    req.job_id,
                    seq,
                )
                .await
            }
        }
    }

    /// Implements the aggregate initialization request portion of the `/aggregate` endpoint for the
    /// helper, described in §4.4.4.1 of draft-gpew-priv-ppm.
    async fn handle_aggregate_init_generic<A: vdaf::Aggregator, C: Clock>(
        datastore: &Datastore<C>,
        vdaf: &A,
        task: &Task,
        verify_param: &A::VerifyParam,
        job_id: AggregationJobId,
        agg_param: Vec<u8>,
        report_shares: Vec<ReportShare>,
    ) -> Result<AggregateResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareStep: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let task_id = task.id;
        let min_batch_duration = task.min_batch_duration;

        // If two ReportShare messages have the same nonce, then the helper MUST abort with
        // error "unrecognizedMessage". (§4.4.4.1)
        let mut seen_nonces = HashSet::with_capacity(report_shares.len());
        for share in &report_shares {
            if !seen_nonces.insert(share.nonce) {
                return Err(Error::UnrecognizedMessage(
                    "aggregate request contains duplicate nonce",
                    Some(task_id),
                ));
            }
        }

        // Decrypt shares & prepare initialization states. (§4.4.4.1)
        // TODO(brandon): reject reports that are "too old" with `report-dropped`.
        // TODO(brandon): reject reports in batches that have completed an aggregate-share request with `batch-collected`.
        struct ReportShareData<A: vdaf::Aggregator>
        where
            for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        {
            report_share: ReportShare,
            trans_data: TransitionTypeSpecificData,
            agg_state: ReportAggregationState<A>,
        }
        let mut saw_continue = false;
        let mut saw_finish = false;
        let mut report_share_data = Vec::new();
        let agg_param = A::AggregationParam::get_decoded(&agg_param)?;
        for report_share in report_shares {
            let hpke_key = task
                .hpke_keys
                .get(&report_share.encrypted_input_share.config_id())
                .ok_or_else(|| {
                    warn!(
                        config_id = ?report_share.encrypted_input_share.config_id(),
                        "Unknown HPKE config ID"
                    );
                    TransitionError::HpkeUnknownConfigId
                });

            // If decryption fails, then the aggregator MUST fail with error `hpke-decrypt-error`. (§4.4.2.2)
            let plaintext = hpke_key.and_then(|(hpke_config, hpke_private_key)| {
                hpke::open(
                    hpke_config,
                    hpke_private_key,
                    &HpkeApplicationInfo::new(
                        task_id,
                        Label::InputShare,
                        Role::Client,
                        Role::Helper,
                    ),
                    &report_share.encrypted_input_share,
                    &report_share.associated_data(),
                )
                .map_err(|err| {
                    warn!(
                        ?task_id,
                        nonce = %report_share.nonce,
                        %err,
                        "Couldn't decrypt report share"
                    );
                    TransitionError::HpkeDecryptError
                })
            });

            // `vdaf-prep-error` probably isn't the right code, but there is no better one & we
            // don't want to fail the entire aggregation job with an UnrecognizedMessage error
            // because a single client sent bad data.
            // TODO: agree on/standardize an error code for "client report data can't be decoded" & use it here
            let input_share = plaintext.and_then(|plaintext| {
                A::InputShare::get_decoded_with_param(verify_param, &plaintext)
                    .map_err(|err| {
                        warn!(?task_id, nonce = %report_share.nonce, %err, "Couldn't decode input share from report share");
                        TransitionError::VdafPrepError
                    })
            });

            // Next, the aggregator runs the preparation-state initialization algorithm for the VDAF
            // associated with the task and computes the first state transition. [...] If either
            // step fails, then the aggregator MUST fail with error `vdaf-prep-error`. (§4.4.2.2)
            let step = input_share.and_then(|input_share| {
                vdaf
                    .prepare_init(
                        verify_param,
                        &agg_param,
                        &report_share.nonce.get_encoded(),
                        &input_share,
                    )
                    .map_err(|err| {
                        warn!(?task_id, nonce = %report_share.nonce, %err, "Couldn't prepare_init report share");
                        TransitionError::VdafPrepError
                    })
            });
            let prep_trans = step.map(|step| vdaf.prepare_step(step, None));

            report_share_data.push(match prep_trans {
                Ok(PrepareTransition::Continue(prep_step, prep_msg)) => {
                    saw_continue = true;
                    ReportShareData {
                        report_share,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: prep_msg.get_encoded(),
                        },
                        agg_state: ReportAggregationState::<A>::Waiting(prep_step, None),
                    }
                }

                Ok(PrepareTransition::Finish(output_share)) => {
                    saw_finish = true;
                    ReportShareData {
                        report_share,
                        trans_data: TransitionTypeSpecificData::Finished,
                        agg_state: ReportAggregationState::<A>::Finished(output_share),
                    }
                }

                Ok(PrepareTransition::Fail(err)) => {
                    warn!(?task_id, nonce = %report_share.nonce, %err, "Couldn't prepare_step report share");
                    ReportShareData {
                        report_share,
                        trans_data: TransitionTypeSpecificData::Failed {
                            error: TransitionError::VdafPrepError,
                        },
                        agg_state: ReportAggregationState::<A>::Failed(TransitionError::VdafPrepError),
                    }
                },

                Err(err) => ReportShareData {
                    report_share,
                    trans_data: TransitionTypeSpecificData::Failed { error: err },
                    agg_state: ReportAggregationState::<A>::Failed(err),
                },
            });
        }

        // Store data to datastore.
        let aggregation_job_state = match (saw_continue, saw_finish) {
            (false, false) => AggregationJobState::Finished, // everything failed, or there were no reports
            (true, false) => AggregationJobState::InProgress,
            (false, true) => AggregationJobState::Finished,
            (true, true) => {
                return Err(Error::Internal(
                    "VDAF took an inconsistent number of rounds to reach Finish state".to_string(),
                ))
            }
        };
        let aggregation_job = Arc::new(AggregationJob::<A> {
            aggregation_job_id: job_id,
            task_id,
            aggregation_param: agg_param,
            state: aggregation_job_state,
        });
        let report_share_data = Arc::new(report_share_data);
        datastore
            .run_tx(|tx| {
                let aggregation_job = aggregation_job.clone();
                let report_share_data = report_share_data.clone();

                Box::pin(async move {
                    // Write aggregation job.
                    tx.put_aggregation_job(&aggregation_job).await?;

                    let mut accumulator = Accumulator::<A>::new(
                        task_id,
                        min_batch_duration,
                        &aggregation_job.aggregation_param,
                    );

                    for (ord, share_data) in report_share_data.as_ref().iter().enumerate() {
                        // Write client report & report aggregation.
                        tx.put_report_share(task_id, &share_data.report_share)
                            .await?;
                        tx.put_report_aggregation(&ReportAggregation::<A> {
                            aggregation_job_id: job_id,
                            task_id,
                            nonce: share_data.report_share.nonce,
                            ord: ord as i64,
                            state: share_data.agg_state.clone(),
                        })
                        .await?;

                        if let ReportAggregationState::<A>::Finished(ref output_share) =
                            share_data.agg_state
                        {
                            accumulator.update(output_share, share_data.report_share.nonce)?;
                        }
                    }

                    accumulator.flush_to_datastore(tx).await?;

                    Ok(())
                })
            })
            .await?;

        // Construct response and return.
        Ok(AggregateResp {
            seq: report_share_data
                .as_ref()
                .iter()
                .map(|d| Transition {
                    nonce: d.report_share.nonce,
                    trans_data: d.trans_data.clone(),
                })
                .collect(),
        })
    }

    async fn handle_aggregate_continue_generic<A: vdaf::Aggregator, C: Clock>(
        datastore: &Datastore<C>,
        vdaf: &A,
        task: &Task,
        verify_param: &A::VerifyParam,
        job_id: AggregationJobId,
        transitions: Vec<Transition>,
    ) -> Result<AggregateResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareStep: Send + Sync + Encode + ParameterizedDecode<A::VerifyParam>,
        A::PrepareMessage: Send + Sync,
        A::OutputShare: Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::VerifyParam: Send + Sync,
    {
        let task_id = task.id;
        let min_batch_duration = task.min_batch_duration;
        let vdaf = Arc::new(vdaf.clone());
        let verify_param = Arc::new(verify_param.clone());
        let transitions = Arc::new(transitions);

        // TODO(brandon): don't hold DB transaction open while computing VDAF updates?
        // TODO(brandon): don't do O(n) network round-trips (where n is the number of transitions)
        // TODO(timg): We have to reject reports in batches that have completed an aggregate-share
        // request with `batch-collected` here as well as in the init case. Suppose that an
        // AggregateShareReq arrives in between the AggregateInitReq and AggregateContinueReq.
        Ok(datastore
            .run_tx(|tx| {
                let vdaf = vdaf.clone();
                let verify_param = verify_param.clone();
                let transitions = transitions.clone();

                Box::pin(async move {
                    // Read existing state.
                    let (aggregation_job, report_aggregations) = try_join!(
                        tx.get_aggregation_job::<A>(task_id, job_id),
                        tx.get_report_aggregations_for_aggregation_job::<A>(
                            &verify_param,
                            task_id,
                            job_id,
                        ),
                    )?;
                    let mut aggregation_job = aggregation_job.ok_or_else(|| datastore::Error::User(Error::UnrecognizedAggregationJob(job_id, task_id).into()))?;

                    // Handle each transition in the request.
                    let mut report_aggregations = report_aggregations.into_iter();
                    let (mut saw_continue, mut saw_finish) = (false, false);
                    let mut response_transitions = Vec::new();

                    let mut accumulator = Accumulator::<A>::new(task_id, min_batch_duration, &aggregation_job.aggregation_param);

                    for transition in transitions.iter() {
                        // Match transition received from leader to stored report aggregation, and
                        // extract the stored preparation step.
                        let mut report_aggregation = loop {
                            let mut report_agg = report_aggregations.next().ok_or_else(|| {
                                warn!(?task_id, ?job_id, nonce = %transition.nonce, "Leader sent unexpected, duplicate, or out-of-order transitions");
                                datastore::Error::User(Error::UnrecognizedMessage(
                                    "leader sent unexpected, duplicate, or out-of-order transitions",
                                    Some(task_id),
                                ).into())
                            })?;
                            if report_agg.nonce != transition.nonce {
                                // This report was omitted by the leader because of a prior failure.
                                // Note that the report was dropped (if it's not already in an error
                                // state) and continue.
                                if matches!(report_agg.state, ReportAggregationState::Waiting(_, _)) {
                                    report_agg.state = ReportAggregationState::Failed(TransitionError::ReportDropped);
                                    tx.update_report_aggregation(&report_agg).await?;
                                }
                                continue;
                            }
                            break report_agg;
                        };
                        let prep_step =
                            match report_aggregation.state {
                                ReportAggregationState::Waiting(prep_step, _) => prep_step,
                                _ => {
                                    warn!(?task_id, ?job_id, nonce = %transition.nonce, "Leader sent transition for non-WAITING report aggregation");
                                    return Err(datastore::Error::User(
                                        Error::UnrecognizedMessage(
                                            "leader sent transition for non-WAITING report aggregation",
                                            Some(task_id),
                                        ).into()
                                    ));
                                },
                            };

                        // Parse preparation message out of transition received from leader.
                        let prep_msg = match &transition.trans_data {
                            TransitionTypeSpecificData::Continued { payload } => {
                                A::PrepareMessage::decode_with_param(
                                    &prep_step,
                                    &mut Cursor::new(payload),
                                )?
                            }
                            _ => {
                                // TODO(brandon): should we record a state change in this case?
                                warn!(?task_id, ?job_id, nonce = %transition.nonce, "Leader sent non-Continued transition");
                                return Err(datastore::Error::User(
                                    Error::UnrecognizedMessage(
                                        "leader sent non-Continued transition",
                                        Some(task_id),
                                    ).into()
                                ));
                            }
                        };

                        // Compute the next transition, prepare to respond & update DB.
                        let prep_trans = vdaf.prepare_step(prep_step, Some(prep_msg));
                        match prep_trans {
                            PrepareTransition::Continue(prep_step, prep_msg) => {
                                saw_continue = true;
                                report_aggregation.state =
                                    ReportAggregationState::Waiting(prep_step, None);
                                response_transitions.push(Transition {
                                    nonce: transition.nonce,
                                    trans_data: TransitionTypeSpecificData::Continued {
                                        payload: prep_msg.get_encoded(),
                                    },
                                })
                            }

                            PrepareTransition::Finish(output_share) => {
                                saw_finish = true;

                                accumulator.update(&output_share, transition.nonce)?;

                                report_aggregation.state =
                                    ReportAggregationState::Finished(output_share);
                                response_transitions.push(Transition {
                                    nonce: transition.nonce,
                                    trans_data: TransitionTypeSpecificData::Finished,
                                });
                            }

                            PrepareTransition::Fail(err) => {
                                warn!(?task_id, ?job_id, nonce = %transition.nonce, %err, "Prepare step failed");
                                report_aggregation.state =
                                    ReportAggregationState::Failed(TransitionError::VdafPrepError);
                                response_transitions.push(Transition {
                                    nonce: transition.nonce,
                                    trans_data: TransitionTypeSpecificData::Failed {
                                        error: TransitionError::VdafPrepError,
                                    },
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
                            report_agg.state = ReportAggregationState::Failed(TransitionError::ReportDropped);
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

                    Ok(AggregateResp {
                        seq: response_transitions,
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
                Self::handle_collect_generic::<Prio3Aes128Count, _>(datastore, task, collect_req)
                    .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => {
                Self::handle_collect_generic::<Prio3Aes128Sum, _>(datastore, task, collect_req)
                    .await
            }
            VdafOps::Prio3Aes128Histogram(_, _) => {
                Self::handle_collect_generic::<Prio3Aes128Histogram, _>(
                    datastore,
                    task,
                    collect_req,
                )
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(_) => {
                Self::handle_collect_generic::<fake::Vdaf, _>(datastore, task, collect_req).await
            }
        }
    }

    #[tracing::instrument(skip(datastore), err)]
    async fn handle_collect_generic<A, C>(
        datastore: &Datastore<C>,
        task: &Task,
        req: &CollectReq,
    ) -> Result<Uuid, Error>
    where
        A: vdaf::Aggregator,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        C: Clock,
    {
        // §4.5: check that the batch interval meets the requirements from §4.6
        if !task.validate_batch_interval(req.batch_interval) {
            return Err(Error::InvalidBatchInterval(req.batch_interval, task.id));
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
                        .get_batch_unit_aggregations_for_task_in_interval::<A>(
                            task.id,
                            req.batch_interval,
                            &aggregation_param,
                        )
                        .await?;
                    Self::validate_batch_lifetime_for_unit_aggregations(
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
                Self::handle_collect_job_generic::<Prio3Aes128Count, _>(
                    datastore,
                    task,
                    collect_job_id,
                )
                .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => {
                Self::handle_collect_job_generic::<Prio3Aes128Sum, _>(
                    datastore,
                    task,
                    collect_job_id,
                )
                .await
            }
            VdafOps::Prio3Aes128Histogram(_, _) => {
                Self::handle_collect_job_generic::<Prio3Aes128Histogram, _>(
                    datastore,
                    task,
                    collect_job_id,
                )
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(_) => {
                Self::handle_collect_job_generic::<fake::Vdaf, _>(datastore, task, collect_job_id)
                    .await
            }
        }
    }

    async fn handle_collect_job_generic<A, C>(
        datastore: &Datastore<C>,
        task: &Task,
        collect_job_id: Uuid,
    ) -> Result<Option<CollectResp>, Error>
    where
        A: vdaf::Aggregator,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        C: Clock,
    {
        let collect_job = datastore
            .run_tx(move |tx| {
                let task = task.clone();
                Box::pin(async move {
                    let collect_job =
                        tx.get_collect_job::<A>(collect_job_id)
                            .await?
                            .ok_or_else(|| {
                                datastore::Error::User(
                                    Error::UnrecognizedCollectJob(collect_job_id).into(),
                                )
                            })?;

                    if collect_job.has_run()? {
                        debug!(?collect_job_id, ?task.id, "serving cached collect job response");
                        return Ok(Some(collect_job));
                    }

                    debug!(?collect_job_id, ?task.id, "collect job has not run yet");
                    Ok(None)
                })
            })
            .await?;

        collect_job
            .map(|job| {
                // §4.4.4.3: HPKE encrypt aggregate share to the collector. We store the leader
                // aggregate share *unencrypted* in the datastore so that we can encrypt cached
                // results to the collector HPKE config valid when the current collect job request
                // was made, and not whatever was valid at the time the aggregate share was first
                // computed.
                // However we store the helper's *encrypted* share.
                // TODO: consider fetching freshly encrypted helper aggregate share if it has been
                // long enough since the encrypted helper share was cached -- tricky thing is
                // deciding what "long enough" is.
                let encrypted_leader_aggregate_share = hpke::seal(
                    &task.collector_hpke_config,
                    &HpkeApplicationInfo::new(
                        task.id,
                        Label::AggregateShare,
                        Role::Leader,
                        Role::Collector,
                    ),
                    &<Vec<u8>>::from(&job.leader_aggregate_share.unwrap()),
                    &job.batch_interval.get_encoded(),
                )?;

                Ok(CollectResp {
                    encrypted_agg_shares: vec![
                        encrypted_leader_aggregate_share,
                        job.helper_aggregate_share.unwrap(),
                    ],
                })
            })
            .transpose()
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
                Self::handle_aggregate_share_generic::<Prio3Aes128Count, C>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => {
                Self::handle_aggregate_share_generic::<Prio3Aes128Sum, C>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }
            VdafOps::Prio3Aes128Histogram(_, _) => {
                Self::handle_aggregate_share_generic::<Prio3Aes128Histogram, C>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(_) => {
                Self::handle_aggregate_share_generic::<fake::Vdaf, C>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }
        }
    }

    /// Check whether any member of `batch_unit_aggregations` has been included in enough collect
    /// jobs (for `task.role` == [`Role::Leader`]) or aggregate share jobs (for `task.role` ==
    /// [`Role::Helper`]) to violate the task's maximum batch lifetime.
    async fn validate_batch_lifetime_for_unit_aggregations<A, C>(
        tx: &Transaction<'_, C>,
        task: &Task,
        batch_unit_aggregations: &[BatchUnitAggregation<A>],
    ) -> Result<(), datastore::Error>
    where
        A: vdaf::Aggregator,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        C: Clock,
    {
        // Check how many rows in the relevant table have a batch interval that includes each batch
        // unit. Each such row consumes one unit of batch lifetime (§4.6).
        //
        // We have to check each batch unit interval separately rather than checking how many times
        // aggregate_share_req.batch_interval overlaps with any row. Suppose we had:
        //
        //   * task.max_batch_lifetime = 2,
        //   * an AggregateShareReq.batch interval that spans two batch units,
        //   * and that each of those batch units has been collected once before.
        //
        // A further AggregateShareReq including either or both of the units is permissible, but
        // if we queried how many rows overlap with that interval, we would get 2 and refuse the
        // request. We must check the unit intervals individually to notice that each has enough
        // remaining lifetime to permit the share request.
        //
        // TODO: We believe this to be a correct implementation of currently specified batch
        // parameter validation, but we also know it to be inadequate. This should work for interop
        // experiments, but we should do better before we allow any real user data to be processed
        // (see issue #149).
        let intervals: Vec<_> = batch_unit_aggregations
            .iter()
            .map(|v| {
                Interval::new(v.unit_interval_start, task.min_batch_duration)
                    .map_err(|e| datastore::Error::User(e.into()))
            })
            .collect::<Result<_, datastore::Error>>()?;

        let overlaps = tx
            .get_aggregate_share_job_counts_for_intervals(task.id, task.role, &intervals)
            .await?;

        for (unit_interval, consumed_batch_lifetime) in overlaps {
            if consumed_batch_lifetime == task.max_batch_lifetime {
                debug!(
                    ?task.id, ?unit_interval,
                    "refusing aggregate share request because lifetime for batch unit has been consumed"
                );
                return Err(datastore::Error::User(
                    Error::BatchLifetimeExceeded(task.id).into(),
                ));
            }
            if consumed_batch_lifetime > task.max_batch_lifetime {
                error!(
                    ?task.id, ?unit_interval,
                    "batch unit lifetime has been consumed more times than task allows"
                );
                panic!("batch unit lifetime has already been consumed more times than task allows");
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(tx), err)]
    async fn service_aggregate_share_request<A, C>(
        tx: &Transaction<'_, C>,
        task: &Task,
        aggregate_share_req: &AggregateShareReq,
    ) -> Result<AggregateShareJob<A>, datastore::Error>
    where
        A: vdaf::Aggregator,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        C: Clock,
    {
        let aggregation_param =
            A::AggregationParam::get_decoded(&aggregate_share_req.aggregation_param)?;
        let batch_unit_aggregations = tx
            .get_batch_unit_aggregations_for_task_in_interval::<A>(
                task.id,
                aggregate_share_req.batch_interval,
                &aggregation_param,
            )
            .await?;

        Self::validate_batch_lifetime_for_unit_aggregations(tx, task, &batch_unit_aggregations)
            .await?;

        // At the moment we handle the AggregateShareReq, there could be some incomplete aggregation
        // jobs whose results not been accumulated into the batch unit aggregations we just queried
        // from the datastore, meaning we will aggregate over an incomplete view of data, which:
        //
        //  * reduces fidelity of the resulting aggregates,
        //  * could cause us to fail to meet the minimum batch size for the task,
        //  * or for particularly pathological timing, could cause us to aggregate a different set
        //    of reports than the leader did (though the checksum will detect this).
        //
        // There's not much the helper can do about this, because an aggregate job might be
        // unfinished because it's waiting on an aggregate sub-protocol message that is never coming
        // because the leader has abandoned that job.
        //
        // Thus the helper has no choice but to assume that any unfinished aggregation jobs were
        // intentionally abandoned by the leader and service the aggregate share request with
        // whatever batch unit aggregations are available now.
        //
        // See issue #104 for more discussion.

        let mut total_report_count = 0;
        let mut total_checksum = NonceChecksum::default();
        let mut total_aggregate_share: Option<A::AggregateShare> = None;

        for batch_unit_aggregation in &batch_unit_aggregations {
            // §4.4.4.3: XOR this batch interval's checksum into the overall checksum
            total_checksum.combine(batch_unit_aggregation.checksum);

            // §4.4.4.3: Sum all the report counts
            total_report_count += batch_unit_aggregation.report_count;

            match &mut total_aggregate_share {
                Some(share) => share
                    .merge(&batch_unit_aggregation.aggregate_share)
                    .map_err(|e| datastore::Error::User(e.into()))?,
                None => {
                    total_aggregate_share = Some(batch_unit_aggregation.aggregate_share.clone())
                }
            }
        }

        let total_aggregate_share = match total_aggregate_share {
            Some(share) => share,
            None => {
                return Err(datastore::Error::User(
                    Error::InsufficientBatchSize(0, task.id).into(),
                ))
            }
        };

        // §4.6: refuse to service aggregate share requests if there are too few reports
        // included.
        if total_report_count < task.min_batch_size {
            return Err(datastore::Error::User(
                Error::InsufficientBatchSize(total_report_count, task.id).into(),
            ));
        }

        // Now that we are satisfied that the request is serviceable, we consume batch lifetime by
        // recording the aggregate share request parameters and the result.
        let aggregate_share_job = AggregateShareJob {
            task_id: task.id,
            batch_interval: aggregate_share_req.batch_interval,
            aggregation_param,
            helper_aggregate_share: total_aggregate_share,
            report_count: total_report_count,
            checksum: total_checksum,
        };

        tx.put_aggregate_share_job(&aggregate_share_job).await?;

        Ok(aggregate_share_job)
    }

    async fn handle_aggregate_share_generic<A, C>(
        datastore: &Datastore<C>,
        task: &Task,
        aggregate_share_req: &AggregateShareReq,
    ) -> Result<AggregateShareResp, Error>
    where
        A: vdaf::Aggregator,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        C: Clock,
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
                            Self::service_aggregate_share_request::<A, C>(
                                tx,
                                &task,
                                &aggregate_share_req,
                            )
                            .await?
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
            return Err(Error::BatchMisalignment {
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
            &HpkeApplicationInfo::new(
                task.id,
                Label::AggregateShare,
                Role::Helper,
                Role::Collector,
            ),
            &<Vec<u8>>::from(&aggregate_share_job.helper_aggregate_share),
            &aggregate_share_req.batch_interval.get_encoded(),
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
enum PpmProblemType {
    UnrecognizedMessage,
    UnrecognizedTask,
    UnrecognizedAggregationJob, // TODO: standardize this value
    OutdatedConfig,
    StaleReport,
    InvalidHmac,
    InvalidBatchInterval,
    InsufficientBatchSize,
    BatchMisaligned,
    BatchLifetimeExceeded,
}

impl PpmProblemType {
    /// Returns the problem type URI for a particular kind of error.
    fn type_uri(&self) -> &'static str {
        match self {
            PpmProblemType::UnrecognizedMessage => "urn:ietf:params:ppm:error:unrecognizedMessage",
            PpmProblemType::UnrecognizedTask => "urn:ietf:params:ppm:error:unrecognizedTask",
            PpmProblemType::UnrecognizedAggregationJob => {
                "urn:ietf:params:ppm:error:unrecognizedAggregationJob"
            }
            PpmProblemType::OutdatedConfig => "urn:ietf:params:ppm:error:outdatedConfig",
            PpmProblemType::StaleReport => "urn:ietf:params:ppm:error:staleReport",
            PpmProblemType::InvalidHmac => "urn:ietf:params:ppm:error:invalidHmac",
            PpmProblemType::InvalidBatchInterval => {
                "urn:ietf:params:ppm:error:invalidBatchInterval"
            }
            PpmProblemType::InsufficientBatchSize => {
                "urn:ietf:params:ppm:error:insufficientBatchSize"
            }
            PpmProblemType::BatchMisaligned => "urn:ietf:params:ppm:error:batchMisaligned",
            PpmProblemType::BatchLifetimeExceeded => {
                "urn:ietf:params:ppm:error:batchLifetimeExceeded"
            }
        }
    }

    /// Returns a human-readable summary of a problem type.
    fn description(&self) -> &'static str {
        match self {
            PpmProblemType::UnrecognizedMessage => {
                "The message type for a response was incorrect or the payload was malformed."
            }
            PpmProblemType::UnrecognizedTask => {
                "An endpoint received a message with an unknown task ID."
            }
            PpmProblemType::UnrecognizedAggregationJob => {
                "An endpoint received a message with an unknown aggregation job ID."
            }
            PpmProblemType::OutdatedConfig => {
                "The message was generated using an outdated configuration."
            }
            PpmProblemType::StaleReport => {
                "Report could not be processed because it arrived too late."
            }
            PpmProblemType::InvalidHmac => "The aggregate message's HMAC was not valid.",
            PpmProblemType::InvalidBatchInterval => {
                "The batch interval in the collect or aggregate share request is not valid for the task."
            }
            PpmProblemType::InsufficientBatchSize => {
                "There are not enough reports in the batch interval."
            }
            PpmProblemType::BatchMisaligned => {
                "The checksums or report counts in the two aggregator's aggregate shares do not match."
            }
            PpmProblemType::BatchLifetimeExceeded => {
                "The batch lifetime has been exceeded for one or more reports included in the batch interval."
            }
        }
    }
}

/// The media type for problem details formatted as a JSON document, per RFC 7807.
static PROBLEM_DETAILS_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Construct an error response in accordance with §3.1.
//
// TODO (issue abetterinternet/ppm-specification#209): The handling of the instance, title,
// detail, and taskid fields are subject to change.
fn build_problem_details_response(error_type: PpmProblemType, task_id: Option<TaskId>) -> Response {
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
            Err(Error::StaleReport(_, task_id)) => {
                build_problem_details_response(PpmProblemType::StaleReport, Some(task_id))
            }
            Err(Error::UnrecognizedMessage(_, task_id)) => {
                build_problem_details_response(PpmProblemType::UnrecognizedMessage, task_id)
            }
            Err(Error::UnrecognizedTask(task_id)) => {
                build_problem_details_response(PpmProblemType::UnrecognizedTask, Some(task_id))
            }
            Err(Error::UnrecognizedAggregationJob(_, task_id)) => build_problem_details_response(
                PpmProblemType::UnrecognizedAggregationJob,
                Some(task_id),
            ),
            Err(Error::UnrecognizedCollectJob(_)) => StatusCode::NOT_FOUND.into_response(),
            Err(Error::OutdatedHpkeConfig(_, task_id)) => {
                build_problem_details_response(PpmProblemType::OutdatedConfig, Some(task_id))
            }
            Err(Error::ReportFromTheFuture(_, _)) => {
                // TODO: build a problem details document once an error type is defined for reports
                // with timestamps too far in the future.
                StatusCode::BAD_REQUEST.into_response()
            }
            Err(Error::InvalidHmac(task_id)) => {
                build_problem_details_response(PpmProblemType::InvalidHmac, Some(task_id))
            }
            Err(Error::InvalidBatchInterval(_, task_id)) => {
                build_problem_details_response(PpmProblemType::InvalidBatchInterval, Some(task_id))
            }
            Err(Error::InsufficientBatchSize(_, task_id)) => {
                build_problem_details_response(PpmProblemType::InsufficientBatchSize, Some(task_id))
            }
            Err(Error::BatchMisalignment { task_id, .. }) => {
                build_problem_details_response(PpmProblemType::BatchMisaligned, Some(task_id))
            }
            Err(Error::BatchLifetimeExceeded(task_id)) => {
                build_problem_details_response(PpmProblemType::BatchLifetimeExceeded, Some(task_id))
            }
            Err(Error::Hpke(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Datastore(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Vdaf(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Internal(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Url(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Err(Error::Message(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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

    let hpke_config_endpoint = warp::path("hpke_config")
        .and(warp::get())
        .and(with_cloned_value(aggregator.clone()))
        .and(warp::query::<HashMap<String, String>>())
        .then(
            |aggregator: Arc<Aggregator<C>>, query_params: HashMap<String, String>| async move {
                let task_id_b64 = query_params
                    .get("task_id")
                    .ok_or(Error::UnrecognizedMessage("task_id", None))?;
                let hpke_config_bytes = aggregator.handle_hpke_config(task_id_b64.as_ref()).await?;
                Ok(reply::with_header(
                    reply::with_status(hpke_config_bytes, StatusCode::OK),
                    CACHE_CONTROL,
                    "max-age=86400",
                )
                .into_response())
            },
        )
        .map(error_handler(&response_counter, "hpke_config"))
        .with(warp::wrap_fn(timing_wrapper(
            &time_value_recorder,
            "hpke_config",
        )))
        .with(trace::named("hpke_config"));

    let upload_endpoint = warp::path("upload")
        .and(warp::post())
        .and(with_cloned_value(aggregator.clone()))
        .and(warp::body::bytes())
        .then(|aggregator: Arc<Aggregator<C>>, body: Bytes| async move {
            aggregator.handle_upload(&body).await?;
            Ok(StatusCode::OK)
        })
        .map(error_handler(&response_counter, "upload"))
        .with(warp::wrap_fn(timing_wrapper(
            &time_value_recorder,
            "upload",
        )))
        .with(trace::named("upload"));

    let aggregate_endpoint = warp::path("aggregate")
        .and(warp::post())
        .and(with_cloned_value(aggregator.clone()))
        .and(warp::body::bytes())
        .then(|aggregator: Arc<Aggregator<C>>, body: Bytes| async move {
            let resp_bytes = aggregator.handle_aggregate(&body).await?;
            Ok(reply::with_status(resp_bytes, StatusCode::OK))
        })
        .map(error_handler(&response_counter, "aggregate"))
        .with(warp::wrap_fn(timing_wrapper(
            &time_value_recorder,
            "aggregate",
        )))
        .with(trace::named("aggregate"));

    let collect_endpoint = warp::path("collect")
        .and(warp::post())
        .and(with_cloned_value(aggregator.clone()))
        .and(warp::body::bytes())
        .then(|aggregator: Arc<Aggregator<C>>, body: Bytes| async move {
            let collect_uri = aggregator.handle_collect(&body).await?;
            // §4.5: Response is an HTTP 303 with the collect URI in a Location
            // header
            Ok(reply::with_status(
                reply::with_header(reply::reply(), LOCATION, collect_uri.as_str()),
                StatusCode::SEE_OTHER,
            ))
        })
        .map(error_handler(&response_counter, "collect"))
        .with(warp::wrap_fn(timing_wrapper(
            &time_value_recorder,
            "collect",
        )))
        .with(trace::named("collect"));

    let collect_jobs_endpoint = warp::path("collect_jobs")
        .and(warp::path::param())
        .and(with_cloned_value(aggregator.clone()))
        .then(
            |collect_job_id: Uuid, aggregator: Arc<Aggregator<C>>| async move {
                let resp_bytes = aggregator.handle_collect_job(collect_job_id).await?;

                match resp_bytes {
                    Some(resp_bytes) => Ok(reply::with_status(resp_bytes, StatusCode::OK)),
                    None => Ok(reply::with_status(vec![], StatusCode::ACCEPTED)),
                }
            },
        )
        .map(error_handler(&response_counter, "collect_jobs"))
        .with(warp::wrap_fn(timing_wrapper(
            &time_value_recorder,
            "collect_jobs",
        )));

    let aggregate_share_endpoint = warp::path("aggregate_share")
        .and(warp::post())
        .and(with_cloned_value(aggregator))
        .and(warp::body::bytes())
        .then(|aggregator: Arc<Aggregator<C>>, body: Bytes| async move {
            let resp_bytes = aggregator.handle_aggregate_share(&body).await?;

            // §4.4.4.3: Response is HTTP 200 OK
            Ok(reply::with_status(resp_bytes, StatusCode::OK))
        })
        .map(error_handler(&response_counter, "aggregate_share"))
        .with(warp::wrap_fn(timing_wrapper(
            &time_value_recorder,
            "aggregate_share",
        )))
        .with(trace::named("aggregate_share"));

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
pub(crate) mod test_util {
    pub mod fake {
        use prio::vdaf::{self, Aggregatable, PrepareTransition, VdafError};
        use std::convert::Infallible;
        use std::fmt::Debug;
        use std::sync::Arc;

        #[derive(Clone)]
        pub struct Vdaf {
            prep_init_fn: Arc<dyn Fn() -> Result<(), VdafError> + 'static + Send + Sync>,
            prep_step_fn:
                Arc<dyn Fn() -> PrepareTransition<(), (), OutputShare> + 'static + Send + Sync>,
        }

        impl Debug for Vdaf {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("Vdaf")
                    .field("prep_init_result", &"[omitted]")
                    .field("prep_step_result", &"[omitted]")
                    .finish()
            }
        }

        impl Vdaf {
            pub fn new() -> Self {
                Vdaf {
                    prep_init_fn: Arc::new(|| -> Result<(), VdafError> { Ok(()) }),
                    prep_step_fn: Arc::new(|| -> PrepareTransition<(), (), OutputShare> {
                        PrepareTransition::Finish(OutputShare())
                    }),
                }
            }

            pub fn with_prep_init_fn<F: Fn() -> Result<(), VdafError>>(mut self, f: F) -> Self
            where
                F: 'static + Send + Sync,
            {
                self.prep_init_fn = Arc::new(f);
                self
            }

            pub fn with_prep_step_fn<F: Fn() -> PrepareTransition<(), (), OutputShare>>(
                mut self,
                f: F,
            ) -> Self
            where
                F: 'static + Send + Sync,
            {
                self.prep_step_fn = Arc::new(f);
                self
            }
        }

        impl vdaf::Vdaf for Vdaf {
            type Measurement = ();
            type AggregateResult = ();
            type AggregationParam = ();
            type PublicParam = ();
            type VerifyParam = ();
            type InputShare = ();
            type OutputShare = OutputShare;
            type AggregateShare = AggregateShare;

            fn setup(&self) -> Result<(Self::PublicParam, Vec<Self::VerifyParam>), VdafError> {
                Ok(((), vec![(), ()]))
            }

            fn num_aggregators(&self) -> usize {
                2
            }
        }

        impl vdaf::Aggregator for Vdaf {
            type PrepareStep = ();
            type PrepareMessage = ();

            fn prepare_init(
                &self,
                _: &Self::VerifyParam,
                _: &Self::AggregationParam,
                _: &[u8],
                _: &Self::InputShare,
            ) -> Result<Self::PrepareStep, VdafError> {
                (self.prep_init_fn)()
            }

            fn prepare_preprocess<M: IntoIterator<Item = Self::PrepareMessage>>(
                &self,
                _: M,
            ) -> Result<Self::PrepareMessage, VdafError> {
                Ok(())
            }

            fn prepare_step(
                &self,
                _: Self::PrepareStep,
                _: Option<Self::PrepareMessage>,
            ) -> PrepareTransition<Self::PrepareStep, Self::PrepareMessage, Self::OutputShare>
            {
                (self.prep_step_fn)()
            }

            fn aggregate<M: IntoIterator<Item = Self::OutputShare>>(
                &self,
                _: &Self::AggregationParam,
                _: M,
            ) -> Result<Self::AggregateShare, VdafError> {
                Ok(AggregateShare())
            }
        }

        impl vdaf::Client for Vdaf {
            fn shard(
                &self,
                _: &Self::PublicParam,
                _: &Self::Measurement,
            ) -> Result<Vec<Self::InputShare>, VdafError> {
                Ok(vec![(), ()])
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct OutputShare();

        impl TryFrom<&[u8]> for OutputShare {
            type Error = Infallible;

            fn try_from(_: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self())
            }
        }

        impl From<&OutputShare> for Vec<u8> {
            fn from(_: &OutputShare) -> Self {
                Self::new()
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct AggregateShare();

        impl Aggregatable for AggregateShare {
            type OutputShare = OutputShare;

            fn merge(&mut self, _: &Self) -> Result<(), VdafError> {
                Ok(())
            }

            fn accumulate(&mut self, _: &Self::OutputShare) -> Result<(), VdafError> {
                Ok(())
            }
        }

        impl From<OutputShare> for AggregateShare {
            fn from(_: OutputShare) -> Self {
                Self()
            }
        }

        impl TryFrom<&[u8]> for AggregateShare {
            type Error = Infallible;

            fn try_from(_: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self())
            }
        }

        impl From<&AggregateShare> for Vec<u8> {
            fn from(_: &AggregateShare) -> Self {
                Self::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregator::test_util::fake,
        datastore::{
            models::BatchUnitAggregation,
            test_util::{ephemeral_datastore, DbHandle},
        },
        message::AuthenticatedResponseDecoder,
        task::{test_util::new_dummy_task, VdafInstance},
        trace::test_util::install_test_trace_subscriber,
    };
    use ::janus_test_util::{run_vdaf, MockClock, PrepareTransition};
    use assert_matches::assert_matches;
    use http::Method;
    use janus::{
        hpke::associated_data_for_report_share,
        hpke::{test_util::generate_hpke_config_and_private_key, HpkePrivateKey, Label},
        message::{Duration, HpkeCiphertext, HpkeConfig, TaskId, Time},
    };
    use prio::{
        codec::Decode,
        field::Field64,
        vdaf::{prio3::Prio3Aes128Count, AggregateShare, Aggregator as _},
    };
    use rand::{thread_rng, Rng};
    use ring::{
        hmac::{self, HMAC_SHA256},
        rand::SystemRandom,
    };
    use std::{collections::HashMap, io::Cursor};
    use uuid::Uuid;
    use warp::{reply::Reply, Rejection};

    #[tokio::test]
    async fn hpke_config() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
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

        let response = warp::test::request()
            .path(&format!("/hpke_config?task_id={}", task_id))
            .method("GET")
            .filter(&aggregator_filter(Arc::new(datastore), clock).unwrap())
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "max-age=86400"
        );

        let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let hpke_config = HpkeConfig::decode(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(hpke_config, want_hpke_key.0);

        let application_info =
            HpkeApplicationInfo::new(task_id, Label::InputShare, Role::Client, Role::Leader);
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
        let associated_data = associated_data_for_report_share(nonce, &extensions);

        let leader_ciphertext = hpke::seal(
            &hpke_key.0,
            &HpkeApplicationInfo::new(task.id, Label::InputShare, Role::Client, Role::Leader),
            message,
            &associated_data,
        )
        .unwrap();
        let helper_ciphertext = hpke::seal(
            &hpke_key.0,
            &HpkeApplicationInfo::new(task.id, Label::InputShare, Role::Client, Role::Leader),
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
            VdafInstance::Prio3Aes128Count,
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
        assert!(hyper::body::to_bytes(response.into_body())
            .await
            .unwrap()
            .is_empty());

        // Verify that we reject duplicate reports with the staleReport type.
        // TODO (issue #34): change this error type.
        let response = drive_filter(Method::POST, "/upload", &report.get_encoded(), &filter)
            .await
            .unwrap();
        let (part, body) = response.into_parts();
        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:error:staleReport",
                "title": "Report could not be processed because it arrived too late.",
                "detail": "Report could not be processed because it arrived too late.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
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

        // should reject a report with only one share with the unrecognizedMessage type.
        let bad_report = Report::new(
            report.task_id(),
            report.nonce(),
            report.extensions().to_vec(),
            vec![report.encrypted_input_shares()[0].clone()],
        );
        let response = drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
            .await
            .unwrap();
        let (part, body) = response.into_parts();
        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "The message type for a response was incorrect or the payload was malformed.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
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
        let response = drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
            .await
            .unwrap();
        let (part, body) = response.into_parts();
        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400u16,
                "type": "urn:ietf:params:ppm:error:outdatedConfig",
                "title": "The message was generated using an outdated configuration.",
                "detail": "The message was generated using an outdated configuration.",
                "instance": "..",
                "taskid": format!("{}", report.task_id()),
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

        // reports from the future should be rejected.
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
        let response = drive_filter(Method::POST, "/upload", &bad_report.get_encoded(), &filter)
            .await
            .unwrap();
        assert!(!response.status().is_success());
        // TODO: update this test once an error type has been defined, and validate the problem
        // details.
        assert_eq!(response.status().as_u16(), 400);
    }

    // Helper should not expose /upload endpoint
    #[tokio::test]
    async fn upload_filter_helper() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let report = setup_report(&task, &datastore, &clock).await;

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (part, body) = warp::test::request()
            .method("POST")
            .path("/upload")
            .body(report.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:error:unrecognizedTask",
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
            VdafInstance::Prio3Aes128Count,
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
        // TODO (issue #34): change this error type.
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::StaleReport(stale_nonce, task_id)) => {
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
        let associated_data = associated_data_for_report_share(report.nonce(), report.extensions());

        let leader_ciphertext = hpke::seal(
            hpke_config,
            &HpkeApplicationInfo::new(
                report.task_id(),
                Label::InputShare,
                Role::Client,
                Role::Leader,
            ),
            message,
            &associated_data,
        )
        .unwrap();

        let helper_ciphertext = hpke::seal(
            hpke_config,
            &HpkeApplicationInfo::new(
                report.task_id(),
                Label::InputShare,
                Role::Client,
                Role::Helper,
            ),
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
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::ReportFromTheFuture(nonce, task_id)) => {
            assert_eq!(task_id, report.task_id());
            assert_eq!(report.nonce(), nonce);
        });
    }

    #[tokio::test]
    async fn aggregate_leader() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let request = AggregateReq {
            task_id,
            job_id: AggregationJobId::random(),
            body: AggregateInitReq {
                agg_param: Vec::new(),
                seq: Vec::new(),
            },
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (part, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert!(!part.status.is_success());
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let problem_details: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": 400,
                "type": "urn:ietf:params:ppm:error:unrecognizedTask",
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

    #[tokio::test]
    async fn aggregate_wrong_agg_auth_key() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let request = AggregateReq {
            task_id,
            job_id: AggregationJobId::random(),
            body: AggregateInitReq {
                agg_param: Vec::new(),
                seq: Vec::new(),
            },
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&generate_hmac_key()))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        let want_status = 400;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:error:invalidHmac",
                "title": "The aggregate message's HMAC was not valid.",
                "detail": "The aggregate message's HMAC was not valid.",
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
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        task.vdaf_verify_parameters = vec![verify_params.iter().last().unwrap().get_encoded()];
        let hpke_key = current_hpke_key(&task.hpke_keys);
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        // report_share_0 is a "happy path" report.
        let nonce_0 = Nonce::generate(&clock);
        let input_share = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce_0, &0)
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
        let associated_data = associated_data_for_report_share(nonce_2, &[]);
        let report_share_2 = generate_helper_report_share_for_plaintext(
            task_id,
            nonce_2,
            &hpke_key.0,
            &input_share_bytes,
            &associated_data,
        );

        // report_share_3 has an unknown HPKE config ID.
        let nonce_3 = Nonce::generate(&clock);
        let wrong_hpke_config = HpkeConfig::new(
            HpkeConfigId::from(u8::from(hpke_key.0.id()) + 1),
            hpke_key.0.kem_id(),
            hpke_key.0.kdf_id(),
            hpke_key.0.aead_id(),
            hpke_key.0.public_key().clone(),
        );
        let report_share_3 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_3,
            &wrong_hpke_config,
            &input_share,
        );

        let request = AggregateReq {
            task_id,
            job_id: AggregationJobId::random(),
            body: AggregateInitReq {
                agg_param: Vec::new(),
                seq: vec![
                    report_share_0.clone(),
                    report_share_1.clone(),
                    report_share_2.clone(),
                    report_share_3.clone(),
                ],
            },
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp: AggregateResp =
            AuthenticatedResponseDecoder::new(Vec::from(body_bytes.as_ref()))
                .unwrap()
                .decode([&hmac_key])
                .unwrap();

        // Validate response.
        assert_eq!(aggregate_resp.seq.len(), 4);

        let transition_0 = aggregate_resp.seq.get(0).unwrap();
        assert_eq!(transition_0.nonce, report_share_0.nonce);
        assert_matches!(
            transition_0.trans_data,
            TransitionTypeSpecificData::Continued { .. }
        );

        let transition_1 = aggregate_resp.seq.get(1).unwrap();
        assert_eq!(transition_1.nonce, report_share_1.nonce);
        assert_matches!(
            transition_1.trans_data,
            TransitionTypeSpecificData::Failed {
                error: TransitionError::HpkeDecryptError
            }
        );

        let transition_2 = aggregate_resp.seq.get(2).unwrap();
        assert_eq!(transition_2.nonce, report_share_2.nonce);
        assert_matches!(
            transition_2.trans_data,
            TransitionTypeSpecificData::Failed {
                error: TransitionError::VdafPrepError
            }
        );

        let transition_3 = aggregate_resp.seq.get(3).unwrap();
        assert_eq!(transition_3.nonce, report_share_3.nonce);
        assert_matches!(
            transition_3.trans_data,
            TransitionTypeSpecificData::Failed {
                error: TransitionError::HpkeUnknownConfigId
            }
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
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let report_share = generate_helper_report_share::<fake::Vdaf>(
            task_id,
            Nonce::generate(&clock),
            &hpke_key.0,
            &(),
        );
        let request = AggregateReq {
            task_id,
            job_id: AggregationJobId::random(),
            body: AggregateInitReq {
                agg_param: Vec::new(),
                seq: vec![report_share.clone()],
            },
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp: AggregateResp =
            AuthenticatedResponseDecoder::new(Vec::from(body_bytes.as_ref()))
                .unwrap()
                .decode([&hmac_key])
                .unwrap();

        // Validate response.
        assert_eq!(aggregate_resp.seq.len(), 1);

        let transition = aggregate_resp.seq.get(0).unwrap();
        assert_eq!(transition.nonce, report_share.nonce);
        assert_matches!(
            transition.trans_data,
            TransitionTypeSpecificData::Failed {
                error: TransitionError::VdafPrepError,
            }
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
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let report_share = generate_helper_report_share::<fake::Vdaf>(
            task_id,
            Nonce::generate(&clock),
            &hpke_key.0,
            &(),
        );
        let request = AggregateReq {
            task_id,
            job_id: AggregationJobId::random(),
            body: AggregateInitReq {
                agg_param: Vec::new(),
                seq: vec![report_share.clone()],
            },
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp: AggregateResp =
            AuthenticatedResponseDecoder::new(Vec::from(body_bytes.as_ref()))
                .unwrap()
                .decode([&hmac_key])
                .unwrap();

        // Validate response.
        assert_eq!(aggregate_resp.seq.len(), 1);

        let transition = aggregate_resp.seq.get(0).unwrap();
        assert_eq!(transition.nonce, report_share.nonce);
        assert_matches!(
            transition.trans_data,
            TransitionTypeSpecificData::Failed {
                error: TransitionError::VdafPrepError,
            }
        );
    }

    #[tokio::test]
    async fn aggregate_init_duplicated_nonce() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::FakeFailsPrepInit, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;

        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

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

        let request = AggregateReq {
            task_id,
            job_id: AggregationJobId::random(),
            body: AggregateInitReq {
                agg_param: Vec::new(),
                seq: vec![report_share.clone(), report_share],
            },
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        let want_status = 400;
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:error:unrecognizedMessage",
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
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Helper);
        let clock = MockClock::default();
        let (datastore, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let datastore = Arc::new(datastore);

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        task.vdaf_verify_parameters = vec![verify_params.iter().last().unwrap().get_encoded()];
        let hpke_key = current_hpke_key(&task.hpke_keys);
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

        // report_share_0 is a "happy path" report.
        let nonce_0 = Nonce::generate(&clock);
        let transcript_0 = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce_0, &0);
        let prep_step_0 = assert_matches!(&transcript_0.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_0 = assert_matches!(&transcript_0.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_0 = transcript_0.combined_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_0,
            &hpke_key.0,
            &transcript_0.input_shares[1],
        );

        // report_share_1 is omitted by the leader's request.
        let nonce_1 = Nonce::generate(&clock);
        let transcript_1 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_1, &0);
        let prep_step_1 = assert_matches!(&transcript_1.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let report_share_1 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_1,
            &hpke_key.0,
            &transcript_1.input_shares[1],
        );

        datastore
            .run_tx(|tx| {
                let task = task.clone();
                let (report_share_0, report_share_1) =
                    (report_share_0.clone(), report_share_1.clone());
                let (prep_step_0, prep_step_1) = (prep_step_0.clone(), prep_step_1.clone());

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(task_id, &report_share_0).await?;
                    tx.put_report_share(task_id, &report_share_1).await?;

                    tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id,
                        task_id,
                        nonce: nonce_0,
                        ord: 0,
                        state: ReportAggregationState::Waiting(prep_step_0, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id,
                        task_id,
                        nonce: nonce_1,
                        ord: 1,
                        state: ReportAggregationState::Waiting(prep_step_1, None),
                    })
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateContinueReq {
                seq: vec![Transition {
                    nonce: nonce_0,
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: prep_msg_0.get_encoded(),
                    },
                }],
            },
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        let mut response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(response.body_mut()).await.unwrap();
        let aggregate_resp: AggregateResp =
            AuthenticatedResponseDecoder::new(Vec::from(body_bytes.as_ref()))
                .unwrap()
                .decode([&hmac_key])
                .unwrap();

        // Validate response.
        assert_eq!(
            aggregate_resp,
            AggregateResp {
                seq: vec![Transition {
                    nonce: nonce_0,
                    trans_data: TransitionTypeSpecificData::Finished,
                }]
            }
        );

        // Validate datastore.
        let (aggregation_job, report_aggregations) = datastore
            .run_tx(|tx| {
                let verify_params = verify_params.clone();

                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<Prio3Aes128Count>(
                            &verify_params[1].clone(),
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
                    state: ReportAggregationState::Failed(TransitionError::ReportDropped),
                },
            ]
        );
    }

    #[tokio::test]
    async fn aggregate_continue_accumulate_batch_unit_aggregation() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let aggregation_job_id_0 = AggregationJobId::random();
        let aggregation_job_id_1 = AggregationJobId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore(MockClock::default()).await;
        let datastore = Arc::new(datastore);
        let first_batch_unit_interval_clock = MockClock::default();
        let second_batch_unit_interval_clock = MockClock::new(
            first_batch_unit_interval_clock
                .now()
                .add(task.min_batch_duration)
                .unwrap(),
        );

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (_, verify_params) = vdaf.setup().unwrap();
        task.vdaf_verify_parameters = vec![verify_params.iter().last().unwrap().get_encoded()];
        let hpke_key = current_hpke_key(&task.hpke_keys);
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

        // report_share_0 is a "happy path" report.
        let nonce_0 = Nonce::generate(&first_batch_unit_interval_clock);
        let transcript_0 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_0, &0);
        let prep_step_0 = assert_matches!(&transcript_0.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_0 = assert_matches!(&transcript_0.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_0 = transcript_0.combined_messages[0].clone();
        let report_share_0 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_0,
            &hpke_key.0,
            &transcript_0.input_shares[1],
        );

        // report_share_1 is another "happy path" report to exercise in-memory accumulation of
        // output shares
        let nonce_1 = Nonce::generate(&first_batch_unit_interval_clock);
        let transcript_1 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_1, &0);
        let prep_step_1 = assert_matches!(&transcript_1.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_1 = assert_matches!(&transcript_1.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_1 = transcript_1.combined_messages[0].clone();
        let report_share_1 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_1,
            &hpke_key.0,
            &transcript_1.input_shares[1],
        );

        // report share 2 aggregates successfully, but into a distinct batch unit aggregation.
        let nonce_2 = Nonce::generate(&second_batch_unit_interval_clock);
        let transcript_2 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_2, &0);
        let prep_step_2 = assert_matches!(&transcript_2.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_2 = assert_matches!(&transcript_2.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_2 = transcript_2.combined_messages[0].clone();
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
                let (prep_step_0, prep_step_1, prep_step_2) = (
                    prep_step_0.clone(),
                    prep_step_1.clone(),
                    prep_step_2.clone(),
                );

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_report_share(task_id, &report_share_0).await?;
                    tx.put_report_share(task_id, &report_share_1).await?;
                    tx.put_report_share(task_id, &report_share_2).await?;

                    tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        nonce: nonce_0,
                        ord: 0,
                        state: ReportAggregationState::Waiting(prep_step_0, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        nonce: nonce_1,
                        ord: 1,
                        state: ReportAggregationState::Waiting(prep_step_1, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_0,
                        task_id,
                        nonce: nonce_2,
                        ord: 2,
                        state: ReportAggregationState::Waiting(prep_step_2, None),
                    })
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id_0,
            body: AggregateContinueReq {
                seq: vec![
                    Transition {
                        nonce: nonce_0,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: prep_msg_0.get_encoded(),
                        },
                    },
                    Transition {
                        nonce: nonce_1,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: prep_msg_1.get_encoded(),
                        },
                    },
                    Transition {
                        nonce: nonce_2,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: prep_msg_2.get_encoded(),
                        },
                    },
                ],
            },
        };

        // Create aggregator filter, send request, and parse response.
        let filter =
            aggregator_filter(datastore.clone(), first_batch_unit_interval_clock.clone()).unwrap();

        let response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let batch_unit_aggregations = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_batch_unit_aggregations_for_task_in_interval::<Prio3Aes128Count>(
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
                BatchUnitAggregation::<Prio3Aes128Count> {
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
                BatchUnitAggregation::<Prio3Aes128Count> {
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
        let transcript_3 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_3, &0);
        let prep_step_3 = assert_matches!(&transcript_3.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_3 = assert_matches!(&transcript_3.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_3 = transcript_3.combined_messages[0].clone();
        let report_share_3 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_3,
            &hpke_key.0,
            &transcript_3.input_shares[1],
        );

        // report_share_4 gets aggregated into the second batch unit interval
        let nonce_4 = Nonce::generate(&second_batch_unit_interval_clock);
        let transcript_4 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_4, &0);
        let prep_step_4 = assert_matches!(&transcript_4.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_4 = assert_matches!(&transcript_4.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_4 = transcript_4.combined_messages[0].clone();
        let report_share_4 = generate_helper_report_share::<Prio3Aes128Count>(
            task_id,
            nonce_4,
            &hpke_key.0,
            &transcript_4.input_shares[1],
        );

        // report share 5 also gets aggregated into the second batch unit interval
        let nonce_5 = Nonce::generate(&second_batch_unit_interval_clock);
        let transcript_5 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_5, &0);
        let prep_step_5 = assert_matches!(&transcript_5.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_5 = assert_matches!(&transcript_5.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_5 = transcript_5.combined_messages[0].clone();
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
                let (prep_step_3, prep_step_4, prep_step_5) = (
                    prep_step_3.clone(),
                    prep_step_4.clone(),
                    prep_step_5.clone(),
                );

                Box::pin(async move {
                    tx.put_report_share(task_id, &report_share_3).await?;
                    tx.put_report_share(task_id, &report_share_4).await?;
                    tx.put_report_share(task_id, &report_share_5).await?;

                    tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        nonce: nonce_3,
                        ord: 3,
                        state: ReportAggregationState::Waiting(prep_step_3, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        nonce: nonce_4,
                        ord: 4,
                        state: ReportAggregationState::Waiting(prep_step_4, None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id: aggregation_job_id_1,
                        task_id,
                        nonce: nonce_5,
                        ord: 5,
                        state: ReportAggregationState::Waiting(prep_step_5, None),
                    })
                    .await?;

                    Ok(())
                })
            })
            .await
            .unwrap();

        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id_1,
            body: AggregateContinueReq {
                seq: vec![
                    Transition {
                        nonce: nonce_3,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: prep_msg_3.get_encoded(),
                        },
                    },
                    Transition {
                        nonce: nonce_4,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: prep_msg_4.get_encoded(),
                        },
                    },
                    Transition {
                        nonce: nonce_5,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: prep_msg_5.get_encoded(),
                        },
                    },
                ],
            },
        };

        // Create aggregator filter, send request, and parse response.
        let filter = aggregator_filter(datastore.clone(), first_batch_unit_interval_clock).unwrap();

        let response = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let batch_unit_aggregations = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_batch_unit_aggregations_for_task_in_interval::<Prio3Aes128Count>(
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
                BatchUnitAggregation::<Prio3Aes128Count> {
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
                BatchUnitAggregation::<Prio3Aes128Count> {
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

        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

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
                    tx.put_aggregation_job(&AggregationJob::<fake::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<fake::Vdaf> {
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
        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateContinueReq {
                seq: vec![Transition {
                    nonce,
                    trans_data: TransitionTypeSpecificData::Finished,
                }],
            },
        };

        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:unrecognizedMessage",
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

        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

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
                    tx.put_aggregation_job(&AggregationJob::<fake::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<fake::Vdaf> {
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
        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateContinueReq {
                seq: vec![Transition {
                    nonce,
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::new(),
                    },
                }],
            },
        };

        let filter = aggregator_filter(datastore.clone(), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(body).await.unwrap();
        let aggregate_resp: AggregateResp =
            AuthenticatedResponseDecoder::new(Vec::from(body_bytes.as_ref()))
                .unwrap()
                .decode([&hmac_key])
                .unwrap();
        assert_eq!(
            aggregate_resp,
            AggregateResp {
                seq: vec![Transition {
                    nonce,
                    trans_data: TransitionTypeSpecificData::Failed {
                        error: TransitionError::VdafPrepError
                    }
                }]
            }
        );

        // Check datastore state.
        let (aggregation_job, report_aggregation) = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<fake::Vdaf>(task_id, aggregation_job_id)
                        .await?;
                    let report_aggregation = tx
                        .get_report_aggregation::<fake::Vdaf>(
                            &(),
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
                state: ReportAggregationState::Failed(TransitionError::VdafPrepError),
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

        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

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
                    tx.put_aggregation_job(&AggregationJob::<fake::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<fake::Vdaf> {
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
        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateContinueReq {
                seq: vec![Transition {
                    nonce: Nonce::new(
                        Time::from_seconds_since_epoch(54321),
                        [8, 7, 6, 5, 4, 3, 2, 1], // not the same as above
                    ),
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::new(),
                    },
                }],
            },
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:unrecognizedMessage",
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

        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

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

                    tx.put_aggregation_job(&AggregationJob::<fake::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<fake::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        nonce: nonce_0,
                        ord: 0,
                        state: ReportAggregationState::Waiting((), None),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<fake::Vdaf> {
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
        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateContinueReq {
                seq: vec![
                    // nonces are in opposite order to what was stored in the datastore.
                    Transition {
                        nonce: nonce_1,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: Vec::new(),
                        },
                    },
                    Transition {
                        nonce: nonce_0,
                        trans_data: TransitionTypeSpecificData::Continued {
                            payload: Vec::new(),
                        },
                    },
                ],
            },
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:unrecognizedMessage",
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

        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

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
                    tx.put_aggregation_job(&AggregationJob::<fake::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        aggregation_param: (),
                        state: AggregationJobState::InProgress,
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<fake::Vdaf> {
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
        let request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateContinueReq {
                seq: vec![Transition {
                    nonce: Nonce::new(
                        Time::from_seconds_since_epoch(54321),
                        [1, 2, 3, 4, 5, 6, 7, 8],
                    ),
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::new(),
                    },
                }],
            },
        };

        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate")
            .body(AuthenticatedEncoder::new(request).encode(&hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        // Check that response is as desired.
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:unrecognizedMessage",
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
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:unrecognizedTask",
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
            .body(request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:invalidBatchInterval",
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
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
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

        // Update the collect job with the leader share. Collect job should still not be complete.
        datastore
            .run_tx(|tx| {
                let leader_aggregate_share = leader_aggregate_share.clone();
                Box::pin(async move {
                    tx.update_collect_job_leader_aggregate_share::<Prio3Aes128Count>(
                        collect_job_id,
                        &leader_aggregate_share,
                        10,
                        NonceChecksum::get_decoded(&[1; 32]).unwrap(),
                    )
                    .await
                    .unwrap();

                    Ok(())
                })
            })
            .await
            .unwrap();

        let collect_job_response = warp::test::request()
            .method("GET")
            .path(&format!("/collect_jobs/{}", collect_job_id))
            .filter(&filter)
            .await
            .unwrap()
            .into_response();
        assert_eq!(collect_job_response.status(), StatusCode::ACCEPTED);

        // Update the collect job with the helper's share. Collect job should now be complete.
        datastore
            .run_tx(|tx| {
                let collector_hpke_config = task.collector_hpke_config.clone();
                let helper_aggregate_share_bytes: Vec<u8> = (&helper_aggregate_share).into();
                Box::pin(async move {
                    let encrypted_helper_aggregate_share = hpke::seal(
                        &collector_hpke_config,
                        &HpkeApplicationInfo::new(
                            task.id,
                            Label::AggregateShare,
                            Role::Helper,
                            Role::Collector,
                        ),
                        &helper_aggregate_share_bytes,
                        &batch_interval.get_encoded(),
                    )
                    .unwrap();

                    tx.update_collect_job_helper_aggregate_share::<Prio3Aes128Count, _>(
                        collect_job_id,
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
        let body_bytes = hyper::body::to_bytes(body).await.unwrap();

        let collect_resp = CollectResp::get_decoded(body_bytes.as_ref()).unwrap();
        assert_eq!(collect_resp.encrypted_agg_shares.len(), 2);

        let decrypted_leader_aggregate_share = hpke::open(
            &task.collector_hpke_config,
            &collector_hpke_recipient,
            &HpkeApplicationInfo::new(
                task_id,
                Label::AggregateShare,
                Role::Leader,
                Role::Collector,
            ),
            &collect_resp.encrypted_agg_shares[0],
            &batch_interval.get_encoded(),
        )
        .unwrap();
        assert_eq!(
            leader_aggregate_share,
            AggregateShare::try_from(decrypted_leader_aggregate_share.as_ref()).unwrap()
        );

        let decrypted_helper_aggregate_share = hpke::open(
            &task.collector_hpke_config,
            &collector_hpke_recipient,
            &HpkeApplicationInfo::new(
                task_id,
                Label::AggregateShare,
                Role::Helper,
                Role::Collector,
            ),
            &collect_resp.encrypted_agg_shares[1],
            &batch_interval.get_encoded(),
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

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<fake::Vdaf> {
                        task_id: task.id,
                        unit_interval_start: Time::from_seconds_since_epoch(0),
                        aggregation_param: (),
                        aggregate_share: fake::AggregateShare(),
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
            .body(invalid_request.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:batchLifetimeExceeded",
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
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();

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
            .body(AuthenticatedEncoder::new(request).encode(hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:unrecognizedTask",
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
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();

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
            .path("/aggregate_share")
            .body(AuthenticatedEncoder::new(request).encode(hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:invalidBatchInterval",
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

        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Helper);
        task.max_batch_lifetime = 3;
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        task.collector_hpke_config = collector_hpke_config.clone();
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let aggregation_param = ();

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
            .body(AuthenticatedEncoder::new(request).encode(hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:insufficientBatchSize",
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
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<Prio3Aes128Count> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(500),
                        aggregation_param,
                        aggregate_share: AggregateShare::from(vec![Field64::from(64)]),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[3; 32]).unwrap(),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<Prio3Aes128Count> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(1500),
                        aggregation_param,
                        aggregate_share: AggregateShare::from(vec![Field64::from(128)]),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[2; 32]).unwrap(),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<Prio3Aes128Count> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(2000),
                        aggregation_param,
                        aggregate_share: AggregateShare::from(vec![Field64::from(256)]),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[4; 32]).unwrap(),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<Prio3Aes128Count> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(2500),
                        aggregation_param,
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
            .body(AuthenticatedEncoder::new(request).encode(hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:insufficientBatchSize",
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
                .body(AuthenticatedEncoder::new(misaligned_request).encode(hmac_key))
                .filter(&filter)
                .await
                .unwrap()
                .into_response()
                .into_parts();

            assert_eq!(parts.status, StatusCode::BAD_REQUEST);
            let problem_details: serde_json::Value =
                serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
            assert_eq!(
                problem_details,
                serde_json::json!({
                    "status": StatusCode::BAD_REQUEST.as_u16(),
                    "type": "urn:ietf:params:ppm:error:batchMisaligned",
                    "title": "The checksums or report counts in the two aggregator's aggregate shares do not match.",
                    "detail": "The checksums or report counts in the two aggregator's aggregate shares do not match.",
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
                    .body(AuthenticatedEncoder::new(request.clone()).encode(hmac_key))
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
                let body_bytes = hyper::body::to_bytes(body).await.unwrap();

                let aggregate_share_resp: AggregateShareResp =
                    AuthenticatedResponseDecoder::new(body_bytes.as_ref())
                        .unwrap()
                        .decode([hmac_key])
                        .unwrap();

                let aggregate_share = hpke::open(
                    &collector_hpke_config,
                    &collector_hpke_recipient,
                    &HpkeApplicationInfo::new(
                        task_id,
                        Label::AggregateShare,
                        Role::Helper,
                        Role::Collector,
                    ),
                    &aggregate_share_resp.encrypted_aggregate_share,
                    &request.batch_interval.get_encoded(),
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
            .body(AuthenticatedEncoder::new(batch_lifetime_violation_request).encode(hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        let problem_details: serde_json::Value =
            serde_json::from_slice(&hyper::body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            serde_json::json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:error:batchLifetimeExceeded",
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
        let associated_data = associated_data_for_report_share(nonce, &[]);
        generate_helper_report_share_for_plaintext(
            task_id,
            nonce,
            cfg,
            &input_share.get_encoded(),
            &associated_data,
        )
    }

    fn generate_helper_report_share_for_plaintext(
        task_id: TaskId,
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
                &HpkeApplicationInfo::new(task_id, Label::InputShare, Role::Client, Role::Helper),
                plaintext,
                associated_data,
            )
            .unwrap(),
        }
    }

    fn generate_hmac_key() -> hmac::Key {
        hmac::Key::generate(HMAC_SHA256, &SystemRandom::new()).unwrap()
    }
}
