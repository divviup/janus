//! Common functionality for PPM aggregators
use crate::{
    datastore::{
        self,
        models::{AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState},
        Datastore,
    },
    hpke::{self, HpkeApplicationInfo, Label},
    message::{
        AggregateReq,
        AggregateReqBody::{AggregateContinueReq, AggregateInitReq},
        AggregateResp, AggregateShareReq, AggregateShareResp, AggregationJobId,
        AuthenticatedDecodeError, AuthenticatedEncoder, AuthenticatedRequestDecoder, CollectReq,
        HpkeConfig, HpkeConfigId, Interval, Nonce, Report, ReportShare, Role, TaskId, Transition,
        TransitionError, TransitionTypeSpecificData,
    },
    task::{self, AggregatorAuthKey, Task},
    time::Clock,
};
use bytes::Bytes;
use futures::try_join;
use http::{
    header::{CACHE_CONTROL, LOCATION},
    StatusCode,
};
use opentelemetry::{
    metrics::{Counter, Unit, ValueRecorder},
    KeyValue,
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    field::FieldError,
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
use tracing::{error, warn};
use url::Url;
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
    Message(#[from] crate::message::Error),
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
        own_checksum: [u8; 32],
        own_report_count: u64,
        peer_checksum: [u8; 32],
        peer_report_count: u64,
    },
    /// Too many queries against a single batch.
    #[error("Maxiumum batch lifetime for task {0:?} exceeded")]
    BatchLifetimeExceeded(TaskId),
    /// HPKE failure.
    #[error("HPKE error: {0}")]
    Hpke(#[from] crate::hpke::Error),
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
    datastore: Arc<Datastore>,
    /// Clock used to sample time.
    clock: C,
    /// Cache of task aggregators.
    task_aggregators: Mutex<HashMap<TaskId, Arc<TaskAggregator>>>,
}

impl<C: Clock> Aggregator<C> {
    fn new(datastore: Arc<Datastore>, clock: C) -> Self {
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

        let task_aggregator = self.task_aggregator_for(report.task_id).await?;
        // Only the leader supports upload.
        if task_aggregator.task.role != Role::Leader {
            return Err(Error::UnrecognizedTask(report.task_id));
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
        let key = task_aggregator.current_aggregator_auth_key();
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
        for key in task_aggregator.task.agg_auth_keys.iter().rev() {
            match decoder.decode(key.as_ref()) {
                Ok(decoded_body) => return Ok((task_aggregator, decoded_body)),
                Err(AuthenticatedDecodeError::InvalidHmac) => continue, // try the next key
                Err(AuthenticatedDecodeError::Codec(err)) => return Err(Error::MessageDecode(err)),
            }
        }
        // If we get here, every available key returned InvalidHmac.
        Err(Error::InvalidHmac(task_id))
    }

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
        Ok(AuthenticatedEncoder::new(resp)
            .encode(task_aggregator.current_aggregator_auth_key().as_ref()))
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
        let vdaf_ops = match &task.vdaf {
            task::Vdaf::Prio3Aes128Count => {
                let vdaf = Prio3Aes128Count::new(2)?;
                let verify_param = <Prio3Aes128Count as Vdaf>::VerifyParam::get_decoded_with_param(
                    &vdaf,
                    &task.vdaf_verify_parameter,
                )?;
                VdafOps::Prio3Aes128Count(vdaf, verify_param)
            }

            task::Vdaf::Prio3Aes128Sum { bits } => {
                let vdaf = Prio3Aes128Sum::new(2, *bits)?;
                let verify_param = <Prio3Aes128Sum as Vdaf>::VerifyParam::get_decoded_with_param(
                    &vdaf,
                    &task.vdaf_verify_parameter,
                )?;
                VdafOps::Prio3Aes128Sum(vdaf, verify_param)
            }

            task::Vdaf::Prio3Aes128Histogram { buckets } => {
                let vdaf = Prio3Aes128Histogram::new(2, &*buckets)?;
                let verify_param =
                    <Prio3Aes128Histogram as Vdaf>::VerifyParam::get_decoded_with_param(
                        &vdaf,
                        &task.vdaf_verify_parameter,
                    )?;
                VdafOps::Prio3Aes128Histogram(vdaf, verify_param)
            }

            #[cfg(test)]
            task::Vdaf::Fake => VdafOps::Fake(fake::Vdaf::new()),

            #[cfg(test)]
            task::Vdaf::FakeFailsPrepInit => VdafOps::Fake(fake::Vdaf::new().with_prep_init_fn(
                || -> Result<(), VdafError> {
                    Err(VdafError::Uncategorized(
                        "FakeFailsPrepInit failed at prep_init".to_string(),
                    ))
                },
            )),

            #[cfg(test)]
            task::Vdaf::FakeFailsPrepStep => VdafOps::Fake(fake::Vdaf::new().with_prep_step_fn(
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

    /// Returns the [`AggregatorAuthKey`] currently used by this aggregator's task to authenticate
    /// aggregate messages.
    fn current_aggregator_auth_key(&self) -> &AggregatorAuthKey {
        self.task.agg_auth_keys.last().unwrap()
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
        datastore: &Datastore,
        clock: &C,
        report: Report,
    ) -> Result<(), Error> {
        // §4.2.2 The leader's report is the first one
        if report.encrypted_input_shares.len() != 2 {
            warn!(
                share_count = report.encrypted_input_shares.len(),
                "Unexpected number of encrypted shares in report"
            );
            return Err(Error::UnrecognizedMessage(
                "unexpected number of encrypted shares in report",
                Some(report.task_id),
            ));
        }
        let leader_report = &report.encrypted_input_shares[0];

        // §4.2.2: verify that the report's HPKE config ID is known
        let (hpke_config, hpke_private_key) = self
            .task
            .hpke_keys
            .get(&leader_report.config_id)
            .ok_or_else(|| {
                warn!(
                    config_id = ?leader_report.config_id,
                    "Unknown HPKE config ID"
                );
                Error::OutdatedHpkeConfig(leader_report.config_id, report.task_id)
            })?;

        let report_deadline = clock.now().add(self.task.tolerable_clock_skew)?;

        // §4.2.4: reject reports from too far in the future
        if report.nonce.time().is_after(report_deadline) {
            warn!(?report.task_id, ?report.nonce, "Report timestamp exceeds tolerable clock skew");
            return Err(Error::ReportFromTheFuture(report.nonce, report.task_id));
        }

        // Check that we can decrypt the report. This isn't required by the spec
        // but this exercises HPKE decryption and saves us the trouble of
        // storing reports we can't use. We don't inform the client if this
        // fails.
        if let Err(err) = hpke::open(
            hpke_config,
            hpke_private_key,
            &HpkeApplicationInfo::new(
                report.task_id,
                Label::InputShare,
                Role::Client,
                self.task.role,
            ),
            leader_report,
            &report.associated_data(),
        ) {
            warn!(?report.task_id, ?report.nonce, ?err, "Report decryption failed");
            return Ok(());
        }

        datastore
            .run_tx(|tx| {
                let report = report.clone();
                Box::pin(async move {
                    // §4.2.2 and 4.3.2.2: reject reports whose nonce has been seen before.
                    if tx
                        .get_client_report(report.task_id, report.nonce)
                        .await?
                        .is_some()
                    {
                        warn!(?report.task_id, ?report.nonce, "Report replayed");
                        // TODO (issue #34): change this error type.
                        return Err(datastore::Error::User(
                            Error::StaleReport(report.nonce, report.task_id).into(),
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

    async fn handle_aggregate(
        &self,
        datastore: &Datastore,
        req: AggregateReq,
    ) -> Result<AggregateResp, Error> {
        self.vdaf_ops
            .handle_aggregate(datastore, &self.task, req)
            .await
    }

    async fn handle_collect(&self, datastore: &Datastore, req: CollectReq) -> Result<Url, Error> {
        // §4.5: check that the batch interval meets the requirements from §4.6
        if !self.task.validate_batch_interval(req.batch_interval) {
            return Err(Error::InvalidBatchInterval(
                req.batch_interval,
                self.task.id,
            ));
        }

        let collect_job_uuid = datastore
            .run_tx(move |tx| {
                let aggregation_param = req.agg_param.clone();
                Box::pin(async move {
                    let collect_job_uuid = tx
                        .get_collect_job_uuid(req.task_id, req.batch_interval, &aggregation_param)
                        .await?;

                    match collect_job_uuid {
                        Some(uuid) => Ok(uuid),
                        None => {
                            tx.put_collect_job(req.task_id, req.batch_interval, &aggregation_param)
                                .await
                        }
                    }
                })
            })
            .await?;

        // TODO(timg): Aggregator configuration needs to include the URL from which collect job URIs
        // are constructed
        let base_url = Url::parse("https://example.com").unwrap();

        Ok(base_url
            .join("collect_jobs/")?
            .join(&collect_job_uuid.to_string())?)
    }

    async fn handle_aggregate_share(
        &self,
        datastore: &Datastore,
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
    async fn handle_aggregate(
        &self,
        datastore: &Datastore,
        task: &Task,
        req: AggregateReq,
    ) -> Result<AggregateResp, Error> {
        match self {
            VdafOps::Prio3Aes128Count(vdaf, verify_param) => {
                Self::handle_aggregate_generic(datastore, vdaf, task, verify_param, req).await
            }
            VdafOps::Prio3Aes128Sum(vdaf, verify_param) => {
                Self::handle_aggregate_generic(datastore, vdaf, task, verify_param, req).await
            }
            VdafOps::Prio3Aes128Histogram(vdaf, verify_param) => {
                Self::handle_aggregate_generic(datastore, vdaf, task, verify_param, req).await
            }

            #[cfg(test)]
            VdafOps::Fake(vdaf) => {
                Self::handle_aggregate_generic(datastore, vdaf, task, &(), req).await
            }
        }
    }

    async fn handle_aggregate_generic<A: vdaf::Aggregator>(
        datastore: &Datastore,
        vdaf: &A,
        task: &Task,
        verify_param: &A::VerifyParam,
        req: AggregateReq,
    ) -> Result<AggregateResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
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
    async fn handle_aggregate_init_generic<A: vdaf::Aggregator>(
        datastore: &Datastore,
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
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareStep: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let task_id = task.id;

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
                .get(&report_share.encrypted_input_share.config_id)
                .ok_or_else(|| {
                    warn!(
                        config_id = ?report_share.encrypted_input_share.config_id,
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
                        agg_state: ReportAggregationState::<A>::Waiting(prep_step),
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
                    }
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

    async fn handle_aggregate_continue_generic<A: vdaf::Aggregator>(
        datastore: &Datastore,
        vdaf: &A,
        task: &Task,
        verify_param: &A::VerifyParam,
        job_id: AggregationJobId,
        transitions: Vec<Transition>,
    ) -> Result<AggregateResp, Error>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareStep: Send + Sync + Encode + ParameterizedDecode<A::VerifyParam>,
        A::PrepareMessage: Send + Sync,
        A::OutputShare: Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::VerifyParam: Send + Sync,
    {
        let task_id = task.id;
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
                                if matches!(report_agg.state, ReportAggregationState::Waiting(_)) {
                                    report_agg.state = ReportAggregationState::Failed(TransitionError::ReportDropped);
                                    tx.update_report_aggregation(&report_agg).await?;
                                }
                                continue;
                            }
                            break report_agg;
                        };
                        let prep_step =
                            match report_aggregation.state {
                                ReportAggregationState::Waiting(prep_step) => prep_step,
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
                                    ReportAggregationState::Waiting(prep_step);
                                response_transitions.push(Transition {
                                    nonce: transition.nonce,
                                    trans_data: TransitionTypeSpecificData::Continued {
                                        payload: prep_msg.get_encoded(),
                                    },
                                })
                            }

                            PrepareTransition::Finish(output_share) => {
                                saw_finish = true;
                                report_aggregation.state =
                                    ReportAggregationState::Finished(output_share);
                                response_transitions.push(Transition {
                                    nonce: transition.nonce,
                                    trans_data: TransitionTypeSpecificData::Finished,
                                });

                                // TODO(timg): when a report's preparation is done, its value should
                                // be accumulated into a batch_unit_aggregations row
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
                        if matches!(report_agg.state, ReportAggregationState::Waiting(_)) {
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

                    Ok(AggregateResp {
                        seq: response_transitions,
                    })
                })
            })
            .await?)
    }

    /// Implements the `/aggregate_share` endpoint for the helper, described in §4.4.4.3
    async fn handle_aggregate_share(
        &self,
        datastore: &Datastore,
        task: &Task,
        aggregate_share_req: &AggregateShareReq,
    ) -> Result<AggregateShareResp, Error> {
        match self {
            VdafOps::Prio3Aes128Count(_, _) => {
                Self::handle_aggregate_share_generic::<Prio3Aes128Count, FieldError>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }
            VdafOps::Prio3Aes128Sum(_, _) => {
                Self::handle_aggregate_share_generic::<Prio3Aes128Sum, FieldError>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }
            VdafOps::Prio3Aes128Histogram(_, _) => {
                Self::handle_aggregate_share_generic::<Prio3Aes128Histogram, FieldError>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }

            #[cfg(test)]
            VdafOps::Fake(_) => {
                Self::handle_aggregate_share_generic::<fake::Vdaf, Infallible>(
                    datastore,
                    task,
                    aggregate_share_req,
                )
                .await
            }
        }
    }

    async fn handle_aggregate_share_generic<A, E>(
        datastore: &Datastore,
        task: &Task,
        aggregate_share_req: &AggregateShareReq,
    ) -> Result<AggregateShareResp, Error>
    where
        A: vdaf::Aggregator,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        E: std::fmt::Display,
        for<'a> A::AggregateShare: TryFrom<&'a [u8], Error = E>,
    {
        // TODO(timg): What should we do if any of the aggregation jobs handling reports relevant to
        // the aggregate share request aren't finished yet? Helper could return an error like
        // "EAGAIN" to leader, or could trust leader not to issue an AggregateShareReq until all of
        // leader's aggregate jobs are done (which should imply that helper's are done).
        // See issue #104.

        let total_aggregate_share = datastore
            .run_tx(move |tx| {
                let task = task.clone();
                let aggregate_share_req = aggregate_share_req.clone();
                Box::pin(async move {
                    // TODO(timg) Look up the aggregate share req in the relevant table. If we've
                    // already computed that aggregate share, just serve it up.

                    // TODO(timg) For each batch unit in the request, check how many rows in
                    // aggregate_share_requests contain that unit, regardless of agg_param. Each
                    // such row consumes one of batch lifetime and we can check that against
                    // task.max_batch_lifetime.

                    let aggregation_param =
                        A::AggregationParam::get_decoded(&aggregate_share_req.aggregation_param)?;
                    let batch_unit_aggregations = tx
                        .get_batch_unit_aggregations_for_task_in_interval::<A>(
                            task.id,
                            aggregate_share_req.batch_interval,
                            &aggregation_param,
                        )
                        .await?;

                    let mut total_report_count = 0;
                    let mut total_checksum = [0u8; 32];
                    let mut total_aggregate_share: Option<A::AggregateShare> = None;

                    for batch_unit_aggregation in &batch_unit_aggregations {
                        // TODO(timg): enforce the max lifetime requirement from §4.6. We need to
                        // make sure that this minimum batch interval's aggregate share has not
                        // previously been included in a collect request with a different batch
                        // interval. This requires the helper to store the aggregate share requests
                        // it has serviced, perhaps in the collect_jobs table used by the leader.

                        // §4.4.4.3: XOR this batch interval's checksum into the overall checksum
                        total_checksum
                            .iter_mut()
                            .zip(batch_unit_aggregation.checksum)
                            .for_each(|(x, y)| *x ^= y);

                        // §4.4.4.3: Sum all the report counts
                        total_report_count += batch_unit_aggregation.report_count;

                        match &mut total_aggregate_share {
                            Some(share) => {
                                if let Err(err) =
                                    share.merge(&batch_unit_aggregation.aggregate_share)
                                {
                                    return Ok(Err(Error::from(err)));
                                }
                            }
                            None => {
                                total_aggregate_share =
                                    Some(batch_unit_aggregation.aggregate_share.clone())
                            }
                        }
                    }

                    // §4.6: refuse to service aggregate share requests if there are too few reports
                    // included.
                    if total_report_count < task.min_batch_size {
                        return Ok(Err(Error::InsufficientBatchSize(
                            total_report_count,
                            task.id,
                        )));
                    }

                    let total_aggregate_share = match total_aggregate_share {
                        Some(share) => share,
                        None => return Ok(Err(Error::InsufficientBatchSize(0, task.id))),
                    };

                    // §4.4.4.3: verify total report count and the checksum we computed against
                    // those reported by the leader.
                    if total_report_count != aggregate_share_req.report_count
                        || total_checksum != aggregate_share_req.checksum
                    {
                        return Ok(Err(Error::BatchMisalignment {
                            task_id: task.id,
                            own_checksum: total_checksum,
                            own_report_count: total_report_count,
                            peer_checksum: aggregate_share_req.checksum,
                            peer_report_count: aggregate_share_req.report_count,
                        }));
                    }

                    // TODO(timg): Once we are satisfied the request is serviceable, consume batch
                    // lifetime by storing the aggregate share request parameters. Make sure to do
                    // so in the same database txn where we queried the batch aggregations.

                    Ok(Ok(total_aggregate_share))
                })
            })
            .await??;

        // §4.4.4.3: HPKE encrypt aggregate share to the collector.
        let encrypted_aggregate_share = hpke::seal(
            &task.collector_hpke_config,
            &HpkeApplicationInfo::new(
                task.id,
                Label::AggregateShare,
                Role::Helper,
                Role::Collector,
            ),
            &<Vec<u8>>::from(&total_aggregate_share),
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
fn aggregator_filter<C>(
    datastore: Arc<Datastore>,
    clock: C,
) -> Result<BoxedFilter<(impl Reply,)>, Error>
where
    C: 'static + Clock,
{
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
        .or(aggregate_share_endpoint)
        .boxed())
}

/// Construct a PPM aggregator server, listening on the provided [`SocketAddr`].
/// If the `SocketAddr`'s `port` is 0, an ephemeral port is used. Returns a
/// `SocketAddr` representing the address and port the server are listening on
/// and a future that can be `await`ed to begin serving requests.
pub fn aggregator_server<C>(
    datastore: Arc<Datastore>,
    clock: C,
    listen_address: SocketAddr,
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()> + 'static), Error>
where
    C: 'static + Clock,
{
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
        hpke::{
            associated_data_for_report_share, test_util::generate_hpke_config_and_private_key,
            HpkePrivateKey, Label,
        },
        message::{
            AuthenticatedResponseDecoder, Duration, HpkeCiphertext, HpkeConfig, TaskId, Time,
        },
        task::{test_util::new_dummy_task, Vdaf},
        time::test_util::MockClock,
        trace::test_util::install_test_trace_subscriber,
    };
    use assert_matches::assert_matches;
    use http::Method;
    use prio::{
        codec::Decode,
        field::Field64,
        vdaf::{prio3::Prio3Aes128Count, AggregateShare},
        vdaf::{Vdaf as VdafTrait, VdafError},
    };
    use rand::{thread_rng, Rng};
    use ring::{
        hmac::{self, HMAC_SHA256},
        rand::SystemRandom,
    };
    use std::{collections::HashMap, io::Cursor};
    use warp::{reply::Reply, Rejection};

    type PrepareTransition<V> = vdaf::PrepareTransition<
        <V as vdaf::Aggregator>::PrepareStep,
        <V as vdaf::Aggregator>::PrepareMessage,
        <V as vdaf::Vdaf>::OutputShare,
    >;

    #[tokio::test]
    async fn hpke_config() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Leader);
        let (datastore, _db_handle) = ephemeral_datastore().await;

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
            .filter(&aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap())
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

    async fn setup_report(task: &Task, datastore: &Datastore, clock: &MockClock) -> Report {
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

        Report {
            task_id: task.id,
            nonce,
            extensions,
            encrypted_input_shares: vec![leader_ciphertext, helper_ciphertext],
        }
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

        let task = new_dummy_task(TaskId::random(), Vdaf::Prio3Aes128Count, Role::Leader);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

        let report = setup_report(&task, &datastore, &clock).await;
        let filter = aggregator_filter(Arc::new(datastore), clock).unwrap();

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
                "taskid": format!("{}", report.task_id),
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
        let mut bad_report = report.clone();
        bad_report.encrypted_input_shares.truncate(1);
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
                "taskid": format!("{}", report.task_id),
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
        let mut bad_report = report.clone();
        bad_report.encrypted_input_shares[0].config_id = HpkeConfigId::from(101);
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
                "taskid": format!("{}", report.task_id),
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
        let mut bad_report = report.clone();
        let bad_report_time = MockClock::default()
            .now()
            .add(Duration::from_minutes(10).unwrap())
            .unwrap()
            .add(Duration::from_seconds(1))
            .unwrap();
        bad_report.nonce = Nonce::new(bad_report_time, bad_report.nonce.rand());
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
        let task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
        Arc<Datastore>,
        DbHandle,
    ) {
        let task = new_dummy_task(TaskId::random(), Vdaf::Prio3Aes128Count, Role::Leader);
        let (datastore, db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let clock = MockClock::default();
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
                Box::pin(async move { tx.get_client_report(report.task_id, report.nonce).await })
            })
            .await
            .unwrap();
        assert_eq!(Some(&report), got_report.as_ref());

        // should reject duplicate reports.
        // TODO (issue #34): change this error type.
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::StaleReport(stale_nonce, task_id)) => {
            assert_eq!(task_id, report.task_id);
            assert_eq!(report.nonce, stale_nonce);
        });
    }

    #[tokio::test]
    async fn upload_wrong_number_of_encrypted_shares() {
        install_test_trace_subscriber();

        let (aggregator, _, mut report, _, _db_handle) = setup_upload_test().await;

        report.encrypted_input_shares = vec![report.encrypted_input_shares[0].clone()];

        assert_matches!(
            aggregator.handle_upload(&report.get_encoded()).await,
            Err(Error::UnrecognizedMessage(_, _))
        );
    }

    #[tokio::test]
    async fn upload_wrong_hpke_config_id() {
        install_test_trace_subscriber();

        let (aggregator, _, mut report, _, _db_handle) = setup_upload_test().await;

        report.encrypted_input_shares[0].config_id = HpkeConfigId::from(101);

        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::OutdatedHpkeConfig(config_id, task_id)) => {
            assert_eq!(task_id, report.task_id);
            assert_eq!(config_id, HpkeConfigId::from(101));
        });
    }

    fn reencrypt_report(report: Report, hpke_config: &HpkeConfig) -> Report {
        let message = b"this is a message";
        let associated_data = associated_data_for_report_share(report.nonce, &report.extensions);

        let leader_ciphertext = hpke::seal(
            hpke_config,
            &HpkeApplicationInfo::new(
                report.task_id,
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
                report.task_id,
                Label::InputShare,
                Role::Client,
                Role::Helper,
            ),
            message,
            &associated_data,
        )
        .unwrap();

        Report {
            task_id: report.task_id,
            nonce: report.nonce,
            extensions: report.extensions,
            encrypted_input_shares: vec![leader_ciphertext, helper_ciphertext],
        }
    }

    #[tokio::test]
    async fn upload_report_in_the_future() {
        install_test_trace_subscriber();

        let (aggregator, task, mut report, datastore, _db_handle) = setup_upload_test().await;

        // Boundary condition
        report.nonce = Nonce::new(
            aggregator
                .clock
                .now()
                .add(task.tolerable_clock_skew)
                .unwrap(),
            report.nonce.rand(),
        );
        let mut report = reencrypt_report(report, &task.hpke_keys.values().next().unwrap().0);
        aggregator
            .handle_upload(&report.get_encoded())
            .await
            .unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                Box::pin(async move { tx.get_client_report(report.task_id, report.nonce).await })
            })
            .await
            .unwrap();
        assert_eq!(Some(&report), got_report.as_ref());

        // Just past the clock skew
        report.nonce = Nonce::new(
            aggregator
                .clock
                .now()
                .add(task.tolerable_clock_skew)
                .unwrap()
                .add(Duration::from_seconds(1))
                .unwrap(),
            report.nonce.rand(),
        );
        let report = reencrypt_report(report, &task.hpke_keys.values().next().unwrap().0);
        assert_matches!(aggregator.handle_upload(&report.get_encoded()).await, Err(Error::ReportFromTheFuture(nonce, task_id)) => {
            assert_eq!(task_id, report.task_id);
            assert_eq!(report.nonce, nonce);
        });
    }

    #[tokio::test]
    async fn aggregate_leader() {
        install_test_trace_subscriber();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Leader);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
        let task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
        let mut task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (_, verify_params) = vdaf.setup().unwrap();
        task.vdaf_verify_parameter = verify_params.iter().last().unwrap().get_encoded();
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
        let input_share = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_0, &0)
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
        report_share_1.encrypted_input_share.payload[0] ^= 0xFF;

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
        let mut wrong_hpke_config = hpke_key.0.clone();
        wrong_hpke_config.id = HpkeConfigId::from(u8::from(wrong_hpke_config.id) + 1);
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
                .decode(&hmac_key)
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
        let task = new_dummy_task(task_id, Vdaf::FakeFailsPrepInit, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
                .decode(&hmac_key)
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
        let task = new_dummy_task(task_id, Vdaf::FakeFailsPrepInit, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
                .decode(&hmac_key)
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
        let task = new_dummy_task(task_id, Vdaf::FakeFailsPrepInit, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
            encrypted_input_share: HpkeCiphertext {
                // bogus, but we never get far enough to notice
                config_id: HpkeConfigId::from(42),
                encapsulated_context: Vec::from("012345"),
                payload: Vec::from("543210"),
            },
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
        let mut task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let clock = MockClock::default();

        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (_, verify_params) = vdaf.setup().unwrap();
        task.vdaf_verify_parameter = verify_params.iter().last().unwrap().get_encoded();
        let hpke_key = current_hpke_key(&task.hpke_keys);
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let hmac_key = hmac_key.clone();

        // report_share_0 is a "happy path" report.
        let nonce_0 = Nonce::generate(&clock);
        let transcript_0 = run_vdaf(&vdaf, &(), &verify_params, &(), nonce_0, &0);
        let prep_step_0 = assert_matches!(&transcript_0.transitions[1][0], PrepareTransition::<Prio3Aes128Count>::Continue(prep_step, _) => prep_step.clone());
        let out_share_0 = assert_matches!(&transcript_0.transitions[1][1], PrepareTransition::<Prio3Aes128Count>::Finish(out_share) => out_share.clone());
        let prep_msg_0 = transcript_0.messages[0].clone();
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
                        state: ReportAggregationState::Waiting(prep_step_0),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                        aggregation_job_id,
                        task_id,
                        nonce: nonce_1,
                        ord: 1,
                        state: ReportAggregationState::Waiting(prep_step_1),
                    })
                    .await
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
                .decode(&hmac_key)
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
                    state: ReportAggregationState::Finished(out_share_0),
                },
                ReportAggregation {
                    aggregation_job_id,
                    task_id,
                    nonce: nonce_1,
                    ord: 1,
                    state: ReportAggregationState::Failed(TransitionError::ReportDropped),
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
        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let clock = MockClock::default();

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
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId::from(42),
                                encapsulated_context: Vec::from("012345"),
                                payload: Vec::from("543210"),
                            },
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
                        state: ReportAggregationState::Waiting(()),
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
        let task = new_dummy_task(task_id, Vdaf::FakeFailsPrepStep, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let clock = MockClock::default();

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
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId::from(42),
                                encapsulated_context: Vec::from("012345"),
                                payload: Vec::from("543210"),
                            },
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
                        state: ReportAggregationState::Waiting(()),
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
                .decode(&hmac_key)
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
        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId::from(42),
                                encapsulated_context: Vec::from("012345"),
                                payload: Vec::from("543210"),
                            },
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
                        state: ReportAggregationState::Waiting(()),
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

        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId::from(42),
                                encapsulated_context: Vec::from("012345"),
                                payload: Vec::from("543210"),
                            },
                        },
                    )
                    .await?;
                    tx.put_report_share(
                        task_id,
                        &ReportShare {
                            nonce: nonce_1,
                            extensions: Vec::new(),
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId::from(42),
                                encapsulated_context: Vec::from("012345"),
                                payload: Vec::from("543210"),
                            },
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
                        state: ReportAggregationState::Waiting(()),
                    })
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<fake::Vdaf> {
                        aggregation_job_id,
                        task_id,
                        nonce: nonce_1,
                        ord: 1,
                        state: ReportAggregationState::Waiting(()),
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

        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId::from(42),
                                encapsulated_context: Vec::from("012345"),
                                payload: Vec::from("543210"),
                            },
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

        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Helper);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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

        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Leader);
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Leader);

        let (datastore, _db_handle) = ephemeral_datastore().await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap();

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
        // TODO(timg): validate collect URI
        assert!(response.headers().get(LOCATION).is_some());
    }

    #[tokio::test]
    async fn aggregate_share_request_to_leader() {
        install_test_trace_subscriber();

        // Prepare parameters.
        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Leader);
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();

        let (datastore, _db_handle) = ephemeral_datastore().await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap();

        let request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                task.min_batch_duration,
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 0,
            checksum: [0; 32],
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
        let task = new_dummy_task(task_id, Vdaf::Fake, Role::Helper);
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();

        let (datastore, _db_handle) = ephemeral_datastore().await;

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(Arc::new(datastore), MockClock::default()).unwrap();

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
            checksum: [0; 32],
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

        let mut task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Helper);
        task.max_batch_lifetime = 1;
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        task.collector_hpke_config = collector_hpke_config.clone();
        let hmac_key: &hmac::Key = task.agg_auth_keys.iter().last().unwrap().as_ref();
        let aggregation_param = ();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);

        datastore
            .run_tx(|tx| {
                let task = task.clone();

                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        let filter = aggregator_filter(datastore.clone(), MockClock::default()).unwrap();

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
            checksum: [0; 32],
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
                        checksum: [3; 32],
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<Prio3Aes128Count> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(1500),
                        aggregation_param,
                        aggregate_share: AggregateShare::from(vec![Field64::from(128)]),
                        report_count: 5,
                        checksum: [2; 32],
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<Prio3Aes128Count> {
                        task_id,
                        unit_interval_start: Time::from_seconds_since_epoch(2000),
                        aggregation_param,
                        aggregate_share: AggregateShare::from(vec![Field64::from(256)]),
                        report_count: 5,
                        checksum: [2; 32],
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
            checksum: [0; 32],
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

        // Interval is big enough, but checksum doesn't match
        let request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(2500),
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 10,
            checksum: [3; 32],
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
                "type": "urn:ietf:params:ppm:error:batchMisaligned",
                "title": "The checksums or report counts in the two aggregator's aggregate shares do not match.",
                "detail": "The checksums or report counts in the two aggregator's aggregate shares do not match.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );

        // Interval is big enough, but report count doesn't match
        let request = AggregateShareReq {
            task_id,
            batch_interval: Interval::new(
                Time::from_seconds_since_epoch(0),
                Duration::from_seconds(2500),
            )
            .unwrap(),
            aggregation_param: vec![],
            report_count: 20,
            checksum: [3 ^ 2; 32],
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
                "type": "urn:ietf:params:ppm:error:batchMisaligned",
                "title": "The checksums or report counts in the two aggregator's aggregate shares do not match.",
                "detail": "The checksums or report counts in the two aggregator's aggregate shares do not match.",
                "instance": "..",
                "taskid": format!("{}", task_id),
            })
        );

        // Interval is big enough, checksum and report count are good
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(2500),
        )
        .unwrap();
        let request = AggregateShareReq {
            task_id,
            batch_interval,
            aggregation_param: vec![],
            report_count: 10,
            checksum: [3 ^ 2; 32],
        };

        let (parts, body) = warp::test::request()
            .method("POST")
            .path("/aggregate_share")
            .body(AuthenticatedEncoder::new(request.clone()).encode(hmac_key))
            .filter(&filter)
            .await
            .unwrap()
            .into_response()
            .into_parts();

        assert_eq!(parts.status, StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(body).await.unwrap();

        let aggregate_share_resp: AggregateShareResp =
            AuthenticatedResponseDecoder::new(body_bytes.as_ref())
                .unwrap()
                .decode(hmac_key)
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
            &batch_interval.get_encoded(),
        )
        .unwrap();

        // Should get the sum over the first and second aggregate shares
        let decoded_aggregate_share =
            <AggregateShare<Field64>>::try_from(aggregate_share.as_ref()).unwrap();
        assert_eq!(
            decoded_aggregate_share,
            AggregateShare::from(vec![Field64::from(64 + 128)])
        );

        // TODO(timg): re-enable this test once handle_aggregate_share_generic handles
        // max_batch_lifetime
        #[cfg(disabled)]
        {
            // Attempt to collect the same interval again.
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
                    "type": "urn:ietf:params:ppm:error:batchLifetimeExceeded",
                    "title": "The batch lifetime has been exceeded for one or more reports included in the batch interval.",
                    "detail": "The batch lifetime has been exceeded for one or more reports included in the batch interval.",
                    "instance": "..",
                    "taskid": format!("{}", task_id),
                })
            );
        }
    }

    /// A transcript of a VDAF run. All fields are indexed by participant index (in PPM terminology,
    /// index 0 = leader, index 1 = helper).
    struct VdafTranscript<V: vdaf::Aggregator>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        input_shares: Vec<V::InputShare>,
        transitions: Vec<Vec<PrepareTransition<V>>>,
        messages: Vec<V::PrepareMessage>,
    }

    // run_vdaf runs a VDAF state machine from sharding through to generating an output share,
    // returning a "transcript" of all states & messages.
    fn run_vdaf<V: vdaf::Aggregator + vdaf::Client>(
        vdaf: &V,
        public_param: &V::PublicParam,
        verify_params: &[V::VerifyParam],
        aggregation_param: &V::AggregationParam,
        nonce: Nonce,
        measurement: &V::Measurement,
    ) -> VdafTranscript<V>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        // Shard inputs into input shares, and initialize the initial PrepareTransitions.
        let input_shares = vdaf.shard(public_param, measurement).unwrap();
        let mut prep_trans: Vec<Vec<PrepareTransition<V>>> = input_shares
            .iter()
            .enumerate()
            .map(|(idx, input_share)| {
                let prep_step = vdaf.prepare_init(
                    &verify_params[idx],
                    aggregation_param,
                    &nonce.get_encoded(),
                    input_share,
                )?;
                let prep_trans = vdaf.prepare_step(prep_step, None);
                Ok(vec![prep_trans])
            })
            .collect::<Result<Vec<Vec<PrepareTransition<V>>>, VdafError>>()
            .unwrap();
        let mut combined_prep_msgs = Vec::new();

        // Repeatedly step the VDAF until we reach a terminal state.
        loop {
            // Gather messages from last round & combine them into next round's message; if any
            // participants have reached a terminal state (Finish or Fail), we are done.
            let mut prep_msgs = Vec::new();
            for pts in &prep_trans {
                match pts.last().unwrap() {
                    PrepareTransition::<V>::Continue(_, prep_msg) => {
                        prep_msgs.push(prep_msg.clone())
                    }
                    _ => {
                        return VdafTranscript {
                            input_shares,
                            transitions: prep_trans,
                            messages: combined_prep_msgs,
                        }
                    }
                }
            }
            let combined_prep_msg = vdaf.prepare_preprocess(prep_msgs).unwrap();
            combined_prep_msgs.push(combined_prep_msg.clone());

            // Compute each participant's next transition.
            for pts in &mut prep_trans {
                let prep_step = assert_matches!(pts.last().unwrap(), PrepareTransition::<V>::Continue(prep_step, _) => prep_step).clone();
                pts.push(vdaf.prepare_step(prep_step, Some(combined_prep_msg.clone())));
            }
        }
    }

    fn current_hpke_key(
        hpke_keys: &HashMap<HpkeConfigId, (HpkeConfig, HpkePrivateKey)>,
    ) -> &(HpkeConfig, HpkePrivateKey) {
        hpke_keys
            .values()
            .max_by_key(|(cfg, _)| u8::from(cfg.id))
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
