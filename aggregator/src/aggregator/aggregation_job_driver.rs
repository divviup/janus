use crate::{
    aggregator::{
        aggregate_step_failure_counter,
        aggregation_job_writer::{
            AggregationJobWriter, AggregationJobWriterMetrics, UpdateWrite,
            WritableReportAggregation,
        },
        error::handle_ping_pong_error,
        http_handlers::AGGREGATION_JOB_ROUTE,
        query_type::CollectableQueryType,
        report_aggregation_success_counter, send_request_to_helper, write_task_aggregation_counter,
        Error, RequestBody,
    },
    metrics::aggregated_report_share_dimension_histogram,
};
use anyhow::{anyhow, Result};
use backoff::backoff::Backoff;
use bytes::Bytes;
use derivative::Derivative;
use futures::future::BoxFuture;
use janus_aggregator_core::{
    datastore::{
        self,
        models::{
            AcquiredAggregationJob, AggregationJob, AggregationJobState, Lease, ReportAggregation,
            ReportAggregationState,
        },
        Datastore,
    },
    task::{self, AggregatorTask, VerifyKey},
};
use janus_core::{
    retries::{is_retryable_http_client_error, is_retryable_http_status},
    time::Clock,
    vdaf_dispatch,
};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    AggregationJobContinueReq, AggregationJobInitializeReq, AggregationJobResp,
    PartialBatchSelector, PrepareContinue, PrepareError, PrepareInit, PrepareStepResult,
    ReportShare, Role,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    KeyValue,
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    topology::ping_pong::{PingPongContinuedValue, PingPongState, PingPongTopology},
    vdaf,
};
use rayon::iter::{IndexedParallelIterator as _, IntoParallelIterator as _, ParallelIterator as _};
use reqwest::Method;
use std::{collections::HashSet, panic, sync::Arc, time::Duration};
use tokio::{join, sync::mpsc, try_join};
use tracing::{debug, error, info, info_span, trace_span, warn, Span};

#[cfg(test)]
mod tests;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct AggregationJobDriver<B> {
    // Configuration.
    batch_aggregation_shard_count: u64,
    task_counter_shard_count: u64,

    // Dependencies.
    http_client: reqwest::Client,
    backoff: B,

    #[derivative(Debug = "ignore")]
    aggregation_success_counter: Counter<u64>,
    #[derivative(Debug = "ignore")]
    aggregate_step_failure_counter: Counter<u64>,
    #[derivative(Debug = "ignore")]
    aggregated_report_share_dimension_histogram: Histogram<u64>,
    #[derivative(Debug = "ignore")]
    job_cancel_counter: Counter<u64>,
    #[derivative(Debug = "ignore")]
    job_retry_counter: Counter<u64>,
    #[derivative(Debug = "ignore")]
    http_request_duration_histogram: Histogram<f64>,
}

impl<B> AggregationJobDriver<B>
where
    B: Backoff + Clone + Send + Sync + 'static,
{
    pub fn new(
        http_client: reqwest::Client,
        backoff: B,
        meter: &Meter,
        batch_aggregation_shard_count: u64,
        task_counter_shard_count: u64,
    ) -> Self {
        let aggregation_success_counter = report_aggregation_success_counter(meter);
        let aggregate_step_failure_counter = aggregate_step_failure_counter(meter);
        let aggregated_report_share_dimension_histogram =
            aggregated_report_share_dimension_histogram(meter);

        let job_cancel_counter = meter
            .u64_counter("janus_job_cancellations")
            .with_description("Count of cancelled jobs.")
            .with_unit("{job}")
            .init();
        job_cancel_counter.add(0, &[]);

        let job_retry_counter = meter
            .u64_counter("janus_job_retries")
            .with_description("Count of retried job steps.")
            .with_unit("{step}")
            .init();
        job_retry_counter.add(0, &[]);

        let http_request_duration_histogram = meter
            .f64_histogram("janus_http_request_duration")
            .with_description(
                "The amount of time elapsed while making an HTTP request to a helper.",
            )
            .with_unit("s")
            .init();

        Self {
            batch_aggregation_shard_count,
            task_counter_shard_count,
            http_client,
            backoff,
            aggregation_success_counter,
            aggregate_step_failure_counter,
            aggregated_report_share_dimension_histogram,
            job_cancel_counter,
            job_retry_counter,
            http_request_duration_histogram,
        }
    }

    async fn step_aggregation_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
    ) -> Result<(), Error> {
        match lease.leased().query_type() {
            task::QueryType::TimeInterval => {
                vdaf_dispatch!(lease.leased().vdaf(), (vdaf, VdafType, VERIFY_KEY_LENGTH) => {
                    self.step_aggregation_job_generic::<VERIFY_KEY_LENGTH, C, TimeInterval, VdafType>(datastore, Arc::new(vdaf), lease).await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_dispatch!(lease.leased().vdaf(), (vdaf, VdafType, VERIFY_KEY_LENGTH) => {
                    self.step_aggregation_job_generic::<VERIFY_KEY_LENGTH, C, FixedSize, VdafType>(datastore, Arc::new(vdaf), lease).await
                })
            }
        }
    }

    async fn step_aggregation_job_generic<
        const SEED_SIZE: usize,
        C: Clock,
        Q: CollectableQueryType,
        A,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        vdaf: Arc<A>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        A::AggregationParam: Send + Sync + PartialEq + Eq,
        A::AggregateShare: Send + Sync,
        A::OutputShare: PartialEq + Eq + Send + Sync,
        for<'a> A::PrepareState:
            PartialEq + Eq + Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
        A::PrepareShare: PartialEq + Eq + Send + Sync,
        A::InputShare: PartialEq + Send + Sync,
        A::PublicShare: PartialEq + Send + Sync,
    {
        // Read all information about the aggregation job.
        let (task, aggregation_job, report_aggregations, verify_key) = datastore
            .run_tx("step_aggregation_job_1", |tx| {
                let (lease, vdaf) = (Arc::clone(&lease), Arc::clone(&vdaf));
                Box::pin(async move {
                    let task = tx
                        .get_aggregator_task(lease.leased().task_id())
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                anyhow!("couldn't find task {}", lease.leased().task_id()).into(),
                            )
                        })?;
                    let verify_key = task.vdaf_verify_key().map_err(|_| {
                        datastore::Error::User(
                            anyhow!("VDAF verification key has wrong length").into(),
                        )
                    })?;

                    let aggregation_job_future = tx.get_aggregation_job::<SEED_SIZE, Q, A>(
                        lease.leased().task_id(),
                        lease.leased().aggregation_job_id(),
                    );
                    let report_aggregations_future = tx
                        .get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            &Role::Leader,
                            lease.leased().task_id(),
                            lease.leased().aggregation_job_id(),
                        );

                    let (aggregation_job, report_aggregations) =
                        try_join!(aggregation_job_future, report_aggregations_future)?;
                    let aggregation_job = aggregation_job.ok_or_else(|| {
                        datastore::Error::User(
                            anyhow!(
                                "couldn't find aggregation job {} for task {}",
                                *lease.leased().aggregation_job_id(),
                                *lease.leased().task_id(),
                            )
                            .into(),
                        )
                    })?;

                    Ok((
                        Arc::new(task),
                        aggregation_job,
                        report_aggregations,
                        verify_key,
                    ))
                })
            })
            .await?;

        // Figure out the next step based on the non-error report aggregation states, and dispatch accordingly.
        let (mut saw_start, mut saw_waiting, mut saw_finished) = (false, false, false);
        for report_aggregation in &report_aggregations {
            match report_aggregation.state() {
                ReportAggregationState::StartLeader { .. } => saw_start = true,
                ReportAggregationState::WaitingLeader { .. } => saw_waiting = true,
                ReportAggregationState::WaitingHelper { .. } => {
                    return Err(Error::Internal(
                        "Leader encountered unexpected ReportAggregationState::WaitingHelper"
                            .to_string(),
                    ));
                }
                ReportAggregationState::Finished => saw_finished = true,
                ReportAggregationState::Failed { .. } => (), // ignore failed aggregations
            }
        }
        match (saw_start, saw_waiting, saw_finished) {
            // Only saw report aggregations in state "start" (or failed or invalid).
            (true, false, false) => {
                self.step_aggregation_job_aggregate_init(
                    Arc::clone(&datastore),
                    vdaf,
                    lease,
                    task,
                    aggregation_job,
                    report_aggregations,
                    verify_key,
                )
                .await
            }

            // Only saw report aggregations in state "waiting" (or failed or invalid).
            (false, true, false) => {
                self.step_aggregation_job_aggregate_continue(
                    Arc::clone(&datastore),
                    vdaf,
                    lease,
                    task,
                    aggregation_job,
                    report_aggregations,
                )
                .await
            }

            _ => Err(Error::Internal(format!(
                "unexpected combination of report aggregation states (saw_start = {saw_start}, \
                saw_waiting = {saw_waiting}, saw_finished = {saw_finished})",
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn step_aggregation_job_aggregate_init<
        const SEED_SIZE: usize,
        C: Clock,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        vdaf: Arc<A>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
        task: Arc<AggregatorTask>,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
        verify_key: VerifyKey<SEED_SIZE>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync + PartialEq + Eq,
        A::AggregateShare: Send + Sync,
        A::InputShare: PartialEq + Send + Sync,
        A::OutputShare: PartialEq + Eq + Send + Sync,
        A::PrepareState: PartialEq + Eq + Send + Sync + Encode,
        A::PrepareShare: PartialEq + Eq + Send + Sync,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
        A::PublicShare: PartialEq + Send + Sync,
    {
        let aggregation_job = Arc::new(aggregation_job);

        // Only process non-failed report aggregations.
        let report_aggregations: Vec<_> = report_aggregations
            .into_iter()
            .filter(|report_aggregation| {
                matches!(
                    report_aggregation.state(),
                    &ReportAggregationState::StartLeader { .. }
                )
            })
            .collect();
        let report_aggregation_count = report_aggregations.len();

        // Compute the next aggregation step.
        //
        // Shutdown on cancellation: if this request is cancelled, the `receiver` will be dropped.
        // This will cause any attempts to send on `sender` to return a `SendError`, which will be
        // returned from the function passed to `try_for_each_with`; `try_for_each_with` will
        // terminate early on receiving an error.
        let (ra_sender, mut ra_receiver) = mpsc::unbounded_channel();
        let (pi_and_sa_sender, mut pi_and_sa_receiver) = mpsc::unbounded_channel();
        let producer_task = tokio::task::spawn_blocking({
            let parent_span = Span::current();
            let vdaf = Arc::clone(&vdaf);
            let task_id = *task.id();
            let aggregation_job = Arc::clone(&aggregation_job);
            let aggregate_step_failure_counter = self.aggregate_step_failure_counter.clone();

            move || {
                let span = info_span!(
                    parent: parent_span,
                    "step_aggregation_job_aggregate_init threadpool task"
                );

                // Compute report shares to send to helper, and decrypt our input shares &
                // initialize preparation state.
                report_aggregations.into_par_iter().try_for_each_with(
                    (span, ra_sender, pi_and_sa_sender),
                    |(span, ra_sender, pi_and_sa_sender), report_aggregation| {
                        let _entered = span.enter();

                    // Extract report data from the report aggregation state.
                    let (
                        public_share,
                        leader_extensions,
                        leader_input_share,
                        helper_encrypted_input_share,
                    ) = match report_aggregation.state() {
                        ReportAggregationState::StartLeader {
                            public_share,
                            leader_extensions,
                            leader_input_share,
                            helper_encrypted_input_share,
                        } => (
                            public_share,
                            leader_extensions,
                            leader_input_share,
                            helper_encrypted_input_share,
                        ),

                        // Panic safety: this can't happen because we filter to only
                        // StartLeader-state report aggregations before this loop.
                        _ => panic!(
                            "Unexpected report aggregation state: {:?}",
                            report_aggregation.state()
                        ),
                    };

                    // Check for repeated extensions.
                    let mut extension_types = HashSet::new();
                    if !leader_extensions
                        .iter()
                        .all(|extension| extension_types.insert(extension.extension_type()))
                    {
                        debug!(
                            report_id = %report_aggregation.report_id(),
                            "Received report with duplicate extensions"
                        );
                        aggregate_step_failure_counter
                            .add(1, &[KeyValue::new("type", "duplicate_extension")]);
                        return ra_sender.send(WritableReportAggregation::new(
                            report_aggregation.with_state(ReportAggregationState::Failed {
                                prepare_error: PrepareError::InvalidMessage,
                            }),
                            None,
                        )).map_err(|_| ());
                    }

                    // Initialize the leader's preparation state from the input share.
                    let public_share_bytes = match public_share.get_encoded() {
                        Ok(public_share_bytes) => public_share_bytes,
                        Err(err) => {
                            debug!(report_id = %report_aggregation.report_id(), ?err, "Could not encode public share");
                            aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", "public_share_encode_failure")]);
                            return ra_sender.send(WritableReportAggregation::new(
                                report_aggregation.with_state(ReportAggregationState::Failed {
                                    prepare_error: PrepareError::InvalidMessage,
                                }),
                                None,
                            )).map_err(|_| ());
                        }
                    };

                    match trace_span!("VDAF preparation (leader initialization)").in_scope(|| {
                        vdaf.leader_initialized(
                            verify_key.as_bytes(),
                            aggregation_job.aggregation_parameter(),
                            // DAP report ID is used as VDAF nonce
                            report_aggregation.report_id().as_ref(),
                            public_share,
                            leader_input_share,
                        )
                        .map_err(|ping_pong_error| {
                            handle_ping_pong_error(
                                &task_id,
                                Role::Leader,
                                report_aggregation.report_id(),
                                ping_pong_error,
                                &aggregate_step_failure_counter,
                            )
                        })
                    }) {
                        Ok((ping_pong_state, ping_pong_message)) => {
                            pi_and_sa_sender.send((
                                report_aggregation.ord(),
                                PrepareInit::new(
                                    ReportShare::new(
                                        report_aggregation.report_metadata(),
                                        public_share_bytes,
                                        helper_encrypted_input_share.clone(),
                                    ),
                                    ping_pong_message,
                                ),
                                SteppedAggregation {
                                    report_aggregation,
                                    leader_state: ping_pong_state,
                                },
                            )).map_err(|_| ())
                        }
                        Err(prepare_error) => {
                            ra_sender.send(WritableReportAggregation::new(
                                report_aggregation
                                    .with_state(ReportAggregationState::Failed { prepare_error }),
                                None,
                            )).map_err(|_| ())
                        }
                    }
                })
            }
        });

        let (report_aggregations_to_write, (prepare_inits, stepped_aggregations)) = join!(
            async move {
                let mut report_aggregations_to_write = Vec::with_capacity(report_aggregation_count);
                while ra_receiver
                    .recv_many(&mut report_aggregations_to_write, 10)
                    .await
                    > 0
                {}
                report_aggregations_to_write
            },
            async move {
                let mut pis_and_sas = Vec::with_capacity(report_aggregation_count);
                while pi_and_sa_receiver.recv_many(&mut pis_and_sas, 10).await > 0 {}
                pis_and_sas.sort_unstable_by_key(|(ord, _, _)| *ord);
                let (prepare_inits, stepped_aggregations): (Vec<_>, Vec<_>) =
                    pis_and_sas.into_iter().map(|(_, pi, sa)| (pi, sa)).unzip();
                (prepare_inits, stepped_aggregations)
            },
        );

        // Await the producer task to resume any panics that may have occurred. The only other
        // errors that can occur are: a `JoinError` indicating cancellation, which is impossible
        // because we do not cancel the task; and a `SendError`, which can only happen if this
        // future is cancelled (in which case we will not run this code at all).
        let _ = producer_task.await.map_err(|join_error| {
            if let Ok(reason) = join_error.try_into_panic() {
                panic::resume_unwind(reason);
            }
        });
        assert_eq!(
            report_aggregations_to_write.len() + prepare_inits.len(),
            report_aggregation_count
        );
        assert_eq!(prepare_inits.len(), stepped_aggregations.len());

        let resp = if !prepare_inits.is_empty() {
            // Construct request, send it to the helper, and process the response.
            let request = AggregationJobInitializeReq::<Q>::new(
                aggregation_job
                    .aggregation_parameter()
                    .get_encoded()
                    .map_err(Error::MessageEncode)?,
                PartialBatchSelector::new(aggregation_job.partial_batch_identifier().clone()),
                prepare_inits,
            );

            let resp_bytes = send_request_to_helper(
                &self.http_client,
                self.backoff.clone(),
                Method::PUT,
                task.aggregation_job_uri(aggregation_job.id())?
                    .ok_or_else(|| {
                        Error::InvalidConfiguration("task is leader and has no aggregate share URI")
                    })?,
                AGGREGATION_JOB_ROUTE,
                Some(RequestBody {
                    content_type: AggregationJobInitializeReq::<Q>::MEDIA_TYPE,
                    body: Bytes::from(request.get_encoded().map_err(Error::MessageEncode)?),
                }),
                // The only way a task wouldn't have an aggregator auth token in it is in the taskprov
                // case, and Janus never acts as the leader with taskprov enabled.
                task.aggregator_auth_token().ok_or_else(|| {
                    Error::InvalidConfiguration("no aggregator auth token in task")
                })?,
                &self.http_request_duration_histogram,
            )
            .await?;
            AggregationJobResp::get_decoded(&resp_bytes).map_err(Error::MessageDecode)?
        } else {
            // If there are no prepare inits to send (because every report aggregation was filtered
            // by the block above), don't send a request to the Helper at all and process an
            // artificial aggregation job response instead, which will finish the aggregation job.
            AggregationJobResp::new(Vec::new())
        };

        let aggregation_job = Arc::unwrap_or_clone(aggregation_job);
        self.process_response_from_helper(
            datastore,
            vdaf,
            lease,
            task,
            aggregation_job,
            stepped_aggregations,
            report_aggregations_to_write,
            resp,
        )
        .await
    }

    async fn step_aggregation_job_aggregate_continue<
        const SEED_SIZE: usize,
        C: Clock,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        vdaf: Arc<A>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
        task: Arc<AggregatorTask>,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync + PartialEq + Eq,
        A::AggregateShare: Send + Sync,
        A::InputShare: Send + Sync,
        A::OutputShare: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::PrepareShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::PublicShare: Send + Sync,
    {
        // Only process non-failed report aggregations.
        let report_aggregations: Vec<_> = report_aggregations
            .into_iter()
            .filter(|report_aggregation| {
                matches!(
                    report_aggregation.state(),
                    &ReportAggregationState::WaitingLeader { .. }
                )
            })
            .collect();
        let report_aggregation_count = report_aggregations.len();

        // Visit the report aggregations, ignoring any that have already failed; compute our own
        // next step & transitions to send to the helper.
        //
        // Shutdown on cancellation: if this request is cancelled, the `receiver` will be dropped.
        // This will cause any attempts to send on `sender` to return a `SendError`, which will be
        // returned from the function passed to `try_for_each_with`; `try_for_each_with` will
        // terminate early on receiving an error.
        let (ra_sender, mut ra_receiver) = mpsc::unbounded_channel();
        let (pc_and_sa_sender, mut pc_and_sa_receiver) = mpsc::unbounded_channel();
        let producer_task = tokio::task::spawn_blocking({
            let parent_span = Span::current();
            let vdaf = Arc::clone(&vdaf);
            let task_id = *task.id();
            let aggregate_step_failure_counter = self.aggregate_step_failure_counter.clone();

            move || {
                let span = info_span!(
                    parent: parent_span,
                    "step_aggregation_job_aggregate_continue threadpool task"
                );

                report_aggregations.into_par_iter().try_for_each_with(
                    (span, ra_sender, pc_and_sa_sender),
                    |(span, ra_sender, pc_and_sa_sender), report_aggregation| {
                        let _entered = span.enter();

                        let transition = match report_aggregation.state() {
                            ReportAggregationState::WaitingLeader { transition } => transition,
                            // Panic safety: this can't happen because we filter to only
                            // WaitingLeader-state report aggregations before this loop.
                            _ => panic!(
                                "Unexpected report aggregation state: {:?}",
                                report_aggregation.state()
                            ),
                        };

                        let result = trace_span!("VDAF preparation (leader transition evaluation)")
                            .in_scope(|| transition.evaluate(vdaf.as_ref()));
                        let (prep_state, message) = match result {
                            Ok((state, message)) => (state, message),
                            Err(error) => {
                                let prepare_error = handle_ping_pong_error(
                                    &task_id,
                                    Role::Leader,
                                    report_aggregation.report_id(),
                                    error,
                                    &aggregate_step_failure_counter,
                                );
                                return ra_sender
                                    .send(WritableReportAggregation::new(
                                        report_aggregation.with_state(
                                            ReportAggregationState::Failed { prepare_error },
                                        ),
                                        None,
                                    ))
                                    .map_err(|_| ());
                            }
                        };

                        return pc_and_sa_sender
                            .send((
                                report_aggregation.ord(),
                                PrepareContinue::new(*report_aggregation.report_id(), message),
                                SteppedAggregation {
                                    report_aggregation,
                                    leader_state: prep_state,
                                },
                            ))
                            .map_err(|_| ());
                    },
                )
            }
        });

        let (report_aggregations_to_write, (prepare_continues, stepped_aggregations)) = join!(
            async move {
                let mut report_aggregations_to_write = Vec::with_capacity(report_aggregation_count);
                while ra_receiver
                    .recv_many(&mut report_aggregations_to_write, 10)
                    .await
                    > 0
                {}
                report_aggregations_to_write
            },
            async move {
                let mut pcs_and_sas = Vec::with_capacity(report_aggregation_count);
                while pc_and_sa_receiver.recv_many(&mut pcs_and_sas, 10).await > 0 {}
                pcs_and_sas.sort_unstable_by_key(|(ord, _, _)| *ord);
                let (prepare_continues, stepped_aggregations): (Vec<_>, Vec<_>) =
                    pcs_and_sas.into_iter().map(|(_, pc, sa)| (pc, sa)).unzip();
                (prepare_continues, stepped_aggregations)
            }
        );

        // Await the producer task to resume any panics that may have occurred. The only other
        // errors that can occur are: a `JoinError` indicating cancellation, which is impossible
        // because we do not cancel the task; and a `SendError`, which can only happen if this
        // future is cancelled (in which case we will not run this code at all).
        let _ = producer_task.await.map_err(|join_error| {
            if let Ok(reason) = join_error.try_into_panic() {
                panic::resume_unwind(reason);
            }
        });
        assert_eq!(
            report_aggregations_to_write.len() + prepare_continues.len(),
            report_aggregation_count
        );
        assert_eq!(prepare_continues.len(), stepped_aggregations.len());

        // Construct request, send it to the helper, and process the response.
        let request = AggregationJobContinueReq::new(aggregation_job.step(), prepare_continues);

        let resp_bytes = send_request_to_helper(
            &self.http_client,
            self.backoff.clone(),
            Method::POST,
            task.aggregation_job_uri(aggregation_job.id())?
                .ok_or_else(|| {
                    Error::InvalidConfiguration("task is not leader and has no aggregate share URI")
                })?,
            AGGREGATION_JOB_ROUTE,
            Some(RequestBody {
                content_type: AggregationJobContinueReq::MEDIA_TYPE,
                body: Bytes::from(request.get_encoded().map_err(Error::MessageEncode)?),
            }),
            // The only way a task wouldn't have an aggregator auth token in it is in the taskprov
            // case, and Janus never acts as the leader with taskprov enabled.
            task.aggregator_auth_token()
                .ok_or_else(|| Error::InvalidConfiguration("no aggregator auth token in task"))?,
            &self.http_request_duration_histogram,
        )
        .await?;
        let resp = AggregationJobResp::get_decoded(&resp_bytes).map_err(Error::MessageDecode)?;

        self.process_response_from_helper(
            datastore,
            vdaf,
            lease,
            task,
            aggregation_job,
            stepped_aggregations,
            report_aggregations_to_write,
            resp,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_response_from_helper<
        const SEED_SIZE: usize,
        C: Clock,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        vdaf: Arc<A>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
        task: Arc<AggregatorTask>,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        stepped_aggregations: Vec<SteppedAggregation<SEED_SIZE, A>>,
        mut report_aggregations_to_write: Vec<WritableReportAggregation<SEED_SIZE, A>>,
        helper_resp: AggregationJobResp,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync + Eq + PartialEq,
        A::AggregateShare: Send + Sync,
        A::InputShare: Send + Sync,
        A::OutputShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::PrepareShare: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
        A::PublicShare: Send + Sync,
    {
        // Handle response, computing the new report aggregations to be stored.
        let expected_report_aggregation_count =
            report_aggregations_to_write.len() + stepped_aggregations.len();
        if stepped_aggregations.len() != helper_resp.prepare_resps().len() {
            return Err(Error::Internal(
                "missing, duplicate, out-of-order, or unexpected prepare steps in response"
                    .to_string(),
            ));
        }
        for (stepped_aggregation, helper_prep_resp) in
            stepped_aggregations.iter().zip(helper_resp.prepare_resps())
        {
            if stepped_aggregation.report_aggregation.report_id() != helper_prep_resp.report_id() {
                return Err(Error::Internal(
                    "missing, duplicate, out-of-order, or unexpected prepare steps in response"
                        .to_string(),
                ));
            }
        }

        // Shutdown on cancellation: if this request is cancelled, the `receiver` will be dropped.
        // This will cause any attempts to send on `sender` to return a `SendError`, which will be
        // returned from the function passed to `try_for_each_with`; `try_for_each_with` will
        // terminate early on receiving an error.
        let (ra_sender, mut ra_receiver) = mpsc::unbounded_channel();
        let aggregation_job = Arc::new(aggregation_job);
        let producer_task = tokio::task::spawn_blocking({
            let parent_span = Span::current();
            let vdaf = Arc::clone(&vdaf);
            let task_id = *task.id();
            let aggregation_job = Arc::clone(&aggregation_job);
            let aggregate_step_failure_counter = self.aggregate_step_failure_counter.clone();

            move || {
                let span = info_span!(
                    parent: parent_span,
                    "process_Response_from_helper threadpool task"
                );

                stepped_aggregations.into_par_iter().zip(helper_resp.prepare_resps()).try_for_each_with(
                    (span, ra_sender),
                    |(span, ra_sender), (stepped_aggregation, helper_prep_resp)| {
                        let _entered = span.enter();

                        let (new_state, output_share) = match helper_prep_resp.result() {
                            PrepareStepResult::Continue {
                                message: helper_prep_msg,
                            } => {
                                let state_and_message = trace_span!("VDAF preparation (leader continuation)")
                                    .in_scope(|| {
                                        vdaf.leader_continued(
                                            stepped_aggregation.leader_state.clone(),
                                            aggregation_job.aggregation_parameter(),
                                            helper_prep_msg,
                                        )
                                        .map_err(|ping_pong_error| {
                                            handle_ping_pong_error(
                                                &task_id,
                                                Role::Leader,
                                                stepped_aggregation.report_aggregation.report_id(),
                                                ping_pong_error,
                                                &aggregate_step_failure_counter,
                                            )
                                        })
                                    });

                                match state_and_message {
                                    Ok(PingPongContinuedValue::WithMessage { transition }) => {
                                        // Leader did not finish. Store our state and outgoing message for the
                                        // next step.
                                        // n.b. it's possible we finished and recovered an output share at the
                                        // VDAF level (i.e., state may be PingPongState::Finished) but we cannot
                                        // finish at the DAP layer and commit the output share until we get
                                        // confirmation from the Helper that they finished, too.
                                        (ReportAggregationState::WaitingLeader { transition }, None)
                                    }
                                    Ok(PingPongContinuedValue::FinishedNoMessage { output_share }) => {
                                        // We finished and have no outgoing message, meaning the Helper was
                                        // already finished. Commit the output share.
                                        (ReportAggregationState::Finished, Some(output_share))
                                    }
                                    Err(prepare_error) => {
                                        (ReportAggregationState::Failed { prepare_error }, None)
                                    }
                                }
                            }

                            PrepareStepResult::Finished => {
                                if let PingPongState::Finished(output_share) = stepped_aggregation.leader_state
                                {
                                    // Helper finished and we had already finished. Commit the output share.
                                    (ReportAggregationState::Finished, Some(output_share))
                                } else {
                                    warn!(
                                        report_id = %stepped_aggregation.report_aggregation.report_id(),
                                        "Helper finished but Leader did not",
                                    );
                                    aggregate_step_failure_counter
                                        .add(1, &[KeyValue::new("type", "finish_mismatch")]);
                                    (
                                        ReportAggregationState::Failed {
                                            prepare_error: PrepareError::VdafPrepError,
                                        },
                                        None,
                                    )
                                }
                            }

                            PrepareStepResult::Reject(err) => {
                                // If the helper failed, we move to FAILED immediately.
                                // TODO(#236): is it correct to just record the transition error that the helper reports?
                                info!(
                                    report_id = %stepped_aggregation.report_aggregation.report_id(),
                                    helper_error = ?err,
                                    "Helper couldn't step report aggregation",
                                );
                                aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "helper_step_failure")]);
                                (
                                    ReportAggregationState::Failed {
                                        prepare_error: *err,
                                    },
                                    None,
                                )
                            }
                        };

                        ra_sender.send(WritableReportAggregation::new(
                            stepped_aggregation.report_aggregation.with_state(new_state),
                            output_share,
                        ))
                    }
                )
            }
        });

        while ra_receiver
            .recv_many(&mut report_aggregations_to_write, 10)
            .await
            > 0
        {}

        // Await the producer task to resume any panics that may have occurred. The only other
        // errors that can occur are: a `JoinError` indicating cancellation, which is impossible
        // because we do not cancel the task; and a `SendError`, which can only happen if this
        // future is cancelled (in which case we will not run this code at all).
        let _ = producer_task.await.map_err(|join_error| {
            if let Ok(reason) = join_error.try_into_panic() {
                panic::resume_unwind(reason);
            }
        });
        assert_eq!(
            report_aggregations_to_write.len(),
            expected_report_aggregation_count
        );

        // Write everything back to storage.
        let aggregation_job = Arc::unwrap_or_clone(aggregation_job);
        let mut aggregation_job_writer =
            AggregationJobWriter::<SEED_SIZE, _, _, UpdateWrite, _>::new(
                Arc::clone(&task),
                self.batch_aggregation_shard_count,
                Some(AggregationJobWriterMetrics {
                    report_aggregation_success_counter: self.aggregation_success_counter.clone(),
                    aggregate_step_failure_counter: self.aggregate_step_failure_counter.clone(),
                    aggregated_report_share_dimension_histogram: self
                        .aggregated_report_share_dimension_histogram
                        .clone(),
                }),
            );
        let new_step = aggregation_job.step().increment();
        aggregation_job_writer.put(
            aggregation_job.with_step(new_step),
            report_aggregations_to_write,
        )?;
        let aggregation_job_writer = Arc::new(aggregation_job_writer);

        let counters = datastore
            .run_tx("step_aggregation_job_2", |tx| {
                let vdaf = Arc::clone(&vdaf);
                let aggregation_job_writer = Arc::clone(&aggregation_job_writer);
                let lease = Arc::clone(&lease);

                Box::pin(async move {
                    let ((_, counters), _) = try_join!(
                        aggregation_job_writer.write(tx, Arc::clone(&vdaf)),
                        tx.release_aggregation_job(&lease),
                    )?;
                    Ok(counters)
                })
            })
            .await?;

        write_task_aggregation_counter(
            datastore,
            self.task_counter_shard_count,
            *task.id(),
            counters,
        );

        Ok(())
    }

    async fn abandon_aggregation_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
    ) -> Result<(), Error> {
        match lease.leased().query_type() {
            task::QueryType::TimeInterval => {
                vdaf_dispatch!(lease.leased().vdaf(), (vdaf, VdafType, VERIFY_KEY_LENGTH) => {
                    self.cancel_aggregation_job_generic::<
                        VERIFY_KEY_LENGTH,
                        C,
                        TimeInterval,
                        VdafType,
                    >(vdaf, datastore, lease)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_dispatch!(lease.leased().vdaf(), (vdaf, VdafType, VERIFY_KEY_LENGTH) => {
                    self.cancel_aggregation_job_generic::<
                        VERIFY_KEY_LENGTH,
                        C,
                        FixedSize,
                        VdafType,
                    >(vdaf, datastore, lease)
                    .await
                })
            }
        }
    }

    async fn cancel_aggregation_job_generic<
        const SEED_SIZE: usize,
        C: Clock,
        Q: CollectableQueryType,
        A,
    >(
        &self,
        vdaf: A,
        datastore: Arc<Datastore<C>>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        A::AggregateShare: Send + Sync,
        A::AggregationParam: Send + Sync + PartialEq + Eq,
        A::InputShare: Send + Sync,
        A::OutputShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PublicShare: Send + Sync,
    {
        let vdaf = Arc::new(vdaf);
        let batch_aggregation_shard_count = self.batch_aggregation_shard_count;
        let (aggregation_job_uri, aggregator_auth_token) = datastore
            .run_tx("cancel_aggregation_job", |tx| {
                let vdaf = Arc::clone(&vdaf);
                let lease = Arc::clone(&lease);

                Box::pin(async move {
                    // On abandoning an aggregation job, we update the aggregation job's state field
                    // to Abandoned, but leave all other state (e.g. report aggregations) alone to
                    // ease debugging.
                    let (task, aggregation_job, report_aggregations) = try_join!(
                        tx.get_aggregator_task(lease.leased().task_id()),
                        tx.get_aggregation_job::<SEED_SIZE, Q, A>(
                            lease.leased().task_id(),
                            lease.leased().aggregation_job_id()
                        ),
                        tx.get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            &Role::Leader,
                            lease.leased().task_id(),
                            lease.leased().aggregation_job_id()
                        ),
                    )?;

                    let task = task.ok_or_else(|| {
                        datastore::Error::User(
                            anyhow!("couldn't find task {}", lease.leased().task_id()).into(),
                        )
                    })?;
                    let aggregation_job = aggregation_job
                        .ok_or_else(|| {
                            datastore::Error::User(
                                anyhow!(
                                    "couldn't find aggregation job {} for task {}",
                                    lease.leased().aggregation_job_id(),
                                    lease.leased().task_id()
                                )
                                .into(),
                            )
                        })?
                        .with_state(AggregationJobState::Abandoned);

                    let report_aggregations = report_aggregations
                        .into_iter()
                        .map(|ra| WritableReportAggregation::new(ra, None))
                        .collect();

                    let aggregation_job_uri =
                        task.aggregation_job_uri(lease.leased().aggregation_job_id());
                    let aggregator_auth_token = task.aggregator_auth_token().cloned();

                    let mut aggregation_job_writer =
                        AggregationJobWriter::<SEED_SIZE, _, _, UpdateWrite, _>::new(
                            Arc::new(task),
                            batch_aggregation_shard_count,
                            None,
                        );
                    aggregation_job_writer.put(aggregation_job, report_aggregations)?;

                    try_join!(
                        aggregation_job_writer.write(tx, vdaf),
                        tx.release_aggregation_job(&lease),
                    )?;

                    Ok((aggregation_job_uri, aggregator_auth_token))
                })
            })
            .await?;

        // We are giving up on the aggregation job. Delete in the helper so they can clean up
        // resources, too. Because DAP aggregators are not required to implement DELETE on
        // aggregation jobs, we don't check whether this succeeds, though failures will still show
        // up in the HTTP request duration histogram.
        //
        // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-09#section-4.5.2.2-20
        let _ = send_request_to_helper(
            &self.http_client,
            self.backoff.clone(),
            Method::DELETE,
            aggregation_job_uri?.ok_or_else(|| {
                Error::InvalidConfiguration("task is leader and has no aggregation job URI")
            })?,
            AGGREGATION_JOB_ROUTE,
            None,
            // The only way a task wouldn't have an aggregator auth token in it is in the taskprov
            // case, and Janus never acts as the leader with taskprov enabled.
            &aggregator_auth_token
                .ok_or_else(|| Error::InvalidConfiguration("task has no aggregator auth token"))?,
            &self.http_request_duration_histogram,
        )
        .await;
        Ok(())
    }

    /// Produce a closure for use as a `[JobDriver::JobAcquirer]`.
    pub fn make_incomplete_job_acquirer_callback<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease_duration: Duration,
    ) -> impl Fn(usize) -> BoxFuture<'static, Result<Vec<Lease<AcquiredAggregationJob>>, datastore::Error>>
    {
        move |max_acquire_count: usize| {
            let datastore = Arc::clone(&datastore);
            Box::pin(async move {
                datastore
                    .run_tx("acquire_aggregation_jobs", |tx| {
                        Box::pin(async move {
                            tx.acquire_incomplete_aggregation_jobs(
                                &lease_duration,
                                max_acquire_count,
                            )
                            .await
                        })
                    })
                    .await
            })
        }
    }

    /// Produce a closure for use as a `[JobDriver::JobStepper]`.
    pub fn make_job_stepper_callback<C: Clock>(
        self: Arc<Self>,
        datastore: Arc<Datastore<C>>,
        maximum_attempts_before_failure: usize,
    ) -> impl Fn(Lease<AcquiredAggregationJob>) -> BoxFuture<'static, Result<(), Error>> {
        move |lease| {
            let (this, datastore) = (Arc::clone(&self), Arc::clone(&datastore));
            let lease = Arc::new(lease);
            Box::pin(async move {
                let attempts = lease.lease_attempts();
                if attempts > maximum_attempts_before_failure {
                    warn!(
                        attempts = %lease.lease_attempts(),
                        max_attempts = %maximum_attempts_before_failure,
                        "Abandoning job due to too many failed attempts"
                    );
                    this.job_cancel_counter.add(1, &[]);
                    return this.abandon_aggregation_job(datastore, lease).await;
                }

                if attempts > 1 {
                    this.job_retry_counter.add(1, &[]);
                }

                match this
                    .step_aggregation_job(Arc::clone(&datastore), Arc::clone(&lease))
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(error) => {
                        if !Self::is_retryable_error(&error) {
                            // Make a best-effort attempt to immediately cancel the aggregation job.
                            // on fatal errors. This protects the helper from performing wasted
                            // work.
                            //
                            // Cancellation might fail, but we will return the first error, since
                            // that's the more interesting error for debugging purposes.
                            //
                            // If cancellation fails, the job will be picked up again. This isn't
                            // a big deal, since stepping an aggregation job is idempotent. It would
                            // just be some wasted work next time around.
                            warn!(
                                %attempts,
                                max_attempts = %maximum_attempts_before_failure,
                                ?error,
                                "Abandoning job due to fatal error"
                            );
                            this.job_cancel_counter.add(1, &[]);
                            if let Err(error) = this.abandon_aggregation_job(datastore, lease).await
                            {
                                error!(error = ?error, "Failed to abandon job");
                            }
                        }
                        Err(error)
                    }
                }
            })
        }
    }

    /// Determines whether the given [`Error`] is retryable in the context of aggregation job
    /// processing.
    fn is_retryable_error(error: &Error) -> bool {
        match error {
            Error::Http(http_error_response) => {
                is_retryable_http_status(http_error_response.status())
            }
            Error::HttpClient(error) => is_retryable_http_client_error(error),
            Error::Datastore(error) => match error {
                datastore::Error::Db(_) | datastore::Error::Pool(_) => true,
                datastore::Error::User(error) => match error.downcast_ref::<Error>() {
                    Some(error) => Self::is_retryable_error(error),
                    None => false,
                },
                _ => false,
            },
            _ => false,
        }
    }
}

/// SteppedAggregation represents a report aggregation along with the associated preparation-state
/// transition representing the next step for the leader.
struct SteppedAggregation<const SEED_SIZE: usize, A: vdaf::Aggregator<SEED_SIZE, 16>> {
    report_aggregation: ReportAggregation<SEED_SIZE, A>,
    leader_state: PingPongState<SEED_SIZE, 16, A>,
}
