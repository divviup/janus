use crate::{
    aggregator::{
        accumulator::Accumulator, aggregate_step_failure_counter, query_type::AccumulableQueryType,
        send_request_to_helper,
    },
    datastore::{
        self,
        models::{
            AcquiredAggregationJob, AggregationJob, AggregationJobState, LeaderStoredReport, Lease,
            ReportAggregation, ReportAggregationState,
        },
        Datastore,
    },
    task::{self, Task, VerifyKey, PRIO3_AES128_VERIFY_KEY_LENGTH},
};
use anyhow::{anyhow, Context as _, Result};
use derivative::Derivative;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31, U63};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32, FixedI64};
use futures::future::{try_join_all, BoxFuture, FutureExt};
use janus_core::{task::VdafInstance, time::Clock};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    AggregationJobContinueReq, AggregationJobInitializeReq, AggregationJobResp,
    PartialBatchSelector, PrepareStep, PrepareStepResult, ReportShare, ReportShareError, Role,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter, Unit},
    Context, KeyValue,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3Aes128FixedPointBoundedL2VecSum;
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
use reqwest::Method;
use std::{collections::HashSet, fmt, sync::Arc, time::Duration};
use tokio::try_join;
use tracing::{info, warn};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct AggregationJobDriver {
    http_client: reqwest::Client,
    #[derivative(Debug = "ignore")]
    aggregate_step_failure_counter: Counter<u64>,
    #[derivative(Debug = "ignore")]
    job_cancel_counter: Counter<u64>,
    #[derivative(Debug = "ignore")]
    http_request_duration_histogram: Histogram<f64>,
}

impl AggregationJobDriver {
    pub fn new(http_client: reqwest::Client, meter: &Meter) -> AggregationJobDriver {
        let aggregate_step_failure_counter = aggregate_step_failure_counter(meter);

        let job_cancel_counter = meter
            .u64_counter("janus_job_cancellations")
            .with_description("Count of cancelled jobs.")
            .init();
        job_cancel_counter.add(&Context::current(), 0, &[]);

        let http_request_duration_histogram = meter
            .f64_histogram("janus_http_request_duration_seconds")
            .with_description(
                "The amount of time elapsed while making an HTTP request to a helper.",
            )
            .with_unit(Unit::new("seconds"))
            .init();

        AggregationJobDriver {
            http_client,
            aggregate_step_failure_counter,
            job_cancel_counter,
            http_request_duration_histogram,
        }
    }

    async fn step_aggregation_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
    ) -> Result<()> {
        match (lease.leased().query_type(), lease.leased().vdaf()) {
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Count) => {
                let vdaf = Arc::new(Prio3::new_aes128_count(2)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Count>(datastore, vdaf, lease)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128CountVec { length }) => {
                let vdaf = Arc::new(Prio3::new_aes128_count_vec_multithreaded(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128CountVecMultithreaded>(datastore, vdaf, lease)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Sum { bits }) => {
                let vdaf = Arc::new(Prio3::new_aes128_sum(2, *bits)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Sum>(datastore, vdaf, lease)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Histogram { buckets }) => {
                let vdaf = Arc::new(Prio3::new_aes128_histogram(2, buckets)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Histogram>(datastore, vdaf, lease)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::TimeInterval,
                VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { length },
            ) => {
                let vdaf = Arc::new(Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(datastore, vdaf, lease)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::TimeInterval,
                VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { length },
            ) => {
                let vdaf = Arc::new(Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(datastore, vdaf, lease)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::TimeInterval,
                VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { length },
            ) => {
                let vdaf = Arc::new(Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(datastore, vdaf, lease)
                    .await
            }

            (task::QueryType::FixedSize { .. }, VdafInstance::Prio3Aes128Count) => {
                let vdaf = Arc::new(Prio3::new_aes128_count(2)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Count>(datastore, vdaf, lease)
                    .await
            }

            (task::QueryType::FixedSize { .. }, VdafInstance::Prio3Aes128CountVec { length }) => {
                let vdaf = Arc::new(Prio3::new_aes128_count_vec_multithreaded(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128CountVecMultithreaded>(datastore, vdaf, lease)
                    .await
            }

            (task::QueryType::FixedSize { .. }, VdafInstance::Prio3Aes128Sum { bits }) => {
                let vdaf = Arc::new(Prio3::new_aes128_sum(2, *bits)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Sum>(datastore, vdaf, lease)
                    .await
            }

            (task::QueryType::FixedSize { .. }, VdafInstance::Prio3Aes128Histogram { buckets }) => {
                let vdaf = Arc::new(Prio3::new_aes128_histogram(2, buckets)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Histogram>(datastore, vdaf, lease)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::FixedSize { .. },
                VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { length },
            ) => {
                let vdaf = Arc::new(Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(datastore, vdaf, lease)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::FixedSize { .. },
                VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { length },
            ) => {
                let vdaf = Arc::new(Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(datastore, vdaf, lease)
                    .await
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            (
                task::QueryType::FixedSize { .. },
                VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { length },
            ) => {
                let vdaf = Arc::new(Prio3::new_aes128_fixedpoint_boundedl2_vec_sum(2, *length)?);
                self.step_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(datastore, vdaf, lease)
                    .await
            }

            _ => panic!(
                "Query type/VDAF {:?}/{:?} is not yet supported",
                lease.leased().query_type(),
                lease.leased().vdaf()
            ),
        }
    }

    async fn step_aggregation_job_generic<
        const L: usize,
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        vdaf: Arc<A>,
        lease: Arc<Lease<AcquiredAggregationJob>>,
    ) -> Result<()>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Debug,
        A::OutputShare: PartialEq + Eq + Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        for<'a> A::PrepareState:
            PartialEq + Eq + Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
        A::InputShare: PartialEq + Send + Sync,
        A::PublicShare: PartialEq + Send + Sync,
    {
        // Read all information about the aggregation job.
        let (task, aggregation_job, report_aggregations, client_reports, verify_key) = datastore
            .run_tx_with_name("step_aggregation_job_1", |tx| {
                let (lease, vdaf) = (Arc::clone(&lease), Arc::clone(&vdaf));
                Box::pin(async move {
                    let task = tx
                        .get_task(lease.leased().task_id())
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                anyhow!("couldn't find task {}", lease.leased().task_id()).into(),
                            )
                        })?;
                    let verify_key = task.primary_vdaf_verify_key().map_err(|_| {
                        datastore::Error::User(
                            anyhow!("VDAF verification key has wrong length").into(),
                        )
                    })?;

                    let aggregation_job_future = tx.get_aggregation_job::<L, Q, A>(
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

                    // Read client reports, but only for report aggregations in state START.
                    // TODO(#224): create "get_client_reports_for_aggregation_job" datastore
                    // operation to avoid needing to join many futures?
                    let client_reports =
                        try_join_all(report_aggregations.iter().filter_map(|report_aggregation| {
                            if report_aggregation.state() == &ReportAggregationState::Start {
                                Some(
                                    tx.get_client_report(
                                        vdaf.as_ref(),
                                        lease.leased().task_id(),
                                        report_aggregation.report_id(),
                                    )
                                    .map(|rslt| {
                                        rslt.context(format!(
                                            "couldn't get report {} for task {}",
                                            *report_aggregation.report_id(),
                                            lease.leased().task_id(),
                                        ))
                                        .and_then(|maybe_report| {
                                            maybe_report.ok_or_else(|| {
                                                anyhow!(
                                                    "couldn't find report {} for task {}",
                                                    report_aggregation.report_id(),
                                                    lease.leased().task_id(),
                                                )
                                            })
                                        })
                                        .map_err(|err| datastore::Error::User(err.into()))
                                    }),
                                )
                            } else {
                                None
                            }
                        }))
                        .await?;

                    Ok((
                        Arc::new(task),
                        aggregation_job,
                        report_aggregations,
                        client_reports,
                        verify_key,
                    ))
                })
            })
            .await?;

        // Figure out the next step based on the non-error report aggregation states, and dispatch accordingly.
        let (mut saw_start, mut saw_waiting, mut saw_finished) = (false, false, false);
        for report_aggregation in &report_aggregations {
            match report_aggregation.state() {
                ReportAggregationState::Start => saw_start = true,
                ReportAggregationState::Waiting(_, _) => saw_waiting = true,
                ReportAggregationState::Finished(_) => saw_finished = true,
                ReportAggregationState::Failed(_) | ReportAggregationState::Invalid => (), // ignore failure aggregation states
            }
        }
        match (saw_start, saw_waiting, saw_finished) {
            // Only saw report aggregations in state "start" (or failed or invalid).
            (true, false, false) => self.step_aggregation_job_aggregate_init(
                &datastore, vdaf.as_ref(), lease, task, aggregation_job, report_aggregations, client_reports, verify_key).await,

            // Only saw report aggregations in state "waiting" (or failed or invalid).
            (false, true, false) => self.step_aggregation_job_aggregate_continue(
                &datastore, vdaf.as_ref(), lease, task, aggregation_job, report_aggregations).await,

            _ => Err(anyhow!("unexpected combination of report aggregation states (saw_start = {}, saw_waiting = {}, saw_finished = {})", saw_start, saw_waiting, saw_finished)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn step_aggregation_job_aggregate_init<
        const L: usize,
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        datastore: &Datastore<C>,
        vdaf: &A,
        lease: Arc<Lease<AcquiredAggregationJob>>,
        task: Arc<Task>,
        aggregation_job: AggregationJob<L, Q, A>,
        report_aggregations: Vec<ReportAggregation<L, A>>,
        client_reports: Vec<LeaderStoredReport<L, A>>,
        verify_key: VerifyKey<L>,
    ) -> Result<()>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Debug,
        A::OutputShare: PartialEq + Eq + Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareState: PartialEq + Eq + Send + Sync + Encode,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
        A::InputShare: PartialEq + Send + Sync,
        A::PublicShare: PartialEq + Send + Sync,
    {
        // Zip the report aggregations at start with the client reports, verifying that their IDs
        // match. We use asserts here as the conditions we are checking should be guaranteed by the
        // caller.
        let report_aggregations: Vec<_> = report_aggregations
            .into_iter()
            .filter(|report_aggregation| {
                report_aggregation.state() == &ReportAggregationState::Start
            })
            .collect();
        assert_eq!(report_aggregations.len(), client_reports.len());
        let reports: Vec<_> = report_aggregations
            .into_iter()
            .zip(client_reports.into_iter())
            .inspect(|(report_aggregation, client_report)| {
                assert_eq!(report_aggregation.task_id(), client_report.task_id());
                assert_eq!(
                    report_aggregation.report_id(),
                    client_report.metadata().id()
                );
            })
            .collect();

        // Compute report shares to send to helper, and decrypt our input shares & initialize
        // preparation state.
        let mut report_aggregations_to_write = Vec::new();
        let mut report_shares = Vec::new();
        let mut stepped_aggregations = Vec::new();
        for (report_aggregation, report) in reports {
            // Check for repeated extensions.
            let mut extension_types = HashSet::new();
            if !report
                .leader_extensions()
                .iter()
                .all(|extension| extension_types.insert(extension.extension_type()))
            {
                info!(report_id = %report_aggregation.report_id(), "Received report with duplicate extensions");
                self.aggregate_step_failure_counter.add(
                    &Context::current(),
                    1,
                    &[KeyValue::new("type", "duplicate_extension")],
                );
                report_aggregations_to_write.push(report_aggregation.with_state(
                    ReportAggregationState::Failed(ReportShareError::UnrecognizedMessage),
                ));
                continue;
            }

            // Initialize the leader's preparation state from the input share.
            let (prep_state, prep_share) = match vdaf.prepare_init(
                verify_key.as_bytes(),
                Role::Leader.index().unwrap(),
                aggregation_job.aggregation_parameter(),
                &report.metadata().id().get_encoded(),
                report.public_share(),
                report.leader_input_share(),
            ) {
                Ok(prep_state_and_share) => prep_state_and_share,
                Err(error) => {
                    info!(report_id = %report_aggregation.report_id(), ?error, "Couldn't initialize leader's preparation state");
                    self.aggregate_step_failure_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("type", "prepare_init_failure")],
                    );
                    report_aggregations_to_write.push(report_aggregation.with_state(
                        ReportAggregationState::Failed(ReportShareError::VdafPrepError),
                    ));
                    continue;
                }
            };

            report_shares.push(ReportShare::new(
                report.metadata().clone(),
                report.public_share().get_encoded(),
                report.helper_encrypted_input_share().clone(),
            ));
            stepped_aggregations.push(SteppedAggregation {
                report_aggregation,
                leader_transition: PrepareTransition::Continue(prep_state, prep_share),
            });
        }

        // Construct request, send it to the helper, and process the response.
        // TODO(#235): abandon work immediately on "terminal" failures from helper, or other
        // unexpected cases such as unknown/unexpected content type.
        let req = AggregationJobInitializeReq::<Q>::new(
            aggregation_job.aggregation_parameter().get_encoded(),
            PartialBatchSelector::new(aggregation_job.partial_batch_identifier().clone()),
            report_shares,
        );

        let resp_bytes = send_request_to_helper(
            &self.http_client,
            Method::PUT,
            task.aggregation_job_uri(aggregation_job.id())?,
            AggregationJobInitializeReq::<Q>::MEDIA_TYPE,
            req,
            task.primary_aggregator_auth_token(),
            &self.http_request_duration_histogram,
        )
        .await?;
        let resp = AggregationJobResp::get_decoded(&resp_bytes)?;

        self.process_response_from_helper(
            datastore,
            vdaf,
            lease,
            task,
            aggregation_job,
            &stepped_aggregations,
            report_aggregations_to_write,
            resp.prepare_steps(),
        )
        .await
    }

    async fn step_aggregation_job_aggregate_continue<
        const L: usize,
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        datastore: &Datastore<C>,
        vdaf: &A,
        lease: Arc<Lease<AcquiredAggregationJob>>,
        task: Arc<Task>,
        aggregation_job: AggregationJob<L, Q, A>,
        report_aggregations: Vec<ReportAggregation<L, A>>,
    ) -> Result<()>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Debug,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareState: Send + Sync + Encode,
        A::PrepareMessage: Send + Sync,
    {
        // Visit the report aggregations, ignoring any that have already failed; compute our own
        // next step & transitions to send to the helper.
        let mut report_aggregations_to_write = Vec::new();
        let mut prepare_steps = Vec::new();
        let mut stepped_aggregations = Vec::new();
        for report_aggregation in report_aggregations {
            if let ReportAggregationState::Waiting(prep_state, prep_msg) =
                report_aggregation.state()
            {
                let prep_msg = prep_msg
                    .as_ref()
                    .ok_or_else(|| anyhow!("report aggregation missing prepare message"))?;

                // Step our own state.
                let leader_transition = match vdaf
                    .prepare_step(prep_state.clone(), prep_msg.clone())
                {
                    Ok(leader_transition) => leader_transition,
                    Err(error) => {
                        info!(report_id = %report_aggregation.report_id(), ?error, "Prepare step failed");
                        self.aggregate_step_failure_counter.add(
                            &Context::current(),
                            1,
                            &[KeyValue::new("type", "prepare_step_failure")],
                        );
                        report_aggregations_to_write.push(report_aggregation.with_state(
                            ReportAggregationState::Failed(ReportShareError::VdafPrepError),
                        ));
                        continue;
                    }
                };

                prepare_steps.push(PrepareStep::new(
                    *report_aggregation.report_id(),
                    PrepareStepResult::Continued(prep_msg.get_encoded()),
                ));
                stepped_aggregations.push(SteppedAggregation {
                    report_aggregation,
                    leader_transition,
                })
            }
        }

        // Construct request, send it to the helper, and process the response.
        // TODO(#235): abandon work immediately on "terminal" failures from helper, or other
        // unexpected cases such as unknown/unexpected content type.
        let req = AggregationJobResp::new(prepare_steps);

        let resp_bytes = send_request_to_helper(
            &self.http_client,
            Method::POST,
            task.aggregation_job_uri(aggregation_job.id())?,
            AggregationJobContinueReq::MEDIA_TYPE,
            req,
            task.primary_aggregator_auth_token(),
            &self.http_request_duration_histogram,
        )
        .await?;
        let resp = AggregationJobResp::get_decoded(&resp_bytes)?;

        self.process_response_from_helper(
            datastore,
            vdaf,
            lease,
            task,
            aggregation_job,
            &stepped_aggregations,
            report_aggregations_to_write,
            resp.prepare_steps(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_response_from_helper<
        const L: usize,
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        datastore: &Datastore<C>,
        vdaf: &A,
        lease: Arc<Lease<AcquiredAggregationJob>>,
        task: Arc<Task>,
        aggregation_job: AggregationJob<L, Q, A>,
        stepped_aggregations: &[SteppedAggregation<L, A>],
        mut report_aggregations_to_write: Vec<ReportAggregation<L, A>>,
        prep_steps: &[PrepareStep],
    ) -> Result<()>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: fmt::Debug,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareState: Send + Sync + Encode,
    {
        // Handle response, computing the new report aggregations to be stored.
        if stepped_aggregations.len() != prep_steps.len() {
            return Err(anyhow!(
                "missing, duplicate, out-of-order, or unexpected prepare steps in response"
            ));
        }
        let mut accumulator = Accumulator::<L, Q, A>::new(
            Arc::clone(&task),
            aggregation_job.aggregation_parameter().clone(),
        );
        for (stepped_aggregation, helper_prep_step) in stepped_aggregations.iter().zip(prep_steps) {
            let (report_aggregation, leader_transition) = (
                &stepped_aggregation.report_aggregation,
                &stepped_aggregation.leader_transition,
            );
            if helper_prep_step.report_id() != report_aggregation.report_id() {
                return Err(anyhow!(
                    "missing, duplicate, out-of-order, or unexpected prepare steps in response"
                ));
            }

            let new_state = match helper_prep_step.result() {
                PrepareStepResult::Continued(payload) => {
                    // If the leader continued too, combine the leader's prepare share with the
                    // helper's to compute next round's prepare message. Prepare to store the
                    // leader's new state & the prepare message. If the leader didn't continue,
                    // transition to INVALID.
                    if let PrepareTransition::Continue(leader_prep_state, leader_prep_share) =
                        leader_transition
                    {
                        let leader_prep_state = leader_prep_state.clone();
                        let helper_prep_share =
                            A::PrepareShare::get_decoded_with_param(&leader_prep_state, payload)
                                .context("couldn't decode helper's prepare message");
                        let prep_msg = helper_prep_share.and_then(|helper_prep_share| {
                            vdaf.prepare_preprocess([leader_prep_share.clone(), helper_prep_share])
                                .context("couldn't preprocess leader & helper prepare shares into prepare message")
                        });
                        match prep_msg {
                            Ok(prep_msg) => {
                                ReportAggregationState::Waiting(leader_prep_state, Some(prep_msg))
                            }
                            Err(error) => {
                                info!(report_id = %report_aggregation.report_id(), ?error, "Couldn't compute prepare message");
                                self.aggregate_step_failure_counter.add(
                                    &Context::current(),
                                    1,
                                    &[KeyValue::new("type", "prepare_message_failure")],
                                );
                                ReportAggregationState::Failed(ReportShareError::VdafPrepError)
                            }
                        }
                    } else {
                        warn!(report_id = %report_aggregation.report_id(), "Helper continued but leader did not");
                        self.aggregate_step_failure_counter.add(
                            &Context::current(),
                            1,
                            &[KeyValue::new("type", "continue_mismatch")],
                        );
                        ReportAggregationState::Invalid
                    }
                }

                PrepareStepResult::Finished => {
                    // If the leader finished too, we are done; prepare to store the output share.
                    // If the leader didn't finish too, we transition to INVALID.
                    if let PrepareTransition::Finish(out_share) = leader_transition {
                        match accumulator.update(
                            aggregation_job.partial_batch_identifier(),
                            report_aggregation.report_id(),
                            report_aggregation.time(),
                            out_share,
                        ) {
                            Ok(_) => ReportAggregationState::Finished(out_share.clone()),
                            Err(error) => {
                                warn!(report_id = %report_aggregation.report_id(), ?error, "Could not update batch aggregation");
                                self.aggregate_step_failure_counter.add(
                                    &Context::current(),
                                    1,
                                    &[KeyValue::new("type", "accumulate_failure")],
                                );
                                ReportAggregationState::Failed(ReportShareError::VdafPrepError)
                            }
                        }
                    } else {
                        warn!(report_id = %report_aggregation.report_id(), "Helper finished but leader did not");
                        self.aggregate_step_failure_counter.add(
                            &Context::current(),
                            1,
                            &[KeyValue::new("type", "finish_mismatch")],
                        );
                        ReportAggregationState::Invalid
                    }
                }

                PrepareStepResult::Failed(err) => {
                    // If the helper failed, we move to FAILED immediately.
                    // TODO(#236): is it correct to just record the transition error that the helper reports?
                    info!(report_id = %report_aggregation.report_id(), helper_error = ?err, "Helper couldn't step report aggregation");
                    self.aggregate_step_failure_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("type", "helper_step_failure")],
                    );
                    ReportAggregationState::Failed(*err)
                }
            };

            report_aggregations_to_write.push(report_aggregation.clone().with_state(new_state));
        }

        // Determine if we've finished the aggregation job (i.e. if all report aggregations are in
        // a terminal state), then write everything back to storage.
        let aggregation_job_is_finished = report_aggregations_to_write
            .iter()
            .all(|ra| !matches!(ra.state(), ReportAggregationState::Waiting(_, _)));
        let aggregation_job_to_write = if aggregation_job_is_finished {
            Some(aggregation_job.with_state(AggregationJobState::Finished))
        } else {
            None
        };
        let report_aggregations_to_write = Arc::new(report_aggregations_to_write);
        let aggregation_job_to_write = Arc::new(aggregation_job_to_write);
        let accumulator = Arc::new(accumulator);
        datastore
            .run_tx_with_name("step_aggregation_job_2", |tx| {
                let (report_aggregations_to_write, aggregation_job_to_write, accumulator, lease) = (
                    Arc::clone(&report_aggregations_to_write),
                    Arc::clone(&aggregation_job_to_write),
                    Arc::clone(&accumulator),
                    Arc::clone(&lease),
                );
                Box::pin(async move {
                    let report_aggregations_future =
                        try_join_all(report_aggregations_to_write.iter().map(
                            |report_aggregation| tx.update_report_aggregation(report_aggregation),
                        ));
                    let aggregation_job_future = try_join_all(
                        aggregation_job_to_write
                            .iter()
                            .map(|aggregation_job| tx.update_aggregation_job(aggregation_job)),
                    );
                    let batch_aggregations_future = accumulator.flush_to_datastore(tx);

                    try_join!(
                        tx.release_aggregation_job(&lease),
                        report_aggregations_future,
                        aggregation_job_future,
                        batch_aggregations_future,
                    )?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    async fn cancel_aggregation_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredAggregationJob>,
    ) -> Result<()> {
        match (lease.leased().query_type(), lease.leased().vdaf()) {
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Count) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Count>(datastore, lease)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128CountVecMultithreaded>(datastore, lease)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Sum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Sum>(datastore, lease)
                    .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Histogram>(datastore, lease)
                    .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(datastore, lease)
                    .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(datastore, lease)
                    .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(datastore, lease)
                    .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Count) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Count>(datastore, lease)
                    .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128CountVecMultithreaded>(datastore, lease)
                    .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Sum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Sum>(datastore, lease)
                    .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Histogram>(datastore, lease)
                    .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize { .. }, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(datastore, lease)
                    .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize { .. }, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(datastore, lease)
                    .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize { .. }, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { .. }) => {
                self.cancel_aggregation_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(datastore, lease)
                    .await
            }

            _ => panic!("Query type/VDAF {:?}/{:?} is not yet supported", lease.leased().query_type(), lease.leased().vdaf()),
        }
    }

    async fn cancel_aggregation_job_generic<
        const L: usize,
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredAggregationJob>,
    ) -> Result<()>
    where
        A: Send + Sync + 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        let lease = Arc::new(lease);
        datastore
            .run_tx_with_name("cancel_aggregation_job", |tx| {
                let lease = Arc::clone(&lease);
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<L, Q, A>(
                            lease.leased().task_id(),
                            lease.leased().aggregation_job_id(),
                        )
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                anyhow!(
                                    "couldn't find aggregation job {} for task {}",
                                    lease.leased().aggregation_job_id(),
                                    lease.leased().task_id()
                                )
                                .into(),
                            )
                        })?;

                    // We leave all other data associated with the aggregation job (e.g. report
                    // aggregations) alone to ease debugging.
                    let aggregation_job =
                        aggregation_job.with_state(AggregationJobState::Abandoned);

                    let write_aggregation_job_future = tx.update_aggregation_job(&aggregation_job);
                    let release_future = tx.release_aggregation_job(&lease);
                    try_join!(write_aggregation_job_future, release_future)?;
                    Ok(())
                })
            })
            .await?;
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
                    .run_tx_with_name("acquire_aggregation_jobs", |tx| {
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
    ) -> impl Fn(Lease<AcquiredAggregationJob>) -> BoxFuture<'static, Result<(), anyhow::Error>>
    {
        move |lease| {
            let (this, datastore) = (Arc::clone(&self), Arc::clone(&datastore));
            Box::pin(async move {
                if lease.lease_attempts() > maximum_attempts_before_failure {
                    warn!(
                        attempts = %lease.lease_attempts(),
                        max_attempts = %maximum_attempts_before_failure,
                        "Canceling job due to too many failed attempts"
                    );
                    this.job_cancel_counter.add(&Context::current(), 1, &[]);
                    return this.cancel_aggregation_job(datastore, lease).await;
                }

                this.step_aggregation_job(datastore, Arc::new(lease)).await
            })
        }
    }
}

/// SteppedAggregation represents a report aggregation along with the associated preparation-state
/// transition representing the next step for the leader.
struct SteppedAggregation<const L: usize, A: vdaf::Aggregator<L>>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    report_aggregation: ReportAggregation<L, A>,
    leader_transition: PrepareTransition<A, L>,
}

#[cfg(test)]
mod tests {
    use super::AggregationJobDriver;
    use crate::{
        aggregator::{CollectableQueryType, DapProblemType, Error},
        binary_utils::job_driver::JobDriver,
        datastore::{
            models::{
                AggregationJob, AggregationJobState, BatchAggregation, LeaderStoredReport,
                ReportAggregation, ReportAggregationState,
            },
            test_util::ephemeral_datastore,
        },
        task::{test_util::TaskBuilder, QueryType, VerifyKey, PRIO3_AES128_VERIFY_KEY_LENGTH},
    };
    use assert_matches::assert_matches;
    use http::{header::CONTENT_TYPE, StatusCode};
    use janus_core::{
        hpke::{
            self, test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo, Label,
        },
        report_id::ReportIdChecksumExt,
        task::VdafInstance,
        test_util::{install_test_trace_subscriber, run_vdaf, runtime::TestRuntimeManager},
        time::{Clock, MockClock, TimeExt},
        Runtime,
    };
    use janus_messages::{
        query_type::{FixedSize, TimeInterval},
        AggregationJobContinueReq, AggregationJobInitializeReq, AggregationJobResp, Duration,
        Extension, ExtensionType, HpkeConfig, InputShareAad, Interval, PartialBatchSelector,
        PlaintextInputShare, PrepareStep, PrepareStepResult, ReportIdChecksum, ReportMetadata,
        ReportShare, ReportShareError, Role, TaskId, Time,
    };
    use mockito::mock;
    use opentelemetry::global::meter;
    use prio::{
        codec::Encode,
        vdaf::{
            self,
            prio3::{Prio3, Prio3Aes128Count},
            Aggregator,
        },
    };
    use rand::random;
    use reqwest::Url;
    use std::{borrow::Borrow, str, sync::Arc, time::Duration as StdDuration};

    #[tokio::test]
    async fn aggregation_job_driver() {
        // This is a minimal test that AggregationJobDriver::run() will successfully find
        // aggregation jobs & step them to completion. More detailed tests of the aggregation job
        // creation logic are contained in other tests which do not exercise the job-acquiry loop.
        // Note that we actually step twice to ensure that lease-release & re-acquiry works as
        // expected.

        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let mut runtime_manager = TestRuntimeManager::new();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()));
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_aggregator_endpoints(Vec::from([
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ]))
        .build();

        let time = clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap();
        let report_metadata = ReportMetadata::new(random(), time);
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();

        let transcript = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata.id(),
            &0,
        );

        let agg_auth_token = task.primary_aggregator_auth_token().clone();
        let helper_hpke_keypair = generate_test_hpke_config_and_private_key();
        let report = generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
            *task.id(),
            report_metadata,
            helper_hpke_keypair.config(),
            (),
            Vec::new(),
            transcript.input_shares.clone(),
        );

        let aggregation_job_id = random();

        ds.run_tx(|tx| {
            let (vdaf, task, report) = (vdaf.clone(), task.clone(), report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(vdaf.borrow(), &report).await?;

                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                >::new(
                    *task.id(),
                    aggregation_job_id,
                    (),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                ))
                .await?;
                tx.put_report_aggregation(&ReportAggregation::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                >::new(
                    *task.id(),
                    aggregation_job_id,
                    *report.metadata().id(),
                    *report.metadata().time(),
                    0,
                    ReportAggregationState::Start,
                ))
                .await
            })
        })
        .await
        .unwrap();

        // Setup: prepare mocked HTTP responses.
        let helper_vdaf_msg = transcript.helper_prep_share(0);
        let helper_responses = Vec::from([
            (
                "PUT",
                AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
                AggregationJobResp::MEDIA_TYPE,
                AggregationJobResp::new(Vec::from([PrepareStep::new(
                    *report.metadata().id(),
                    PrepareStepResult::Continued(helper_vdaf_msg.get_encoded()),
                )]))
                .get_encoded(),
            ),
            (
                "POST",
                AggregationJobContinueReq::MEDIA_TYPE,
                AggregationJobResp::MEDIA_TYPE,
                AggregationJobResp::new(Vec::from([PrepareStep::new(
                    *report.metadata().id(),
                    PrepareStepResult::Finished,
                )]))
                .get_encoded(),
            ),
        ]);
        let mocked_aggregates: Vec<_> = helper_responses
            .into_iter()
            .map(
                |(req_method, req_content_type, resp_content_type, resp_body)| {
                    mock(
                        req_method,
                        task.aggregation_job_uri(&aggregation_job_id)
                            .unwrap()
                            .path(),
                    )
                    .match_header(
                        "DAP-Auth-Token",
                        str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
                    )
                    .match_header(CONTENT_TYPE.as_str(), req_content_type)
                    .with_status(200)
                    .with_header(CONTENT_TYPE.as_str(), resp_content_type)
                    .with_body(resp_body)
                    .create()
                },
            )
            .collect();
        let meter = meter("aggregation_job_driver");
        let aggregation_job_driver =
            Arc::new(AggregationJobDriver::new(reqwest::Client::new(), &meter));

        // Run. Let the aggregation job driver step aggregation jobs, then kill it.
        let aggregation_job_driver = Arc::new(JobDriver::new(
            clock,
            runtime_manager.with_label("stepper"),
            meter,
            StdDuration::from_secs(1),
            StdDuration::from_secs(1),
            10,
            StdDuration::from_secs(60),
            aggregation_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&ds),
                StdDuration::from_secs(600),
            ),
            aggregation_job_driver.make_job_stepper_callback(Arc::clone(&ds), 5),
        ));

        let task_handle = runtime_manager.with_label("driver").spawn({
            let aggregation_job_driver = aggregation_job_driver.clone();
            async move { aggregation_job_driver.run().await }
        });

        tracing::info!("awaiting stepper tasks");
        // Wait for all of the aggregate job stepper tasks to complete.
        runtime_manager.wait_for_completed_tasks("stepper", 2).await;
        // Stop the aggregate job driver task.
        task_handle.abort();

        // Verify.
        for mocked_aggregate in mocked_aggregates {
            mocked_aggregate.assert();
        }

        let want_aggregation_job =
            AggregationJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            );
        let want_report_aggregation =
            ReportAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                *report.metadata().id(),
                *report.metadata().time(),
                0,
                ReportAggregationState::Finished(transcript.output_share(Role::Leader).clone()),
            );

        let (got_aggregation_job, got_report_aggregation) = ds
            .run_tx(|tx| {
                let (vdaf, task, report_id) =
                    (Arc::clone(&vdaf), task.clone(), *report.metadata().id());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await?
                        .unwrap();
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
    }

    #[tokio::test]
    async fn step_time_interval_aggregation_job_init() {
        // Setup: insert a client report and add it to a new aggregation job.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()));
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_aggregator_endpoints(Vec::from([
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ]))
        .build();

        let time = clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap();
        let report_metadata = ReportMetadata::new(random(), time);
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();

        let transcript = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata.id(),
            &0,
        );

        let agg_auth_token = task.primary_aggregator_auth_token();
        let helper_hpke_keypair = generate_test_hpke_config_and_private_key();
        let report = generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
            *task.id(),
            report_metadata,
            helper_hpke_keypair.config(),
            (),
            Vec::new(),
            transcript.input_shares.clone(),
        );
        let repeated_extension_report =
            generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
                *task.id(),
                ReportMetadata::new(random(), time),
                helper_hpke_keypair.config(),
                (),
                Vec::from([
                    Extension::new(ExtensionType::Tbd, Vec::new()),
                    Extension::new(ExtensionType::Tbd, Vec::new()),
                ]),
                transcript.input_shares.clone(),
            );
        let aggregation_job_id = random();

        let lease = ds
            .run_tx(|tx| {
                let (vdaf, task, report, repeated_extension_report) = (
                    vdaf.clone(),
                    task.clone(),
                    report.clone(),
                    repeated_extension_report.clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(vdaf.borrow(), &report).await?;
                    tx.put_client_report(vdaf.borrow(), &repeated_extension_report)
                        .await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        *report.metadata().time(),
                        0,
                        ReportAggregationState::Start,
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *repeated_extension_report.metadata().id(),
                        *repeated_extension_report.metadata().time(),
                        1,
                        ReportAggregationState::Start,
                    ))
                    .await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(&StdDuration::from_secs(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id(), task.id());
        assert_eq!(lease.leased().aggregation_job_id(), &aggregation_job_id);

        // Setup: prepare mocked HTTP response. (first an error response, then a success)
        // (This is fragile in that it expects the leader request to be deterministically encoded.
        // It would be nicer to retrieve the request bytes from the mock, then do our own parsing &
        // verification -- but mockito does not expose this functionality at time of writing.)
        let leader_request = AggregationJobInitializeReq::new(
            ().get_encoded(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([ReportShare::new(
                report.metadata().clone(),
                report.public_share().get_encoded(),
                report.helper_encrypted_input_share().clone(),
            )]),
        );
        let helper_vdaf_msg = transcript.helper_prep_share(0);
        let helper_response = AggregationJobResp::new(Vec::from([PrepareStep::new(
            *report.metadata().id(),
            PrepareStepResult::Continued(helper_vdaf_msg.get_encoded()),
        )]));
        let mocked_aggregate_failure = mock(
            "PUT",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .with_status(500)
        .with_header("Content-Type", "application/problem+json")
        .with_body("{\"type\": \"urn:ietf:params:ppm:dap:error:unauthorizedRequest\"}")
        .create();
        let mocked_aggregate_success = mock(
            "PUT",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .match_header(
            "DAP-Auth-Token",
            str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
        )
        .match_header(
            CONTENT_TYPE.as_str(),
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .match_body(leader_request.get_encoded())
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), AggregationJobResp::MEDIA_TYPE)
        .with_body(helper_response.get_encoded())
        .create();

        // Run: create an aggregation job driver & try to step the aggregation we've created twice.
        let meter = meter("aggregation_job_driver");
        let aggregation_job_driver =
            AggregationJobDriver::new(reqwest::Client::builder().build().unwrap(), &meter);
        let error = aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease.clone()))
            .await
            .unwrap_err();
        assert_matches!(
            error.downcast().unwrap(),
            Error::Http { problem_details, dap_problem_type } => {
                assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(dap_problem_type, Some(DapProblemType::UnauthorizedRequest));
            }
        );
        aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease))
            .await
            .unwrap();

        // Verify.
        mocked_aggregate_failure.assert();
        mocked_aggregate_success.assert();

        let want_aggregation_job =
            AggregationJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::InProgress,
            );
        let leader_prep_state = transcript.prep_state(0, Role::Leader).clone();
        let prep_msg = transcript.prepare_messages[0].clone();
        let want_report_aggregation =
            ReportAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                *report.metadata().id(),
                *report.metadata().time(),
                0,
                ReportAggregationState::Waiting(leader_prep_state, Some(prep_msg)),
            );
        let want_repeated_extension_report_aggregation =
            ReportAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                *repeated_extension_report.metadata().id(),
                *repeated_extension_report.metadata().time(),
                1,
                ReportAggregationState::Failed(ReportShareError::UnrecognizedMessage),
            );

        let (got_aggregation_job, got_report_aggregation, got_repeated_extension_report_aggregation) = ds
            .run_tx(|tx| {
                let (vdaf, task, report_id, repeated_extension_report_id) =
                    (Arc::clone(&vdaf), task.clone(), *report.metadata().id(), *repeated_extension_report.metadata().id());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await?
                        .unwrap();
                    let repeated_extension_report_aggregation = tx.get_report_aggregation(vdaf.as_ref(), &Role::Leader, task.id(), &aggregation_job_id, &repeated_extension_report_id).await?.unwrap();
                    Ok((aggregation_job, report_aggregation, repeated_extension_report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
        assert_eq!(
            want_repeated_extension_report_aggregation,
            got_repeated_extension_report_aggregation
        );
    }

    #[tokio::test]
    async fn step_fixed_size_aggregation_job_init() {
        // Setup: insert a client report and add it to a new aggregation job.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()));
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());

        let task = TaskBuilder::new(
            QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_aggregator_endpoints(Vec::from([
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ]))
        .build();

        let report_metadata = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();

        let transcript = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata.id(),
            &0,
        );

        let agg_auth_token = task.primary_aggregator_auth_token();
        let helper_hpke_keypair = generate_test_hpke_config_and_private_key();
        let report = generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
            *task.id(),
            report_metadata,
            helper_hpke_keypair.config(),
            (),
            Vec::new(),
            transcript.input_shares.clone(),
        );
        let batch_id = random();
        let aggregation_job_id = random();

        let lease = ds
            .run_tx(|tx| {
                let (vdaf, task, report) = (vdaf.clone(), task.clone(), report.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(vdaf.borrow(), &report).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        FixedSize,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        batch_id,
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        *report.metadata().time(),
                        0,
                        ReportAggregationState::Start,
                    ))
                    .await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(&StdDuration::from_secs(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id(), task.id());
        assert_eq!(lease.leased().aggregation_job_id(), &aggregation_job_id);

        // Setup: prepare mocked HTTP response. (first an error response, then a success)
        // (This is fragile in that it expects the leader request to be deterministically encoded.
        // It would be nicer to retrieve the request bytes from the mock, then do our own parsing &
        // verification -- but mockito does not expose this functionality at time of writing.)
        let leader_request = AggregationJobInitializeReq::new(
            ().get_encoded(),
            PartialBatchSelector::new_fixed_size(batch_id),
            Vec::from([ReportShare::new(
                report.metadata().clone(),
                report.public_share().get_encoded(),
                report.helper_encrypted_input_share().clone(),
            )]),
        );
        let helper_vdaf_msg = transcript.helper_prep_share(0);
        let helper_response = AggregationJobResp::new(Vec::from([PrepareStep::new(
            *report.metadata().id(),
            PrepareStepResult::Continued(helper_vdaf_msg.get_encoded()),
        )]));
        let mocked_aggregate_failure = mock(
            "PUT",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .with_status(500)
        .with_header("Content-Type", "application/problem+json")
        .with_body("{\"type\": \"urn:ietf:params:ppm:dap:error:unauthorizedRequest\"}")
        .create();
        let mocked_aggregate_success = mock(
            "PUT",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .match_header(
            "DAP-Auth-Token",
            str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
        )
        .match_header(
            CONTENT_TYPE.as_str(),
            AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
        )
        .match_body(leader_request.get_encoded())
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), AggregationJobResp::MEDIA_TYPE)
        .with_body(helper_response.get_encoded())
        .create();

        // Run: create an aggregation job driver & try to step the aggregation we've created twice.
        let meter = meter("aggregation_job_driver");
        let aggregation_job_driver =
            AggregationJobDriver::new(reqwest::Client::builder().build().unwrap(), &meter);
        let error = aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease.clone()))
            .await
            .unwrap_err();
        assert_matches!(
            error.downcast().unwrap(),
            Error::Http { problem_details, dap_problem_type } => {
                assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(dap_problem_type, Some(DapProblemType::UnauthorizedRequest));
            }
        );
        aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease))
            .await
            .unwrap();

        // Verify.
        mocked_aggregate_failure.assert();
        mocked_aggregate_success.assert();

        let want_aggregation_job =
            AggregationJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, FixedSize, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                (),
                batch_id,
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::InProgress,
            );
        let want_report_aggregation =
            ReportAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                *report.metadata().id(),
                *report.metadata().time(),
                0,
                ReportAggregationState::Waiting(
                    transcript.prep_state(0, Role::Leader).clone(),
                    Some(transcript.prepare_messages[0].clone()),
                ),
            );

        let (got_aggregation_job, got_report_aggregation) = ds
            .run_tx(|tx| {
                let (vdaf, task, report_id) =
                    (Arc::clone(&vdaf), task.clone(), *report.metadata().id());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, FixedSize, Prio3Aes128Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await?
                        .unwrap();
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
    }

    #[tokio::test]
    async fn step_time_interval_aggregation_job_continue() {
        // Setup: insert a client report and add it to an aggregation job whose state has already
        // been stepped once.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()));
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_aggregator_endpoints(Vec::from([
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ]))
        .build();
        let time = clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap();
        let report_metadata = ReportMetadata::new(random(), time);
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();

        let transcript = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata.id(),
            &0,
        );

        let agg_auth_token = task.primary_aggregator_auth_token();
        let helper_hpke_keypair = generate_test_hpke_config_and_private_key();
        let report = generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
            *task.id(),
            report_metadata,
            helper_hpke_keypair.config(),
            (),
            Vec::new(),
            transcript.input_shares.clone(),
        );
        let aggregation_job_id = random();

        let leader_prep_state = transcript.prep_state(0, Role::Leader);
        let leader_aggregate_share = vdaf
            .aggregate(&(), [transcript.output_share(Role::Leader).clone()])
            .unwrap();
        let prep_msg = &transcript.prepare_messages[0];

        let lease = ds
            .run_tx(|tx| {
                let (vdaf, task, report, leader_prep_state, prep_msg) = (
                    vdaf.clone(),
                    task.clone(),
                    report.clone(),
                    leader_prep_state.clone(),
                    prep_msg.clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(vdaf.borrow(), &report).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        (),
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        *report.metadata().time(),
                        0,
                        ReportAggregationState::Waiting(leader_prep_state, Some(prep_msg)),
                    ))
                    .await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(&StdDuration::from_secs(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id(), task.id());
        assert_eq!(lease.leased().aggregation_job_id(), &aggregation_job_id);

        // Setup: prepare mocked HTTP responses. (first an error response, then a success)
        // (This is fragile in that it expects the leader request to be deterministically encoded.
        // It would be nicer to retrieve the request bytes from the mock, then do our own parsing &
        // verification -- but mockito does not expose this functionality at time of writing.)
        let leader_request = AggregationJobContinueReq::new(Vec::from([PrepareStep::new(
            *report.metadata().id(),
            PrepareStepResult::Continued(prep_msg.get_encoded()),
        )]));
        let helper_response = AggregationJobResp::new(Vec::from([PrepareStep::new(
            *report.metadata().id(),
            PrepareStepResult::Finished,
        )]));
        let mocked_aggregate_failure = mock(
            "POST",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .with_status(500)
        .with_header("Content-Type", "application/problem+json")
        .with_body("{\"type\": \"urn:ietf:params:ppm:dap:error:unrecognizedTask\"}")
        .create();
        let mocked_aggregate_success = mock(
            "POST",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .match_header(
            "DAP-Auth-Token",
            str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
        )
        .match_header(CONTENT_TYPE.as_str(), AggregationJobContinueReq::MEDIA_TYPE)
        .match_body(leader_request.get_encoded())
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), AggregationJobResp::MEDIA_TYPE)
        .with_body(helper_response.get_encoded())
        .create();

        // Run: create an aggregation job driver & try to step the aggregation we've created twice.
        let meter = meter("aggregation_job_driver");
        let aggregation_job_driver =
            AggregationJobDriver::new(reqwest::Client::builder().build().unwrap(), &meter);
        let error = aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease.clone()))
            .await
            .unwrap_err();
        assert_matches!(
            error.downcast().unwrap(),
            Error::Http { problem_details, dap_problem_type } => {
                assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(dap_problem_type, Some(DapProblemType::UnrecognizedTask));
            }
        );
        aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease))
            .await
            .unwrap();

        // Verify.
        mocked_aggregate_failure.assert();
        mocked_aggregate_success.assert();

        let want_aggregation_job =
            AggregationJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            );
        let want_report_aggregation =
            ReportAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                *report.metadata().id(),
                *report.metadata().time(),
                0,
                ReportAggregationState::Finished(transcript.output_share(Role::Leader).clone()),
            );
        let batch_interval_start = report
            .metadata()
            .time()
            .to_batch_interval_start(task.time_precision())
            .unwrap();
        let want_batch_aggregations = Vec::from([BatchAggregation::<
            PRIO3_AES128_VERIFY_KEY_LENGTH,
            TimeInterval,
            Prio3Aes128Count,
        >::new(
            *task.id(),
            Interval::new(batch_interval_start, *task.time_precision()).unwrap(),
            (),
            leader_aggregate_share,
            1,
            ReportIdChecksum::for_report_id(report.metadata().id()),
        )]);

        let (got_aggregation_job, got_report_aggregation, got_batch_aggregations) = ds
            .run_tx(|tx| {
                let (vdaf, task, report_metadata) = (Arc::clone(&vdaf), task.clone(), report.metadata().clone());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            report_metadata.id(),
                        )
                        .await?
                        .unwrap();
                    let batch_aggregations = TimeInterval::get_batch_aggregations_for_collect_identifier::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count, _>(
                        tx,
                        &task,
                        &Interval::new(
                            report_metadata.time().to_batch_interval_start(task.time_precision()).unwrap(),
                            *task.time_precision()).unwrap(),
                        &(),
                    ).await.unwrap();
                    Ok((aggregation_job, report_aggregation, batch_aggregations))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
        assert_eq!(want_batch_aggregations, got_batch_aggregations);
    }

    #[tokio::test]
    async fn step_fixed_size_aggregation_job_continue() {
        // Setup: insert a client report and add it to an aggregation job whose state has already
        // been stepped once.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()));
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());

        let task = TaskBuilder::new(
            QueryType::FixedSize { max_batch_size: 10 },
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_aggregator_endpoints(Vec::from([
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ]))
        .build();
        let report_metadata = ReportMetadata::new(
            random(),
            clock
                .now()
                .to_batch_interval_start(task.time_precision())
                .unwrap(),
        );
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();

        let transcript = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata.id(),
            &0,
        );

        let agg_auth_token = task.primary_aggregator_auth_token();
        let helper_hpke_keypair = generate_test_hpke_config_and_private_key();
        let report = generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
            *task.id(),
            report_metadata,
            helper_hpke_keypair.config(),
            (),
            Vec::new(),
            transcript.input_shares.clone(),
        );
        let batch_id = random();
        let aggregation_job_id = random();

        let leader_prep_state = transcript.prep_state(0, Role::Leader);
        let leader_aggregate_share = vdaf
            .aggregate(&(), [transcript.output_share(Role::Leader).clone()])
            .unwrap();
        let prep_msg = &transcript.prepare_messages[0];

        let lease = ds
            .run_tx(|tx| {
                let (vdaf, task, report, leader_prep_state, prep_msg) = (
                    vdaf.clone(),
                    task.clone(),
                    report.clone(),
                    leader_prep_state.clone(),
                    prep_msg.clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(vdaf.borrow(), &report).await?;

                    tx.put_aggregation_job(&AggregationJob::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        FixedSize,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        (),
                        batch_id,
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                    ))
                    .await?;
                    tx.put_report_aggregation(&ReportAggregation::<
                        PRIO3_AES128_VERIFY_KEY_LENGTH,
                        Prio3Aes128Count,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        *report.metadata().time(),
                        0,
                        ReportAggregationState::Waiting(leader_prep_state, Some(prep_msg)),
                    ))
                    .await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(&StdDuration::from_secs(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id(), task.id());
        assert_eq!(lease.leased().aggregation_job_id(), &aggregation_job_id);

        // Setup: prepare mocked HTTP responses. (first an error response, then a success)
        // (This is fragile in that it expects the leader request to be deterministically encoded.
        // It would be nicer to retrieve the request bytes from the mock, then do our own parsing &
        // verification -- but mockito does not expose this functionality at time of writing.)
        let leader_request = AggregationJobContinueReq::new(Vec::from([PrepareStep::new(
            *report.metadata().id(),
            PrepareStepResult::Continued(prep_msg.get_encoded()),
        )]));
        let helper_response = AggregationJobResp::new(Vec::from([PrepareStep::new(
            *report.metadata().id(),
            PrepareStepResult::Finished,
        )]));
        let mocked_aggregate_failure = mock(
            "POST",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .with_status(500)
        .with_header("Content-Type", "application/problem+json")
        .with_body("{\"type\": \"urn:ietf:params:ppm:dap:error:unrecognizedTask\"}")
        .create();
        let mocked_aggregate_success = mock(
            "POST",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .match_header(
            "DAP-Auth-Token",
            str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
        )
        .match_header(CONTENT_TYPE.as_str(), AggregationJobContinueReq::MEDIA_TYPE)
        .match_body(leader_request.get_encoded())
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), AggregationJobResp::MEDIA_TYPE)
        .with_body(helper_response.get_encoded())
        .create();

        // Run: create an aggregation job driver & try to step the aggregation we've created twice.
        let meter = meter("aggregation_job_driver");
        let aggregation_job_driver =
            AggregationJobDriver::new(reqwest::Client::builder().build().unwrap(), &meter);
        let error = aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease.clone()))
            .await
            .unwrap_err();
        assert_matches!(
            error.downcast().unwrap(),
            Error::Http { problem_details, dap_problem_type } => {
                assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(dap_problem_type, Some(DapProblemType::UnrecognizedTask));
            }
        );
        aggregation_job_driver
            .step_aggregation_job(ds.clone(), Arc::new(lease))
            .await
            .unwrap();

        // Verify.
        mocked_aggregate_failure.assert();
        mocked_aggregate_success.assert();

        let want_aggregation_job =
            AggregationJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, FixedSize, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                (),
                batch_id,
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Finished,
            );
        let leader_output_share = transcript.output_share(Role::Leader);
        let want_report_aggregation =
            ReportAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                *report.metadata().id(),
                *report.metadata().time(),
                0,
                ReportAggregationState::Finished(leader_output_share.clone()),
            );
        let want_batch_aggregations = Vec::from([BatchAggregation::<
            PRIO3_AES128_VERIFY_KEY_LENGTH,
            FixedSize,
            Prio3Aes128Count,
        >::new(
            *task.id(),
            batch_id,
            (),
            leader_aggregate_share,
            1,
            ReportIdChecksum::for_report_id(report.metadata().id()),
        )]);

        let (got_aggregation_job, got_report_aggregation, got_batch_aggregations) = ds
            .run_tx(|tx| {
                let (vdaf, task, report_metadata) = (Arc::clone(&vdaf), task.clone(), report.metadata().clone());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, FixedSize, Prio3Aes128Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            report_metadata.id(),
                        )
                        .await?
                        .unwrap();
                    let batch_aggregations = FixedSize::get_batch_aggregations_for_collect_identifier::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count, _>(
                        tx,
                        &task,
                        &batch_id,
                        &(),
                    ).await?;
                    Ok((aggregation_job, report_aggregation, batch_aggregations))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
        assert_eq!(want_batch_aggregations, got_batch_aggregations);
    }

    #[tokio::test]
    async fn cancel_aggregation_job() {
        // Setup: insert a client report and add it to a new aggregation job.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()));
        let vdaf = Arc::new(Prio3::new_aes128_count(2).unwrap());

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_aggregator_endpoints(Vec::from([
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ]))
        .build();
        let time = clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap();
        let report_metadata = ReportMetadata::new(random(), time);
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();

        let transcript = run_vdaf(
            vdaf.as_ref(),
            verify_key.as_bytes(),
            &(),
            report_metadata.id(),
            &0,
        );

        let helper_hpke_keypair = generate_test_hpke_config_and_private_key();
        let report = generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
            *task.id(),
            report_metadata,
            helper_hpke_keypair.config(),
            (),
            Vec::new(),
            transcript.input_shares,
        );
        let aggregation_job_id = random();

        let aggregation_job =
            AggregationJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::InProgress,
            );
        let report_aggregation =
            ReportAggregation::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                *report.metadata().id(),
                *report.metadata().time(),
                0,
                ReportAggregationState::Start,
            );

        let lease = ds
            .run_tx(|tx| {
                let (vdaf, task, report, aggregation_job, report_aggregation) = (
                    vdaf.clone(),
                    task.clone(),
                    report.clone(),
                    aggregation_job.clone(),
                    report_aggregation.clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(vdaf.borrow(), &report).await?;
                    tx.put_aggregation_job(&aggregation_job).await?;
                    tx.put_report_aggregation(&report_aggregation).await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(&StdDuration::from_secs(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id(), task.id());
        assert_eq!(lease.leased().aggregation_job_id(), &aggregation_job_id);

        // Run: create an aggregation job driver & cancel the aggregation job.
        let meter = meter("aggregation_job_driver");
        let aggregation_job_driver =
            AggregationJobDriver::new(reqwest::Client::builder().build().unwrap(), &meter);
        aggregation_job_driver
            .cancel_aggregation_job(Arc::clone(&ds), lease)
            .await
            .unwrap();

        // Verify: check that the datastore state is updated as expected (the aggregation job is
        // abandoned, the report aggregation is untouched) and sanity-check that the job can no
        // longer be acquired.
        let want_aggregation_job = aggregation_job.with_state(AggregationJobState::Abandoned);
        let want_report_aggregation = report_aggregation;

        let (got_aggregation_job, got_report_aggregation, got_leases) = ds
            .run_tx(|tx| {
                let (vdaf, task, report_id) =
                    (Arc::clone(&vdaf), task.clone(), *report.metadata().id());
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                            task.id(),
                            &aggregation_job_id,
                        )
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation(
                            vdaf.as_ref(),
                            &Role::Leader,
                            task.id(),
                            &aggregation_job_id,
                            &report_id,
                        )
                        .await?
                        .unwrap();
                    let leases = tx
                        .acquire_incomplete_aggregation_jobs(&StdDuration::from_secs(60), 1)
                        .await?;
                    Ok((aggregation_job, report_aggregation, leases))
                })
            })
            .await
            .unwrap();
        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
        assert!(got_leases.is_empty());
    }

    /// Returns a [`LeaderStoredReport`] with the given task ID & metadata values and encrypted
    /// input shares corresponding to the given HPKE configs & input shares.
    fn generate_report<const L: usize, A>(
        task_id: TaskId,
        report_metadata: ReportMetadata,
        helper_hpke_config: &HpkeConfig,
        public_share: A::PublicShare,
        extensions: Vec<Extension>,
        input_shares: Vec<A::InputShare>,
    ) -> LeaderStoredReport<L, A>
    where
        A: vdaf::Aggregator<L>,
        A::InputShare: PartialEq,
        A::PublicShare: PartialEq,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    {
        assert_eq!(input_shares.len(), 2);

        let encrypted_helper_input_share = hpke::seal(
            helper_hpke_config,
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
            &PlaintextInputShare::new(
                Vec::new(),
                input_shares
                    .get(Role::Helper.index().unwrap())
                    .unwrap()
                    .get_encoded(),
            )
            .get_encoded(),
            &InputShareAad::new(task_id, report_metadata.clone(), public_share.get_encoded())
                .get_encoded(),
        )
        .unwrap();

        LeaderStoredReport::new(
            task_id,
            report_metadata,
            public_share,
            extensions,
            input_shares
                .get(Role::Leader.index().unwrap())
                .unwrap()
                .clone(),
            encrypted_helper_input_share,
        )
    }

    #[tokio::test]
    async fn abandon_failing_aggregation_job() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let mut runtime_manager = TestRuntimeManager::new();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Prio3Aes128Count,
            Role::Leader,
        )
        .with_aggregator_endpoints(Vec::from([
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ]))
        .build();
        let agg_auth_token = task.primary_aggregator_auth_token();
        let aggregation_job_id = random();
        let verify_key: VerifyKey<PRIO3_AES128_VERIFY_KEY_LENGTH> =
            task.primary_vdaf_verify_key().unwrap();

        let helper_hpke_keypair = generate_test_hpke_config_and_private_key();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let time = clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap();
        let report_metadata = ReportMetadata::new(random(), time);
        let transcript = run_vdaf(&vdaf, verify_key.as_bytes(), &(), report_metadata.id(), &0);
        let report = generate_report::<PRIO3_AES128_VERIFY_KEY_LENGTH, Prio3Aes128Count>(
            *task.id(),
            report_metadata,
            helper_hpke_keypair.config(),
            (),
            Vec::new(),
            transcript.input_shares,
        );

        // Set up fixtures in the database.
        ds.run_tx(|tx| {
            let vdaf = vdaf.clone();
            let task = task.clone();
            let report = report.clone();
            Box::pin(async move {
                tx.put_task(&task).await?;

                // We need to store a well-formed report, as it will get parsed by the leader and
                // run through initial VDAF preparation before sending a request to the helper.
                tx.put_client_report(&vdaf, &report).await?;

                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    TimeInterval,
                    Prio3Aes128Count,
                >::new(
                    *task.id(),
                    aggregation_job_id,
                    (),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                ))
                .await?;

                tx.put_report_aggregation(&ReportAggregation::<
                    PRIO3_AES128_VERIFY_KEY_LENGTH,
                    Prio3Aes128Count,
                >::new(
                    *task.id(),
                    aggregation_job_id,
                    *report.metadata().id(),
                    *report.metadata().time(),
                    0,
                    ReportAggregationState::Start,
                ))
                .await?;

                Ok(())
            })
        })
        .await
        .unwrap();

        // Set up the aggregation job driver.
        let meter = meter("aggregation_job_driver");
        let aggregation_job_driver =
            Arc::new(AggregationJobDriver::new(reqwest::Client::new(), &meter));
        let job_driver = Arc::new(JobDriver::new(
            clock.clone(),
            runtime_manager.with_label("stepper"),
            meter,
            StdDuration::from_secs(1),
            StdDuration::from_secs(1),
            10,
            StdDuration::from_secs(60),
            aggregation_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&ds),
                StdDuration::from_secs(600),
            ),
            aggregation_job_driver.make_job_stepper_callback(Arc::clone(&ds), 3),
        ));

        // Set up three error responses from our mock helper. These will cause errors in the
        // leader, because the response body is empty and cannot be decoded.
        let failure_mock = mock(
            "PUT",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .match_header(
            "DAP-Auth-Token",
            str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
        )
        .match_header(
            CONTENT_TYPE.as_str(),
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_status(500)
        .expect(3)
        .create();
        // Set up an extra response that should never be used, to make sure the job driver doesn't
        // make more requests than we expect. If there were no remaining mocks, mockito would have
        // respond with a fallback error response instead.
        let no_more_requests_mock = mock(
            "PUT",
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .match_header(
            "DAP-Auth-Token",
            str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
        )
        .match_header(
            CONTENT_TYPE.as_str(),
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_status(500)
        .expect(1)
        .create();

        // Start up the job driver.
        let task_handle = runtime_manager
            .with_label("driver")
            .spawn(async move { job_driver.run().await });

        // Run the job driver until we try to step the collection job four times. The first three
        // attempts make network requests and fail, while the fourth attempt just marks the job
        // as abandoned.
        for i in 1..=4 {
            // Wait for the next task to be spawned and to complete.
            runtime_manager.wait_for_completed_tasks("stepper", i).await;
            // Advance the clock by the lease duration, so that the job driver can pick up the job
            // and try again.
            clock.advance(Duration::from_seconds(600));
        }
        task_handle.abort();

        // Check that the job driver made the HTTP requests we expected.
        failure_mock.assert();
        assert!(!no_more_requests_mock.matched());

        // Confirm in the database that the job was abandoned.
        let aggregation_job_after = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.get_aggregation_job::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>(
                        task.id(),
                        &aggregation_job_id,
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            aggregation_job_after,
            AggregationJob::<PRIO3_AES128_VERIFY_KEY_LENGTH, TimeInterval, Prio3Aes128Count>::new(
                *task.id(),
                aggregation_job_id,
                (),
                (),
                Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                    .unwrap(),
                AggregationJobState::Abandoned,
            ),
        );
    }
}
