use anyhow::{anyhow, Context, Result};
use futures::{
    future::{try_join_all, FutureExt},
    try_join,
};
use http::header::CONTENT_TYPE;
use janus::{
    hpke::{self, associated_data_for_report_share, HpkeApplicationInfo, Label},
    message::{Duration, Report, Role},
    time::{Clock, RealClock},
};
use janus_server::{
    binary_utils::{janus_main, job_driver::JobDriver, BinaryOptions, CommonBinaryOptions},
    config::AggregationJobDriverConfig,
    datastore::{
        self,
        models::{
            AcquiredAggregationJob, AggregationJob, AggregationJobState, Lease, ReportAggregation,
            ReportAggregationState,
        },
        Datastore,
    },
    message::{
        AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq,
        AggregateInitializeResp, PrepareStep, PrepareStepResult, ReportShare, ReportShareError,
    },
    task::{Task, VdafInstance, DAP_AUTH_HEADER},
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf::{
        self,
        prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        PrepareTransition,
    },
};
use std::{fmt::Debug, sync::Arc};
use structopt::StructOpt;
use tracing::{error, warn};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-aggregation-job-driver",
    about = "Janus aggregation job driver",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    #[structopt(flatten)]
    common: CommonBinaryOptions,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        &self.common
    }
}

const CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/aggregation_job_driver",
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main::<Options, _, _, _, _>(
        RealClock::default(),
        |clock, config: AggregationJobDriverConfig, datastore| async move {
            let datastore = Arc::new(datastore);
            let aggregation_job_driver = Arc::new(AggregationJobDriver {
                http_client: reqwest::Client::builder()
                    .user_agent(CLIENT_USER_AGENT)
                    .build()
                    .context("couldn't create HTTP client")?,
            });
            let lease_duration =
                Duration::from_seconds(config.job_driver_config.worker_lease_duration_secs);

            // Start running.
            Arc::new(JobDriver::new(
                clock,
                Duration::from_seconds(config.job_driver_config.min_job_discovery_delay_secs),
                Duration::from_seconds(config.job_driver_config.max_job_discovery_delay_secs),
                config.job_driver_config.max_concurrent_job_workers,
                Duration::from_seconds(
                    config
                        .job_driver_config
                        .worker_lease_clock_skew_allowance_secs,
                ),
                {
                    let datastore = Arc::clone(&datastore);
                    move |max_acquire_count| {
                        let datastore = Arc::clone(&datastore);
                        async move {
                            datastore
                                .run_tx(|tx| {
                                    Box::pin(async move {
                                        // TODO(#193): only acquire jobs whose batch units have not
                                        // already been collected (probably by modifying
                                        // acquire_incomplete_aggregation_jobs)
                                        tx.acquire_incomplete_aggregation_jobs(
                                            lease_duration,
                                            max_acquire_count,
                                        )
                                        .await
                                    })
                                })
                                .await
                        }
                    }
                },
                {
                    let datastore = Arc::clone(&datastore);
                    move |aggregation_job_lease| {
                        let (datastore, aggregation_job_driver) =
                            (Arc::clone(&datastore), Arc::clone(&aggregation_job_driver));
                        async move {
                            if aggregation_job_lease.lease_attempts()
                                >= config.job_driver_config.maximum_attempts_before_failure
                            {
                                warn!(attempts = ?aggregation_job_lease.lease_attempts(),
                                    max_attempts = ?config.job_driver_config.maximum_attempts_before_failure,
                                    "Canceling job due to too many failed attempts");
                                return aggregation_job_driver
                                    .cancel_aggregation_job(datastore, aggregation_job_lease)
                                    .await;
                            }

                            aggregation_job_driver
                                .step_aggregation_job(datastore, aggregation_job_lease)
                                .await
                        }
                    }
                },
            ))
            .run()
            .await;

            Ok(())
        },
    )
    .await
}

#[derive(Debug)]
struct AggregationJobDriver {
    http_client: reqwest::Client,
}

impl AggregationJobDriver {
    async fn step_aggregation_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredAggregationJob>,
    ) -> Result<()> {
        match lease.leased().vdaf {
            VdafInstance::Real(janus::task::VdafInstance::Prio3Aes128Count) => {
                let vdaf = Prio3Aes128Count::new(2)?;
                self.step_aggregation_job_generic(datastore, vdaf, lease)
                    .await
            }
            VdafInstance::Real(janus::task::VdafInstance::Prio3Aes128Sum { bits }) => {
                let vdaf = Prio3Aes128Sum::new(2, bits)?;
                self.step_aggregation_job_generic(datastore, vdaf, lease)
                    .await
            }
            VdafInstance::Real(janus::task::VdafInstance::Prio3Aes128Histogram { ref buckets }) => {
                let vdaf = Prio3Aes128Histogram::new(2, buckets)?;
                self.step_aggregation_job_generic(datastore, vdaf, lease)
                    .await
            }

            _ => panic!("VDAF {:?} is not yet supported", lease.leased().vdaf),
        }
    }

    async fn step_aggregation_job_generic<C, A>(
        &self,
        datastore: Arc<Datastore<C>>,
        vdaf: A,
        lease: Lease<AcquiredAggregationJob>,
    ) -> Result<()>
    where
        C: Clock,
        A: vdaf::Aggregator + 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: PartialEq + Eq + Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareStep: PartialEq + Eq + Send + Sync + Encode + ParameterizedDecode<A::VerifyParam>,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
        A::VerifyParam: Send + Sync + ParameterizedDecode<A>,
    {
        // Read all information about the aggregation job.
        let vdaf = Arc::new(vdaf);
        let task_id = lease.leased().task_id;
        let aggregation_job_id = lease.leased().aggregation_job_id;
        let (task, aggregation_job, report_aggregations, client_reports, verify_param) = datastore
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);
                Box::pin(async move {
                    let task = tx.get_task(task_id).await?.ok_or_else(|| {
                        datastore::Error::User(anyhow!("couldn't find task {}", task_id).into())
                    })?;
                    let verify_param = A::VerifyParam::get_decoded_with_param(
                        &vdaf,
                        task.vdaf_verify_parameters.get(0).unwrap(),
                    )?;

                    let aggregation_job_future =
                        tx.get_aggregation_job::<A>(task_id, aggregation_job_id);
                    let report_aggregations_future = tx
                        .get_report_aggregations_for_aggregation_job::<A>(
                            &verify_param,
                            task_id,
                            aggregation_job_id,
                        );

                    let (aggregation_job, report_aggregations) =
                        try_join!(aggregation_job_future, report_aggregations_future)?;
                    let aggregation_job = aggregation_job.ok_or_else(|| {
                        datastore::Error::User(
                            anyhow!(
                                "couldn't find aggregation job {} for task {}",
                                aggregation_job_id,
                                task_id
                            )
                            .into(),
                        )
                    })?;

                    // Read client reports, but only for report aggregations in state START.
                    // TODO(#224): create "get_client_reports_for_aggregation_job" datastore
                    // operation to avoid needing to join many futures?
                    let client_reports =
                        try_join_all(report_aggregations.iter().filter_map(|report_aggregation| {
                            if report_aggregation.state == ReportAggregationState::Start {
                                Some(tx.get_client_report(task_id, report_aggregation.nonce).map(
                                    |rslt| {
                                        rslt.context(format!(
                                            "couldn't get report {} for task {}",
                                            report_aggregation.nonce, task_id,
                                        ))
                                        .and_then(
                                            |maybe_report| {
                                                maybe_report.ok_or_else(|| {
                                                    anyhow!(
                                                        "couldn't find report {} for task {}",
                                                        report_aggregation.nonce,
                                                        task_id
                                                    )
                                                })
                                            },
                                        )
                                    },
                                ))
                            } else {
                                None
                            }
                        }))
                        .await
                        .map_err(|err| datastore::Error::User(err.into()))?;

                    Ok((
                        task,
                        aggregation_job,
                        report_aggregations,
                        client_reports,
                        verify_param,
                    ))
                })
            })
            .await?;

        // Figure out the next step based on the non-error report aggregation states, and dispatch accordingly.
        let (mut saw_start, mut saw_waiting, mut saw_finished) = (false, false, false);
        for report_aggregation in &report_aggregations {
            match report_aggregation.state {
                ReportAggregationState::Start => saw_start = true,
                ReportAggregationState::Waiting(_, _) => saw_waiting = true,
                ReportAggregationState::Finished(_) => saw_finished = true,
                ReportAggregationState::Failed(_) | ReportAggregationState::Invalid => (), // ignore failure aggregation states
            }
        }
        match (saw_start, saw_waiting, saw_finished) {
            // Only saw report aggregations in state "start" (or failed or invalid).
            (true, false, false) => self.step_aggregation_job_aggregate_init(
                &datastore, vdaf.as_ref(), lease, task, aggregation_job, report_aggregations, client_reports, verify_param).await,

            // Only saw report aggregations in state "waiting" (or failed or invalid).
            (false, true, false) => self.step_aggregation_job_aggregate_continue(
                &datastore, vdaf.as_ref(), lease, task, aggregation_job, report_aggregations).await,

            _ => return Err(anyhow!("unexpected combination of report aggregation states (saw_start = {}, saw_waiting = {}, saw_finished = {})", saw_start, saw_waiting, saw_finished)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn step_aggregation_job_aggregate_init<C, A>(
        &self,
        datastore: &Datastore<C>,
        vdaf: &A,
        lease: Lease<AcquiredAggregationJob>,
        task: Task,
        aggregation_job: AggregationJob<A>,
        report_aggregations: Vec<ReportAggregation<A>>,
        client_reports: Vec<Report>,
        verify_param: A::VerifyParam,
    ) -> Result<()>
    where
        C: Clock,
        A: vdaf::Aggregator + 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: PartialEq + Eq + Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareStep: PartialEq + Eq + Send + Sync + Encode,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
    {
        // Zip the report aggregations at start with the client reports, verifying that their nonces
        // match. We use asserts here as the conditions we are checking should be guaranteed by the
        // caller.
        let report_aggregations: Vec<_> = report_aggregations
            .into_iter()
            .filter(|report_aggregation| report_aggregation.state == ReportAggregationState::Start)
            .collect();
        assert_eq!(report_aggregations.len(), client_reports.len());
        let reports: Vec<_> = report_aggregations
            .into_iter()
            .zip(client_reports.into_iter())
            .collect();
        for (report_aggregation, client_report) in &reports {
            assert_eq!(report_aggregation.task_id, client_report.task_id());
            assert_eq!(report_aggregation.nonce, client_report.nonce());
        }

        // Compute report shares to send to helper, and decrypt our input shares & initialize
        // preparation state.
        let mut report_aggregations_to_write = Vec::new();
        let mut report_shares = Vec::new();
        let mut stepped_aggregations = Vec::new();
        for (mut report_aggregation, report) in reports {
            // Retrieve input shares.
            let leader_encrypted_input_share = match report
                .encrypted_input_shares()
                .get(Role::Leader.index().unwrap())
            {
                Some(leader_encrypted_input_share) => leader_encrypted_input_share,
                None => {
                    error!(report_nonce = %report_aggregation.nonce, "Client report missing leader encrypted input share");
                    report_aggregation.state = ReportAggregationState::Invalid;
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };

            let helper_encrypted_input_share = match report
                .encrypted_input_shares()
                .get(Role::Helper.index().unwrap())
            {
                Some(helper_encrypted_input_share) => helper_encrypted_input_share,
                None => {
                    error!(report_nonce = %report_aggregation.nonce, "Client report missing helper encrypted input share");
                    report_aggregation.state = ReportAggregationState::Invalid;
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };

            // Decrypt leader input share & transform into our first transition.
            let (hpke_config, hpke_private_key) = match task
                .hpke_keys
                .get(&leader_encrypted_input_share.config_id())
            {
                Some((hpke_config, hpke_private_key)) => (hpke_config, hpke_private_key),
                None => {
                    error!(report_nonce = %report_aggregation.nonce, hpke_config_id = %leader_encrypted_input_share.config_id(), "Leader encrypted input share references unknown HPKE config ID");
                    report_aggregation.state =
                        ReportAggregationState::Failed(ReportShareError::HpkeUnknownConfigId);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };
            let hpke_application_info =
                HpkeApplicationInfo::new(Label::InputShare, Role::Client, Role::Leader);
            let associated_data =
                associated_data_for_report_share(task.id, report.nonce(), report.extensions());
            let leader_input_share_bytes = match hpke::open(
                hpke_config,
                hpke_private_key,
                &hpke_application_info,
                leader_encrypted_input_share,
                &associated_data,
            ) {
                Ok(leader_input_share_bytes) => leader_input_share_bytes,
                Err(err) => {
                    error!(report_nonce = %report_aggregation.nonce, ?err, "Couldn't decrypt leader's encrypted input share");
                    report_aggregation.state =
                        ReportAggregationState::Failed(ReportShareError::HpkeDecryptError);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };
            let leader_input_share = match A::InputShare::get_decoded_with_param(
                &verify_param,
                &leader_input_share_bytes,
            ) {
                Ok(leader_input_share) => leader_input_share,
                Err(err) => {
                    // TODO(https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/255): is moving to Invalid on a decoding error appropriate?
                    error!(report_nonce = %report_aggregation.nonce, ?err, "Couldn't decode leader's input share");
                    report_aggregation.state = ReportAggregationState::Invalid;
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };

            // Initialize the leader's preparation state from the input share.
            let prep_state = match vdaf.prepare_init(
                &verify_param,
                &aggregation_job.aggregation_param,
                &report.nonce().get_encoded(),
                &leader_input_share,
            ) {
                Ok(prep_state) => prep_state,
                Err(err) => {
                    error!(report_nonce = %report_aggregation.nonce, ?err, "Couldn't initialize leader's preparation state");
                    report_aggregation.state =
                        ReportAggregationState::Failed(ReportShareError::VdafPrepError);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };
            let leader_transition = vdaf.prepare_step(prep_state, None);
            if let PrepareTransition::Fail(err) = leader_transition {
                error!(report_nonce = %report_aggregation.nonce, ?err, "Couldn't step leader's initial preparation state");
                report_aggregation.state =
                    ReportAggregationState::Failed(ReportShareError::VdafPrepError);
                report_aggregations_to_write.push(report_aggregation);
                continue;
            };

            report_shares.push(ReportShare {
                nonce: report.nonce(),
                extensions: report.extensions().to_vec(),
                encrypted_input_share: helper_encrypted_input_share.clone(),
            });
            stepped_aggregations.push(SteppedAggregation {
                report_aggregation,
                leader_transition,
            });
        }

        // Construct request, send it to the helper, and process the response.
        // TODO(#235): abandon work immediately on "terminal" failures from helper, or other
        // unexepected cases such as unknown/unexpected content type.
        let req = AggregateInitializeReq {
            task_id: task.id,
            job_id: aggregation_job.aggregation_job_id,
            agg_param: aggregation_job.aggregation_param.get_encoded(),
            report_shares,
        };

        let response = self
            .http_client
            .post(task.aggregator_url(Role::Helper)?.join("/aggregate")?)
            .header(CONTENT_TYPE, AggregateInitializeReq::MEDIA_TYPE)
            .header(
                DAP_AUTH_HEADER,
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .body(req.get_encoded())
            .send()
            .await?;
        let resp = AggregateInitializeResp::get_decoded(&response.bytes().await?)?;

        self.process_response_from_helper(
            datastore,
            vdaf,
            lease,
            aggregation_job,
            stepped_aggregations,
            report_aggregations_to_write,
            resp.prepare_steps,
        )
        .await
    }

    async fn step_aggregation_job_aggregate_continue<C, A>(
        &self,
        datastore: &Datastore<C>,
        vdaf: &A,
        lease: Lease<AcquiredAggregationJob>,
        task: Task,
        aggregation_job: AggregationJob<A>,
        report_aggregations: Vec<ReportAggregation<A>>,
    ) -> Result<()>
    where
        C: Clock,
        A: vdaf::Aggregator + 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareStep: Send + Sync + Encode,
        A::PrepareMessage: Send + Sync,
    {
        // Visit the report aggregations, ignoring any that have already failed; compute our own
        // next step & transitions to send to the helper.
        let mut report_aggregations_to_write = Vec::new();
        let mut prepare_steps = Vec::new();
        let mut stepped_aggregations = Vec::new();
        for mut report_aggregation in report_aggregations {
            if let ReportAggregationState::Waiting(prep_state, prep_msg) = &report_aggregation.state
            {
                let prep_msg = prep_msg
                    .as_ref()
                    .ok_or_else(|| anyhow!("report aggregation missing prepare message"))?;

                // Step our own state.
                let leader_transition =
                    vdaf.prepare_step(prep_state.clone(), Some(prep_msg.clone()));
                if let PrepareTransition::Fail(err) = leader_transition {
                    error!(report_nonce = %report_aggregation.nonce, ?err, "Couldn't step report aggregation");
                    report_aggregation.state =
                        ReportAggregationState::Failed(ReportShareError::VdafPrepError);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }

                prepare_steps.push(PrepareStep {
                    nonce: report_aggregation.nonce,
                    result: PrepareStepResult::Continued(prep_msg.get_encoded()),
                });
                stepped_aggregations.push(SteppedAggregation {
                    report_aggregation,
                    leader_transition,
                })
            }
        }

        // Construct request, send it to the helper, and process the response.
        // TODO(#235): abandon work immediately on "terminal" failures from helper, or other
        // unexepected cases such as unknown/unexpected content type.
        let req = AggregateContinueReq {
            task_id: task.id,
            job_id: aggregation_job.aggregation_job_id,
            prepare_steps,
        };

        let response = self
            .http_client
            .post(task.aggregator_url(Role::Helper)?.join("/aggregate")?)
            .header(CONTENT_TYPE, AggregateContinueReq::MEDIA_TYPE)
            .header(
                DAP_AUTH_HEADER,
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .body(req.get_encoded())
            .send()
            .await?;
        let resp = AggregateContinueResp::get_decoded(&response.bytes().await?)?;

        self.process_response_from_helper(
            datastore,
            vdaf,
            lease,
            aggregation_job,
            stepped_aggregations,
            report_aggregations_to_write,
            resp.prepare_steps,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_response_from_helper<C, A>(
        &self,
        datastore: &Datastore<C>,
        vdaf: &A,
        lease: Lease<AcquiredAggregationJob>,
        aggregation_job: AggregationJob<A>,
        stepped_aggregations: Vec<SteppedAggregation<A>>,
        mut report_aggregations_to_write: Vec<ReportAggregation<A>>,
        prep_steps: Vec<PrepareStep>,
    ) -> Result<()>
    where
        C: Clock,
        A: vdaf::Aggregator + 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareStep: Send + Sync + Encode,
    {
        // Handle response, computing the new report aggregations to be stored.
        if stepped_aggregations.len() != prep_steps.len() {
            return Err(anyhow!(
                "missing, duplicate, out-of-order, or unexpected prepare steps in response"
            ));
        }
        for (stepped_aggregation, helper_prep_step) in
            stepped_aggregations.into_iter().zip(prep_steps)
        {
            let (mut report_aggregation, leader_transition) = (
                stepped_aggregation.report_aggregation,
                stepped_aggregation.leader_transition,
            );
            if helper_prep_step.nonce != report_aggregation.nonce {
                return Err(anyhow!(
                    "missing, duplicate, out-of-order, or unexpected prepare steps in response"
                ));
            }
            match helper_prep_step.result {
                PrepareStepResult::Continued(payload) => {
                    // If the leader continued too, combine the leader's message with the helper's
                    // and prepare to store the leader's new state & the combined message for the
                    // next round. If the leader didn't continue, transition to INVALID.
                    if let PrepareTransition::Continue(leader_prep_state, leader_prep_msg) =
                        leader_transition
                    {
                        let helper_prep_msg =
                            A::PrepareMessage::get_decoded_with_param(&leader_prep_state, &payload)
                                .context("couldn't decode helper's prepare message");
                        let combined_prep_msg = helper_prep_msg.and_then(|helper_prep_msg| {
                            vdaf.prepare_preprocess([leader_prep_msg, helper_prep_msg])
                                .context("couldn't combine leader & helper prepare messages")
                        });
                        report_aggregation.state = match combined_prep_msg {
                            Ok(combined_prep_msg) => ReportAggregationState::Waiting(
                                leader_prep_state,
                                Some(combined_prep_msg),
                            ),
                            Err(err) => {
                                error!(report_nonce = %report_aggregation.nonce, ?err, "Couldn't compute combined prepare message");
                                ReportAggregationState::Failed(ReportShareError::VdafPrepError)
                            }
                        }
                    } else {
                        error!(report_nonce = %report_aggregation.nonce, leader_transition = ?leader_transition, "Helper continued but leader did not");
                        report_aggregation.state = ReportAggregationState::Invalid;
                    }
                }

                PrepareStepResult::Finished => {
                    // If the leader finished too, we are done; prepare to store the output share.
                    // If the leader didn't finish too, we transition to INVALID.
                    if let PrepareTransition::Finish(out_share) = leader_transition {
                        report_aggregation.state = ReportAggregationState::Finished(out_share);
                    } else {
                        error!(report_nonce = %report_aggregation.nonce, leader_transition = ?leader_transition, "Helper finished but leader did not");
                        report_aggregation.state = ReportAggregationState::Invalid;
                    }
                }

                PrepareStepResult::Failed(err) => {
                    // If the helper failed, we move to FAILED immediately.
                    // TODO(#236): is it correct to just record the transition error that the helper reports?
                    error!(report_nonce = %report_aggregation.nonce, helper_err = ?err, "Helper couldn't step report aggregation");
                    report_aggregation.state = ReportAggregationState::Failed(err);
                }
            }
            report_aggregations_to_write.push(report_aggregation);
        }

        // Determine if we've finished the aggregation job (i.e. if all report aggregations are in
        // a terminal state), then write everything back to storage.
        // TODO(#220): also update batch_unit_aggregations if this aggregation job finished.
        let aggregation_job_is_finished = report_aggregations_to_write
            .iter()
            .all(|ra| !matches!(ra.state, ReportAggregationState::Waiting(_, _)));
        let aggregation_job_to_write = if aggregation_job_is_finished {
            let mut aggregation_job = aggregation_job;
            aggregation_job.state = AggregationJobState::Finished;
            Some(aggregation_job)
        } else {
            None
        };
        let report_aggregations_to_write = Arc::new(report_aggregations_to_write);
        let aggregation_job_to_write = Arc::new(aggregation_job_to_write);
        let lease = Arc::new(lease);
        datastore
            .run_tx(|tx| {
                let (report_aggregations_to_write, aggregation_job_to_write, lease) = (
                    Arc::clone(&report_aggregations_to_write),
                    Arc::clone(&aggregation_job_to_write),
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

                    try_join!(
                        tx.release_aggregation_job(&lease),
                        report_aggregations_future,
                        aggregation_job_future
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
        match &lease.leased().vdaf {
            VdafInstance::Real(janus::task::VdafInstance::Prio3Aes128Count) => {
                self.cancel_aggregation_job_generic::<C, Prio3Aes128Count>(datastore, lease)
                    .await
            }
            VdafInstance::Real(janus::task::VdafInstance::Prio3Aes128Sum { .. }) => {
                self.cancel_aggregation_job_generic::<C, Prio3Aes128Sum>(datastore, lease)
                    .await
            }
            VdafInstance::Real(janus::task::VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.cancel_aggregation_job_generic::<C, Prio3Aes128Histogram>(datastore, lease)
                    .await
            }

            _ => panic!("VDAF {:?} is not yet supported", lease.leased().vdaf),
        }
    }

    async fn cancel_aggregation_job_generic<C, A>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredAggregationJob>,
    ) -> Result<()>
    where
        A: vdaf::Aggregator + Send + Sync + 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        C: Clock,
    {
        let lease = Arc::new(lease);
        let (task_id, aggregation_job_id) =
            (lease.leased().task_id, lease.leased().aggregation_job_id);
        datastore
            .run_tx(|tx| {
                let lease = Arc::clone(&lease);
                Box::pin(async move {
                    let mut aggregation_job = tx
                        .get_aggregation_job::<A>(task_id, aggregation_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                anyhow!(
                                    "couldn't find aggregation job {} for task {}",
                                    aggregation_job_id,
                                    task_id
                                )
                                .into(),
                            )
                        })?;

                    // We leave all other data associated with the aggregation job (e.g. report
                    // aggregations) alone to ease debugging.
                    aggregation_job.state = AggregationJobState::Abandoned;

                    let write_aggregation_job_future = tx.update_aggregation_job(&aggregation_job);
                    let release_future = tx.release_aggregation_job(&lease);
                    try_join!(write_aggregation_job_future, release_future)?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }
}

/// SteppedAggregation represents a report aggregation along with the associated preparation-state
/// transition representing the next step for the leader.
struct SteppedAggregation<A: vdaf::Aggregator>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    report_aggregation: ReportAggregation<A>,
    leader_transition: PrepareTransition<A::PrepareStep, A::PrepareMessage, A::OutputShare>,
}

#[cfg(test)]
mod tests {
    use crate::AggregationJobDriver;
    use assert_matches::assert_matches;
    use http::header::CONTENT_TYPE;
    use janus::{
        hpke::{
            self, associated_data_for_report_share,
            test_util::generate_hpke_config_and_private_key, HpkeApplicationInfo, Label,
        },
        message::{Duration, HpkeConfig, Nonce, Report, Role, TaskId},
        task::VdafInstance,
        time::Clock,
    };
    use janus_server::{
        binary_utils::job_driver::JobDriver,
        datastore::{
            models::{
                AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
            },
            Crypter, Datastore,
        },
        message::{
            AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq,
            AggregateInitializeResp, AggregationJobId, PrepareStep, PrepareStepResult, ReportShare,
        },
        task::test_util::new_dummy_task,
        trace::test_util::install_test_trace_subscriber,
    };
    use janus_test_util::{run_vdaf, MockClock};
    use mockito::mock;
    use prio::{
        codec::Encode,
        vdaf::{prio3::Prio3Aes128Count, PrepareTransition, Vdaf},
    };
    use reqwest::Url;
    use std::{str, sync::Arc};
    use tokio::{task, time};

    janus_test_util::define_ephemeral_datastore!();

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
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);
        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        let leader_verify_param = verify_params.get(Role::Leader.index().unwrap()).unwrap();
        let nonce = Nonce::generate(&clock);
        let transcript = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce, &0);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count.into(), Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.vdaf_verify_parameters = vec![verify_params
            .get(Role::Leader.index().unwrap())
            .unwrap()
            .get_encoded()];

        let agg_auth_token = task.primary_aggregator_auth_token().clone();
        let (leader_hpke_config, _) = task.hpke_keys.iter().next().unwrap().1;
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();
        let report = generate_report(
            task_id,
            nonce,
            &[leader_hpke_config, &helper_hpke_config],
            &transcript.input_shares,
        );
        let aggregation_job_id = AggregationJobId::random();

        ds.run_tx(|tx| {
            let (task, report) = (task.clone(), report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&report).await?;

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
                    nonce: report.nonce(),
                    ord: 0,
                    state: ReportAggregationState::Start,
                })
                .await
            })
        })
        .await
        .unwrap();

        // Setup: prepare mocked HTTP responses.
        let helper_vdaf_msg = assert_matches!(&transcript.transitions[Role::Helper.index().unwrap()][0], PrepareTransition::Continue(_, prep_msg) => prep_msg);
        let helper_responses = vec![
            (
                AggregateInitializeReq::MEDIA_TYPE,
                AggregateInitializeResp::MEDIA_TYPE,
                AggregateInitializeResp {
                    job_id: aggregation_job_id,
                    prepare_steps: vec![PrepareStep {
                        nonce,
                        result: PrepareStepResult::Continued(helper_vdaf_msg.get_encoded()),
                    }],
                }
                .get_encoded(),
            ),
            (
                AggregateContinueReq::MEDIA_TYPE,
                AggregateContinueResp::MEDIA_TYPE,
                AggregateContinueResp {
                    job_id: aggregation_job_id,
                    prepare_steps: vec![PrepareStep {
                        nonce,
                        result: PrepareStepResult::Finished,
                    }],
                }
                .get_encoded(),
            ),
        ];
        let mocked_aggregates: Vec<_> = helper_responses
            .into_iter()
            .map(|(req_content_type, resp_content_type, resp_body)| {
                mock("POST", "/aggregate")
                    .match_header(
                        "DAP-Auth-Token",
                        str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
                    )
                    .match_header(CONTENT_TYPE.as_str(), req_content_type)
                    .with_status(200)
                    .with_header(CONTENT_TYPE.as_str(), resp_content_type)
                    .with_body(resp_body)
                    .create()
            })
            .collect();
        let aggregation_job_driver = Arc::new(AggregationJobDriver {
            http_client: reqwest::Client::builder()
                .user_agent(super::CLIENT_USER_AGENT)
                .build()
                .unwrap(),
        });
        // Run. Give the aggregation job driver enough time to step aggregation jobs, then kill it.
        let aggregation_job_driver = Arc::new(JobDriver::new(
            clock,
            Duration::from_seconds(1),
            Duration::from_seconds(1),
            10,
            Duration::from_seconds(60),
            {
                let datastore = Arc::clone(&ds);
                move |max_acquire_count| {
                    let datastore = Arc::clone(&datastore);
                    async move {
                        datastore
                            .run_tx(|tx| {
                                Box::pin(async move {
                                    tx.acquire_incomplete_aggregation_jobs(
                                        Duration::from_seconds(600),
                                        max_acquire_count,
                                    )
                                    .await
                                })
                            })
                            .await
                    }
                }
            },
            {
                let datastore = Arc::clone(&ds);
                move |aggregation_job_lease| {
                    let (datastore, aggregation_job_driver) =
                        (Arc::clone(&datastore), Arc::clone(&aggregation_job_driver));
                    async move {
                        aggregation_job_driver
                            .step_aggregation_job(datastore, aggregation_job_lease)
                            .await
                    }
                }
            },
        ));

        let task_handle = task::spawn({
            let aggregation_job_driver = aggregation_job_driver.clone();
            async move { aggregation_job_driver.run().await }
        });

        // TODO(#234): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing, calling time::pause() breaks interaction with the
        // database -- the job-acquiry transaction deadlocks on attempting to start a transaction,
        // even if the main test loops on calling yield_now().
        time::sleep(time::Duration::from_secs(5)).await;
        task_handle.abort();

        // Verify.
        for mocked_aggregate in mocked_aggregates {
            mocked_aggregate.assert();
        }

        let want_aggregation_job = AggregationJob::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            aggregation_param: (),
            state: AggregationJobState::Finished,
        };
        let leader_output_share = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][1], PrepareTransition::Finish(leader_output_share) => leader_output_share.clone());
        let want_report_aggregation = ReportAggregation::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            nonce,
            ord: 0,
            state: ReportAggregationState::Finished(leader_output_share),
        };

        let (got_aggregation_job, got_report_aggregation) = ds
            .run_tx(|tx| {
                let leader_verify_param = leader_verify_param.clone();
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation::<Prio3Aes128Count>(
                            &leader_verify_param,
                            task_id,
                            aggregation_job_id,
                            nonce,
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
    async fn step_aggregation_job_init() {
        // Setup: insert a client report and add it to a new aggregation job.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);
        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        let leader_verify_param = verify_params.get(Role::Leader.index().unwrap()).unwrap();
        let nonce = Nonce::generate(&clock);
        let transcript = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce, &0);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count.into(), Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.vdaf_verify_parameters = vec![leader_verify_param.get_encoded()];

        let agg_auth_token = task.primary_aggregator_auth_token();
        let (leader_hpke_config, _) = task.hpke_keys.iter().next().unwrap().1;
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();
        let report = generate_report(
            task_id,
            nonce,
            &[leader_hpke_config, &helper_hpke_config],
            &transcript.input_shares,
        );
        let aggregation_job_id = AggregationJobId::random();

        let lease = ds
            .run_tx(|tx| {
                let (task, report) = (task.clone(), report.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(&report).await?;

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
                        nonce: report.nonce(),
                        ord: 0,
                        state: ReportAggregationState::Start,
                    })
                    .await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(Duration::from_seconds(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id, task_id);
        assert_eq!(lease.leased().aggregation_job_id, aggregation_job_id);

        // Setup: prepare mocked HTTP response.
        // (This is fragile in that it expects the leader request to be deterministically encoded.
        // It would be nicer to retrieve the request bytes from the mock, then do our own parsing &
        // verification -- but mockito does not expose this functionality at time of writing.)
        let leader_request = AggregateInitializeReq {
            task_id,
            job_id: aggregation_job_id,
            agg_param: ().get_encoded(),
            report_shares: vec![ReportShare {
                nonce,
                extensions: Vec::new(),
                encrypted_input_share: report
                    .encrypted_input_shares()
                    .get(Role::Helper.index().unwrap())
                    .unwrap()
                    .clone(),
            }],
        };
        let helper_vdaf_msg = assert_matches!(&transcript.transitions[Role::Helper.index().unwrap()][0], PrepareTransition::Continue(_, prep_msg) => prep_msg);
        let helper_response = AggregateInitializeResp {
            job_id: aggregation_job_id,
            prepare_steps: vec![PrepareStep {
                nonce,
                result: PrepareStepResult::Continued(helper_vdaf_msg.get_encoded()),
            }],
        };
        let mocked_aggregate = mock("POST", "/aggregate")
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(CONTENT_TYPE.as_str(), AggregateInitializeReq::MEDIA_TYPE)
            .match_body(leader_request.get_encoded())
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), AggregateInitializeResp::MEDIA_TYPE)
            .with_body(helper_response.get_encoded())
            .create();

        // Run: create an aggregation job driver & step the aggregation we've created.
        let aggregation_job_driver = AggregationJobDriver {
            http_client: reqwest::Client::builder().build().unwrap(),
        };
        aggregation_job_driver
            .step_aggregation_job(ds.clone(), lease)
            .await
            .unwrap();

        // Verify.
        mocked_aggregate.assert();

        let want_aggregation_job = AggregationJob::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            aggregation_param: (),
            state: AggregationJobState::InProgress,
        };
        let leader_prep_state = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][0], PrepareTransition::Continue(prep_state, _) => prep_state.clone());
        let combined_prep_msg = transcript.combined_messages[0].clone();
        let want_report_aggregation = ReportAggregation::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            nonce,
            ord: 0,
            state: ReportAggregationState::Waiting(leader_prep_state, Some(combined_prep_msg)),
        };

        let (got_aggregation_job, got_report_aggregation) = ds
            .run_tx(|tx| {
                let leader_verify_param = leader_verify_param.clone();
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation::<Prio3Aes128Count>(
                            &leader_verify_param,
                            task_id,
                            aggregation_job_id,
                            nonce,
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
    async fn step_aggregation_job_continue() {
        // Setup: insert a client report and add it to an aggregation job whose state has already
        // been stepped once.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);
        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        let leader_verify_param = verify_params.get(Role::Leader.index().unwrap()).unwrap();
        let nonce = Nonce::generate(&clock);
        let transcript = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce, &0);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count.into(), Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.vdaf_verify_parameters = vec![leader_verify_param.get_encoded()];

        let agg_auth_token = task.primary_aggregator_auth_token();
        let (leader_hpke_config, _) = task.hpke_keys.iter().next().unwrap().1;
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();
        let report = generate_report(
            task_id,
            nonce,
            &[leader_hpke_config, &helper_hpke_config],
            &transcript.input_shares,
        );
        let aggregation_job_id = AggregationJobId::random();

        let leader_prep_state = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][0], PrepareTransition::Continue(prep_state, _) => prep_state);
        let combined_msg = &transcript.combined_messages[0];

        let lease = ds
            .run_tx(|tx| {
                let (task, report, leader_prep_state, combined_msg) = (
                    task.clone(),
                    report.clone(),
                    leader_prep_state.clone(),
                    combined_msg.clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(&report).await?;

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
                        nonce: report.nonce(),
                        ord: 0,
                        state: ReportAggregationState::Waiting(
                            leader_prep_state,
                            Some(combined_msg),
                        ),
                    })
                    .await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(Duration::from_seconds(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id, task_id);
        assert_eq!(lease.leased().aggregation_job_id, aggregation_job_id);

        // Setup: prepare mocked HTTP response.
        // (This is fragile in that it expects the leader request to be deterministically encoded.
        // It would be nicer to retrieve the request bytes from the mock, then do our own parsing &
        // verification -- but mockito does not expose this functionality at time of writing.)
        let leader_request = AggregateContinueReq {
            task_id,
            job_id: aggregation_job_id,
            prepare_steps: vec![PrepareStep {
                nonce,
                result: PrepareStepResult::Continued(combined_msg.get_encoded()),
            }],
        };
        let helper_response = AggregateContinueResp {
            job_id: aggregation_job_id,
            prepare_steps: vec![PrepareStep {
                nonce,
                result: PrepareStepResult::Finished,
            }],
        };
        let mocked_aggregate = mock("POST", "/aggregate")
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(CONTENT_TYPE.as_str(), AggregateContinueReq::MEDIA_TYPE)
            .match_body(leader_request.get_encoded())
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), AggregateContinueResp::MEDIA_TYPE)
            .with_body(helper_response.get_encoded())
            .create();

        // Run: create an aggregation job driver & step the aggregation we've created.
        let aggregation_job_driver = AggregationJobDriver {
            http_client: reqwest::Client::builder().build().unwrap(),
        };
        aggregation_job_driver
            .step_aggregation_job(ds.clone(), lease)
            .await
            .unwrap();

        // Verify.
        mocked_aggregate.assert();

        let want_aggregation_job = AggregationJob::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            aggregation_param: (),
            state: AggregationJobState::Finished,
        };
        let leader_output_share = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][1], PrepareTransition::Finish(leader_output_share) => leader_output_share.clone());
        let want_report_aggregation = ReportAggregation::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            nonce,
            ord: 0,
            state: ReportAggregationState::Finished(leader_output_share),
        };

        let (got_aggregation_job, got_report_aggregation) = ds
            .run_tx(|tx| {
                let leader_verify_param = leader_verify_param.clone();
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation::<Prio3Aes128Count>(
                            &leader_verify_param,
                            task_id,
                            aggregation_job_id,
                            nonce,
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
    async fn cancel_aggregation_job() {
        // Setup: insert a client report and add it to a new aggregation job.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);
        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        let leader_verify_param = verify_params.get(Role::Leader.index().unwrap()).unwrap();
        let nonce = Nonce::generate(&clock);
        let input_shares =
            run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce, &0).input_shares;

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count.into(), Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.vdaf_verify_parameters = vec![leader_verify_param.get_encoded()];

        let (leader_hpke_config, _) = task.hpke_keys.iter().next().unwrap().1;
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();
        let report = generate_report(
            task_id,
            nonce,
            &[leader_hpke_config, &helper_hpke_config],
            &input_shares,
        );
        let aggregation_job_id = AggregationJobId::random();

        let aggregation_job = AggregationJob::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            aggregation_param: (),
            state: AggregationJobState::InProgress,
        };
        let report_aggregation = ReportAggregation::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            nonce,
            ord: 0,
            state: ReportAggregationState::Start,
        };

        let lease = ds
            .run_tx(|tx| {
                let (task, report, aggregation_job, report_aggregation) = (
                    task.clone(),
                    report.clone(),
                    aggregation_job.clone(),
                    report_aggregation.clone(),
                );
                Box::pin(async move {
                    tx.put_task(&task).await?;
                    tx.put_client_report(&report).await?;
                    tx.put_aggregation_job(&aggregation_job).await?;
                    tx.put_report_aggregation(&report_aggregation).await?;

                    Ok(tx
                        .acquire_incomplete_aggregation_jobs(Duration::from_seconds(60), 1)
                        .await?
                        .remove(0))
                })
            })
            .await
            .unwrap();
        assert_eq!(lease.leased().task_id, task_id);
        assert_eq!(lease.leased().aggregation_job_id, aggregation_job_id);

        // Run: create an aggregation job driver & cancel the aggregation job.
        let aggregation_job_driver = AggregationJobDriver {
            http_client: reqwest::Client::builder().build().unwrap(),
        };
        aggregation_job_driver
            .cancel_aggregation_job(Arc::clone(&ds), lease)
            .await
            .unwrap();

        // Verify: check that the datastore state is updated as expected (the aggregation job is
        // finished, the report aggregation is untouched) and sanity-check that the job can no
        // longer be acquired.
        let want_aggregation_job = AggregationJob {
            state: AggregationJobState::Abandoned,
            ..aggregation_job
        };
        let want_report_aggregation = report_aggregation;

        let (got_aggregation_job, got_report_aggregation, got_leases) = ds
            .run_tx(|tx| {
                let leader_verify_param = leader_verify_param.clone();
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation::<Prio3Aes128Count>(
                            &leader_verify_param,
                            task_id,
                            aggregation_job_id,
                            nonce,
                        )
                        .await?
                        .unwrap();
                    let leases = tx
                        .acquire_incomplete_aggregation_jobs(Duration::from_seconds(60), 1)
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

    /// Returns a report with the given task ID & nonce values, no extensions, and encrypted input
    /// shares corresponding to the given HPKE configs & input shares.
    fn generate_report<I: Encode>(
        task_id: TaskId,
        nonce: Nonce,
        hpke_configs: &[&HpkeConfig],
        input_shares: &[I],
    ) -> Report {
        assert_eq!(hpke_configs.len(), 2);
        assert_eq!(input_shares.len(), 2);

        let encrypted_input_shares: Vec<_> = [Role::Leader, Role::Helper]
            .into_iter()
            .map(|role| {
                hpke::seal(
                    hpke_configs.get(role.index().unwrap()).unwrap(),
                    &HpkeApplicationInfo::new(Label::InputShare, Role::Client, role),
                    &input_shares
                        .get(role.index().unwrap())
                        .unwrap()
                        .get_encoded(),
                    &associated_data_for_report_share(task_id, nonce, &[]),
                )
            })
            .collect::<Result<_, _>>()
            .unwrap();

        Report::new(task_id, nonce, Vec::new(), encrypted_input_shares)
    }
}
