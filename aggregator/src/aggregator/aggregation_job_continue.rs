//! Implements portions of aggregation job continuation for the helper.

use super::error::handle_ping_pong_error;
use crate::aggregator::{accumulator::Accumulator, Error, VdafOps};
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::{
        self,
        models::{AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState},
        Transaction,
    },
    query_type::AccumulableQueryType,
    task::AggregatorTask,
};
use janus_core::time::Clock;
use janus_messages::{
    AggregationJobContinueReq, AggregationJobResp, PrepareError, PrepareResp, PrepareStepResult,
    Role,
};
use opentelemetry::metrics::Counter;
use prio::{
    codec::{Encode, ParameterizedDecode},
    topology::ping_pong::{PingPongContinuedValue, PingPongState, PingPongTopology},
    vdaf,
};
use std::sync::Arc;
use tokio::try_join;
use tracing::trace_span;

impl VdafOps {
    /// Step the helper's aggregation job to the next step using the step `n` ping pong state in
    /// `report_aggregations` with the step `n+1` ping pong messages in `leader_aggregation_job`.
    pub(super) async fn step_aggregation_job<const SEED_SIZE: usize, C, Q, A>(
        tx: &Transaction<'_, C>,
        task: Arc<AggregatorTask>,
        vdaf: Arc<A>,
        batch_aggregation_shard_count: u64,
        helper_aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        mut report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
        leader_aggregation_job: Arc<AggregationJobContinueReq>,
        request_hash: [u8; 32],
        aggregate_step_failure_counter: Counter<u64>,
    ) -> Result<AggregationJobResp, datastore::Error>
    where
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'static + Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
    {
        // Handle each transition in the request.
        let mut report_aggregations_iter = report_aggregations.iter_mut();
        let mut accumulator = Accumulator::<SEED_SIZE, Q, A>::new(
            Arc::clone(&task),
            batch_aggregation_shard_count,
            helper_aggregation_job.aggregation_parameter().clone(),
        );

        for prep_step in leader_aggregation_job.prepare_steps() {
            // Match preparation step received from leader to stored report aggregation, and extract
            // the stored preparation step.
            let report_aggregation = loop {
                let report_agg = report_aggregations_iter.next().ok_or_else(|| {
                    datastore::Error::User(
                        Error::InvalidMessage(
                            Some(*task.id()),
                            "leader sent unexpected, duplicate, or out-of-order prepare steps",
                        )
                        .into(),
                    )
                })?;
                if report_agg.report_id() != prep_step.report_id() {
                    // This report was omitted by the leader because of a prior failure. Note that
                    // the report was dropped (if it's not already in an error state) and continue.
                    if matches!(report_agg.state(), ReportAggregationState::WaitingHelper(_)) {
                        *report_agg = report_agg
                            .clone()
                            .with_state(ReportAggregationState::Failed(PrepareError::ReportDropped))
                            .with_last_prep_resp(None);
                    }
                    continue;
                }
                break report_agg;
            };

            // Make sure this report isn't in an interval that has already started collection.
            let conflicting_aggregate_share_jobs = tx
                .get_aggregate_share_jobs_including_time::<SEED_SIZE, A>(
                    &vdaf,
                    task.id(),
                    report_aggregation.time(),
                )
                .await?;

            if !conflicting_aggregate_share_jobs.is_empty() {
                *report_aggregation = report_aggregation
                    .clone()
                    .with_state(ReportAggregationState::Failed(PrepareError::BatchCollected))
                    .with_last_prep_resp(Some(PrepareResp::new(
                        *prep_step.report_id(),
                        PrepareStepResult::Reject(PrepareError::BatchCollected),
                    )));
                continue;
            }

            let prep_state = match report_aggregation.state() {
                ReportAggregationState::WaitingHelper(prep_state) => prep_state,
                ReportAggregationState::WaitingLeader(_) => {
                    return Err(datastore::Error::User(
                        Error::Internal(
                            "helper encountered unexpected ReportAggregationState::WaitingLeader"
                                .to_string(),
                        )
                        .into(),
                    ))
                }
                _ => {
                    return Err(datastore::Error::User(
                        Error::InvalidMessage(
                            Some(*task.id()),
                            "leader sent prepare step for non-WAITING report aggregation",
                        )
                        .into(),
                    ));
                }
            };

            let (report_aggregation_state, prepare_step_result, output_share) =
                trace_span!("VDAF preparation")
                    .in_scope(|| {
                        // Continue with the incoming message.
                        vdaf.helper_continued(
                            PingPongState::Continued(prep_state.clone()),
                            helper_aggregation_job.aggregation_parameter(),
                            prep_step.message(),
                        )
                        .and_then(
                            |continued_value| match continued_value {
                                PingPongContinuedValue::WithMessage { transition } => {
                                    let (new_state, message) =
                                        transition.evaluate(vdaf.as_ref())?;
                                    let (report_aggregation_state, output_share) = match new_state {
                                        // Helper did not finish. Store the new state and await the
                                        // next message from the Leader to advance preparation.
                                        PingPongState::Continued(prep_state) => (
                                            ReportAggregationState::WaitingHelper(prep_state),
                                            None,
                                        ),
                                        // Helper finished. Commit the output share.
                                        PingPongState::Finished(output_share) => {
                                            (ReportAggregationState::Finished, Some(output_share))
                                        }
                                    };

                                    Ok((
                                        report_aggregation_state,
                                        // Helper has an outgoing message for Leader
                                        PrepareStepResult::Continue { message },
                                        output_share,
                                    ))
                                }
                                PingPongContinuedValue::FinishedNoMessage { output_share } => Ok((
                                    ReportAggregationState::Finished,
                                    PrepareStepResult::Finished,
                                    Some(output_share),
                                )),
                            },
                        )
                    })
                    .map_err(|error| {
                        handle_ping_pong_error(
                            task.id(),
                            Role::Leader,
                            prep_step.report_id(),
                            error,
                            &aggregate_step_failure_counter,
                        )
                    })
                    .unwrap_or_else(|prepare_error| {
                        (
                            ReportAggregationState::Failed(prepare_error),
                            PrepareStepResult::Reject(prepare_error),
                            None,
                        )
                    });

            *report_aggregation = report_aggregation
                .clone()
                .with_state(report_aggregation_state)
                .with_last_prep_resp(Some(PrepareResp::new(
                    *prep_step.report_id(),
                    prepare_step_result,
                )));
            if let Some(output_share) = output_share {
                accumulator.update(
                    helper_aggregation_job.partial_batch_identifier(),
                    prep_step.report_id(),
                    report_aggregation.time(),
                    &output_share,
                )?;
            }
        }

        for report_agg in report_aggregations_iter {
            // This report was omitted by the leader because of a prior failure. Note that the
            // report was dropped (if it's not already in an error state) and continue.
            if matches!(report_agg.state(), ReportAggregationState::WaitingHelper(_)) {
                *report_agg = report_agg
                    .clone()
                    .with_state(ReportAggregationState::Failed(PrepareError::ReportDropped))
                    .with_last_prep_resp(None);
            }
        }

        // Write accumulated aggregation values back to the datastore; mark any reports that can't
        // be aggregated because the batch is collected with error BatchCollected.
        let unwritable_reports = accumulator.flush_to_datastore(tx, &vdaf).await?;
        for report_aggregation in &mut report_aggregations {
            if unwritable_reports.contains(report_aggregation.report_id()) {
                *report_aggregation = report_aggregation
                    .clone()
                    .with_state(ReportAggregationState::Failed(PrepareError::BatchCollected))
                    .with_last_prep_resp(Some(PrepareResp::new(
                        *report_aggregation.report_id(),
                        PrepareStepResult::Reject(PrepareError::BatchCollected),
                    )));
            }
        }

        let saw_continue = report_aggregations.iter().any(|report_agg| {
            matches!(
                report_agg.last_prep_resp().map(PrepareResp::result),
                Some(PrepareStepResult::Continue { .. })
            )
        });
        let saw_finish = report_aggregations.iter().any(|report_agg| {
            matches!(
                report_agg.last_prep_resp().map(PrepareResp::result),
                Some(PrepareStepResult::Finished { .. })
            )
        });
        let helper_aggregation_job = helper_aggregation_job
            // Advance the job to the leader's step
            .with_step(leader_aggregation_job.step())
            .with_state(match (saw_continue, saw_finish) {
                (false, false) => AggregationJobState::Finished, // everything failed, or there were no reports
                (true, false) => AggregationJobState::InProgress,
                (false, true) => AggregationJobState::Finished,
                (true, true) => {
                    return Err(datastore::Error::User(
                        Error::Internal(
                            "VDAF took an inconsistent number of steps to reach Finish state"
                                .to_string(),
                        )
                        .into(),
                    ))
                }
            })
            .with_last_request_hash(request_hash);

        try_join!(
            tx.update_aggregation_job(&helper_aggregation_job),
            try_join_all(
                report_aggregations
                    .iter()
                    .map(|report_agg| tx.update_report_aggregation(report_agg)),
            ),
        )?;

        Ok(Self::aggregation_job_resp_for(report_aggregations))
    }

    /// Constructs an AggregationJobResp from a given set of Helper report aggregations.
    pub(super) fn aggregation_job_resp_for<const SEED_SIZE: usize, A>(
        report_aggregations: impl IntoIterator<Item = ReportAggregation<SEED_SIZE, A>>,
    ) -> AggregationJobResp
    where
        A: vdaf::Aggregator<SEED_SIZE, 16>,
    {
        AggregationJobResp::new(
            report_aggregations
                .into_iter()
                .filter_map(|v| v.last_prep_resp().cloned())
                .collect(),
        )
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use crate::aggregator::http_handlers::test_util::{decode_response_body, take_problem_details};
    use janus_aggregator_core::task::test_util::Task;
    use janus_messages::{AggregationJobContinueReq, AggregationJobId, AggregationJobResp};
    use prio::codec::Encode;
    use serde_json::json;
    use trillium::{Handler, KnownHeaderName, Status};
    use trillium_testing::{assert_headers, prelude::post, TestConn};

    async fn post_aggregation_job(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        handler: &impl Handler,
    ) -> TestConn {
        let (header, value) = task.aggregator_auth_token().request_authentication();
        post(task.aggregation_job_uri(aggregation_job_id).unwrap().path())
            .with_request_header(header, value)
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregationJobContinueReq::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(handler)
            .await
    }

    pub async fn post_aggregation_job_and_decode(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        handler: &impl Handler,
    ) -> AggregationJobResp {
        let mut test_conn = post_aggregation_job(task, aggregation_job_id, request, handler).await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(&test_conn, "content-type" => (AggregationJobResp::MEDIA_TYPE));
        decode_response_body::<AggregationJobResp>(&mut test_conn).await
    }

    pub async fn post_aggregation_job_expecting_status(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        handler: &impl Handler,
        want_status: Status,
    ) -> TestConn {
        let test_conn = post_aggregation_job(task, aggregation_job_id, request, handler).await;

        assert_eq!(want_status, test_conn.status().unwrap());

        test_conn
    }

    pub async fn post_aggregation_job_expecting_error(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        handler: &impl Handler,
        want_status: Status,
        want_error_type: &str,
        want_error_title: &str,
    ) {
        let mut test_conn = post_aggregation_job_expecting_status(
            task,
            aggregation_job_id,
            request,
            handler,
            want_status,
        )
        .await;

        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status as u16,
                "type": want_error_type,
                "title": want_error_title,
                "taskid": format!("{}", task.id()),
            })
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::{
        aggregate_init_tests::PrepareInitGenerator,
        aggregation_job_continue::test_util::{
            post_aggregation_job_and_decode, post_aggregation_job_expecting_error,
            post_aggregation_job_expecting_status,
        },
        http_handlers::aggregator_handler,
        tests::default_aggregator_config,
    };
    use janus_aggregator_core::{
        datastore::{
            models::{
                AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
            },
            test_util::{ephemeral_datastore, EphemeralDatastore},
            Datastore,
        },
        task::{
            test_util::{Task, TaskBuilder},
            QueryType,
        },
        test_util::noop_meter,
    };
    use janus_core::{
        test_util::install_test_trace_subscriber,
        time::{IntervalExt, MockClock},
        vdaf::{VdafInstance, VERIFY_KEY_LENGTH},
    };
    use janus_messages::{
        query_type::TimeInterval, AggregationJobContinueReq, AggregationJobId, AggregationJobResp,
        AggregationJobStep, Interval, PrepareContinue, PrepareResp, PrepareStepResult, Role,
    };
    use prio::{
        idpf::IdpfInput,
        vdaf::{
            poplar1::{Poplar1, Poplar1AggregationParam},
            xof::XofShake128,
            Aggregator,
        },
    };
    use rand::random;
    use std::sync::Arc;
    use trillium::{Handler, Status};

    struct AggregationJobContinueTestCase<
        const VERIFY_KEY_LENGTH: usize,
        V: Aggregator<VERIFY_KEY_LENGTH, 16>,
    > {
        task: Task,
        datastore: Arc<Datastore<MockClock>>,
        prepare_init_generator: PrepareInitGenerator<VERIFY_KEY_LENGTH, V>,
        aggregation_job_id: AggregationJobId,
        first_continue_request: AggregationJobContinueReq,
        first_continue_response: Option<AggregationJobResp>,
        handler: Box<dyn Handler>,
        _ephemeral_datastore: EphemeralDatastore,
    }

    /// Set up a helper with an aggregation job in step 0
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_test(
    ) -> AggregationJobContinueTestCase<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>> {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let aggregation_job_id = random();
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Poplar1 { bits: 1 }).build();
        let helper_task = task.helper_view().unwrap();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let meter = noop_meter();
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let aggregation_param = Poplar1AggregationParam::try_from_prefixes(Vec::from([
            IdpfInput::from_bools(&[false]),
        ]))
        .unwrap();
        let prepare_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            Poplar1::new_shake128(1),
            aggregation_param.clone(),
        );

        let (prepare_init, transcript) =
            prepare_init_generator.next(&IdpfInput::from_bools(&[true]));

        datastore
            .run_unnamed_tx(|tx| {
                let (task, aggregation_param, prepare_init, transcript) = (
                    helper_task.clone(),
                    aggregation_param.clone(),
                    prepare_init.clone(),
                    transcript.clone(),
                );

                Box::pin(async move {
                    tx.put_aggregator_task(&task).await.unwrap();
                    tx.put_report_share(task.id(), prepare_init.report_share())
                        .await
                        .unwrap();

                    tx.put_aggregation_job(&AggregationJob::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Poplar1<XofShake128, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param,
                        (),
                        Interval::from_time(prepare_init.report_share().metadata().time()).unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobStep::from(0),
                    ))
                    .await
                    .unwrap();

                    tx.put_report_aggregation::<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *prepare_init.report_share().metadata().id(),
                            *prepare_init.report_share().metadata().time(),
                            0,
                            None,
                            ReportAggregationState::WaitingHelper(
                                transcript.helper_prepare_transitions[0]
                                    .prepare_state()
                                    .clone(),
                            ),
                        ),
                    )
                    .await
                    .unwrap();

                    Ok(())
                })
            })
            .await
            .unwrap();

        let first_continue_request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            Vec::from([PrepareContinue::new(
                *prepare_init.report_share().metadata().id(),
                transcript.leader_prepare_transitions[1].message.clone(),
            )]),
        );

        // Create aggregator handler.
        let handler = aggregator_handler(
            Arc::clone(&datastore),
            clock,
            &meter,
            default_aggregator_config(),
        )
        .await
        .unwrap();

        AggregationJobContinueTestCase {
            task,
            datastore,
            prepare_init_generator,
            aggregation_job_id,
            first_continue_request,
            first_continue_response: None,
            handler: Box::new(handler),
            _ephemeral_datastore: ephemeral_datastore,
        }
    }

    /// Set up a helper with an aggregation job in step 1.
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_step_recovery_test(
    ) -> AggregationJobContinueTestCase<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>> {
        let mut test_case = setup_aggregation_job_continue_test().await;

        let first_continue_response = post_aggregation_job_and_decode(
            &test_case.task,
            &test_case.aggregation_job_id,
            &test_case.first_continue_request,
            &test_case.handler,
        )
        .await;

        // Validate response.
        assert_eq!(
            first_continue_response,
            AggregationJobResp::new(
                test_case
                    .first_continue_request
                    .prepare_steps()
                    .iter()
                    .map(|step| PrepareResp::new(*step.report_id(), PrepareStepResult::Finished))
                    .collect()
            )
        );

        test_case.first_continue_response = Some(first_continue_response);
        test_case
    }

    #[tokio::test]
    async fn aggregation_job_continue_step_zero() {
        let test_case = setup_aggregation_job_continue_test().await;

        // The job is initialized into step 0 but has never been continued. Send a continue request
        // to advance to step 0. Should be rejected because that is an illegal transition.
        let step_zero_request = AggregationJobContinueReq::new(
            AggregationJobStep::from(0),
            test_case.first_continue_request.prepare_steps().to_vec(),
        );

        post_aggregation_job_expecting_error(
            &test_case.task,
            &test_case.aggregation_job_id,
            &step_zero_request,
            &test_case.handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:invalidMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregation_job_continue_step_recovery_replay_request() {
        let test_case = setup_aggregation_job_continue_step_recovery_test().await;

        // Re-send the request, simulating the leader crashing and losing the helper's response. The
        // helper should send back the exact same response.
        let second_continue_resp = post_aggregation_job_and_decode(
            &test_case.task,
            &test_case.aggregation_job_id,
            &test_case.first_continue_request,
            &test_case.handler,
        )
        .await;
        assert_eq!(
            test_case.first_continue_response.unwrap(),
            second_continue_resp
        );
    }

    #[tokio::test]
    #[allow(clippy::unit_arg)]
    async fn aggregation_job_continue_step_recovery_mutate_continue_request() {
        let test_case = setup_aggregation_job_continue_step_recovery_test().await;

        let (unrelated_prepare_init, unrelated_transcript) = test_case
            .prepare_init_generator
            .next(&IdpfInput::from_bools(&[false]));

        let (before_aggregation_job, before_report_aggregations) = test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let (task_id, unrelated_prepare_init, aggregation_job_id) = (
                    *test_case.task.id(),
                    unrelated_prepare_init.clone(),
                    test_case.aggregation_job_id,
                );
                Box::pin(async move {
                    tx.put_report_share(&task_id, unrelated_prepare_init.report_share())
                        .await
                        .unwrap();

                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>>(
                            &Poplar1::new_shake128(1),
                            &Role::Helper,
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    Ok((aggregation_job, report_aggregations))
                })
            })
            .await
            .unwrap();

        // Send another continue request for the same aggregation job, but with a different report
        // ID.
        let modified_request = AggregationJobContinueReq::new(
            test_case.first_continue_request.step(),
            Vec::from([PrepareContinue::new(
                *unrelated_prepare_init.report_share().metadata().id(),
                unrelated_transcript.leader_prepare_transitions[1]
                    .message
                    .clone(),
            )]),
        );

        let _ = post_aggregation_job_expecting_status(
            &test_case.task,
            &test_case.aggregation_job_id,
            &modified_request,
            &test_case.handler,
            Status::Conflict,
        )
        .await;

        // Make sure the state of the aggregation job and report aggregations has not changed
        let (after_aggregation_job, after_report_aggregations) = test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let (task_id, aggregation_job_id) =
                    (*test_case.task.id(), test_case.aggregation_job_id);
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<VERIFY_KEY_LENGTH, Poplar1<XofShake128, 16>>(
                            &Poplar1::new_shake128(1),
                            &Role::Helper,
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    Ok((aggregation_job, report_aggregations))
                })
            })
            .await
            .unwrap();

        assert_eq!(before_aggregation_job, after_aggregation_job);
        assert_eq!(before_report_aggregations, after_report_aggregations);
    }

    #[tokio::test]
    async fn aggregation_job_continue_step_recovery_past_step() {
        let test_case = setup_aggregation_job_continue_step_recovery_test().await;

        test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let (task_id, aggregation_job_id) =
                    (*test_case.task.id(), test_case.aggregation_job_id);
                Box::pin(async move {
                    // This is a cheat: dummy_vdaf only has a single step, so we artificially force
                    // this job into step 2 so that we can send a request for step 1 and force a
                    // step mismatch error instead of tripping the check for a request to continue
                    // to step 0.
                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofShake128, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap()
                        .with_step(AggregationJobStep::from(2));

                    tx.update_aggregation_job(&aggregation_job).await.unwrap();

                    Ok(())
                })
            })
            .await
            .unwrap();

        // Send another request for a step that the helper is past. Should fail.
        let past_step_request = AggregationJobContinueReq::new(
            AggregationJobStep::from(1),
            test_case.first_continue_request.prepare_steps().to_vec(),
        );

        post_aggregation_job_expecting_error(
            &test_case.task,
            &test_case.aggregation_job_id,
            &past_step_request,
            &test_case.handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:stepMismatch",
            "The leader and helper are not on the same step of VDAF preparation.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregation_job_continue_step_recovery_future_step() {
        let test_case = setup_aggregation_job_continue_step_recovery_test().await;

        // Send another request for a step too far past the helper's step. Should fail because the
        // helper isn't on that step.
        let future_step_request = AggregationJobContinueReq::new(
            AggregationJobStep::from(17),
            test_case.first_continue_request.prepare_steps().to_vec(),
        );

        post_aggregation_job_expecting_error(
            &test_case.task,
            &test_case.aggregation_job_id,
            &future_step_request,
            &test_case.handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:stepMismatch",
            "The leader and helper are not on the same step of VDAF preparation.",
        )
        .await;
    }
}
