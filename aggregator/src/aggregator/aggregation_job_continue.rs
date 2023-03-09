//! Implements portions of aggregation job continuation for the helper.

use crate::aggregator::{accumulator::Accumulator, Error, VdafOps};
use janus_aggregator_core::{
    datastore::{
        self,
        models::{
            AggregationJob, AggregationJobState, PrepareMessageOrShare, ReportAggregation,
            ReportAggregationState,
        },
        Transaction,
    },
    query_type::AccumulableQueryType,
    task::Task,
};
use janus_core::time::Clock;
use janus_messages::{
    AggregationJobContinueReq, AggregationJobResp, PrepareStep, PrepareStepResult, ReportShareError,
};
use opentelemetry::{metrics::Counter, Context, KeyValue};
use prio::{
    codec::{Encode, ParameterizedDecode},
    vdaf::{self, PrepareTransition},
};
use std::{io::Cursor, sync::Arc};
use tracing::info;

impl VdafOps {
    /// Step the helper's aggregation job to the next round of VDAF preparation using the round `n`
    /// prepare state in `report_aggregations` with the round `n+1` broadcast prepare messages in
    /// `leader_aggregation_job`.
    pub(super) async fn step_aggregation_job<const L: usize, C, Q, A>(
        tx: &Transaction<'_, C>,
        task: &Arc<Task>,
        vdaf: &Arc<A>,
        batch_aggregation_shard_count: u64,
        helper_aggregation_job: AggregationJob<L, Q, A>,
        report_aggregations: Vec<ReportAggregation<L, A>>,
        leader_aggregation_job: &Arc<AggregationJobContinueReq>,
        request_hash: [u8; 32],
        aggregate_step_failure_counter: &Counter<u64>,
    ) -> Result<AggregationJobResp, datastore::Error>
    where
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L, 16> + 'static + Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
    {
        // Handle each transition in the request.
        let mut report_aggregations = report_aggregations.into_iter();
        let (mut saw_continue, mut saw_finish) = (false, false);
        let mut response_prep_steps = Vec::new();
        let mut accumulator = Accumulator::<L, Q, A>::new(
            Arc::clone(task),
            batch_aggregation_shard_count,
            helper_aggregation_job.aggregation_parameter().clone(),
        );

        for prep_step in leader_aggregation_job.prepare_steps() {
            // Match preparation step received from leader to stored report aggregation, and extract
            // the stored preparation step.
            let report_aggregation = loop {
                let report_agg = report_aggregations.next().ok_or_else(|| {
                    datastore::Error::User(
                        Error::UnrecognizedMessage(
                            Some(*task.id()),
                            "leader sent unexpected, duplicate, or out-of-order prepare steps",
                        )
                        .into(),
                    )
                })?;
                if report_agg.report_id() != prep_step.report_id() {
                    // This report was omitted by the leader because of a prior failure. Note that
                    // the report was dropped (if it's not already in an error state) and continue.
                    if matches!(report_agg.state(), ReportAggregationState::Waiting(_, _)) {
                        tx.update_report_aggregation(&report_agg.with_state(
                            ReportAggregationState::Failed(ReportShareError::ReportDropped),
                        ))
                        .await?;
                    }
                    continue;
                }
                break report_agg;
            };

            // Make sure this report isn't in an interval that has already started collection.
            let conflicting_aggregate_share_jobs = tx
                .get_aggregate_share_jobs_including_time::<L, A>(
                    vdaf,
                    task.id(),
                    report_aggregation.time(),
                )
                .await?;
            if !conflicting_aggregate_share_jobs.is_empty() {
                response_prep_steps.push(PrepareStep::new(
                    *prep_step.report_id(),
                    PrepareStepResult::Failed(ReportShareError::BatchCollected),
                ));
                tx.update_report_aggregation(&report_aggregation.with_state(
                    ReportAggregationState::Failed(ReportShareError::BatchCollected),
                ))
                .await?;
                continue;
            }

            let prep_state = match report_aggregation.state() {
                ReportAggregationState::Waiting(prep_state, _) => prep_state,
                _ => {
                    return Err(datastore::Error::User(
                        Error::UnrecognizedMessage(
                            Some(*task.id()),
                            "leader sent prepare step for non-WAITING report aggregation",
                        )
                        .into(),
                    ));
                }
            };

            // Parse preparation message out of prepare step received from leader.
            let prep_msg = match prep_step.result() {
                PrepareStepResult::Continued(payload) => A::PrepareMessage::decode_with_param(
                    prep_state,
                    &mut Cursor::new(payload.as_ref()),
                )?,
                _ => {
                    return Err(datastore::Error::User(
                        Error::UnrecognizedMessage(
                            Some(*task.id()),
                            "leader sent non-Continued prepare step",
                        )
                        .into(),
                    ));
                }
            };

            // Compute the next transition, prepare to respond & update DB.
            let next_state = match vdaf.prepare_step(prep_state.clone(), prep_msg) {
                Ok(PrepareTransition::Continue(prep_state, prep_share)) => {
                    saw_continue = true;
                    response_prep_steps.push(PrepareStep::new(
                        *prep_step.report_id(),
                        PrepareStepResult::Continued(prep_share.get_encoded()),
                    ));
                    ReportAggregationState::Waiting(
                        prep_state,
                        PrepareMessageOrShare::Helper(prep_share),
                    )
                }

                Ok(PrepareTransition::Finish(output_share)) => {
                    saw_finish = true;
                    accumulator.update(
                        helper_aggregation_job.partial_batch_identifier(),
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
                    info!(
                        task_id = %task.id(),
                        job_id = %helper_aggregation_job.id(),
                        report_id = %prep_step.report_id(),
                        ?error, "Prepare step failed",
                    );
                    aggregate_step_failure_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("type", "prepare_step_failure")],
                    );
                    response_prep_steps.push(PrepareStep::new(
                        *prep_step.report_id(),
                        PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                    ));
                    ReportAggregationState::Failed(ReportShareError::VdafPrepError)
                }
            };

            tx.update_report_aggregation(&report_aggregation.with_state(next_state))
                .await?;
        }

        for report_agg in report_aggregations {
            // This report was omitted by the leader because of a prior failure. Note that the
            // report was dropped (if it's not already in an error state) and continue.
            if matches!(report_agg.state(), ReportAggregationState::Waiting(_, _)) {
                tx.update_report_aggregation(&report_agg.with_state(
                    ReportAggregationState::Failed(ReportShareError::ReportDropped),
                ))
                .await?;
            }
        }

        let helper_aggregation_job = helper_aggregation_job
            // Advance the job to the leader's round
            .with_round(leader_aggregation_job.round())
            .with_state(match (saw_continue, saw_finish) {
                (false, false) => AggregationJobState::Finished, // everything failed, or there were no reports
                (true, false) => AggregationJobState::InProgress,
                (false, true) => AggregationJobState::Finished,
                (true, true) => {
                    return Err(datastore::Error::User(
                        Error::Internal(
                            "VDAF took an inconsistent number of rounds to reach Finish state"
                                .to_string(),
                        )
                        .into(),
                    ))
                }
            })
            .with_last_continue_request_hash(request_hash);
        tx.update_aggregation_job(&helper_aggregation_job).await?;

        accumulator.flush_to_datastore(tx, vdaf).await?;

        Ok(AggregationJobResp::new(response_prep_steps))
    }

    /// Fetch previously-computed prepare message shares and replay them back to the leader.
    pub(super) fn replay_aggregation_job_round<C, const L: usize, Q, A>(
        report_aggregations: Vec<ReportAggregation<L, A>>,
    ) -> Result<AggregationJobResp, datastore::Error>
    where
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<L, 16> + 'static + Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
    {
        let response_prep_steps = report_aggregations
            .iter()
            .map(|report_aggregation| {
                let prepare_step_state = match report_aggregation.state() {
                    ReportAggregationState::Waiting(_, prep_msg) => PrepareStepResult::Continued(
                        prep_msg.get_helper_prepare_share()?.get_encoded(),
                    ),
                    ReportAggregationState::Finished(_) => PrepareStepResult::Finished,
                    ReportAggregationState::Failed(report_share_error) => {
                        PrepareStepResult::Failed(*report_share_error)
                    }
                    state => {
                        return Err(datastore::Error::User(
                            Error::Internal(format!(
                                "report aggregation {} unexpectedly in state {state:?}",
                                report_aggregation.report_id()
                            ))
                            .into(),
                        ));
                    }
                };

                Ok(PrepareStep::new(
                    *report_aggregation.report_id(),
                    prepare_step_state,
                ))
            })
            .collect::<Result<_, _>>()?;

        Ok(AggregationJobResp::new(response_prep_steps))
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use http::{header::CONTENT_TYPE, StatusCode};
    use hyper::{body, Body};
    use janus_aggregator_core::task::Task;
    use janus_messages::{AggregationJobContinueReq, AggregationJobId, AggregationJobResp};
    use prio::codec::{Decode, Encode};
    use serde_json::json;
    use warp::{filters::BoxedFilter, reply::Response, Reply};

    async fn post_aggregation_job(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        filter: &BoxedFilter<(impl Reply + 'static,)>,
    ) -> Response {
        warp::test::request()
            .method("POST")
            .path(task.aggregation_job_uri(aggregation_job_id).unwrap().path())
            .header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .header(CONTENT_TYPE, AggregationJobContinueReq::MEDIA_TYPE)
            .body(request.get_encoded())
            .filter(filter)
            .await
            .unwrap()
            .into_response()
    }

    pub async fn post_aggregation_job_and_decode(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        filter: &BoxedFilter<(impl Reply + 'static,)>,
    ) -> AggregationJobResp {
        let mut response = post_aggregation_job(task, aggregation_job_id, request, filter).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            AggregationJobResp::MEDIA_TYPE
        );
        let body_bytes = body::to_bytes(response.body_mut()).await.unwrap();
        AggregationJobResp::get_decoded(&body_bytes).unwrap()
    }

    pub async fn post_aggregation_job_expecting_status(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        filter: &BoxedFilter<(impl Reply + 'static,)>,
        want_status: StatusCode,
    ) -> Body {
        let (parts, body) = post_aggregation_job(task, aggregation_job_id, request, filter)
            .await
            .into_parts();

        assert_eq!(want_status, parts.status);

        body
    }

    pub async fn post_aggregation_job_expecting_error(
        task: &Task,
        aggregation_job_id: &AggregationJobId,
        request: &AggregationJobContinueReq,
        filter: &BoxedFilter<(impl Reply + 'static,)>,
        want_status: StatusCode,
        want_error_type: &str,
        want_error_title: &str,
    ) {
        let body = post_aggregation_job_expecting_status(
            task,
            aggregation_job_id,
            request,
            filter,
            want_status,
        )
        .await;

        let problem_details: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(body).await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status.as_u16(),
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
        aggregate_init_tests::ReportShareGenerator,
        aggregation_job_continue::test_util::{
            post_aggregation_job_and_decode, post_aggregation_job_expecting_error,
            post_aggregation_job_expecting_status,
        },
        aggregator_filter,
        tests::default_aggregator_config,
    };
    use http::StatusCode;
    use janus_aggregator_core::{
        datastore::{
            models::{
                AggregationJob, AggregationJobState, PrepareMessageOrShare, ReportAggregation,
                ReportAggregationState,
            },
            test_util::{ephemeral_datastore, EphemeralDatastore},
            Datastore,
        },
        task::{test_util::TaskBuilder, QueryType, Task},
    };
    use janus_core::{
        task::VdafInstance,
        test_util::{dummy_vdaf, install_test_trace_subscriber},
        time::{IntervalExt, MockClock},
    };
    use janus_messages::{
        query_type::TimeInterval, AggregationJobContinueReq, AggregationJobId, AggregationJobResp,
        AggregationJobRound, Interval, PrepareStep, PrepareStepResult, Role,
    };
    use prio::codec::Encode;
    use rand::random;
    use std::sync::Arc;
    use warp::{filters::BoxedFilter, Reply};

    struct AggregationJobContinueTestCase<R> {
        task: Task,
        datastore: Arc<Datastore<MockClock>>,
        report_generator: ReportShareGenerator,
        aggregation_job_id: AggregationJobId,
        first_continue_request: AggregationJobContinueReq,
        first_continue_response: Option<AggregationJobResp>,
        filter: BoxedFilter<(R,)>,
        _ephemeral_datastore: EphemeralDatastore,
    }

    /// Set up a helper with an aggregation job in round 0
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_test(
    ) -> AggregationJobContinueTestCase<impl Reply + 'static> {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let aggregation_job_id = random();
        let task =
            TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        let report_generator = ReportShareGenerator::new(
            clock.clone(),
            task.clone(),
            dummy_vdaf::AggregationParam::default(),
        );

        let report = report_generator.next();

        datastore
            .run_tx(|tx| {
                let (task, report) = (task.clone(), report.clone());

                Box::pin(async move {
                    tx.put_task(&task).await.unwrap();
                    tx.put_report_share(task.id(), &report.0).await.unwrap();

                    tx.put_aggregation_job(
                        &AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            aggregation_job_id,
                            dummy_vdaf::AggregationParam::default(),
                            (),
                            Interval::from_time(report.0.metadata().time()).unwrap(),
                            AggregationJobState::InProgress,
                            AggregationJobRound::from(0),
                        ),
                    )
                    .await
                    .unwrap();

                    let (prep_state, prep_share) = report.1.helper_prep_state(0);
                    tx.put_report_aggregation::<0, dummy_vdaf::Vdaf>(&ReportAggregation::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.0.metadata().id(),
                        *report.0.metadata().time(),
                        0,
                        ReportAggregationState::Waiting(
                            *prep_state,
                            PrepareMessageOrShare::Helper(*prep_share),
                        ),
                    ))
                    .await
                    .unwrap();

                    Ok(())
                })
            })
            .await
            .unwrap();

        let first_continue_request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            Vec::from([PrepareStep::new(
                *report.0.metadata().id(),
                PrepareStepResult::Continued(report.1.prepare_messages[0].get_encoded()),
            )]),
        );

        // Create aggregator filter.
        let filter =
            aggregator_filter(datastore.clone(), clock, default_aggregator_config()).unwrap();

        AggregationJobContinueTestCase {
            task,
            datastore,
            report_generator,
            aggregation_job_id,
            first_continue_request,
            first_continue_response: None,
            filter,
            _ephemeral_datastore: ephemeral_datastore,
        }
    }

    /// Set up a helper with an aggregation job in round 1
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_round_recovery_test(
    ) -> AggregationJobContinueTestCase<impl Reply + 'static> {
        let mut test_case = setup_aggregation_job_continue_test().await;

        let first_continue_response = post_aggregation_job_and_decode(
            &test_case.task,
            &test_case.aggregation_job_id,
            &test_case.first_continue_request,
            &test_case.filter,
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
                    .map(|step| PrepareStep::new(*step.report_id(), PrepareStepResult::Finished))
                    .collect()
            )
        );

        test_case.first_continue_response = Some(first_continue_response);
        test_case
    }

    #[tokio::test]
    async fn aggregation_job_continue_round_zero() {
        let test_case = setup_aggregation_job_continue_test().await;

        // The job is initialized into round 0 but has never been continued. Send a continue request
        // to advance to round 0. Should be rejected because that is an illegal transition.
        let round_zero_request = AggregationJobContinueReq::new(
            AggregationJobRound::from(0),
            test_case.first_continue_request.prepare_steps().to_vec(),
        );

        post_aggregation_job_expecting_error(
            &test_case.task,
            &test_case.aggregation_job_id,
            &round_zero_request,
            &test_case.filter,
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
            "The message type for a response was incorrect or the payload was malformed.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregation_job_continue_round_recovery_replay_request() {
        let test_case = setup_aggregation_job_continue_round_recovery_test().await;

        // Re-send the request, simulating the leader crashing and losing the helper's response. The
        // helper should send back the exact same response.
        let second_continue_resp = post_aggregation_job_and_decode(
            &test_case.task,
            &test_case.aggregation_job_id,
            &test_case.first_continue_request,
            &test_case.filter,
        )
        .await;
        assert_eq!(
            test_case.first_continue_response.unwrap(),
            second_continue_resp
        );
    }

    #[tokio::test]
    #[allow(clippy::unit_arg)]
    async fn aggregation_job_continue_round_recovery_mutate_continue_request() {
        let test_case = setup_aggregation_job_continue_round_recovery_test().await;

        let unrelated_report = test_case.report_generator.next();

        let (before_aggregation_job, before_report_aggregations) = test_case
            .datastore
            .run_tx(|tx| {
                let (task_id, unrelated_report, aggregation_job_id) = (
                    *test_case.task.id(),
                    unrelated_report.clone(),
                    test_case.aggregation_job_id,
                );
                Box::pin(async move {
                    tx.put_report_share(&task_id, &unrelated_report.0)
                        .await
                        .unwrap();

                    let aggregation_job = tx
                        .get_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<0, dummy_vdaf::Vdaf>(
                            &dummy_vdaf::Vdaf::new(),
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
            test_case.first_continue_request.round(),
            Vec::from([PrepareStep::new(
                *unrelated_report.0.metadata().id(),
                PrepareStepResult::Continued(unrelated_report.1.prepare_messages[0].get_encoded()),
            )]),
        );

        let _ = post_aggregation_job_expecting_status(
            &test_case.task,
            &test_case.aggregation_job_id,
            &modified_request,
            &test_case.filter,
            StatusCode::CONFLICT,
        )
        .await;

        // Make sure the state of the aggregation job and report aggregations has not changed
        let (after_aggregation_job, after_report_aggregations) = test_case
            .datastore
            .run_tx(|tx| {
                let (task_id, aggregation_job_id) =
                    (*test_case.task.id(), test_case.aggregation_job_id);
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<0, dummy_vdaf::Vdaf>(
                            &dummy_vdaf::Vdaf::new(),
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
    async fn aggregation_job_continue_round_recovery_past_round() {
        let test_case = setup_aggregation_job_continue_round_recovery_test().await;

        test_case
            .datastore
            .run_tx(|tx| {
                let (task_id, aggregation_job_id) =
                    (*test_case.task.id(), test_case.aggregation_job_id);
                Box::pin(async move {
                    // This is a cheat: dummy_vdaf only has a single round, so we artificially force
                    // this job into round 2 so that we can send a request for round 1 and force a
                    // round mismatch error instead of tripping the check for a request to continue
                    // to round 0.
                    let aggregation_job = tx
                        .get_aggregation_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap()
                        .with_round(AggregationJobRound::from(2));

                    tx.update_aggregation_job(&aggregation_job).await.unwrap();

                    Ok(())
                })
            })
            .await
            .unwrap();

        // Send another request for a round that the helper is past. Should fail.
        let past_round_request = AggregationJobContinueReq::new(
            AggregationJobRound::from(1),
            test_case.first_continue_request.prepare_steps().to_vec(),
        );

        post_aggregation_job_expecting_error(
            &test_case.task,
            &test_case.aggregation_job_id,
            &past_round_request,
            &test_case.filter,
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:ppm:dap:error:roundMismatch",
            "The leader and helper are not on the same round of VDAF preparation.",
        )
        .await;
    }

    #[tokio::test]
    async fn aggregation_job_continue_round_recovery_future_round() {
        let test_case = setup_aggregation_job_continue_round_recovery_test().await;

        // Send another request for a round too far past the helper's round. Should fail because the
        // helper isn't on that round.
        let future_round_request = AggregationJobContinueReq::new(
            AggregationJobRound::from(17),
            test_case.first_continue_request.prepare_steps().to_vec(),
        );

        post_aggregation_job_expecting_error(
            &test_case.task,
            &test_case.aggregation_job_id,
            &future_round_request,
            &test_case.filter,
            StatusCode::BAD_REQUEST,
            "urn:ietf:params:ppm:dap:error:roundMismatch",
            "The leader and helper are not on the same round of VDAF preparation.",
        )
        .await;
    }
}
