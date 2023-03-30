//! Implements portions of aggregation job continuation for the helper.

use crate::aggregator::{accumulator::Accumulator, Error, VdafOps};
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::{
        self,
        models::{AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState},
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
use tokio::try_join;
use tracing::info;

impl VdafOps {
    /// Step the helper's aggregation job to the next round of VDAF preparation using the round `n`
    /// prepare state in `report_aggregations` with the round `n+1` broadcast prepare messages in
    /// `leader_aggregation_job`.
    pub(super) async fn step_aggregation_job<const SEED_SIZE: usize, C, Q, A>(
        tx: &Transaction<'_, C>,
        task: Arc<Task>,
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
                        *report_agg = report_agg
                            .clone()
                            .with_state(ReportAggregationState::Failed(
                                ReportShareError::ReportDropped,
                            ))
                            .with_last_prep_step(None);
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
                    .with_state(ReportAggregationState::Failed(
                        ReportShareError::BatchCollected,
                    ))
                    .with_last_prep_step(Some(PrepareStep::new(
                        *prep_step.report_id(),
                        PrepareStepResult::Failed(ReportShareError::BatchCollected),
                    )));
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

            // Parse preparation message out of prepare step received from Leader.
            let prep_msg = A::PrepareMessage::decode_with_param(
                prep_state,
                &mut Cursor::new(match prep_step.result() {
                    PrepareStepResult::Continued { prep_msg, .. } => prep_msg,
                    PrepareStepResult::Finished { prep_msg } => prep_msg,
                    _ => {
                        return Err(datastore::Error::User(
                            Error::UnrecognizedMessage(
                                Some(*task.id()),
                                "leader sent non-Continued/Finished prepare step",
                            )
                            .into(),
                        ));
                    }
                }),
            )?;

            // Compute the next transition; if we're finished, we terminate here. Otherwise,
            // retrieve our updated state as well as the leader & helper prepare shares.
            let (prep_state, leader_prep_share, helper_prep_share) = match vdaf
                .prepare_step(prep_state.clone(), prep_msg)
            {
                Ok(PrepareTransition::Continue(prep_state, helper_prep_share)) => {
                    if let PrepareStepResult::Continued { prep_share, .. } = prep_step.result() {
                        let leader_prep_share = match A::PrepareShare::get_decoded_with_param(
                            &prep_state,
                            prep_share,
                        ) {
                            Ok(leader_prep_share) => leader_prep_share,
                            Err(err) => {
                                info!(
                                    task_id = %task.id(),
                                    job_id = %helper_aggregation_job.id(),
                                    report_id = %prep_step.report_id(),
                                    ?err,
                                    "Couldn't parse Leader's prepare share"
                                );
                                *report_aggregation = report_aggregation
                                    .clone()
                                    .with_state(ReportAggregationState::Failed(
                                        ReportShareError::VdafPrepError,
                                    ))
                                    .with_last_prep_step(Some(PrepareStep::new(
                                        *prep_step.report_id(),
                                        PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                                    )));
                                continue;
                            }
                        };
                        (prep_state, leader_prep_share, helper_prep_share)
                    } else {
                        info!(
                            task_id = %task.id(),
                            job_id = %helper_aggregation_job.id(),
                            report_id = %prep_step.report_id(),
                            "Leader finished but Helper did not",
                        );
                        *report_aggregation = report_aggregation
                            .clone()
                            .with_state(ReportAggregationState::Failed(
                                ReportShareError::VdafPrepError,
                            ))
                            .with_last_prep_step(Some(PrepareStep::new(
                                *prep_step.report_id(),
                                PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                            )));
                        continue;
                    }
                }

                Ok(PrepareTransition::Finish(out_share)) => {
                    // If we finished but the Leader didn't, fail out.
                    if !matches!(prep_step.result(), PrepareStepResult::Finished { .. }) {
                        info!(
                            task_id = %task.id(),
                            job_id = %helper_aggregation_job.id(),
                            report_id = %prep_step.report_id(),
                            "Helper finished but Leader did not",
                        );
                        *report_aggregation = report_aggregation
                            .clone()
                            .with_state(ReportAggregationState::Failed(
                                ReportShareError::VdafPrepError,
                            ))
                            .with_last_prep_step(Some(PrepareStep::new(
                                *prep_step.report_id(),
                                PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                            )));
                        continue;
                    }

                    // If both aggregators finished here, record our output share & respond with
                    // a finished message.
                    accumulator.update(
                        helper_aggregation_job.partial_batch_identifier(),
                        prep_step.report_id(),
                        report_aggregation.time(),
                        &out_share,
                    )?;
                    *report_aggregation = report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Finished(out_share))
                        .with_last_prep_step(Some(PrepareStep::new(
                            *prep_step.report_id(),
                            PrepareStepResult::Finished {
                                prep_msg: Vec::new(),
                            },
                        )));
                    continue;
                }

                Err(err) => {
                    info!(
                        task_id = %task.id(),
                        job_id = %helper_aggregation_job.id(),
                        report_id = %prep_step.report_id(),
                        ?err, "Prepare step failed",
                    );
                    aggregate_step_failure_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("type", "prepare_step_failure")],
                    );
                    *report_aggregation = report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Failed(
                            ReportShareError::VdafPrepError,
                        ))
                        .with_last_prep_step(Some(PrepareStep::new(
                            *prep_step.report_id(),
                            PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                        )));
                    continue;
                }
            };

            // Merge the leader & helper prepare shares into the next message.
            let prep_msg = match vdaf.prepare_preprocess([leader_prep_share, helper_prep_share]) {
                Ok(prep_msg) => prep_msg,
                Err(err) => {
                    info!(
                        task_id = %task.id(),
                        job_id = %helper_aggregation_job.id(),
                        report_id = %prep_step.report_id(),
                        ?err,
                        "Couldn't compute prepare message",
                    );
                    *report_aggregation = report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Failed(
                            ReportShareError::VdafPrepError,
                        ))
                        .with_last_prep_step(Some(PrepareStep::new(
                            *prep_step.report_id(),
                            PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                        )));
                    continue;
                }
            };

            // Compute the next step based on the merged message.
            let encoded_prep_msg = prep_msg.get_encoded();
            match vdaf.prepare_step(prep_state, prep_msg) {
                Ok(PrepareTransition::Continue(prep_state, helper_prep_share)) => {
                    *report_aggregation = report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Waiting(prep_state, None))
                        .with_last_prep_step(Some(PrepareStep::new(
                            *prep_step.report_id(),
                            PrepareStepResult::Continued {
                                prep_msg: encoded_prep_msg,
                                prep_share: helper_prep_share.get_encoded(),
                            },
                        )));
                }

                Ok(PrepareTransition::Finish(out_share)) => {
                    *report_aggregation = report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Finished(out_share))
                        .with_last_prep_step(Some(PrepareStep::new(
                            *prep_step.report_id(),
                            PrepareStepResult::Finished {
                                prep_msg: encoded_prep_msg,
                            },
                        )));
                }

                Err(err) => {
                    info!(
                        task_id = %task.id(),
                        job_id = %helper_aggregation_job.id(),
                        report_id = %prep_step.report_id(),
                        ?err,
                        "Prepare step failed",
                    );
                    *report_aggregation = report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Failed(
                            ReportShareError::VdafPrepError,
                        ))
                        .with_last_prep_step(Some(PrepareStep::new(
                            *prep_step.report_id(),
                            PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                        )));
                }
            }
        }

        for report_agg in report_aggregations_iter {
            // This report was omitted by the leader because of a prior failure. Note that the
            // report was dropped (if it's not already in an error state) and continue.
            if matches!(report_agg.state(), ReportAggregationState::Waiting(_, _)) {
                *report_agg = report_agg
                    .clone()
                    .with_state(ReportAggregationState::Failed(
                        ReportShareError::ReportDropped,
                    ))
                    .with_last_prep_step(None);
            }
        }

        let saw_continue = report_aggregations.iter().any(|report_agg| {
            matches!(
                report_agg.last_prep_step().map(PrepareStep::result),
                Some(PrepareStepResult::Continued { .. })
            )
        });
        let saw_finish = report_aggregations.iter().any(|report_agg| {
            matches!(
                report_agg.last_prep_step().map(PrepareStep::result),
                Some(PrepareStepResult::Finished { .. })
            )
        });
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

        try_join!(
            tx.update_aggregation_job(&helper_aggregation_job),
            try_join_all(
                report_aggregations
                    .iter()
                    .map(|report_agg| tx.update_report_aggregation(report_agg)),
            ),
            accumulator.flush_to_datastore(tx, &vdaf)
        )?;

        Ok(Self::aggregation_job_resp_for::<SEED_SIZE, A>(
            report_aggregations,
        ))
    }

    /// Construct an AggregationJobResp from a given set of Helper report aggregations.
    pub(super) fn aggregation_job_resp_for<const SEED_SIZE: usize, A>(
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
    ) -> AggregationJobResp
    where
        A: vdaf::Aggregator<SEED_SIZE, 16>,
    {
        AggregationJobResp::new(
            report_aggregations
                .iter()
                .filter_map(ReportAggregation::last_prep_step)
                .cloned()
                .collect(),
        )
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
        aggregate_init_tests::ReportInitGenerator,
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
                AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
            },
            test_util::{ephemeral_datastore, EphemeralDatastore},
            Datastore,
        },
        task::{test_util::TaskBuilder, QueryType, Task},
    };
    use janus_core::{
        task::{VdafInstance, VERIFY_KEY_LEN},
        test_util::install_test_trace_subscriber,
        time::{IntervalExt, MockClock},
    };
    use janus_messages::{
        query_type::TimeInterval, AggregationJobContinueReq, AggregationJobId, AggregationJobResp,
        AggregationJobRound, Interval, PrepareStep, PrepareStepResult, Role,
    };
    use prio::{
        codec::Encode,
        idpf::IdpfInput,
        vdaf::{
            poplar1::{Poplar1, Poplar1AggregationParam},
            prg::PrgSha3,
            Vdaf,
        },
    };
    use rand::random;
    use std::sync::Arc;
    use warp::{filters::BoxedFilter, Reply};

    struct AggregationJobContinueTestCase<R, V>
    where
        V: Vdaf,
    {
        task: Task,
        datastore: Arc<Datastore<MockClock>>,
        report_generator: ReportInitGenerator<VERIFY_KEY_LEN, V>,
        aggregation_job_id: AggregationJobId,
        first_continue_request: AggregationJobContinueReq,
        first_continue_response: Option<AggregationJobResp>,
        filter: BoxedFilter<(R,)>,
        _ephemeral_datastore: EphemeralDatastore,
    }

    /// Set up a helper with an aggregation job in round 0
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_test(
    ) -> AggregationJobContinueTestCase<impl Reply + 'static, Poplar1<PrgSha3, 16>> {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let aggregation_job_id = random();
        let task = TaskBuilder::new(
            QueryType::TimeInterval,
            VdafInstance::Poplar1 { bits: 1 },
            Role::Helper,
        )
        .build();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

        let aggregation_param = Poplar1AggregationParam::try_from_prefixes(Vec::from([
            IdpfInput::from_bools(&[false]),
        ]))
        .unwrap();
        let report_generator = ReportInitGenerator::new(
            clock.clone(),
            task.clone(),
            Poplar1::new_sha3(1),
            aggregation_param.clone(),
        );

        let (report_init, transcript) = report_generator.next(&IdpfInput::from_bools(&[true]));

        datastore
            .run_tx(|tx| {
                let (task, aggregation_param, report_init, transcript) = (
                    task.clone(),
                    aggregation_param.clone(),
                    report_init.clone(),
                    transcript.clone(),
                );

                Box::pin(async move {
                    tx.put_task(&task).await.unwrap();
                    tx.put_report_share(task.id(), report_init.report_share())
                        .await
                        .unwrap();

                    tx.put_aggregation_job(&AggregationJob::<
                        VERIFY_KEY_LEN,
                        TimeInterval,
                        Poplar1<PrgSha3, 16>,
                    >::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param,
                        (),
                        Interval::from_time(report_init.report_share().metadata().time()).unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ))
                    .await
                    .unwrap();

                    let (prep_state, _) = transcript.helper_prep_state(1);
                    tx.put_report_aggregation::<VERIFY_KEY_LEN, Poplar1<PrgSha3, 16>>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *report_init.report_share().metadata().id(),
                            *report_init.report_share().metadata().time(),
                            0,
                            None,
                            ReportAggregationState::Waiting(prep_state.clone(), None),
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
            AggregationJobRound::from(1),
            Vec::from([PrepareStep::new(
                *report_init.report_share().metadata().id(),
                PrepareStepResult::Finished {
                    prep_msg: transcript.prepare_messages[1].get_encoded(),
                },
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

    /// Set up a helper with an aggregation job in round 1.
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_round_recovery_test(
    ) -> AggregationJobContinueTestCase<impl Reply + 'static, Poplar1<PrgSha3, 16>> {
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
                    .map(|step| PrepareStep::new(
                        *step.report_id(),
                        PrepareStepResult::Finished {
                            prep_msg: Vec::new()
                        }
                    ))
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

        let (unrelated_report_init, unrelated_transcript) = test_case
            .report_generator
            .next(&IdpfInput::from_bools(&[false]));

        let (before_aggregation_job, before_report_aggregations) = test_case
            .datastore
            .run_tx(|tx| {
                let (task_id, unrelated_report_init, aggregation_job_id) = (
                    *test_case.task.id(),
                    unrelated_report_init.clone(),
                    test_case.aggregation_job_id,
                );
                Box::pin(async move {
                    tx.put_report_share(&task_id, unrelated_report_init.report_share())
                        .await
                        .unwrap();

                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LEN, TimeInterval, Poplar1<PrgSha3, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<VERIFY_KEY_LEN, Poplar1<PrgSha3, 16>>(
                            &Poplar1::new_sha3(1),
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
                *unrelated_report_init.report_share().metadata().id(),
                PrepareStepResult::Finished {
                    prep_msg: unrelated_transcript.prepare_messages[1].get_encoded(),
                },
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
                        .get_aggregation_job::<VERIFY_KEY_LEN, TimeInterval, Poplar1<PrgSha3, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<VERIFY_KEY_LEN, Poplar1<PrgSha3, 16>>(
                            &Poplar1::new_sha3(1),
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
                        .get_aggregation_job::<VERIFY_KEY_LEN, TimeInterval, Poplar1<PrgSha3, 16>>(
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
