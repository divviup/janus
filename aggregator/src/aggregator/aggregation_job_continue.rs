//! Implements portions of aggregation job continuation for the helper.

use crate::aggregator::{
    aggregation_job_writer::{AggregationJobWriter, UpdateWrite, WritableReportAggregation},
    error::handle_ping_pong_error,
    AggregatorMetrics, Error, VdafOps,
};
use janus_aggregator_core::{
    datastore::{
        self,
        models::{
            AggregationJob, ReportAggregation, ReportAggregationState, TaskAggregationCounter,
        },
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
use prio::{
    codec::{Encode, ParameterizedDecode},
    topology::ping_pong::{PingPongContinuedValue, PingPongState, PingPongTopology},
    vdaf,
};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use std::{panic, sync::Arc};
use tokio::sync::mpsc;
use tracing::{info_span, trace_span, Span};

impl VdafOps {
    /// Step the helper's aggregation job to the next step using the step `n` ping pong state in
    /// `report_aggregations` with the step `n+1` ping pong messages in `leader_aggregation_job`.
    pub(super) async fn step_aggregation_job<const SEED_SIZE: usize, C, Q, A>(
        tx: &Transaction<'_, C>,
        task: Arc<AggregatorTask>,
        vdaf: Arc<A>,
        batch_aggregation_shard_count: u64,
        aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
        req: Arc<AggregationJobContinueReq>,
        request_hash: [u8; 32],
        metrics: &AggregatorMetrics,
    ) -> Result<(AggregationJobResp, TaskAggregationCounter), datastore::Error>
    where
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'static + Send + Sync,
        A::AggregationParam: Send + Sync + PartialEq + Eq,
        A::InputShare: Send + Sync,
        A::OutputShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::PublicShare: Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
    {
        let request_step = req.step();

        // Match preparation step received from leader to stored report aggregation, and extract
        // the stored preparation step.
        let report_aggregation_count = report_aggregations.len();
        let mut report_aggregations_iter = report_aggregations.into_iter();

        let mut prep_steps_and_ras = Vec::with_capacity(req.prepare_steps().len()); // matched to prep_steps
        let mut report_aggregations_to_write = Vec::with_capacity(report_aggregation_count);
        for prep_step in req.prepare_steps() {
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
                    if matches!(
                        report_agg.state(),
                        ReportAggregationState::WaitingHelper { .. }
                    ) {
                        report_aggregations_to_write.push(WritableReportAggregation::new(
                            report_agg
                                .clone()
                                .with_state(ReportAggregationState::Failed {
                                    prepare_error: PrepareError::ReportDropped,
                                })
                                .with_last_prep_resp(None),
                            None,
                        ));
                    }
                    continue;
                }
                break report_agg;
            };

            let prep_state = match report_aggregation.state() {
                ReportAggregationState::WaitingHelper { prepare_state } => prepare_state.clone(),
                ReportAggregationState::WaitingLeader { .. } => {
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

            prep_steps_and_ras.push((prep_step.clone(), report_aggregation, prep_state));
        }

        for report_aggregation in report_aggregations_iter {
            // This report was omitted by the leader because of a prior failure. Note that
            // the report was dropped (if it's not already in an error state) and continue.
            if matches!(
                report_aggregation.state(),
                ReportAggregationState::WaitingHelper { .. }
            ) {
                report_aggregations_to_write.push(WritableReportAggregation::new(
                    report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Failed {
                            prepare_error: PrepareError::ReportDropped,
                        })
                        .with_last_prep_resp(None),
                    None,
                ));
            }
        }

        // Compute the next aggregation step.
        //
        // Shutdown on cancellation: if this request is cancelled, the `receiver` will be dropped.
        // This will cause any attempts to send on `sender` to return a `SendError`, which will be
        // returned from the function passed to `try_for_each_with`; `try_for_each_with` will
        // terminate early on receiving an error.
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let aggregation_job = Arc::new(aggregation_job);
        let producer_task = tokio::task::spawn_blocking({
            let parent_span = Span::current();
            let metrics = metrics.clone();
            let task = Arc::clone(&task);
            let vdaf = Arc::clone(&vdaf);
            let aggregation_job = Arc::clone(&aggregation_job);

            move || {
                let span = info_span!(parent: parent_span, "step_aggregation_job threadpool task");

                prep_steps_and_ras.into_par_iter().try_for_each_with(
                    (sender, span),
                    |(sender, span), (prep_step, report_aggregation, prep_state)| {
                        let _entered = span.enter();

                        let (report_aggregation_state, prepare_step_result, output_share) =
                            trace_span!("VDAF preparation (helper continuation)")
                                .in_scope(|| {
                                    // Continue with the incoming message.
                                    vdaf.helper_continued(
                                        PingPongState::Continued(prep_state.clone()),
                                        aggregation_job.aggregation_parameter(),
                                        prep_step.message(),
                                    )
                                    .and_then(
                                        |continued_value| {
                                            match continued_value {
                                                PingPongContinuedValue::WithMessage {
                                                    transition,
                                                } => {
                                                    let (new_state, message) =
                                                        transition.evaluate(vdaf.as_ref())?;
                                                    let (report_aggregation_state, output_share) =
                                                        match new_state {
                                                            // Helper did not finish. Store the new
                                                            // state and await the next message from
                                                            // the Leader to advance preparation.
                                                            PingPongState::Continued(prepare_state) => (
                                                                ReportAggregationState::WaitingHelper {
                                                                    prepare_state,
                                                                },
                                                                None,
                                                            ),
                                                            // Helper finished. Commit the output
                                                            // share.
                                                            PingPongState::Finished(output_share) => (
                                                                ReportAggregationState::Finished,
                                                                Some(output_share),
                                                            ),
                                                        };

                                                    Ok((
                                                        report_aggregation_state,
                                                        // Helper has an outgoing message for Leader
                                                        PrepareStepResult::Continue { message },
                                                        output_share,
                                                    ))
                                                }

                                                PingPongContinuedValue::FinishedNoMessage {
                                                    output_share,
                                                } => Ok((
                                                    ReportAggregationState::Finished,
                                                    PrepareStepResult::Finished,
                                                    Some(output_share),
                                                )),
                                            }
                                        },
                                    )
                                })
                                .map_err(|error| {
                                    handle_ping_pong_error(
                                        task.id(),
                                        Role::Leader,
                                        prep_step.report_id(),
                                        error,
                                        &metrics.aggregate_step_failure_counter,
                                    )
                                })
                                .unwrap_or_else(|prepare_error| {
                                    (
                                        ReportAggregationState::Failed { prepare_error },
                                        PrepareStepResult::Reject(prepare_error),
                                        None,
                                    )
                                });

                        sender.send(WritableReportAggregation::new(
                            report_aggregation
                                .clone()
                                .with_state(report_aggregation_state)
                                .with_last_prep_resp(Some(PrepareResp::new(
                                    *prep_step.report_id(),
                                    prepare_step_result,
                                ))),
                            output_share,
                        ))
                    },
                )
            }
        });

        while receiver
            .recv_many(&mut report_aggregations_to_write, 10)
            .await
            > 0
        {}

        // Await the producer task to resume any panics that may have occurred, and to ensure we can
        // unwrap the aggregation job's Arc in a few lines. The only other errors that can occur
        // are: a `JoinError` indicating cancellation, which is impossible because we do not cancel
        // the task; and a `SendError`, which can only happen if this future is cancelled (in which
        // case we will not run this code at all).
        let _ = producer_task.await.map_err(|join_error| {
            if let Ok(reason) = join_error.try_into_panic() {
                panic::resume_unwind(reason);
            }
        });
        assert_eq!(report_aggregations_to_write.len(), report_aggregation_count);

        // Write accumulated aggregation values back to the datastore; this will mark any reports
        // that can't be aggregated because the batch is collected with error BatchCollected.
        let aggregation_job_id = *aggregation_job.id();
        let aggregation_job = Arc::unwrap_or_clone(aggregation_job)
            .with_step(request_step) // Advance the job to the leader's step
            .with_last_request_hash(request_hash);
        let mut aggregation_job_writer =
            AggregationJobWriter::<SEED_SIZE, _, _, UpdateWrite, _>::new(
                task,
                batch_aggregation_shard_count,
                Some(metrics.for_aggregation_job_writer()),
            );
        aggregation_job_writer.put(aggregation_job, report_aggregations_to_write)?;
        let (mut prep_resps_by_agg_job, counters) = aggregation_job_writer.write(tx, vdaf).await?;
        Ok((
            AggregationJobResp::new(
                prep_resps_by_agg_job
                    .remove(&aggregation_job_id)
                    .unwrap_or_default(),
            ),
            counters,
        ))
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use crate::aggregator::http_handlers::test_util::{decode_response_body, take_problem_details};
    use assert_matches::assert_matches;
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
            .with_request_body(request.get_encoded().unwrap())
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
        want_aggregation_job_id: Option<&AggregationJobId>,
    ) {
        let mut test_conn = post_aggregation_job_expecting_status(
            task,
            aggregation_job_id,
            request,
            handler,
            want_status,
        )
        .await;

        let mut expected_problem_details = json!({
            "status": want_status as u16,
            "type": want_error_type,
            "title": want_error_title,
            "taskid": format!("{}", task.id()),
        });

        if let Some(job_id) = want_aggregation_job_id {
            assert_matches!(expected_problem_details, serde_json::Value::Object(ref mut map) => {
                map.insert("aggregation_job_id".into(), format!("{}", job_id).into());
            });
        }

        assert_eq!(
            take_problem_details(&mut test_conn).await,
            expected_problem_details,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::{
        aggregate_init_tests::{put_aggregation_job, PrepareInitGenerator},
        aggregation_job_continue::test_util::{
            post_aggregation_job_and_decode, post_aggregation_job_expecting_error,
            post_aggregation_job_expecting_status,
        },
        http_handlers::{
            aggregator_handler,
            test_util::{take_problem_details, HttpHandlerTest},
        },
        test_util::default_aggregator_config,
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
        test_util::{install_test_trace_subscriber, runtime::TestRuntime},
        time::{IntervalExt, MockClock},
        vdaf::{VdafInstance, VERIFY_KEY_LENGTH},
    };
    use janus_messages::{
        query_type::TimeInterval, AggregationJobContinueReq, AggregationJobId,
        AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep, Interval,
        PartialBatchSelector, PrepareContinue, PrepareResp, PrepareStepResult, Role,
    };
    use prio::{
        codec::Encode,
        idpf::IdpfInput,
        vdaf::{
            poplar1::{Poplar1, Poplar1AggregationParam},
            xof::XofTurboShake128,
            Aggregator,
        },
    };
    use rand::random;
    use serde_json::json;
    use std::sync::Arc;
    use trillium::{Handler, Status};
    use trillium_testing::prelude::delete;

    struct AggregationJobContinueTestCase<
        const VERIFY_KEY_LENGTH: usize,
        V: Aggregator<VERIFY_KEY_LENGTH, 16>,
    > {
        task: Task,
        datastore: Arc<Datastore<MockClock>>,
        prepare_init_generator: PrepareInitGenerator<VERIFY_KEY_LENGTH, V>,
        aggregation_job_id: AggregationJobId,
        aggregation_parameter: V::AggregationParam,
        first_continue_request: AggregationJobContinueReq,
        first_continue_response: Option<AggregationJobResp>,
        handler: Box<dyn Handler>,
        _ephemeral_datastore: EphemeralDatastore,
    }

    /// Set up a helper with an aggregation job in step 0
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_test(
    ) -> AggregationJobContinueTestCase<VERIFY_KEY_LENGTH, Poplar1<XofTurboShake128, 16>> {
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
        let keypair = datastore.put_global_hpke_key().await.unwrap();

        let aggregation_parameter = Poplar1AggregationParam::try_from_prefixes(Vec::from([
            IdpfInput::from_bools(&[false]),
        ]))
        .unwrap();
        let prepare_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            keypair.config().clone(),
            Poplar1::new_turboshake128(1),
            aggregation_parameter.clone(),
        );

        let (prepare_init, transcript) =
            prepare_init_generator.next(&IdpfInput::from_bools(&[true]));

        datastore
            .run_unnamed_tx(|tx| {
                let (task, aggregation_param, prepare_init, transcript) = (
                    helper_task.clone(),
                    aggregation_parameter.clone(),
                    prepare_init.clone(),
                    transcript.clone(),
                );

                Box::pin(async move {
                    tx.put_aggregator_task(&task).await.unwrap();
                    tx.put_scrubbed_report(task.id(), prepare_init.report_share())
                        .await
                        .unwrap();

                    tx.put_aggregation_job(&AggregationJob::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        Poplar1<XofTurboShake128, 16>,
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

                    tx.put_report_aggregation::<VERIFY_KEY_LENGTH, Poplar1<XofTurboShake128, 16>>(
                        &ReportAggregation::new(
                            *task.id(),
                            aggregation_job_id,
                            *prepare_init.report_share().metadata().id(),
                            *prepare_init.report_share().metadata().time(),
                            0,
                            None,
                            ReportAggregationState::WaitingHelper {
                                prepare_state: transcript.helper_prepare_transitions[0]
                                    .prepare_state()
                                    .clone(),
                            },
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
            TestRuntime::default(),
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
            aggregation_parameter,
            first_continue_request,
            first_continue_response: None,
            handler: Box::new(handler),
            _ephemeral_datastore: ephemeral_datastore,
        }
    }

    /// Set up a helper with an aggregation job in step 1.
    #[allow(clippy::unit_arg)]
    async fn setup_aggregation_job_continue_step_recovery_test(
    ) -> AggregationJobContinueTestCase<VERIFY_KEY_LENGTH, Poplar1<XofTurboShake128, 16>> {
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
    async fn leader_rejects_aggregation_job_post() {
        let HttpHandlerTest {
            ephemeral_datastore: _ephemeral_datastore,
            datastore,
            handler,
            ..
        } = HttpHandlerTest::new().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build();
        datastore
            .put_aggregator_task(&task.leader_view().unwrap())
            .await
            .unwrap();

        let request = AggregationJobContinueReq::new(AggregationJobStep::from(1), Vec::new());
        let aggregation_job_id = random();

        post_aggregation_job_expecting_error(
            &task,
            &aggregation_job_id,
            &request,
            &handler,
            Status::BadRequest,
            "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            "An endpoint received a message with an unknown task ID.",
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn leader_rejects_aggregation_job_delete() {
        let HttpHandlerTest {
            ephemeral_datastore: _ephemeral_datastore,
            datastore,
            handler,
            ..
        } = HttpHandlerTest::new().await;

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build();
        datastore
            .put_aggregator_task(&task.leader_view().unwrap())
            .await
            .unwrap();

        let aggregation_job_id: AggregationJobId = random();

        let (header, value) = task.aggregator_auth_token().request_authentication();
        let mut test_conn = delete(
            task.aggregation_job_uri(&aggregation_job_id)
                .unwrap()
                .path(),
        )
        .with_request_header(header, value)
        .run_async(&handler)
        .await;

        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
                "title": "An endpoint received a message with an unknown task ID.",
                "taskid": format!("{}", task.id()),
            })
        );
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
            None,
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
                    tx.put_scrubbed_report(&task_id, unrelated_prepare_init.report_share())
                        .await
                        .unwrap();

                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofTurboShake128, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<VERIFY_KEY_LENGTH, Poplar1<XofTurboShake128, 16>>(
                            &Poplar1::new_turboshake128(1),
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
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofTurboShake128, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<VERIFY_KEY_LENGTH, Poplar1<XofTurboShake128, 16>>(
                            &Poplar1::new_turboshake128(1),
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
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofTurboShake128, 16>>(
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
            None,
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
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn aggregation_job_deletion() {
        let test_case = setup_aggregation_job_continue_test().await;

        // Delete the aggregation job. This should be idempotent.
        let (header, value) = test_case
            .task
            .aggregator_auth_token()
            .request_authentication();
        for _ in 0..2 {
            let test_conn = delete(
                test_case
                    .task
                    .aggregation_job_uri(&test_case.aggregation_job_id)
                    .unwrap()
                    .path(),
            )
            .with_request_header(header, value.clone())
            .run_async(&test_case.handler)
            .await;

            assert_eq!(test_conn.status(), Some(Status::NoContent),);
        }

        test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let (task_id, aggregation_job_id) =
                    (*test_case.task.id(), test_case.aggregation_job_id);
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<VERIFY_KEY_LENGTH, TimeInterval, Poplar1<XofTurboShake128, 16>>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap()
                        .unwrap();

                    assert_eq!(*aggregation_job.state(), AggregationJobState::Deleted);

                    Ok(())
                })
            })
            .await
            .unwrap();

        // Subsequent attempts to initialize the job should fail.
        let (prep_init, _) = test_case
            .prepare_init_generator
            .next(&IdpfInput::from_bools(&[true]));
        let init_req = AggregationJobInitializeReq::new(
            test_case.aggregation_parameter.get_encoded().unwrap(),
            PartialBatchSelector::new_time_interval(),
            Vec::from([prep_init]),
        );
        let mut test_conn = put_aggregation_job(
            &test_case.task,
            &test_case.aggregation_job_id,
            &init_req,
            &test_case.handler,
        )
        .await;

        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::Gone as u16,
                "type": "https://docs.divviup.org/references/janus-errors#aggregation-job-deleted",
                "title": "The aggregation job has been deleted.",
                "taskid": format!("{}", test_case.task.id()),
                "aggregation_job_id": format!("{}", test_case.aggregation_job_id),
            })
        );

        // Subsequent attempts to continue the job should fail.
        post_aggregation_job_expecting_error(
            &test_case.task,
            &test_case.aggregation_job_id,
            &test_case.first_continue_request,
            &test_case.handler,
            Status::Gone,
            "https://docs.divviup.org/references/janus-errors#aggregation-job-deleted",
            "The aggregation job has been deleted.",
            Some(&test_case.aggregation_job_id),
        )
        .await;
    }
}
