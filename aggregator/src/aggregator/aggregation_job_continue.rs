//! Implements portions of aggregation job continuation for the Helper.

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

        assert_eq!(test_conn.status(), Some(Status::Accepted));
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
            test_util::{take_problem_details, HttpHandlerTest},
            AggregatorHandlerBuilder,
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
            AggregationMode, BatchMode,
        },
        test_util::noop_meter,
    };
    use janus_core::{
        test_util::{install_test_trace_subscriber, runtime::TestRuntime},
        time::{IntervalExt, MockClock},
        vdaf::VdafInstance,
    };
    use janus_messages::{
        batch_mode::TimeInterval, AggregationJobContinueReq, AggregationJobId,
        AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep, Interval,
        PartialBatchSelector, PrepareContinue, PrepareResp, PrepareStepResult, Role,
    };
    use prio::{
        codec::Encode as _,
        vdaf::{dummy, Aggregator},
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
    async fn setup_aggregation_job_continue_test() -> AggregationJobContinueTestCase<0, dummy::Vdaf>
    {
        // Prepare datastore & request.
        install_test_trace_subscriber();

        let aggregation_job_id = random();
        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Fake { rounds: 2 },
        )
        .build();
        let helper_task = task.helper_view().unwrap();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let meter = noop_meter();
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let keypair = datastore.put_hpke_key().await.unwrap();

        let aggregation_parameter = dummy::AggregationParam(7);
        let prepare_init_generator = PrepareInitGenerator::new(
            clock.clone(),
            helper_task.clone(),
            keypair.config().clone(),
            dummy::Vdaf::new(2),
            aggregation_parameter,
        );

        let (prepare_init, transcript) = prepare_init_generator.next(&13);

        datastore
            .run_unnamed_tx(|tx| {
                let helper_task = helper_task.clone();
                let prepare_init = prepare_init.clone();
                let transcript = transcript.clone();

                Box::pin(async move {
                    tx.put_aggregator_task(&helper_task).await.unwrap();
                    tx.put_scrubbed_report(
                        helper_task.id(),
                        prepare_init.report_share().metadata().id(),
                        prepare_init.report_share().metadata().time(),
                    )
                    .await
                    .unwrap();

                    tx.put_aggregation_job(&AggregationJob::<0, TimeInterval, dummy::Vdaf>::new(
                        *helper_task.id(),
                        aggregation_job_id,
                        aggregation_parameter,
                        (),
                        Interval::from_time(prepare_init.report_share().metadata().time()).unwrap(),
                        AggregationJobState::Active,
                        AggregationJobStep::from(0),
                    ))
                    .await
                    .unwrap();

                    tx.put_report_aggregation::<0, dummy::Vdaf>(&ReportAggregation::new(
                        *helper_task.id(),
                        aggregation_job_id,
                        *prepare_init.report_share().metadata().id(),
                        *prepare_init.report_share().metadata().time(),
                        0,
                        None,
                        ReportAggregationState::HelperContinue {
                            prepare_state: *transcript.helper_prepare_transitions[0]
                                .prepare_state(),
                        },
                    ))
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
        let handler = AggregatorHandlerBuilder::new(
            Arc::clone(&datastore),
            clock,
            TestRuntime::default(),
            &meter,
            default_aggregator_config(),
        )
        .await
        .unwrap()
        .build()
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
    ) -> AggregationJobContinueTestCase<0, dummy::Vdaf> {
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
            AggregationJobResp::Finished {
                prepare_resps: test_case
                    .first_continue_request
                    .prepare_continues()
                    .iter()
                    .map(|step| PrepareResp::new(*step.report_id(), PrepareStepResult::Finished))
                    .collect()
            }
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

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .build();
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

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .build();
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
            test_case
                .first_continue_request
                .prepare_continues()
                .to_vec(),
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

        let (unrelated_prepare_init, unrelated_transcript) =
            test_case.prepare_init_generator.next(&13);

        let (before_aggregation_job, before_report_aggregations) = test_case
            .datastore
            .run_unnamed_tx(|tx| {
                let task_id = *test_case.task.id();
                let unrelated_prepare_init = unrelated_prepare_init.clone();
                let aggregation_job_id = test_case.aggregation_job_id;

                Box::pin(async move {
                    tx.put_scrubbed_report(
                        &task_id,
                        unrelated_prepare_init.report_share().metadata().id(),
                        unrelated_prepare_init.report_share().metadata().time(),
                    )
                    .await
                    .unwrap();

                    let aggregation_job = tx
                        .get_aggregation_job::<0, TimeInterval, dummy::Vdaf>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<0, dummy::Vdaf>(
                            &dummy::Vdaf::new(2),
                            &Role::Helper,
                            &task_id,
                            &aggregation_job_id,
                            &test_case.aggregation_parameter,
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
                        .get_aggregation_job::<0, TimeInterval, dummy::Vdaf>(
                            &task_id,
                            &aggregation_job_id,
                        )
                        .await
                        .unwrap();

                    let report_aggregations = tx
                        .get_report_aggregations_for_aggregation_job::<0, dummy::Vdaf>(
                            &dummy::Vdaf::new(2),
                            &Role::Helper,
                            &task_id,
                            &aggregation_job_id,
                            &test_case.aggregation_parameter,
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
                    let aggregation_job = tx
                        .get_aggregation_job::<0, TimeInterval, dummy::Vdaf>(
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
            test_case
                .first_continue_request
                .prepare_continues()
                .to_vec(),
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
            test_case
                .first_continue_request
                .prepare_continues()
                .to_vec(),
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
                        .get_aggregation_job::<0, TimeInterval, dummy::Vdaf>(
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
        let (prep_init, _) = test_case.prepare_init_generator.next(&13);
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
