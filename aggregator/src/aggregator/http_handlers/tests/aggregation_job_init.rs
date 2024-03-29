use crate::aggregator::{
    aggregate_init_tests::{put_aggregation_job, PrepareInitGenerator},
    empty_batch_aggregations,
    http_handlers::{
        aggregator_handler,
        test_util::{decode_response_body, setup_http_handler_test, take_problem_details},
    },
    test_util::{default_aggregator_config, BATCH_AGGREGATION_SHARD_COUNT},
    tests::{generate_helper_report_share, generate_helper_report_share_for_plaintext},
};
use assert_matches::assert_matches;
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::models::{
        AggregationJob, AggregationJobState, BatchAggregation, BatchAggregationState,
        ReportAggregation, ReportAggregationState,
    },
    task::{test_util::TaskBuilder, QueryType, VerifyKey},
    test_util::noop_meter,
};
use janus_core::{
    auth_tokens::AuthenticationToken,
    hpke::test_util::{
        generate_test_hpke_config_and_private_key,
        generate_test_hpke_config_and_private_key_with_id,
    },
    report_id::ReportIdChecksumExt,
    test_util::{run_vdaf, runtime::TestRuntime},
    time::{Clock, MockClock, TimeExt},
    vdaf::VdafInstance,
};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    AggregationJobId, AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep,
    Duration, Extension, ExtensionType, HpkeCiphertext, HpkeConfigId, InputShareAad, Interval,
    PartialBatchSelector, PrepareError, PrepareInit, PrepareStepResult, ReportIdChecksum,
    ReportMetadata, ReportShare, Time,
};
use prio::{codec::Encode, vdaf::dummy};
use rand::random;
use serde_json::json;
use trillium::{KnownHeaderName, Status};
use trillium_testing::{assert_headers, prelude::put, TestConn};

#[tokio::test]
async fn aggregate_leader() {
    let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build();
    datastore
        .put_aggregator_task(&task.leader_view().unwrap())
        .await
        .unwrap();

    let request = AggregationJobInitializeReq::new(
        Vec::new(),
        PartialBatchSelector::new_time_interval(),
        Vec::new(),
    );
    let aggregation_job_id: AggregationJobId = random();

    let mut test_conn = put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
    assert!(!test_conn.status().unwrap().is_success());

    let problem_details = take_problem_details(&mut test_conn).await;
    assert_eq!(
        problem_details,
        json!({
            "status": 400,
            "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            "title": "An endpoint received a message with an unknown task ID.",
            "taskid": format!("{}", task.id()),
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
        test_conn.status().unwrap() as u16 as u64
    );

    // Check that CORS headers don't bleed over to other routes.
    assert_headers!(
        &test_conn,
        "access-control-allow-origin" => None,
        "access-control-allow-methods" => None,
        "access-control-max-age" => None,
    );

    let test_conn = TestConn::build(
        trillium::Method::Options,
        task.aggregation_job_uri(&aggregation_job_id)
            .unwrap()
            .path(),
        (),
    )
    .with_request_header(KnownHeaderName::Origin, "https://example.com/")
    .with_request_header(KnownHeaderName::AccessControlRequestMethod, "PUT")
    .run_async(&handler)
    .await;
    assert_headers!(&test_conn, "access-control-allow-methods" => None);
}

#[tokio::test]
async fn aggregate_wrong_agg_auth_token() {
    let (_, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let dap_auth_token = AuthenticationToken::DapAuth(random());

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
        .with_aggregator_auth_token(dap_auth_token.clone())
        .build();

    datastore
        .put_aggregator_task(&task.helper_view().unwrap())
        .await
        .unwrap();

    let request = AggregationJobInitializeReq::new(
        Vec::new(),
        PartialBatchSelector::new_time_interval(),
        Vec::new(),
    );
    let aggregation_job_id: AggregationJobId = random();

    let wrong_token_value = random();

    // Send the right token, but the wrong format: convert the DAP auth token to an equivalent
    // Bearer token, which should be rejected.
    let wrong_token_format =
        AuthenticationToken::new_bearer_token_from_bytes(dap_auth_token.as_ref()).unwrap();

    for auth_token in [Some(wrong_token_value), Some(wrong_token_format), None] {
        let mut test_conn = put(task
            .aggregation_job_uri(&aggregation_job_id)
            .unwrap()
            .path())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(request.get_encoded().unwrap());

        if let Some(auth_token) = auth_token {
            let (auth_header, auth_value) = auth_token.request_authentication();
            test_conn = test_conn.with_request_header(auth_header, auth_value);
        }

        let mut test_conn = test_conn.run_async(&handler).await;

        let want_status = 400;
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": want_status,
                "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
                "title": "The request's authorization is not valid.",
                "taskid": format!("{}", task.id()),
            })
        );
        assert_eq!(want_status, test_conn.status().unwrap() as u16);
    }
}

#[tokio::test]
// Silence the unit_arg lint so that we can work with dummy::Vdaf::{InputShare,
// Measurement} values (whose type is ()).
#[allow(clippy::unit_arg, clippy::let_unit_value)]
async fn aggregate_init() {
    let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake { rounds: 1 }).build();

    let helper_task = task.helper_view().unwrap();

    let vdaf = dummy::Vdaf::new(1);
    let verify_key: VerifyKey<0> = task.vdaf_verify_key().unwrap();
    let hpke_key = helper_task.current_hpke_key();
    let measurement = 0;
    let prep_init_generator = PrepareInitGenerator::new(
        clock.clone(),
        helper_task.clone(),
        vdaf.clone(),
        dummy::AggregationParam(0),
    );

    // prepare_init_0 is a "happy path" report.
    let (prepare_init_0, transcript_0) = prep_init_generator.next(&measurement);

    // report_share_1 fails decryption.
    let (prepare_init_1, transcript_1) = prep_init_generator.next(&measurement);

    let encrypted_input_share = prepare_init_1.report_share().encrypted_input_share();
    let mut corrupted_payload = encrypted_input_share.payload().to_vec();
    corrupted_payload[0] ^= 0xFF;
    let corrupted_input_share = HpkeCiphertext::new(
        *encrypted_input_share.config_id(),
        encrypted_input_share.encapsulated_key().to_vec(),
        corrupted_payload,
    );

    let prepare_init_1 = PrepareInit::new(
        ReportShare::new(
            prepare_init_1.report_share().metadata().clone(),
            transcript_1.public_share.get_encoded().unwrap(),
            corrupted_input_share,
        ),
        prepare_init_1.message().clone(),
    );

    // prepare_init_2 fails decoding due to an issue with the input share.
    let (prepare_init_2, transcript_2) = prep_init_generator.next(&measurement);

    let mut input_share_bytes = transcript_2.helper_input_share.get_encoded().unwrap();
    input_share_bytes.push(0); // can no longer be decoded.
    let report_share_2 = generate_helper_report_share_for_plaintext(
        prepare_init_2.report_share().metadata().clone(),
        hpke_key.config(),
        transcript_2.public_share.get_encoded().unwrap(),
        &input_share_bytes,
        &InputShareAad::new(
            *task.id(),
            prepare_init_2.report_share().metadata().clone(),
            transcript_2.public_share.get_encoded().unwrap(),
        )
        .get_encoded()
        .unwrap(),
    );

    let prepare_init_2 = PrepareInit::new(report_share_2, prepare_init_2.message().clone());

    // prepare_init_3 has an unknown HPKE config ID.
    let (prepare_init_3, transcript_3) = prep_init_generator.next(&measurement);

    let wrong_hpke_config = loop {
        let hpke_config = generate_test_hpke_config_and_private_key().config().clone();
        if helper_task.hpke_keys().contains_key(hpke_config.id()) {
            continue;
        }
        break hpke_config;
    };

    let report_share_3 = generate_helper_report_share::<dummy::Vdaf>(
        *task.id(),
        prepare_init_3.report_share().metadata().clone(),
        &wrong_hpke_config,
        &transcript_3.public_share,
        Vec::new(),
        &transcript_3.helper_input_share,
    );

    let prepare_init_3 = PrepareInit::new(report_share_3, prepare_init_3.message().clone());

    // prepare_init_4 has already been aggregated in another aggregation job, with the same
    // aggregation parameter.
    let (prepare_init_4, _) = prep_init_generator.next(&measurement);

    // prepare_init_5 falls into a batch that has already been collected.
    let past_clock = MockClock::new(Time::from_seconds_since_epoch(
        task.time_precision().as_seconds() / 2,
    ));
    let report_metadata_5 = ReportMetadata::new(
        random(),
        past_clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap(),
    );
    let transcript_5 = run_vdaf(
        &vdaf,
        verify_key.as_bytes(),
        &dummy::AggregationParam(0),
        report_metadata_5.id(),
        &measurement,
    );
    let report_share_5 = generate_helper_report_share::<dummy::Vdaf>(
        *task.id(),
        report_metadata_5,
        hpke_key.config(),
        &transcript_5.public_share,
        Vec::new(),
        &transcript_5.helper_input_share,
    );

    let prepare_init_5 = PrepareInit::new(
        report_share_5,
        transcript_5.leader_prepare_transitions[0].message.clone(),
    );

    // prepare_init_6 fails decoding due to an issue with the public share.
    let public_share_6 = Vec::from([0]);
    let report_metadata_6 = ReportMetadata::new(
        random(),
        clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap(),
    );
    let transcript_6 = run_vdaf(
        &vdaf,
        verify_key.as_bytes(),
        &dummy::AggregationParam(0),
        report_metadata_6.id(),
        &measurement,
    );
    let report_share_6 = generate_helper_report_share_for_plaintext(
        report_metadata_6.clone(),
        hpke_key.config(),
        public_share_6.clone(),
        &transcript_6.helper_input_share.get_encoded().unwrap(),
        &InputShareAad::new(*task.id(), report_metadata_6, public_share_6)
            .get_encoded()
            .unwrap(),
    );

    let prepare_init_6 = PrepareInit::new(
        report_share_6,
        transcript_6.leader_prepare_transitions[0].message.clone(),
    );

    // prepare_init_7 fails due to having repeated extensions.
    let report_metadata_7 = ReportMetadata::new(
        random(),
        clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap(),
    );
    let transcript_7 = run_vdaf(
        &vdaf,
        verify_key.as_bytes(),
        &dummy::AggregationParam(0),
        report_metadata_7.id(),
        &measurement,
    );
    let report_share_7 = generate_helper_report_share::<dummy::Vdaf>(
        *task.id(),
        report_metadata_7,
        hpke_key.config(),
        &transcript_7.public_share,
        Vec::from([
            Extension::new(ExtensionType::Tbd, Vec::new()),
            Extension::new(ExtensionType::Tbd, Vec::new()),
        ]),
        &transcript_7.helper_input_share,
    );

    let prepare_init_7 = PrepareInit::new(
        report_share_7,
        transcript_7.leader_prepare_transitions[0].message.clone(),
    );

    // prepare_init_8 has already been aggregated in another aggregation job, with a different
    // aggregation parameter.
    let (prepare_init_8, transcript_8) = prep_init_generator.next(&measurement);

    let mut batch_aggregations_results = vec![];
    let mut aggregation_jobs_results = vec![];
    let (conflicting_aggregation_job, non_conflicting_aggregation_job) = datastore
        .run_unnamed_tx(|tx| {
            let task = helper_task.clone();
            let report_share_4 = prepare_init_4.report_share().clone();
            let report_share_8 = prepare_init_8.report_share().clone();

            Box::pin(async move {
                tx.put_aggregator_task(&task).await.unwrap();

                // report_share_4 and report_share_8 are already in the datastore as they were
                // referenced by existing aggregation jobs.
                tx.put_scrubbed_report(task.id(), &report_share_4)
                    .await
                    .unwrap();
                tx.put_scrubbed_report(task.id(), &report_share_8)
                    .await
                    .unwrap();

                // Put in an aggregation job and report aggregation for report_share_4. It uses
                // the same aggregation parameter as the aggregation job this test will later
                // add and so should cause report_share_4 to fail to prepare.
                let conflicting_aggregation_job = AggregationJob::new(
                    *task.id(),
                    random(),
                    dummy::AggregationParam(0),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobStep::from(0),
                );
                tx.put_aggregation_job::<0, TimeInterval, dummy::Vdaf>(
                    &conflicting_aggregation_job,
                )
                .await
                .unwrap();
                tx.put_report_aggregation::<0, dummy::Vdaf>(&ReportAggregation::new(
                    *task.id(),
                    *conflicting_aggregation_job.id(),
                    *report_share_4.metadata().id(),
                    *report_share_4.metadata().time(),
                    0,
                    None,
                    ReportAggregationState::Finished,
                ))
                .await
                .unwrap();

                // Put in an aggregation job and report aggregation for report_share_8, using a
                // a different aggregation parameter. As the aggregation parameter differs,
                // report_share_8 should prepare successfully in the aggregation job we'll PUT
                // later.
                let non_conflicting_aggregation_job = AggregationJob::new(
                    *task.id(),
                    random(),
                    dummy::AggregationParam(1),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobStep::from(0),
                );
                tx.put_aggregation_job::<0, TimeInterval, dummy::Vdaf>(
                    &non_conflicting_aggregation_job,
                )
                .await
                .unwrap();
                tx.put_report_aggregation::<0, dummy::Vdaf>(&ReportAggregation::new(
                    *task.id(),
                    *non_conflicting_aggregation_job.id(),
                    *report_share_8.metadata().id(),
                    *report_share_8.metadata().time(),
                    0,
                    None,
                    ReportAggregationState::Finished,
                ))
                .await
                .unwrap();

                // Write collected batch aggregations for the interval that report_share_5 falls
                // into, which will cause it to fail to prepare.
                try_join_all(
                    empty_batch_aggregations::<0, TimeInterval, dummy::Vdaf>(
                        &task,
                        BATCH_AGGREGATION_SHARD_COUNT,
                        &Interval::new(Time::from_seconds_since_epoch(0), *task.time_precision())
                            .unwrap(),
                        &dummy::AggregationParam(0),
                        &[],
                    )
                    .iter()
                    .map(|ba| tx.put_batch_aggregation(ba)),
                )
                .await
                .unwrap();

                Ok((conflicting_aggregation_job, non_conflicting_aggregation_job))
            })
        })
        .await
        .unwrap();

    let aggregation_param = dummy::AggregationParam(0);
    let request = AggregationJobInitializeReq::new(
        aggregation_param.get_encoded().unwrap(),
        PartialBatchSelector::new_time_interval(),
        Vec::from([
            prepare_init_0.clone(),
            prepare_init_1.clone(),
            prepare_init_2.clone(),
            prepare_init_3.clone(),
            prepare_init_4.clone(),
            prepare_init_5.clone(),
            prepare_init_6.clone(),
            prepare_init_7.clone(),
            prepare_init_8.clone(),
        ]),
    );

    // Send request, parse response. Do this twice to prove that the request is idempotent.
    let aggregation_job_id: AggregationJobId = random();
    for _ in 0..2 {
        let mut test_conn =
            put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_headers!(
            &test_conn,
            "content-type" => (AggregationJobResp::MEDIA_TYPE)
        );
        let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

        // Validate response.
        assert_eq!(aggregate_resp.prepare_resps().len(), 9);

        let prepare_step_0 = aggregate_resp.prepare_resps().first().unwrap();
        assert_eq!(
            prepare_step_0.report_id(),
            prepare_init_0.report_share().metadata().id()
        );
        assert_matches!(prepare_step_0.result(), PrepareStepResult::Continue { message } => {
            assert_eq!(message, &transcript_0.helper_prepare_transitions[0].message);
        });

        let prepare_step_1 = aggregate_resp.prepare_resps().get(1).unwrap();
        assert_eq!(
            prepare_step_1.report_id(),
            prepare_init_1.report_share().metadata().id()
        );
        assert_matches!(
            prepare_step_1.result(),
            &PrepareStepResult::Reject(PrepareError::HpkeDecryptError)
        );

        let prepare_step_2 = aggregate_resp.prepare_resps().get(2).unwrap();
        assert_eq!(
            prepare_step_2.report_id(),
            prepare_init_2.report_share().metadata().id()
        );
        assert_matches!(
            prepare_step_2.result(),
            &PrepareStepResult::Reject(PrepareError::InvalidMessage)
        );

        let prepare_step_3 = aggregate_resp.prepare_resps().get(3).unwrap();
        assert_eq!(
            prepare_step_3.report_id(),
            prepare_init_3.report_share().metadata().id()
        );
        assert_matches!(
            prepare_step_3.result(),
            &PrepareStepResult::Reject(PrepareError::HpkeUnknownConfigId)
        );

        let prepare_step_4 = aggregate_resp.prepare_resps().get(4).unwrap();
        assert_eq!(
            prepare_step_4.report_id(),
            prepare_init_4.report_share().metadata().id()
        );
        assert_eq!(
            prepare_step_4.result(),
            &PrepareStepResult::Reject(PrepareError::ReportReplayed)
        );

        let prepare_step_5 = aggregate_resp.prepare_resps().get(5).unwrap();
        assert_eq!(
            prepare_step_5.report_id(),
            prepare_init_5.report_share().metadata().id()
        );
        assert_eq!(
            prepare_step_5.result(),
            &PrepareStepResult::Reject(PrepareError::BatchCollected)
        );

        let prepare_step_6 = aggregate_resp.prepare_resps().get(6).unwrap();
        assert_eq!(
            prepare_step_6.report_id(),
            prepare_init_6.report_share().metadata().id()
        );
        assert_eq!(
            prepare_step_6.result(),
            &PrepareStepResult::Reject(PrepareError::InvalidMessage),
        );

        let prepare_step_7 = aggregate_resp.prepare_resps().get(7).unwrap();
        assert_eq!(
            prepare_step_7.report_id(),
            prepare_init_7.report_share().metadata().id()
        );
        assert_eq!(
            prepare_step_7.result(),
            &PrepareStepResult::Reject(PrepareError::InvalidMessage),
        );

        let prepare_step_8 = aggregate_resp.prepare_resps().get(8).unwrap();
        assert_eq!(
            prepare_step_8.report_id(),
            prepare_init_8.report_share().metadata().id()
        );
        assert_matches!(prepare_step_8.result(), PrepareStepResult::Continue { message } => {
            assert_eq!(message, &transcript_8.helper_prepare_transitions[0].message);
        });

        // Check aggregation job in datastore.
        let (aggregation_jobs, batch_aggregations) = datastore
            .run_unnamed_tx(|tx| {
                let task = task.clone();
                let vdaf = vdaf.clone();
                Box::pin(async move {
                    Ok((
                        tx.get_aggregation_jobs_for_task::<0, TimeInterval, dummy::Vdaf>(task.id())
                            .await
                            .unwrap(),
                        tx.get_batch_aggregations_for_task::<0, TimeInterval, _>(&vdaf, task.id())
                            .await
                            .unwrap(),
                    ))
                })
            })
            .await
            .unwrap();

        assert_eq!(aggregation_jobs.len(), 3);

        let mut saw_conflicting_aggregation_job = false;
        let mut saw_non_conflicting_aggregation_job = false;
        let mut saw_new_aggregation_job = false;

        for aggregation_job in &aggregation_jobs {
            if aggregation_job.eq(&conflicting_aggregation_job) {
                saw_conflicting_aggregation_job = true;
            } else if aggregation_job.eq(&non_conflicting_aggregation_job) {
                saw_non_conflicting_aggregation_job = true;
            } else if aggregation_job.task_id().eq(task.id())
                && aggregation_job.id().eq(&aggregation_job_id)
                && aggregation_job.partial_batch_identifier().eq(&())
                && aggregation_job.state().eq(&AggregationJobState::Finished)
            {
                saw_new_aggregation_job = true;
            }
        }

        assert!(saw_conflicting_aggregation_job);
        assert!(saw_non_conflicting_aggregation_job);
        assert!(saw_new_aggregation_job);

        aggregation_jobs_results.push(aggregation_jobs);
        batch_aggregations_results.push(batch_aggregations);
    }

    assert!(aggregation_jobs_results.windows(2).all(|v| v[0] == v[1]));
    assert!(batch_aggregations_results.windows(2).all(|v| v[0] == v[1]));
}

#[tokio::test]
async fn aggregate_init_batch_already_collected() {
    let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let task = TaskBuilder::new(
        QueryType::FixedSize {
            max_batch_size: Some(100),
            batch_time_window_size: None,
        },
        VdafInstance::Fake { rounds: 1 },
    )
    .build();

    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    let vdaf = dummy::Vdaf::new(1);
    let prep_init_generator = PrepareInitGenerator::new(
        clock.clone(),
        helper_task.clone(),
        vdaf.clone(),
        dummy::AggregationParam(0),
    );

    let (prepare_init, _) = prep_init_generator.next(&0);

    let aggregation_param = dummy::AggregationParam(0);
    let batch_id = random();
    let request = AggregationJobInitializeReq::new(
        aggregation_param.get_encoded().unwrap(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([prepare_init.clone()]),
    );

    // Pretend that we're another concurrently running process: insert some aggregations to the
    // same batch ID and mark them collected.
    datastore
        .run_unnamed_tx(|tx| {
            let task = task.clone();
            let timestamp = *prepare_init.report_share().metadata().time();
            Box::pin(async move {
                let interval = Interval::new(timestamp, Duration::from_seconds(1)).unwrap();

                // Insert for all possible shards, since we non-deterministically assign shards
                // to batches on insertion.
                for shard in 0..BATCH_AGGREGATION_SHARD_COUNT {
                    let batch_aggregation = BatchAggregation::<0, FixedSize, dummy::Vdaf>::new(
                        *task.id(),
                        batch_id,
                        dummy::AggregationParam(0),
                        shard,
                        interval,
                        BatchAggregationState::Collected {
                            aggregate_share: Some(dummy::OutputShare(0).into()),
                            report_count: 1,
                            checksum: ReportIdChecksum::for_report_id(&random()),
                            aggregation_jobs_created: 1,
                            aggregation_jobs_terminated: 1,
                        },
                    );
                    tx.put_batch_aggregation(&batch_aggregation).await.unwrap();
                }

                Ok(())
            })
        })
        .await
        .unwrap();

    let aggregation_job_id: AggregationJobId = random();
    let (header, value) = task.aggregator_auth_token().request_authentication();
    let mut test_conn = put(task
        .aggregation_job_uri(&aggregation_job_id)
        .unwrap()
        .path())
    .with_request_header(header, value)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
    )
    .with_request_body(request.get_encoded().unwrap())
    .run_async(&handler)
    .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

    let prepare_step = aggregate_resp.prepare_resps().first().unwrap();
    assert_eq!(
        prepare_step.report_id(),
        prepare_init.report_share().metadata().id()
    );
    assert_eq!(
        prepare_step.result(),
        &PrepareStepResult::Reject(PrepareError::BatchCollected)
    );
}

#[tokio::test]
#[allow(clippy::unit_arg)]
async fn aggregate_init_with_reports_encrypted_by_global_key() {
    let (clock, _ephemeral_datastore, datastore, _) = setup_http_handler_test().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake { rounds: 1 }).build();

    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();
    let vdaf = dummy::Vdaf::new(1);
    let aggregation_param = dummy::AggregationParam(0);
    let prep_init_generator = PrepareInitGenerator::new(
        clock.clone(),
        helper_task.clone(),
        vdaf.clone(),
        aggregation_param,
    );

    // Insert some global HPKE keys.
    // Same ID as the task to test having both keys to choose from.
    let global_hpke_keypair_same_id = generate_test_hpke_config_and_private_key_with_id(
        (*helper_task.current_hpke_key().config().id()).into(),
    );
    // Different ID to test misses on the task key.
    let global_hpke_keypair_different_id = generate_test_hpke_config_and_private_key_with_id(
        (0..)
            .map(HpkeConfigId::from)
            .find(|id| !helper_task.hpke_keys().contains_key(id))
            .unwrap()
            .into(),
    );
    datastore
        .run_unnamed_tx(|tx| {
            let global_hpke_keypair_same_id = global_hpke_keypair_same_id.clone();
            let global_hpke_keypair_different_id = global_hpke_keypair_different_id.clone();
            Box::pin(async move {
                // Leave these in the PENDING state--they should still be decryptable.
                tx.put_global_hpke_keypair(&global_hpke_keypair_same_id)
                    .await
                    .unwrap();
                tx.put_global_hpke_keypair(&global_hpke_keypair_different_id)
                    .await
                    .unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

    // Create new handler _after_ the keys have been inserted so that they come pre-cached.
    let handler = aggregator_handler(
        datastore.clone(),
        clock.clone(),
        TestRuntime::default(),
        &noop_meter(),
        default_aggregator_config(),
    )
    .await
    .unwrap();

    let verify_key: VerifyKey<0> = task.vdaf_verify_key().unwrap();

    // This report was encrypted with a global HPKE config that has the same config
    // ID as the task's HPKE config.
    let (prepare_init_same_id, transcript_same_id) = prep_init_generator.next(&0);

    // This report was encrypted with a global HPKE config that has the same config
    // ID as the task's HPKE config, but will fail to decrypt.
    let (prepare_init_same_id_corrupted, transcript_same_id_corrupted) =
        prep_init_generator.next(&0);

    let encrypted_input_share = prepare_init_same_id_corrupted
        .report_share()
        .encrypted_input_share();
    let mut corrupted_payload = encrypted_input_share.payload().to_vec();
    corrupted_payload[0] ^= 0xFF;
    let corrupted_input_share = HpkeCiphertext::new(
        *encrypted_input_share.config_id(),
        encrypted_input_share.encapsulated_key().to_vec(),
        corrupted_payload,
    );

    let prepare_init_same_id_corrupted = PrepareInit::new(
        ReportShare::new(
            prepare_init_same_id_corrupted
                .report_share()
                .metadata()
                .clone(),
            transcript_same_id_corrupted
                .public_share
                .get_encoded()
                .unwrap(),
            corrupted_input_share,
        ),
        prepare_init_same_id_corrupted.message().clone(),
    );

    // This report was encrypted with a global HPKE config that doesn't collide
    // with the task HPKE config's ID.
    let report_metadata_different_id = ReportMetadata::new(
        random(),
        clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap(),
    );
    let transcript_different_id = run_vdaf(
        &vdaf,
        verify_key.as_bytes(),
        &dummy::AggregationParam(0),
        report_metadata_different_id.id(),
        &0,
    );
    let report_share_different_id = generate_helper_report_share::<dummy::Vdaf>(
        *task.id(),
        report_metadata_different_id,
        global_hpke_keypair_different_id.config(),
        &transcript_different_id.public_share,
        Vec::new(),
        &transcript_different_id.helper_input_share,
    );

    let prepare_init_different_id = PrepareInit::new(
        report_share_different_id,
        transcript_different_id.leader_prepare_transitions[0]
            .message
            .clone(),
    );

    // This report was encrypted with a global HPKE config that doesn't collide
    // with the task HPKE config's ID, but will fail decryption.
    let report_metadata_different_id_corrupted = ReportMetadata::new(
        random(),
        clock
            .now()
            .to_batch_interval_start(task.time_precision())
            .unwrap(),
    );
    let transcript_different_id_corrupted = run_vdaf(
        &vdaf,
        verify_key.as_bytes(),
        &dummy::AggregationParam(0),
        report_metadata_different_id_corrupted.id(),
        &0,
    );
    let report_share_different_id_corrupted = generate_helper_report_share::<dummy::Vdaf>(
        *task.id(),
        report_metadata_different_id_corrupted.clone(),
        global_hpke_keypair_different_id.config(),
        &transcript_different_id_corrupted.public_share,
        Vec::new(),
        &transcript_different_id_corrupted.helper_input_share,
    );
    let encrypted_input_share = report_share_different_id_corrupted.encrypted_input_share();
    let mut corrupted_payload = encrypted_input_share.payload().to_vec();
    corrupted_payload[0] ^= 0xFF;
    let corrupted_input_share = HpkeCiphertext::new(
        *encrypted_input_share.config_id(),
        encrypted_input_share.encapsulated_key().to_vec(),
        corrupted_payload,
    );
    let encoded_public_share = transcript_different_id_corrupted
        .public_share
        .get_encoded()
        .unwrap();

    let prepare_init_different_id_corrupted = PrepareInit::new(
        ReportShare::new(
            report_metadata_different_id_corrupted,
            encoded_public_share.clone(),
            corrupted_input_share,
        ),
        transcript_different_id_corrupted.leader_prepare_transitions[0]
            .message
            .clone(),
    );

    let aggregation_job_id: AggregationJobId = random();
    let request = AggregationJobInitializeReq::new(
        dummy::AggregationParam(0).get_encoded().unwrap(),
        PartialBatchSelector::new_time_interval(),
        Vec::from([
            prepare_init_same_id.clone(),
            prepare_init_different_id.clone(),
            prepare_init_same_id_corrupted.clone(),
            prepare_init_different_id_corrupted.clone(),
        ]),
    );

    let mut test_conn = put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

    // Validate response.
    assert_eq!(aggregate_resp.prepare_resps().len(), 4);

    let prepare_step_same_id = aggregate_resp.prepare_resps().first().unwrap();
    assert_eq!(
        prepare_step_same_id.report_id(),
        prepare_init_same_id.report_share().metadata().id()
    );
    assert_matches!(prepare_step_same_id.result(), PrepareStepResult::Continue { message } => {
        assert_eq!(message, &transcript_same_id.helper_prepare_transitions[0].message);
    });

    let prepare_step_different_id = aggregate_resp.prepare_resps().get(1).unwrap();
    assert_eq!(
        prepare_step_different_id.report_id(),
        prepare_init_different_id.report_share().metadata().id()
    );
    assert_matches!(
        prepare_step_different_id.result(),
        PrepareStepResult::Continue { message } => {
            assert_eq!(message, &transcript_different_id.helper_prepare_transitions[0].message);
        }
    );

    let prepare_step_same_id_corrupted = aggregate_resp.prepare_resps().get(2).unwrap();
    assert_eq!(
        prepare_step_same_id_corrupted.report_id(),
        prepare_init_same_id_corrupted
            .report_share()
            .metadata()
            .id(),
    );
    assert_matches!(
        prepare_step_same_id_corrupted.result(),
        &PrepareStepResult::Reject(PrepareError::HpkeDecryptError)
    );

    let prepare_step_different_id_corrupted = aggregate_resp.prepare_resps().get(3).unwrap();
    assert_eq!(
        prepare_step_different_id_corrupted.report_id(),
        prepare_init_different_id_corrupted
            .report_share()
            .metadata()
            .id()
    );
    assert_matches!(
        prepare_step_different_id_corrupted.result(),
        &PrepareStepResult::Reject(PrepareError::HpkeDecryptError)
    );
}

#[tokio::test]
async fn aggregate_init_prep_init_failed() {
    let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::FakeFailsPrepInit).build();
    let helper_task = task.helper_view().unwrap();
    let prep_init_generator = PrepareInitGenerator::new(
        clock.clone(),
        helper_task.clone(),
        dummy::Vdaf::new(1),
        dummy::AggregationParam(0),
    );

    datastore.put_aggregator_task(&helper_task).await.unwrap();

    let (prepare_init, _) = prep_init_generator.next(&0);
    let request = AggregationJobInitializeReq::new(
        dummy::AggregationParam(0).get_encoded().unwrap(),
        PartialBatchSelector::new_time_interval(),
        Vec::from([prepare_init.clone()]),
    );

    // Send request, and parse response.
    let aggregation_job_id: AggregationJobId = random();
    let mut test_conn = put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(
        &test_conn,
        "content-type" => (AggregationJobResp::MEDIA_TYPE)
    );
    let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

    // Validate response.
    assert_eq!(aggregate_resp.prepare_resps().len(), 1);

    let prepare_step = aggregate_resp.prepare_resps().first().unwrap();
    assert_eq!(
        prepare_step.report_id(),
        prepare_init.report_share().metadata().id()
    );
    assert_matches!(
        prepare_step.result(),
        &PrepareStepResult::Reject(PrepareError::VdafPrepError)
    );
}

#[tokio::test]
async fn aggregate_init_prep_step_failed() {
    let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::FakeFailsPrepStep).build();
    let helper_task = task.helper_view().unwrap();
    let prep_init_generator = PrepareInitGenerator::new(
        clock.clone(),
        helper_task.clone(),
        dummy::Vdaf::new(1),
        dummy::AggregationParam(0),
    );

    datastore.put_aggregator_task(&helper_task).await.unwrap();

    let (prepare_init, _) = prep_init_generator.next(&0);
    let request = AggregationJobInitializeReq::new(
        dummy::AggregationParam(0).get_encoded().unwrap(),
        PartialBatchSelector::new_time_interval(),
        Vec::from([prepare_init.clone()]),
    );

    let aggregation_job_id: AggregationJobId = random();
    let mut test_conn = put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(
        &test_conn,
        "content-type" => (AggregationJobResp::MEDIA_TYPE)
    );
    let aggregate_resp: AggregationJobResp = decode_response_body(&mut test_conn).await;

    // Validate response.
    assert_eq!(aggregate_resp.prepare_resps().len(), 1);

    let prepare_step = aggregate_resp.prepare_resps().first().unwrap();
    assert_eq!(
        prepare_step.report_id(),
        prepare_init.report_share().metadata().id()
    );
    assert_matches!(
        prepare_step.result(),
        &PrepareStepResult::Reject(PrepareError::VdafPrepError)
    );
}

#[tokio::test]
async fn aggregate_init_duplicated_report_id() {
    let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake { rounds: 1 }).build();

    let helper_task = task.helper_view().unwrap();
    let prep_init_generator = PrepareInitGenerator::new(
        clock.clone(),
        helper_task.clone(),
        dummy::Vdaf::new(1),
        dummy::AggregationParam(0),
    );

    datastore.put_aggregator_task(&helper_task).await.unwrap();

    let (prepare_init, _) = prep_init_generator.next(&0);

    let request = AggregationJobInitializeReq::new(
        dummy::AggregationParam(0).get_encoded().unwrap(),
        PartialBatchSelector::new_time_interval(),
        Vec::from([prepare_init.clone(), prepare_init]),
    );
    let aggregation_job_id: AggregationJobId = random();

    let mut test_conn = put_aggregation_job(&task, &aggregation_job_id, &request, &handler).await;

    let want_status = 400;
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": want_status,
            "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
            "title": "The message type for a response was incorrect or the payload was malformed.",
            "taskid": format!("{}", task.id()),
        })
    );
    assert_eq!(want_status, test_conn.status().unwrap());
}
