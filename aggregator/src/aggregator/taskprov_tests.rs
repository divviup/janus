use crate::aggregator::{
    http_handlers::{
        aggregator_handler,
        test_util::{take_problem_details, take_response_body},
    },
    tests::generate_helper_report_share,
    Config,
};
use assert_matches::assert_matches;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator_core::{
    datastore::{
        models::{
            AggregateShareJob, AggregationJob, AggregationJobState, Batch, BatchAggregation,
            BatchAggregationState, BatchState, ReportAggregation, ReportAggregationState,
        },
        test_util::{ephemeral_datastore, EphemeralDatastore},
        Datastore,
    },
    task::{QueryType, Task},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{
        self, aggregate_share_aad, test_util::generate_test_hpke_config_and_private_key,
        HpkeApplicationInfo, HpkeKeypair, Label,
    },
    report_id::ReportIdChecksumExt,
    task::{AuthenticationToken, PRIO3_VERIFY_KEY_LENGTH},
    taskprov::TASKPROV_HEADER,
    test_util::{install_test_trace_subscriber, run_vdaf, VdafTranscript},
    time::{Clock, DurationExt, MockClock, TimeExt},
};
use janus_messages::{
    codec::{Decode, Encode},
    query_type::FixedSize,
    taskprov::{
        DpConfig, DpMechanism, Query as TaskprovQuery, QueryConfig, TaskConfig, VdafConfig,
        VdafType,
    },
    AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq, AggregateInitializeResp,
    AggregateShareReq, AggregateShareResp, AggregationJobId, BatchSelector, Duration, Interval,
    PartialBatchSelector, PrepareStep, PrepareStepResult, ReportIdChecksum, ReportMetadata,
    ReportShare, Role, TaskId, Time,
};
use prio::{
    field::Field64,
    vdaf::{
        prio3::{Prio3, Prio3Aes128Count},
        AggregateShare, OutputShare,
    },
};
use rand::random;
use ring::digest::{digest, SHA256};
use serde_json::json;
use std::sync::Arc;
use trillium::{Handler, KnownHeaderName, Status};
use trillium_testing::{assert_headers, prelude::post};

type TestVdaf = Prio3Aes128Count;

pub struct TaskprovTestCase {
    _ephemeral_datastore: EphemeralDatastore,
    clock: MockClock,
    collector_hpke_keypair: HpkeKeypair,
    datastore: Arc<Datastore<MockClock>>,
    handler: Box<dyn Handler>,
    report_metadata: ReportMetadata,
    transcript: VdafTranscript<16, TestVdaf>,
    report_share: ReportShare,
    task: Task,
    task_config: TaskConfig,
    task_id: TaskId,
    aggregator_auth_token: AuthenticationToken,
}

async fn setup_taskprov_test() -> TaskprovTestCase {
    install_test_trace_subscriber();

    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    let global_hpke_key = generate_test_hpke_config_and_private_key();
    let collector_hpke_keypair = generate_test_hpke_config_and_private_key();
    let aggregator_auth_token: AuthenticationToken = random();

    datastore
        .run_tx(|tx| {
            let global_hpke_key = global_hpke_key.clone();
            Box::pin(async move {
                tx.put_global_hpke_keypair(&global_hpke_key).await.unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

    let tolerable_clock_skew = Duration::from_seconds(60);
    let config = Config {
        collector_hpke_config: collector_hpke_keypair.config().clone(),
        verify_key_init: random(),
        auth_tokens: vec![aggregator_auth_token.clone()],
        tolerable_clock_skew,
        ..Default::default()
    };

    let handler = aggregator_handler(
        Arc::clone(&datastore),
        clock.clone(),
        &noop_meter(),
        config.clone(),
    )
    .await
    .unwrap();

    let time_precision = Duration::from_seconds(1);
    let max_batch_query_count = 1;
    let min_batch_size = 1;
    let max_batch_size = 1;
    let task_expiration = clock.now().add(&Duration::from_hours(24).unwrap()).unwrap();
    let task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        Vec::from([
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
            "https://helper.example.com/".as_bytes().try_into().unwrap(),
        ]),
        QueryConfig::new(
            time_precision,
            max_batch_query_count,
            min_batch_size,
            TaskprovQuery::FixedSize { max_batch_size },
        ),
        task_expiration,
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();

    let mut task_config_encoded = vec![];
    task_config.encode(&mut task_config_encoded);

    // We use a real VDAF since taskprov doesn't have any allowance for a test VDAF.
    let vdaf = Prio3::new_aes128_count(2).unwrap();

    let task_id = TaskId::try_from(digest(&SHA256, &task_config_encoded).as_ref()).unwrap();
    let vdaf_instance = task_config.vdaf_config().vdaf_type().try_into().unwrap();
    let vdaf_verify_key = config
        .verify_key_init
        .derive_vdaf_verify_key(&task_id, &vdaf_instance);

    let task = janus_aggregator_core::taskprov::Task::new(
        task_id,
        Vec::from([
            url::Url::parse("https://leader.example.com/").unwrap(),
            url::Url::parse("https://helper.example.com/").unwrap(),
        ]),
        QueryType::FixedSize {
            max_batch_size: max_batch_size as u64,
            batch_time_window_size: None,
        },
        vdaf_instance,
        Role::Helper,
        Vec::from([vdaf_verify_key.clone()]),
        max_batch_query_count as u64,
        Some(task_expiration),
        config.report_expiry_age,
        min_batch_size as u64,
        Duration::from_seconds(1),
        tolerable_clock_skew,
    )
    .unwrap();

    let report_metadata = ReportMetadata::new(
        random(),
        clock
            .now()
            .to_batch_interval_start(task.task().time_precision())
            .unwrap(),
        Vec::new(),
    );
    let transcript = run_vdaf(
        &vdaf,
        vdaf_verify_key.as_ref().try_into().unwrap(),
        &(),
        report_metadata.id(),
        &1,
    );
    let report_share = generate_helper_report_share::<TestVdaf>(
        task_id,
        report_metadata.clone(),
        global_hpke_key.config(),
        &transcript.public_share,
        &transcript.input_shares[1],
    );

    TaskprovTestCase {
        _ephemeral_datastore: ephemeral_datastore,
        clock,
        collector_hpke_keypair,
        datastore,
        handler: Box::new(handler),
        task: task.into(),
        task_config,
        task_id,
        report_metadata,
        transcript,
        report_share,
        aggregator_auth_token,
    }
}

#[tokio::test]
async fn taskprov_aggregate_init() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    let aggregation_job_id: AggregationJobId = random();

    let request = AggregateInitializeReq::new(
        *test.task.id(),
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([test.report_share.clone()]),
    );

    let auth = test.aggregator_auth_token.request_authentication();

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, "Bearer invalid_token")
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(request.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
            "title": "The request's authorization is not valid.",
            "taskid": format!("{}", test.task_id),
        })
    );

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(request.get_encoded())
        .run_async(&test.handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(
        &test_conn,
        "content-type" => (AggregateInitializeResp::MEDIA_TYPE)
    );
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregateInitializeResp::get_decoded(&body_bytes).unwrap();

    assert_eq!(aggregate_resp.prepare_steps().len(), 1);
    let prepare_step = aggregate_resp.prepare_steps().get(0).unwrap();
    assert_eq!(prepare_step.report_id(), test.report_share.metadata().id());
    assert_matches!(prepare_step.result(), &PrepareStepResult::Continued(..));

    let (aggregation_jobs, got_task) = test
        .datastore
        .run_tx(|tx| {
            let task_id = test.task_id;
            Box::pin(async move {
                Ok((
                    tx.get_aggregation_jobs_for_task::<16, FixedSize, TestVdaf>(&task_id)
                        .await
                        .unwrap(),
                    tx.get_task(&task_id).await.unwrap(),
                ))
            })
        })
        .await
        .unwrap();

    assert_eq!(aggregation_jobs.len(), 1);
    assert!(
        aggregation_jobs[0].task_id().eq(&test.task_id)
            && aggregation_jobs[0].id().eq(&aggregation_job_id)
            && aggregation_jobs[0].partial_batch_identifier().eq(&batch_id)
            && aggregation_jobs[0]
                .state()
                .eq(&AggregationJobState::InProgress)
    );
    assert_eq!(test.task, got_task.unwrap());
}

#[tokio::test]
async fn taskprov_opt_out_task_expired() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    let aggregation_job_id: AggregationJobId = random();

    let request = AggregateInitializeReq::new(
        *test.task.id(),
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([test.report_share.clone()]),
    );

    let auth = test.aggregator_auth_token.request_authentication();

    // Advance clock past task expiry.
    test.clock.advance(&Duration::from_hours(48).unwrap());

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(request.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:invalidTask",
            "title": "Aggregator has opted out of the indicated task.",
            "taskid": format!("{}", test.task_id),
        })
    );
}

#[tokio::test]
async fn taskprov_opt_out_mismatched_task_id() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    let aggregation_job_id: AggregationJobId = random();

    let request = AggregateInitializeReq::new(
        *test.task.id(),
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([test.report_share.clone()]),
    );

    let task_expiration = test
        .clock
        .now()
        .add(&Duration::from_hours(24).unwrap())
        .unwrap();
    let another_task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        Vec::from([
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
            "https://helper.example.com/".as_bytes().try_into().unwrap(),
        ]),
        // Query configuration is different from the normal test case.
        QueryConfig::new(
            Duration::from_seconds(1),
            100,
            100,
            TaskprovQuery::FixedSize {
                max_batch_size: 100,
            },
        ),
        task_expiration,
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();

    let auth = test.aggregator_auth_token.request_authentication();

    let mut test_conn = post(
        test
            // Use the test case task's ID.
            .task
            .aggregation_job_uri()
            .unwrap()
            .path(),
    )
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
    )
    .with_request_header(
        TASKPROV_HEADER,
        // Use a different task than the URL's.
        URL_SAFE_NO_PAD.encode(another_task_config.get_encoded()),
    )
    .with_request_body(request.get_encoded())
    .run_async(&test.handler)
    .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
            "title": "The message type for a response was incorrect or the payload was malformed.",
            "taskid": format!("{}", test.task_id),
        })
    );
}

#[tokio::test]
async fn taskprov_opt_out_missing_aggregator() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    let aggregation_job_id: AggregationJobId = random();

    let task_expiration = test
        .clock
        .now()
        .add(&Duration::from_hours(24).unwrap())
        .unwrap();
    let another_task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        // Only one aggregator!
        Vec::from(["https://leader.example.com/".as_bytes().try_into().unwrap()]),
        QueryConfig::new(
            Duration::from_seconds(1),
            100,
            100,
            TaskprovQuery::FixedSize {
                max_batch_size: 100,
            },
        ),
        task_expiration,
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();
    let another_task_config_encoded = another_task_config.get_encoded();
    let another_task_id: TaskId = digest(&SHA256, &another_task_config_encoded)
        .as_ref()
        .try_into()
        .unwrap();

    let request = AggregateInitializeReq::new(
        another_task_id,
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([test.report_share.clone()]),
    );

    let auth = test.aggregator_auth_token.request_authentication();

    let mut test_conn = post(
        test
            // Use the test case task's ID.
            .task
            .aggregation_job_uri()
            .unwrap()
            .path(),
    )
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
    )
    .with_request_header(
        TASKPROV_HEADER,
        URL_SAFE_NO_PAD.encode(another_task_config_encoded),
    )
    .with_request_body(request.get_encoded())
    .run_async(&test.handler)
    .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
            "title": "The message type for a response was incorrect or the payload was malformed.",
            "taskid": format!("{}", another_task_id),
        })
    );
}

#[tokio::test]
async fn taskprov_aggregate_continue() {
    let test = setup_taskprov_test().await;

    let aggregation_job_id = random();
    let batch_id = random();

    let (prep_state, _) = test.transcript.helper_prep_state(0);
    let prep_msg = test.transcript.prepare_messages[0].clone();

    test.datastore
        .run_tx(|tx| {
            let task = test.task.clone();
            let report_share = test.report_share.clone();
            let prep_state = prep_state.clone();
            let report_metadata = test.report_metadata.clone();

            Box::pin(async move {
                // Aggregate continue is only possible if the task has already been inserted.
                tx.put_task(&task).await?;

                tx.put_report_share(task.id(), &report_share).await?;

                tx.put_aggregation_job(&AggregationJob::<
                    PRIO3_VERIFY_KEY_LENGTH,
                    FixedSize,
                    TestVdaf,
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

                tx.put_report_aggregation::<PRIO3_VERIFY_KEY_LENGTH, TestVdaf>(
                    &ReportAggregation::new(
                        *task.id(),
                        aggregation_job_id,
                        *report_metadata.id(),
                        *report_metadata.time(),
                        0,
                        ReportAggregationState::Waiting(prep_state, None),
                    ),
                )
                .await?;

                tx.put_aggregate_share_job::<PRIO3_VERIFY_KEY_LENGTH, FixedSize, TestVdaf>(
                    &AggregateShareJob::new(
                        *task.id(),
                        batch_id,
                        (),
                        AggregateShare::from(OutputShare::from(Vec::from([Field64::from(7)]))),
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await
            })
        })
        .await
        .unwrap();

    let request = AggregateContinueReq::new(
        *test.task.id(),
        aggregation_job_id,
        Vec::from([PrepareStep::new(
            *test.report_metadata.id(),
            PrepareStepResult::Continued(prep_msg.get_encoded()),
        )]),
    );

    let auth = test.aggregator_auth_token.request_authentication();

    // Attempt using the wrong credentials, should reject.
    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, "Bearer invalid_token")
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateContinueReq::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(request.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
            "title": "The request's authorization is not valid.",
            "taskid": format!("{}", test.task_id),
        })
    );

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateContinueReq::MEDIA_TYPE,
        )
        .with_request_body(request.get_encoded())
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .run_async(&test.handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_eq!(
        test_conn
            .response_headers()
            .get(KnownHeaderName::ContentType)
            .unwrap(),
        AggregateContinueResp::MEDIA_TYPE
    );
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregateContinueResp::get_decoded(&body_bytes).unwrap();

    // We'll only validate the response. Taskprov doesn't touch functionality beyond the authorization
    // of the request.
    assert_eq!(
        aggregate_resp,
        AggregateContinueResp::new(Vec::from([PrepareStep::new(
            *test.report_metadata.id(),
            PrepareStepResult::Finished
        )]))
    );
}

#[tokio::test]
async fn taskprov_aggregate_share() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    test.datastore
        .run_tx(|tx| {
            let task = test.task.clone();
            let interval =
                Interval::new(Time::from_seconds_since_epoch(6000), *task.time_precision())
                    .unwrap();

            Box::pin(async move {
                tx.put_task(&task).await?;

                tx.put_batch(&Batch::<16, FixedSize, TestVdaf>::new(
                    *task.id(),
                    batch_id,
                    (),
                    BatchState::Closed,
                    0,
                    interval,
                ))
                .await
                .unwrap();

                tx.put_batch_aggregation(&BatchAggregation::<16, FixedSize, TestVdaf>::new(
                    *task.id(),
                    batch_id,
                    (),
                    0,
                    BatchAggregationState::Aggregating,
                    Some(AggregateShare::from(OutputShare::from(Vec::from([
                        Field64::from(7),
                    ])))),
                    1,
                    interval,
                    ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                ))
                .await
                .unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

    let request = AggregateShareReq::new(
        *test.task.id(),
        BatchSelector::new_fixed_size(batch_id),
        ().get_encoded(),
        1,
        ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
    );

    let auth = test.aggregator_auth_token.request_authentication();

    // Attempt using the wrong credentials, should reject.
    let mut test_conn = post(test.task.aggregate_shares_uri().unwrap().path())
        .with_request_header(auth.0, "Bearer invalid_token")
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateShareReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(request.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
            "title": "The request's authorization is not valid.",
            "taskid": format!("{}", test.task_id),
        })
    );

    let mut test_conn = post(test.task.aggregate_shares_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateShareReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_body(request.get_encoded())
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .run_async(&test.handler)
        .await;

    println!("{:?}", test_conn);

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(
        &test_conn,
        "content-type" => (AggregateShareResp::MEDIA_TYPE)
    );
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_share_resp = AggregateShareResp::get_decoded(&body_bytes).unwrap();

    hpke::open(
        test.collector_hpke_keypair.config(),
        test.collector_hpke_keypair.private_key(),
        &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
        aggregate_share_resp.encrypted_aggregate_share(),
        &aggregate_share_aad(&test.task_id, request.batch_selector()),
    )
    .unwrap();
}

/// This runs aggregate init, aggregate continue, and aggregate share requests against a
/// taskprov-enabled helper, and confirms that correct results are returned.
#[tokio::test]
async fn end_to_end() {
    let test = setup_taskprov_test().await;
    let (auth_header_name, auth_header_value) = test.aggregator_auth_token.request_authentication();

    let batch_id = random();
    let aggregation_job_id = random();

    let aggregate_init_request = AggregateInitializeReq::new(
        *test.task.id(),
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([test.report_share.clone()]),
    );

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth_header_name, auth_header_value.clone())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(aggregate_init_request.get_encoded())
        .run_async(&test.handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => (AggregateInitializeResp::MEDIA_TYPE));
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregateInitializeResp::get_decoded(&body_bytes).unwrap();

    assert_eq!(aggregate_resp.prepare_steps().len(), 1);
    let prepare_step = &aggregate_resp.prepare_steps()[0];
    assert_eq!(prepare_step.report_id(), test.report_metadata.id());
    let encoded_prep_share = assert_matches!(
        prepare_step.result(),
        PrepareStepResult::Continued(payload) => payload.clone()
    );
    assert_eq!(
        encoded_prep_share,
        test.transcript.helper_prep_state(0).1.get_encoded()
    );

    let aggregate_continue_request = AggregateContinueReq::new(
        *test.task.id(),
        aggregation_job_id,
        Vec::from([PrepareStep::new(
            *test.report_metadata.id(),
            PrepareStepResult::Continued(test.transcript.prepare_messages[0].get_encoded()),
        )]),
    );

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth_header_name, auth_header_value.clone())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateContinueReq::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(aggregate_continue_request.get_encoded())
        .run_async(&test.handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => (AggregateContinueResp::MEDIA_TYPE));
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregateContinueResp::get_decoded(&body_bytes).unwrap();

    assert_eq!(aggregate_resp.prepare_steps().len(), 1);
    let prepare_step = &aggregate_resp.prepare_steps()[0];
    assert_eq!(prepare_step.report_id(), test.report_metadata.id());
    assert_matches!(prepare_step.result(), PrepareStepResult::Finished);

    let checksum = ReportIdChecksum::for_report_id(test.report_metadata.id());
    let aggregate_share_request = AggregateShareReq::new(
        *test.task.id(),
        BatchSelector::new_fixed_size(batch_id),
        ().get_encoded(),
        1,
        checksum,
    );

    let mut test_conn = post(test.task.aggregate_shares_uri().unwrap().path())
        .with_request_header(auth_header_name, auth_header_value.clone())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateShareReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_header(
            TASKPROV_HEADER,
            URL_SAFE_NO_PAD.encode(test.task_config.get_encoded()),
        )
        .with_request_body(aggregate_share_request.get_encoded())
        .run_async(&test.handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => (AggregateShareResp::MEDIA_TYPE));
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_share_resp = AggregateShareResp::get_decoded(&body_bytes).unwrap();

    let plaintext = hpke::open(
        test.collector_hpke_keypair.config(),
        test.collector_hpke_keypair.private_key(),
        &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
        aggregate_share_resp.encrypted_aggregate_share(),
        &aggregate_share_aad(&test.task_id, aggregate_share_request.batch_selector()),
    )
    .unwrap();
    assert_eq!(
        plaintext,
        Vec::<u8>::from(&test.transcript.aggregate_shares[1])
    );
}
