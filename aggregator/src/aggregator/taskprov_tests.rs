use crate::{
    aggregator::{
        http_handlers::{
            aggregator_handler,
            test_util::{take_problem_details, take_response_body},
        },
        tests::generate_helper_report_share,
        Config,
    },
    config::TaskprovConfig,
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
    taskprov::{test_util::PeerAggregatorBuilder, PeerAggregator},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{
        self, test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo,
        HpkeKeypair, Label,
    },
    task::VERIFY_KEY_LEN,
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
    AggregateShare as AggregateShareMessage, AggregateShareAad, AggregateShareReq,
    AggregationJobContinueReq, AggregationJobId, AggregationJobInitializeReq, AggregationJobResp,
    AggregationJobRound, BatchSelector, Duration, Interval, PartialBatchSelector, PrepareContinue,
    PrepareInit, PrepareResp, PrepareStepResult, ReportIdChecksum, ReportMetadata, ReportShare,
    Role, TaskId, Time,
};
use prio::{
    idpf::IdpfInput,
    vdaf::{
        poplar1::{Poplar1, Poplar1AggregationParam},
        prg::PrgSha3,
    },
};
use rand::random;
use ring::digest::{digest, SHA256};
use serde_json::json;
use std::sync::Arc;
use trillium::{Handler, KnownHeaderName, Status};
use trillium_testing::{
    assert_headers,
    prelude::{post, put},
};

type TestVdaf = Poplar1<PrgSha3, 16>;

pub struct TaskprovTestCase {
    _ephemeral_datastore: EphemeralDatastore,
    clock: MockClock,
    collector_hpke_keypair: HpkeKeypair,
    datastore: Arc<Datastore<MockClock>>,
    handler: Box<dyn Handler>,
    peer_aggregator: PeerAggregator,
    report_metadata: ReportMetadata,
    transcript: VdafTranscript<16, TestVdaf>,
    report_share: ReportShare,
    task: Task,
    task_config: TaskConfig,
    task_id: TaskId,
    aggregation_param: Poplar1AggregationParam,
}

async fn setup_taskprov_test() -> TaskprovTestCase {
    install_test_trace_subscriber();

    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    let global_hpke_key = generate_test_hpke_config_and_private_key();
    let collector_hpke_keypair = generate_test_hpke_config_and_private_key();
    let peer_aggregator = PeerAggregatorBuilder::new()
        .with_endpoint(url::Url::parse("https://leader.example.com/").unwrap())
        .with_role(Role::Leader)
        .with_collector_hpke_config(collector_hpke_keypair.config().clone())
        .build();

    datastore
        .run_tx(|tx| {
            let global_hpke_key = global_hpke_key.clone();
            let peer_aggregator = peer_aggregator.clone();
            Box::pin(async move {
                tx.put_global_hpke_keypair(&global_hpke_key).await.unwrap();
                tx.put_taskprov_peer_aggregator(&peer_aggregator)
                    .await
                    .unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

    let handler = aggregator_handler(
        Arc::clone(&datastore),
        clock.clone(),
        &noop_meter(),
        Config {
            taskprov_config: TaskprovConfig { enabled: true },
            ..Default::default()
        },
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
        VdafConfig::new(
            DpConfig::new(DpMechanism::None),
            VdafType::Poplar1 { bits: 1 },
        )
        .unwrap(),
    )
    .unwrap();

    let mut task_config_encoded = vec![];
    task_config.encode(&mut task_config_encoded);

    // We use a real VDAF since taskprov doesn't have any allowance for a test VDAF, and we use
    // Poplar1 so that the VDAF wil take more than one round, so we can exercise aggregation
    // continuation.
    let vdaf = Poplar1::new(1);

    let task_id = TaskId::try_from(digest(&SHA256, &task_config_encoded).as_ref()).unwrap();
    let vdaf_instance = task_config.vdaf_config().vdaf_type().try_into().unwrap();
    let vdaf_verify_key = peer_aggregator.derive_vdaf_verify_key(&task_id, &vdaf_instance);
    let aggregation_param =
        Poplar1AggregationParam::try_from_prefixes(Vec::from([IdpfInput::from_bools(&[true])]))
            .unwrap();
    let measurement = IdpfInput::from_bools(&[true]);

    let task = janus_aggregator_core::taskprov::Task::new(
        task_id,
        url::Url::parse("https://leader.example.com/").unwrap(),
        url::Url::parse("https://helper.example.com/").unwrap(),
        QueryType::FixedSize {
            max_batch_size: max_batch_size as u64,
            batch_time_window_size: None,
        },
        vdaf_instance,
        Role::Helper,
        Vec::from([vdaf_verify_key.clone()]),
        max_batch_query_count as u64,
        Some(task_expiration),
        peer_aggregator.report_expiry_age().copied(),
        min_batch_size as u64,
        Duration::from_seconds(1),
        Duration::from_seconds(1),
    )
    .unwrap();

    let report_metadata = ReportMetadata::new(
        random(),
        clock
            .now()
            .to_batch_interval_start(task.task().time_precision())
            .unwrap(),
    );
    let transcript = run_vdaf(
        &vdaf,
        vdaf_verify_key.as_ref().try_into().unwrap(),
        &aggregation_param,
        report_metadata.id(),
        &measurement,
    );
    let report_share = generate_helper_report_share::<TestVdaf>(
        task_id,
        report_metadata.clone(),
        global_hpke_key.config(),
        &transcript.public_share,
        Vec::new(),
        &transcript.helper_input_share,
    );

    TaskprovTestCase {
        _ephemeral_datastore: ephemeral_datastore,
        clock,
        collector_hpke_keypair,
        datastore,
        handler: Box::new(handler),
        peer_aggregator,
        task: task.into(),
        task_config,
        task_id,
        report_metadata,
        transcript,
        report_share,
        aggregation_param,
    }
}

#[tokio::test]
async fn taskprov_aggregate_init() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    let request = AggregationJobInitializeReq::new(
        test.aggregation_param.get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([PrepareInit::new(
            test.report_share.clone(),
            test.transcript.leader_prepare_transitions[0].2.clone(),
        )]),
    );

    let aggregation_job_id: AggregationJobId = random();

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

    let mut test_conn = put(test
        .task
        .aggregation_job_uri(&aggregation_job_id)
        .unwrap()
        .path())
    .with_request_header(auth.0, "Bearer invalid_token")
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
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

    let mut test_conn = put(test
        .task
        .aggregation_job_uri(&aggregation_job_id)
        .unwrap()
        .path())
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
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
        "content-type" => (AggregationJobResp::MEDIA_TYPE)
    );
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregationJobResp::get_decoded(&body_bytes).unwrap();

    assert_eq!(aggregate_resp.prepare_resps().len(), 1);
    let prepare_step = aggregate_resp.prepare_resps().get(0).unwrap();
    assert_eq!(prepare_step.report_id(), test.report_share.metadata().id());
    assert_matches!(prepare_step.result(), &PrepareStepResult::Continue { .. });

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
    let request = AggregationJobInitializeReq::new(
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([PrepareInit::new(
            test.report_share.clone(),
            test.transcript.leader_prepare_transitions[0].2.clone(),
        )]),
    );

    let aggregation_job_id: AggregationJobId = random();

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

    // Advance clock past task expiry.
    test.clock.advance(&Duration::from_hours(48).unwrap());

    let mut test_conn = put(test
        .task
        .aggregation_job_uri(&aggregation_job_id)
        .unwrap()
        .path())
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
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
    let request = AggregationJobInitializeReq::new(
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([PrepareInit::new(
            test.report_share.clone(),
            test.transcript.leader_prepare_transitions[0].2.clone(),
        )]),
    );

    let aggregation_job_id: AggregationJobId = random();

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
        VdafConfig::new(
            DpConfig::new(DpMechanism::None),
            VdafType::Poplar1 { bits: 1 },
        )
        .unwrap(),
    )
    .unwrap();

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

    let mut test_conn = put(test
        // Use the test case task's ID.
        .task
        .aggregation_job_uri(&aggregation_job_id)
        .unwrap()
        .path())
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
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
    let request = AggregationJobInitializeReq::new(
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([PrepareInit::new(
            test.report_share.clone(),
            test.transcript.leader_prepare_transitions[0].2.clone(),
        )]),
    );

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
        VdafConfig::new(
            DpConfig::new(DpMechanism::None),
            VdafType::Poplar1 { bits: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    let another_task_config_encoded = another_task_config.get_encoded();
    let another_task_id: TaskId = digest(&SHA256, &another_task_config_encoded)
        .as_ref()
        .try_into()
        .unwrap();

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

    let mut test_conn = put(format!(
        "/tasks/{another_task_id}/aggregation_jobs/{aggregation_job_id}"
    ))
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
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
async fn taskprov_opt_out_peer_aggregator_wrong_role() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    let request = AggregationJobInitializeReq::new(
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([PrepareInit::new(
            test.report_share.clone(),
            test.transcript.leader_prepare_transitions[0].2.clone(),
        )]),
    );

    let aggregation_job_id: AggregationJobId = random();

    let task_expiration = test
        .clock
        .now()
        .add(&Duration::from_hours(24).unwrap())
        .unwrap();
    let another_task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        // Attempt to configure leader as a helper.
        Vec::from([
            "https://helper.example.com/".as_bytes().try_into().unwrap(),
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
        ]),
        QueryConfig::new(
            Duration::from_seconds(1),
            100,
            100,
            TaskprovQuery::FixedSize {
                max_batch_size: 100,
            },
        ),
        task_expiration,
        VdafConfig::new(
            DpConfig::new(DpMechanism::None),
            VdafType::Poplar1 { bits: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    let another_task_config_encoded = another_task_config.get_encoded();
    let another_task_id: TaskId = digest(&SHA256, &another_task_config_encoded)
        .as_ref()
        .try_into()
        .unwrap();

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

    let mut test_conn = put(format!(
        "/tasks/{another_task_id}/aggregation_jobs/{aggregation_job_id}"
    ))
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
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
                "type": "urn:ietf:params:ppm:dap:error:invalidTask",
                "title": "Aggregator has opted out of the indicated task.",
                "taskid": format!("{}", another_task_id
        ),
            })
    );
}

#[tokio::test]
async fn taskprov_opt_out_peer_aggregator_does_not_exist() {
    let test = setup_taskprov_test().await;

    let batch_id = random();
    let request = AggregationJobInitializeReq::new(
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([PrepareInit::new(
            test.report_share.clone(),
            test.transcript.leader_prepare_transitions[0].2.clone(),
        )]),
    );

    let aggregation_job_id: AggregationJobId = random();

    let task_expiration = test
        .clock
        .now()
        .add(&Duration::from_hours(24).unwrap())
        .unwrap();
    let another_task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        Vec::from([
            // Some non-existent aggregator.
            "https://foobar.example.com/".as_bytes().try_into().unwrap(),
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
        ]),
        QueryConfig::new(
            Duration::from_seconds(1),
            100,
            100,
            TaskprovQuery::FixedSize {
                max_batch_size: 100,
            },
        ),
        task_expiration,
        VdafConfig::new(
            DpConfig::new(DpMechanism::None),
            VdafType::Poplar1 { bits: 1 },
        )
        .unwrap(),
    )
    .unwrap();
    let another_task_config_encoded = another_task_config.get_encoded();
    let another_task_id: TaskId = digest(&SHA256, &another_task_config_encoded)
        .as_ref()
        .try_into()
        .unwrap();

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

    let mut test_conn = put(format!(
        "/tasks/{another_task_id}/aggregation_jobs/{aggregation_job_id}"
    ))
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<FixedSize>::MEDIA_TYPE,
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
                "type": "urn:ietf:params:ppm:dap:error:invalidTask",
                "title": "Aggregator has opted out of the indicated task.",
                "taskid": format!("{}", another_task_id
        ),
            })
    );
}

#[tokio::test]
async fn taskprov_aggregate_continue() {
    let test = setup_taskprov_test().await;

    let aggregation_job_id = random();
    let batch_id = random();

    test.datastore
        .run_tx(|tx| {
            let task = test.task.clone();
            let report_share = test.report_share.clone();
            let report_metadata = test.report_metadata.clone();
            let transcript = test.transcript.clone();
            let aggregation_param = test.aggregation_param.clone();

            Box::pin(async move {
                // Aggregate continue is only possible if the task has already been inserted.
                tx.put_task(&task).await?;

                tx.put_report_share(task.id(), &report_share).await?;

                tx.put_aggregation_job(
                    &AggregationJob::<VERIFY_KEY_LEN, FixedSize, TestVdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        aggregation_param.clone(),
                        batch_id,
                        Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                            .unwrap(),
                        AggregationJobState::InProgress,
                        AggregationJobRound::from(0),
                    ),
                )
                .await?;

                tx.put_report_aggregation::<VERIFY_KEY_LEN, TestVdaf>(&ReportAggregation::new(
                    *task.id(),
                    aggregation_job_id,
                    *report_metadata.id(),
                    *report_metadata.time(),
                    0,
                    None,
                    ReportAggregationState::Waiting(
                        transcript.helper_prepare_transitions[0].0.clone(),
                    ),
                ))
                .await?;

                tx.put_aggregate_share_job::<VERIFY_KEY_LEN, FixedSize, TestVdaf>(
                    &AggregateShareJob::new(
                        *task.id(),
                        batch_id,
                        aggregation_param,
                        transcript.helper_aggregate_share,
                        0,
                        ReportIdChecksum::default(),
                    ),
                )
                .await
            })
        })
        .await
        .unwrap();

    let request = AggregationJobContinueReq::new(
        AggregationJobRound::from(1),
        Vec::from([PrepareContinue::new(
            *test.report_metadata.id(),
            test.transcript.leader_prepare_transitions[1].2.clone(),
        )]),
    );

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

    // Attempt using the wrong credentials, should reject.
    let mut test_conn = post(
        test.task
            .aggregation_job_uri(&aggregation_job_id)
            .unwrap()
            .path(),
    )
    .with_request_header(auth.0, "Bearer invalid_token")
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobContinueReq::MEDIA_TYPE,
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

    let mut test_conn = post(
        test.task
            .aggregation_job_uri(&aggregation_job_id)
            .unwrap()
            .path(),
    )
    .with_request_header(auth.0, auth.1)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobContinueReq::MEDIA_TYPE,
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
        AggregationJobResp::MEDIA_TYPE
    );
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregationJobResp::get_decoded(&body_bytes).unwrap();

    // We'll only validate the response. Taskprov doesn't touch functionality beyond the
    // authorization of the request.
    assert_eq!(
        aggregate_resp,
        AggregationJobResp::new(Vec::from([PrepareResp::new(
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
            let aggregation_param = test.aggregation_param.clone();
            let transcript = test.transcript.clone();

            Box::pin(async move {
                tx.put_task(&task).await?;

                tx.put_batch(&Batch::<16, FixedSize, TestVdaf>::new(
                    *task.id(),
                    batch_id,
                    aggregation_param.clone(),
                    BatchState::Closed,
                    0,
                    interval,
                ))
                .await
                .unwrap();

                tx.put_batch_aggregation(&BatchAggregation::<16, FixedSize, TestVdaf>::new(
                    *task.id(),
                    batch_id,
                    aggregation_param,
                    0,
                    BatchAggregationState::Aggregating,
                    Some(transcript.helper_aggregate_share),
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
        BatchSelector::new_fixed_size(batch_id),
        test.aggregation_param.get_encoded(),
        1,
        ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
    );

    let auth = test
        .peer_aggregator
        .primary_aggregator_auth_token()
        .request_authentication();

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

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(
        &test_conn,
        "content-type" => (AggregateShareMessage::MEDIA_TYPE)
    );
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_share_resp = AggregateShareMessage::get_decoded(&body_bytes).unwrap();

    hpke::open(
        test.collector_hpke_keypair.config(),
        test.collector_hpke_keypair.private_key(),
        &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
        aggregate_share_resp.encrypted_aggregate_share(),
        &AggregateShareAad::new(test.task_id, request.batch_selector().clone()).get_encoded(),
    )
    .unwrap();
}
