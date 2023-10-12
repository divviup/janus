use crate::aggregator::{
    aggregate_init_tests::setup_aggregate_init_test_without_sending_request,
    http_handlers::{
        aggregator_handler,
        test_util::{take_problem_details, take_response_body},
    },
    tests::generate_helper_report_share,
    Config,
};
use assert_matches::assert_matches;
use janus_aggregator_core::{
    datastore::test_util::ephemeral_datastore, task::QueryType, taskprov::VerifyKeyInit,
    test_util::noop_meter,
};
use janus_core::{
    hpke::{
        self, aggregate_share_aad, test_util::generate_test_hpke_config_and_private_key,
        HpkeApplicationInfo, Label,
    },
    report_id::ReportIdChecksumExt,
    task::AuthenticationToken,
    test_util::{install_test_trace_subscriber, run_vdaf},
    time::{Clock, DurationExt, MockClock, TimeExt},
};
use janus_messages::{
    codec::{Decode, Encode},
    query_type::{FixedSize, TimeInterval},
    taskprov::{
        DpConfig, DpMechanism, Query as TaskprovQuery, QueryConfig, TaskConfig, VdafConfig,
        VdafType,
    },
    AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq, AggregateInitializeResp,
    AggregateShareReq, AggregateShareResp, AggregationJobId, BatchSelector, Duration, Extension,
    ExtensionType, PartialBatchSelector, PrepareStep, PrepareStepResult, ReportIdChecksum,
    ReportMetadata, Role, TaskId,
};
use prio::vdaf::prio3::Prio3Aes128Count;
use rand::random;
use ring::digest::{digest, SHA256};
use serde_json::json;
use std::sync::Arc;
use trillium::{KnownHeaderName, Status};
use trillium_testing::{assert_headers, prelude::post};

#[tokio::test]
async fn taskprov_opt_in_time_interval() {
    let test = setup_aggregate_init_test_without_sending_request().await;

    let auth = test.auth_token.request_authentication();

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, "Bearer invalid_token")
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(test.aggregation_job_init_req.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:unauthorizedRequest",
            "title": "The request's authorization is not valid.",
            "taskid": format!("{}", test.task.id()),
        })
    );

    let test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(test.aggregation_job_init_req.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));

    let got_task = test
        .datastore
        .run_tx(|tx| {
            let task_id = *test.task.id();
            Box::pin(async move { tx.get_task(&task_id).await })
        })
        .await
        .unwrap();

    assert_eq!(test.task, got_task.unwrap());
}

#[tokio::test]
async fn taskprov_opt_in_fixed_size() {
    let test = setup_aggregate_init_test_without_sending_request().await;

    let batch_id = random();
    let aggregation_job_id: AggregationJobId = random();

    let vdaf = Prio3Aes128Count::new_aes128_count(2).unwrap();
    let task_expiration = test
        .clock
        .now()
        .add(&Duration::from_hours(24).unwrap())
        .unwrap();

    let max_batch_query_count = 100;
    let min_batch_size = 100;
    let task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        Vec::from([
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
            "https://helper.example.com/".as_bytes().try_into().unwrap(),
        ]),
        QueryConfig::new(
            Duration::from_seconds(1),
            min_batch_size,
            max_batch_query_count,
            TaskprovQuery::FixedSize {
                max_batch_size: min_batch_size as u32,
            },
        ),
        task_expiration,
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();
    let task_config_encoded = task_config.get_encoded();
    let task_id: TaskId = digest(&SHA256, &task_config_encoded)
        .as_ref()
        .try_into()
        .unwrap();
    let vdaf_instance = task_config.vdaf_config().vdaf_type().try_into().unwrap();
    let vdaf_verify_key = test
        .verify_key_init
        .derive_vdaf_verify_key(&task_id, &vdaf_instance);

    let task = janus_aggregator_core::taskprov::Task::new(
        task_id,
        Vec::from([
            url::Url::parse("https://leader.example.com/").unwrap(),
            url::Url::parse("https://helper.example.com/").unwrap(),
        ]),
        QueryType::FixedSize {
            max_batch_size: min_batch_size as u64,
            batch_time_window_size: None,
        },
        vdaf_instance,
        Role::Helper,
        Vec::from([vdaf_verify_key.clone()]),
        max_batch_query_count as u64,
        Some(task_expiration),
        test.config.report_expiry_age,
        min_batch_size as u64,
        Duration::from_seconds(1),
        test.config.tolerable_clock_skew,
    )
    .unwrap();

    let report_metadata = ReportMetadata::new(
        random(),
        test.clock
            .now()
            .to_batch_interval_start(test.task.time_precision())
            .unwrap(),
        Vec::from([Extension::new(
            ExtensionType::Taskprov,
            task_config_encoded.clone(),
        )]),
    );
    let transcript = run_vdaf(
        &vdaf,
        vdaf_verify_key.as_ref().try_into().unwrap(),
        &(),
        report_metadata.id(),
        &1u64,
    );
    let report_share = generate_helper_report_share::<Prio3Aes128Count>(
        task_id,
        report_metadata,
        test.hpke_key.config(),
        &transcript.public_share,
        &transcript.input_shares[1],
    );
    let request = AggregateInitializeReq::new(
        task_id,
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([report_share.clone()]),
    );

    let auth = test.auth_token.request_authentication();

    let test_conn = post(task.task().aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_body(request.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));

    let got_task = test
        .datastore
        .run_tx(|tx| {
            let task_id = *task.task().id();
            Box::pin(async move { tx.get_task(&task_id).await })
        })
        .await
        .unwrap();

    assert_eq!(task.task(), &got_task.unwrap());
}

#[tokio::test]
async fn taskprov_opt_out_task_expired() {
    let test = setup_aggregate_init_test_without_sending_request().await;

    let auth = test.auth_token.request_authentication();

    // Advance clock past task expiry.
    test.clock.advance(&Duration::from_hours(48).unwrap());

    let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(test.aggregation_job_init_req.get_encoded())
        .run_async(&test.handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:invalidTask",
            "title": "Aggregator has opted out of the indicated task.",
            "taskid": format!("{}", test.task.id()),
        })
    );
}

#[tokio::test]
async fn taskprov_reject_aggregate_init_with_bad_extension_payloads() {
    let test = setup_aggregate_init_test_without_sending_request().await;

    let another_task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        Vec::from([
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
            "https://helper.example.com/".as_bytes().try_into().unwrap(),
        ]),
        QueryConfig::new(
            Duration::from_seconds(1),
            1,
            1,
            TaskprovQuery::FixedSize {
                max_batch_size: 100,
            },
        ),
        *test.task.task_expiration().unwrap(),
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();
    let another_task_config_encoded = another_task_config.get_encoded();

    let (report_share_no_extension, _) =
        test.report_share_generator
            .next_with_metadata(ReportMetadata::new(
                random(),
                test.clock
                    .now()
                    .to_batch_interval_start(test.task.time_precision())
                    .unwrap(),
                Vec::new(),
            ));

    let (report_share_mismatched_extension, _) =
        test.report_share_generator
            .next_with_metadata(ReportMetadata::new(
                random(),
                test.clock
                    .now()
                    .to_batch_interval_start(test.task.time_precision())
                    .unwrap(),
                Vec::from([Extension::new(
                    ExtensionType::Taskprov,
                    another_task_config_encoded.clone(),
                )]),
            ));

    let auth = test.auth_token.request_authentication();

    for (name, report_shares) in [
        (
            "missing_report_share_extensions",
            vec![test.report_shares[0].clone(), report_share_no_extension],
        ),
        (
            "mismatched_report_share_extensions",
            vec![
                test.report_shares[0].clone(),
                report_share_mismatched_extension,
            ],
        ),
        ("no_report_shares", vec![]),
    ] {
        let batch_id = random();
        let aggregation_job_id = random();
        let request = AggregateInitializeReq::new(
            *test.task.id(),
            aggregation_job_id,
            ().get_encoded(),
            PartialBatchSelector::new_fixed_size(batch_id),
            report_shares,
        );

        let mut test_conn = post(test.task.aggregation_job_uri().unwrap().path())
            .with_request_header(auth.0, auth.1.clone())
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(&test.handler)
            .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest), "{name}");
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:unrecognizedMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "taskid": format!("{}", test.task.id()),
            }),
            "{name}"
        );
    }
}

#[tokio::test]
async fn taskprov_opt_out_mismatched_task_id() {
    let test = setup_aggregate_init_test_without_sending_request().await;

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
        QueryConfig::new(
            Duration::from_seconds(1),
            100,
            100,
            TaskprovQuery::TimeInterval,
        ),
        task_expiration,
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();

    let aggregation_job_id: AggregationJobId = random();

    let (report_share, _) = test
        .report_share_generator
        .next_with_metadata(ReportMetadata::new(
            random(),
            test.clock
                .now()
                .to_batch_interval_start(test.task.time_precision())
                .unwrap(),
            Vec::from([Extension::new(
                ExtensionType::Taskprov,
                another_task_config.get_encoded(),
            )]),
        ));

    let request = AggregateInitializeReq::new(
        *test.task.id(),
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_time_interval(),
        Vec::from([report_share.clone()]),
    );

    let auth = test.auth_token.request_authentication();

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
            "taskid": format!("{}", test.task.id()),
        })
    );
}

#[tokio::test]
async fn taskprov_opt_out_missing_aggregator() {
    let test = setup_aggregate_init_test_without_sending_request().await;

    let batch_id = random();
    let aggregation_job_id: AggregationJobId = random();

    let vdaf = Prio3Aes128Count::new_aes128_count(2).unwrap();
    let task_expiration = test
        .clock
        .now()
        .add(&Duration::from_hours(24).unwrap())
        .unwrap();
    let task_config = TaskConfig::new(
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
    let task_config_encoded = task_config.get_encoded();
    let task_id: TaskId = digest(&SHA256, &task_config_encoded)
        .as_ref()
        .try_into()
        .unwrap();
    let vdaf_instance = task_config.vdaf_config().vdaf_type().try_into().unwrap();
    let vdaf_verify_key = test
        .verify_key_init
        .derive_vdaf_verify_key(&task_id, &vdaf_instance);

    let report_metadata = ReportMetadata::new(
        random(),
        test.clock
            .now()
            .to_batch_interval_start(test.task.time_precision())
            .unwrap(),
        Vec::from([Extension::new(
            ExtensionType::Taskprov,
            task_config_encoded.clone(),
        )]),
    );
    let transcript = run_vdaf(
        &vdaf,
        vdaf_verify_key.as_ref().try_into().unwrap(),
        &(),
        report_metadata.id(),
        &1u64,
    );
    let report_share = generate_helper_report_share::<Prio3Aes128Count>(
        task_id,
        report_metadata,
        test.hpke_key.config(),
        &transcript.public_share,
        &transcript.input_shares[1],
    );
    let request = AggregateInitializeReq::new(
        task_id,
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([report_share.clone()]),
    );

    let auth = test.auth_token.request_authentication();

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
            "taskid": format!("{}", task_id),
        })
    );
}

/// This runs aggregate init, aggregate continue, and aggregate share requests against a
/// taskprov-enabled helper, and confirms that correct results are returned.
#[tokio::test]
async fn end_to_end() {
    install_test_trace_subscriber();

    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    let global_hpke_key = generate_test_hpke_config_and_private_key();
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

    let auth_token: AuthenticationToken = random();
    let verify_key_init: VerifyKeyInit = random();
    let collector_hpke_key = generate_test_hpke_config_and_private_key();

    let tolerable_clock_skew = Duration::from_seconds(60);
    let config = Config {
        auth_tokens: vec![auth_token.clone()],
        verify_key_init,
        collector_hpke_config: collector_hpke_key.config().clone(),
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

    let batch_id = random();
    let aggregation_job_id: AggregationJobId = random();

    let vdaf = Prio3Aes128Count::new_aes128_count(2).unwrap();
    let task_expiration = clock.now().add(&Duration::from_hours(24).unwrap()).unwrap();

    let max_batch_query_count = 1;
    let min_batch_size = 1;
    let task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        Vec::from([
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
            "https://helper.example.com/".as_bytes().try_into().unwrap(),
        ]),
        QueryConfig::new(
            Duration::from_seconds(1),
            min_batch_size,
            max_batch_query_count,
            TaskprovQuery::FixedSize {
                max_batch_size: min_batch_size as u32,
            },
        ),
        task_expiration,
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();
    let task_config_encoded = task_config.get_encoded();
    let task_id: TaskId = digest(&SHA256, &task_config_encoded)
        .as_ref()
        .try_into()
        .unwrap();
    let vdaf_instance = task_config.vdaf_config().vdaf_type().try_into().unwrap();
    let vdaf_verify_key = verify_key_init.derive_vdaf_verify_key(&task_id, &vdaf_instance);

    let task = janus_aggregator_core::taskprov::Task::new(
        task_id,
        Vec::from([
            url::Url::parse("https://leader.example.com/").unwrap(),
            url::Url::parse("https://helper.example.com/").unwrap(),
        ]),
        QueryType::FixedSize {
            max_batch_size: min_batch_size as u64,
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
        config.tolerable_clock_skew,
    )
    .unwrap();

    let report_metadata = ReportMetadata::new(
        random(),
        clock
            .now()
            .to_batch_interval_start(task.task().time_precision())
            .unwrap(),
        Vec::from([Extension::new(
            ExtensionType::Taskprov,
            task_config_encoded.clone(),
        )]),
    );
    let transcript = run_vdaf(
        &vdaf,
        vdaf_verify_key.as_ref().try_into().unwrap(),
        &(),
        report_metadata.id(),
        &1u64,
    );
    let report_share = generate_helper_report_share::<Prio3Aes128Count>(
        task_id,
        report_metadata.clone(),
        global_hpke_key.config(),
        &transcript.public_share,
        &transcript.input_shares[1],
    );

    let aggregate_init_request = AggregateInitializeReq::new(
        task_id,
        aggregation_job_id,
        ().get_encoded(),
        PartialBatchSelector::new_fixed_size(batch_id),
        Vec::from([report_share.clone()]),
    );

    let auth = auth_token.request_authentication();

    let mut test_conn = post(task.task().aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1.clone())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_body(aggregate_init_request.get_encoded())
        .run_async(&handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => (AggregateInitializeResp::MEDIA_TYPE));
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregateInitializeResp::get_decoded(&body_bytes).unwrap();

    assert_eq!(aggregate_resp.prepare_steps().len(), 1);
    let prepare_step = &aggregate_resp.prepare_steps()[0];
    assert_eq!(prepare_step.report_id(), report_metadata.id());
    let encoded_prep_share = assert_matches!(
        prepare_step.result(),
        PrepareStepResult::Continued(payload) => payload.clone()
    );
    assert_eq!(
        encoded_prep_share,
        transcript.helper_prep_state(0).1.get_encoded()
    );

    let aggregate_continue_request = AggregateContinueReq::new(
        *task.task().id(),
        aggregation_job_id,
        Vec::from([PrepareStep::new(
            *report_metadata.id(),
            PrepareStepResult::Continued(transcript.prepare_messages[0].get_encoded()),
        )]),
    );

    let mut test_conn = post(task.task().aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1.clone())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateContinueReq::MEDIA_TYPE,
        )
        .with_request_body(aggregate_continue_request.get_encoded())
        .run_async(&handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => (AggregateContinueResp::MEDIA_TYPE));
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_resp = AggregateContinueResp::get_decoded(&body_bytes).unwrap();

    assert_eq!(aggregate_resp.prepare_steps().len(), 1);
    let prepare_step = &aggregate_resp.prepare_steps()[0];
    assert_eq!(prepare_step.report_id(), report_metadata.id());
    assert_matches!(prepare_step.result(), PrepareStepResult::Finished);

    let checksum = ReportIdChecksum::for_report_id(report_metadata.id());
    let aggregate_share_request = AggregateShareReq::new(
        *task.task().id(),
        BatchSelector::new_fixed_size(batch_id),
        ().get_encoded(),
        1,
        checksum,
    );

    let mut test_conn = post(task.task().aggregate_shares_uri().unwrap().path())
        .with_request_header(auth.0, auth.1.clone())
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateShareReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_body(aggregate_share_request.get_encoded())
        .run_async(&handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => (AggregateShareResp::MEDIA_TYPE));
    let body_bytes = take_response_body(&mut test_conn).await;
    let aggregate_share_resp = AggregateShareResp::get_decoded(&body_bytes).unwrap();

    let plaintext = hpke::open(
        collector_hpke_key.config(),
        collector_hpke_key.private_key(),
        &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
        aggregate_share_resp.encrypted_aggregate_share(),
        &aggregate_share_aad(&task_id, aggregate_share_request.batch_selector()),
    )
    .unwrap();
    assert_eq!(plaintext, Vec::<u8>::from(&transcript.aggregate_shares[1]));
}
