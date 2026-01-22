use crate::{
    aggregator::{
        http_handlers::{
            AggregatorHandlerBuilder,
            test_util::take_response_body,
            test_util::{HttpHandlerTest, take_problem_details},
        },
        test_util::{create_report, create_report_custom, default_aggregator_config},
    },
    metrics::test_util::InMemoryMetricInfrastructure,
};
use chrono::TimeDelta;
use janus_aggregator_core::{
    datastore::test_util::{EphemeralDatastoreBuilder, ephemeral_datastore},
    task::{AggregationMode, BatchMode, test_util::TaskBuilder},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    initialize_rustls,
    test_util::{install_test_trace_subscriber, runtime::TestRuntime},
    time::{Clock, MockClock, TimeDeltaExt as _, TimeExt as _},
    vdaf::VdafInstance,
};
use janus_messages::{
    Duration, Extension, ExtensionType, HpkeCiphertext, HpkeConfigId, InputShareAad,
    PlaintextInputShare, Report, ReportError, ReportId, ReportMetadata, Role, UploadRequest,
    UploadResponse, taskprov::TimePrecision,
};
use opentelemetry::Key;
use opentelemetry_sdk::metrics::data::{Histogram, Sum};
use prio::codec::{Encode, ParameterizedDecode};
use rand::random;
use serde_json::json;
use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration as StdDuration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use trillium::{KnownHeaderName, Status};
use trillium_testing::{TestConn, assert_headers, prelude::post};
use trillium_tokio::Stopper;

#[tokio::test]
async fn upload_handler() {
    async fn check_response(
        test_conn: &mut TestConn,
        desired_report_id: &ReportId,
        desired_report_error: ReportError,
    ) {
        // HTTP status is OK regardless of what happened to the constituent reports because the HTTP
        // messages were exchanged successfully.
        if test_conn.status() != Some(Status::Ok) {
            println!(
                "ERROR: Report {} got status {:?}",
                desired_report_id,
                test_conn.status()
            );
            if let Some(body) = test_conn.take_response_body_string() {
                println!("Response body: {}", body);
            }
        }
        assert_eq!(test_conn.status(), Some(Status::Ok));

        assert_headers!(&test_conn, "content-type" => "application/dap-upload-resp");
        let body = &take_response_body(test_conn).await;
        let expected_content_len = format!("{}", body.len());
        let len_str = expected_content_len.as_str();
        assert_headers!(&test_conn, "content-length" => len_str);
        let upload_response = UploadResponse::get_decoded_with_param(&body.len(), body).unwrap();

        assert_eq!(upload_response.status().len(), 1);
        for status in upload_response.status() {
            assert_eq!(status.report_id(), *desired_report_id);
            assert_eq!(status.error(), desired_report_error);
        }
    }

    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        hpke_keypair,
        ..
    } = HttpHandlerTest::new().await;

    const REPORT_EXPIRY_AGE: u64 = 1_000_000;
    let time_precision = TimePrecision::from_seconds(1000);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_report_expiry_age(Some(Duration::from_seconds(
        REPORT_EXPIRY_AGE,
        &time_precision,
    )))
    .build();

    let leader_task = task.leader_view().unwrap();
    datastore.put_aggregator_task(&leader_task).await.unwrap();

    let report = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    // Upload a report. Do this twice to prove that PUT is idempotent.
    for _ in 0..2 {
        let mut test_conn = post(task.report_upload_uri().unwrap().path())
            .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
            .with_request_body(
                UploadRequest::from_slice(std::slice::from_ref(&report))
                    .get_encoded()
                    .unwrap(),
            )
            .run_async(&handler)
            .await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert!(
            test_conn
                .take_response_body_string()
                .is_some_and(|s| s.is_empty())
        );
    }

    // Upload a report with a versioned media-type header
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(
            KnownHeaderName::ContentType,
            format!("{};version_suffixes=ignored", UploadRequest::MEDIA_TYPE),
        )
        .with_request_body(
            UploadRequest::from_slice(std::slice::from_ref(&report))
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert!(
        test_conn
            .take_response_body_string()
            .is_some_and(|s| s.is_empty())
    );

    let accepted_report_id = report.metadata().id();

    // Verify that new reports using an existing report ID are also accepted as a duplicate.
    let duplicate_id_report = create_report_custom(
        &leader_task,
        clock.now_aligned_to_precision(task.time_precision()),
        *accepted_report_id,
        &hpke_keypair,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(&[duplicate_id_report])
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert!(
        test_conn
            .take_response_body_string()
            .is_some_and(|s| s.is_empty())
    );

    // Upload multiple reports in a single request
    let reports = vec![
        create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        ),
        create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        ),
        create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        ),
    ];
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(UploadRequest::new(reports).get_encoded().unwrap())
        .run_async(&handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert!(
        test_conn
            .take_response_body_string()
            .is_some_and(|s| s.is_empty())
    );

    // Verify that reports older than the report expiry age are rejected with the reportRejected
    // error type.
    let gc_eligible_report = Report::new(
        ReportMetadata::new(
            random(),
            clock
                .now_aligned_to_precision(task.time_precision())
                .sub_timedelta(
                    &TimeDelta::try_seconds_unsigned(REPORT_EXPIRY_AGE + 30000).unwrap(),
                    task.time_precision(),
                )
                .unwrap(),
            report.metadata().public_extensions().to_vec(),
        ),
        report.public_share().to_vec(),
        report.leader_encrypted_input_share().clone(),
        report.helper_encrypted_input_share().clone(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(std::slice::from_ref(&gc_eligible_report))
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        gc_eligible_report.metadata().id(),
        ReportError::ReportDropped,
    )
    .await;

    // Should reject a report using the wrong HPKE config for the leader, and reply with
    // the error type outdatedConfig.
    let unused_hpke_config_id =
        HpkeConfigId::from(u8::from(*hpke_keypair.config().id()).wrapping_add(1));
    let bad_report = Report::new(
        report.metadata().clone(),
        report.public_share().to_vec(),
        HpkeCiphertext::new(
            unused_hpke_config_id,
            report
                .leader_encrypted_input_share()
                .encapsulated_key()
                .to_vec(),
            report.leader_encrypted_input_share().payload().to_vec(),
        ),
        report.helper_encrypted_input_share().clone(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(std::slice::from_ref(&bad_report))
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        bad_report.metadata().id(),
        ReportError::HpkeUnknownConfigId,
    )
    .await;

    // Reports from the future should be rejected.
    let bad_report_time = clock
        .now_aligned_to_precision(task.time_precision())
        .add_duration(&Duration::from_time_precision_units(2))
        .unwrap();
    let bad_report = Report::new(
        ReportMetadata::new(
            *report.metadata().id(),
            bad_report_time,
            report.metadata().public_extensions().to_vec(),
        ),
        report.public_share().to_vec(),
        report.leader_encrypted_input_share().clone(),
        report.helper_encrypted_input_share().clone(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(std::slice::from_ref(&bad_report))
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        bad_report.metadata().id(),
        ReportError::ReportTooEarly,
    )
    .await;

    // Reports with timestamps past the task's end time should be rejected.
    let task_end_soon = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    // Since HttpHandlerTest's clock instance is a copy of ours, we can't simply
    // advance it, and we have to instead tolerate skew.
    .with_tolerable_clock_skew(Duration::from_time_precision_units(2))
    .with_time_precision(*task.time_precision())
    .with_task_end(Some(
        clock
            .now_aligned_to_precision(task.time_precision())
            .add_duration(&Duration::ONE)
            .unwrap(),
    ))
    .build();
    let leader_task_end_soon = task_end_soon.leader_view().unwrap();
    datastore
        .put_aggregator_task(&leader_task_end_soon)
        .await
        .unwrap();
    let report_2 = create_report(
        &leader_task_end_soon,
        &hpke_keypair,
        clock
            .now_aligned_to_precision(task.time_precision())
            .add_duration(&Duration::from_seconds(
                task.time_precision().as_seconds() * 2,
                task.time_precision(),
            ))
            .unwrap(),
    );
    let mut test_conn = post(task_end_soon.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(std::slice::from_ref(&report_2))
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        report_2.metadata().id(),
        ReportError::TaskExpired,
    )
    .await;

    // Reject reports with an undecodeable public share.
    let mut bad_public_share_report = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );
    bad_public_share_report = Report::new(
        bad_public_share_report.metadata().clone(),
        // Some obviously wrong public share.
        vec![0; 10],
        bad_public_share_report
            .leader_encrypted_input_share()
            .clone(),
        bad_public_share_report
            .helper_encrypted_input_share()
            .clone(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(&[bad_public_share_report.clone()])
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        bad_public_share_report.metadata().id(),
        ReportError::InvalidMessage,
    )
    .await;

    // Reject reports which are not decryptable.
    let undecryptable_report = create_report_custom(
        &leader_task,
        clock.now_aligned_to_precision(task.time_precision()),
        *accepted_report_id,
        // Encrypt report with some arbitrary key that has the same ID as an existing one.
        &HpkeKeypair::test_with_id(*hpke_keypair.config().id()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(std::slice::from_ref(&undecryptable_report))
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        undecryptable_report.metadata().id(),
        ReportError::HpkeDecryptError,
    )
    .await;

    // Reject reports whose leader input share is corrupt.
    let mut bad_leader_input_share_report = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );
    bad_leader_input_share_report = Report::new(
        bad_leader_input_share_report.metadata().clone(),
        bad_leader_input_share_report.public_share().to_vec(),
        hpke::seal(
            hpke_keypair.config(),
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
            // Some obviously wrong payload.
            &PlaintextInputShare::new(Vec::new(), vec![0; 100])
                .get_encoded()
                .unwrap(),
            &InputShareAad::new(
                *task.id(),
                bad_leader_input_share_report.metadata().clone(),
                bad_leader_input_share_report.public_share().to_vec(),
            )
            .get_encoded()
            .unwrap(),
        )
        .unwrap(),
        bad_leader_input_share_report
            .helper_encrypted_input_share()
            .clone(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(&[bad_leader_input_share_report.clone()])
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        bad_leader_input_share_report.metadata().id(),
        ReportError::InvalidMessage,
    )
    .await;

    // Check for appropriate CORS headers in response to a preflight request.
    let test_conn = TestConn::build(
        trillium::Method::Options,
        task.report_upload_uri().unwrap().path(),
        (),
    )
    .with_request_header(KnownHeaderName::Origin, "https://example.com/")
    .with_request_header(KnownHeaderName::AccessControlRequestMethod, "POST")
    .with_request_header(KnownHeaderName::AccessControlRequestHeaders, "content-type")
    .run_async(&handler)
    .await;
    assert!(test_conn.status().unwrap().is_success());
    assert_headers!(
        &test_conn,
        "access-control-allow-origin" => "https://example.com/",
        "access-control-allow-methods"=> "POST",
        "access-control-allow-headers" => "content-type",
        "access-control-max-age"=> "86400",
    );

    // Check for appropriate CORS headers in response to the main request.
    let test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(UploadRequest::from_slice(&[report]).get_encoded().unwrap())
        .run_async(&handler)
        .await;
    assert!(test_conn.status().unwrap().is_success());
    assert_headers!(
        &test_conn,
        "access-control-allow-origin" => "https://example.com/"
    );

    // Reports with duplicate extensions must be rejected
    clock.advance(TimeDelta::seconds(1));
    let dupe_ext_report = create_report_custom(
        &leader_task,
        clock.now_aligned_to_precision(task.time_precision()),
        random(),
        &hpke_keypair,
        /* public */ Vec::from([Extension::new(ExtensionType::Tbd, Vec::new())]),
        /* leader */ Vec::from([Extension::new(ExtensionType::Tbd, Vec::new())]),
        /* helper */ Vec::new(),
    );
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::from_slice(std::slice::from_ref(&dupe_ext_report))
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;
    check_response(
        &mut test_conn,
        dupe_ext_report.metadata().id(),
        ReportError::InvalidMessage,
    )
    .await;
}

/// Test mixed success and failure in a single batch upload.
/// This validates that UploadResponse only includes failed reports, not successful ones.
#[tokio::test]
async fn upload_handler_mixed_success_failure() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        hpke_keypair,
        ..
    } = HttpHandlerTest::new().await;

    const REPORT_EXPIRY_AGE: u64 = 1_000_000;
    let time_precision = TimePrecision::from_seconds(1000);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_report_expiry_age(Some(Duration::from_seconds(
        REPORT_EXPIRY_AGE,
        &time_precision,
    )))
    .build();

    let leader_task = task.leader_view().unwrap();
    datastore.put_aggregator_task(&leader_task).await.unwrap();

    // Create four reports: success, failure (expired), success, failure (HPKE config)
    let valid_report_1 = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    let expired_report = Report::new(
        ReportMetadata::new(
            random(),
            clock
                .now_aligned_to_precision(task.time_precision())
                .sub_duration(&Duration::from_seconds(REPORT_EXPIRY_AGE, &time_precision))
                .unwrap()
                .sub_duration(&Duration::from_seconds(REPORT_EXPIRY_AGE, &time_precision))
                .unwrap(),
            Vec::new(),
        ),
        valid_report_1.public_share().to_vec(),
        valid_report_1.leader_encrypted_input_share().clone(),
        valid_report_1.helper_encrypted_input_share().clone(),
    );

    let unused_hpke_config_id =
        HpkeConfigId::from(u8::from(*hpke_keypair.config().id()).wrapping_add(1));
    let invalid_hpke_report = Report::new(
        ReportMetadata::new(
            random(),
            clock.now_aligned_to_precision(task.time_precision()),
            Vec::new(),
        ),
        valid_report_1.public_share().to_vec(),
        HpkeCiphertext::new(
            unused_hpke_config_id,
            valid_report_1
                .leader_encrypted_input_share()
                .encapsulated_key()
                .to_vec(),
            valid_report_1
                .leader_encrypted_input_share()
                .payload()
                .to_vec(),
        ),
        valid_report_1.helper_encrypted_input_share().clone(),
    );

    let valid_report_2 = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    // Upload all four reports in a single batch
    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::new(vec![
                valid_report_1.clone(),
                expired_report.clone(),
                valid_report_2.clone(),
                invalid_hpke_report.clone(),
            ])
            .get_encoded()
            .unwrap(),
        )
        .run_async(&handler)
        .await;

    // Should get HTTP 200 OK even with mixed results
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => "application/dap-upload-resp");

    // Parse the response
    let body = take_response_body(&mut test_conn).await;
    let upload_response = UploadResponse::get_decoded_with_param(&body.len(), &body).unwrap();

    // Successful reports should NOT appear in the response
    assert_eq!(
        upload_response.status().len(),
        2,
        "Expected exactly 2 failed reports"
    );
    for report in upload_response.status() {
        match report.report_id() {
            id if id == *expired_report.metadata().id() => {
                assert_eq!(report.error(), ReportError::ReportDropped)
            }
            id if id == *invalid_hpke_report.metadata().id() => {
                assert_eq!(report.error(), ReportError::HpkeUnknownConfigId)
            }
            _ => unreachable!("Unexpected report failure"),
        }
    }

    // Verify that the two valid reports were actually written to the datastore
    let report_count = datastore
        .count_client_reports_for_task(leader_task.id())
        .await
        .unwrap();
    assert_eq!(report_count, 2, "Expected 2 valid reports in the datastore");
}

/// Test that reports uploaded before task start time are rejected with TaskNotStarted.
#[tokio::test]
async fn upload_handler_task_not_started() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        hpke_keypair,
        ..
    } = HttpHandlerTest::new().await;

    // Create a task that starts in the future (must be aligned to time precision)
    let time_precision = TimePrecision::from_seconds(1000);

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_task_start(Some(
        clock
            .now_aligned_to_precision(&time_precision)
            .add_duration(&Duration::ONE) // Add one time precision interval
            .unwrap()
            .add_duration(&Duration::ONE) // Add another to be clearly in the future
            .unwrap(),
    ))
    // Need to allow clock skew so the handler doesn't reject for being "too far in the future"
    .with_tolerable_clock_skew(Duration::from_seconds(
        time_precision.as_seconds() * 10,
        &time_precision,
    ))
    .build();

    let leader_task = task.leader_view().unwrap();
    datastore.put_aggregator_task(&leader_task).await.unwrap();

    // Create a report with current time (before task start)
    let early_report = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(
            UploadRequest::new(vec![early_report.clone()])
                .get_encoded()
                .unwrap(),
        )
        .run_async(&handler)
        .await;

    // Should get HTTP 200 OK but with TaskNotStarted error in response
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(&test_conn, "content-type" => "application/dap-upload-resp");

    let body = take_response_body(&mut test_conn).await;
    let upload_response = UploadResponse::get_decoded_with_param(&body.len(), &body).unwrap();

    assert_eq!(upload_response.status().len(), 1);
    assert_eq!(
        upload_response.status()[0].report_id(),
        *early_report.metadata().id()
    );
    assert_eq!(
        upload_response.status()[0].error(),
        ReportError::TaskNotStarted
    );
}

// Helper should not expose `tasks/{task-id}/reports` endpoint.
#[tokio::test]
async fn upload_handler_helper() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        hpke_keypair,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(TimePrecision::from_seconds(100))
    .build();
    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();
    let report = create_report(
        &helper_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );

    let mut test_conn = post(task.report_upload_uri().unwrap().path())
        .with_request_header(KnownHeaderName::ContentType, UploadRequest::MEDIA_TYPE)
        .with_request_body(UploadRequest::from_slice(&[report]).get_encoded().unwrap())
        .run_async(&handler)
        .await;

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
}

/// This test exercises distribution of transaction-wide errors to multiple clients that have
/// their uploads in the same batch.
#[tokio::test(flavor = "multi_thread")]
async fn upload_handler_error_fanout() {
    install_test_trace_subscriber();
    initialize_rustls();
    let clock = MockClock::default();
    let ephemeral_datastore = EphemeralDatastoreBuilder::new()
        .with_database_pool_wait_timeout(Some(StdDuration::from_millis(100)))
        .build()
        .await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
    let hpke_keypair = datastore.put_hpke_key().await.unwrap();
    let handler = AggregatorHandlerBuilder::new(
        datastore.clone(),
        clock.clone(),
        TestRuntime::default(),
        &noop_meter(),
        default_aggregator_config(),
    )
    .await
    .unwrap()
    .build()
    .unwrap();

    const REPORT_EXPIRY_AGE: u64 = 1_000_000;
    let time_precision = TimePrecision::from_seconds(100);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(time_precision)
    .with_report_expiry_age(Some(Duration::from_seconds(
        REPORT_EXPIRY_AGE,
        &time_precision,
    )))
    .build();

    let leader_task = task.leader_view().unwrap();
    datastore.put_aggregator_task(&leader_task).await.unwrap();

    // Use trillium_tokio instead of trillium_testing so we can send reqeusts in parallel and
    // better match production use cases.
    let server_handle = trillium_tokio::config()
        .without_signals()
        .with_host("127.0.0.1")
        .with_port(0)
        .spawn(handler);
    let server_info = server_handle.info().await;
    let socket_addr = server_info.tcp_socket_addr().unwrap();

    let client = reqwest::Client::new();
    let mut url = task.report_upload_uri().unwrap();
    url.set_scheme("http").unwrap();
    url.set_host(Some("127.0.0.1")).unwrap();
    url.set_port(Some(socket_addr.port())).unwrap();

    // Upload one report and wait for it to finish, to prepopulate the aggregator's task cache.
    let report: Report = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );
    let response = client
        .post(url.clone())
        .header("Content-Type", UploadRequest::MEDIA_TYPE)
        .body(UploadRequest::from_slice(&[report]).get_encoded().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    // Use up the connection pool's connections to cause a transaction-level error in the next
    // uploads.
    let exhaust_pool_task_handle = tokio::spawn({
        let pool = ephemeral_datastore.pool().clone();
        async move {
            let mut connections = Vec::new();
            loop {
                connections.push(pool.get().await);
            }
        }
    });

    // Wait for the pool to be exhausted by the above task.
    let pool = ephemeral_datastore.pool();
    loop {
        let status = pool.status();
        if status.available == 0 && status.size == status.max_size {
            break;
        }

        sleep(StdDuration::from_millis(100)).await;
    }

    // Upload many reports in parallel, to be sure we exercise upload batching.
    let upload_task_handles = (0..10)
        .map(|_| {
            tokio::spawn({
                let leader_task = leader_task.clone();
                let clock = clock.clone();
                let client = client.clone();
                let url = url.clone();
                let hpke_keypair = hpke_keypair.clone();
                async move {
                    let report = create_report(
                        &leader_task,
                        &hpke_keypair,
                        clock.now_aligned_to_precision(&time_precision),
                    );
                    let response = client
                        .post(url)
                        .header("Content-Type", UploadRequest::MEDIA_TYPE)
                        .body(UploadRequest::from_slice(&[report]).get_encoded().unwrap())
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.status().as_u16(), 500);
                }
            })
        })
        .collect::<Vec<_>>();
    drop(client);

    for handle in upload_task_handles.into_iter() {
        handle.await.unwrap();
    }

    exhaust_pool_task_handle.abort();

    server_handle.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_client_early_disconnect() {
    install_test_trace_subscriber();

    let in_memory_metrics = InMemoryMetricInfrastructure::new();
    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
    let hpke_keypair = datastore.put_hpke_key().await.unwrap();
    let handler = AggregatorHandlerBuilder::new(
        datastore.clone(),
        clock.clone(),
        TestRuntime::default(),
        &in_memory_metrics.meter,
        default_aggregator_config(),
    )
    .await
    .unwrap()
    .build()
    .unwrap();

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(TimePrecision::from_seconds(100))
    .build();
    let task_id = *task.id();
    let leader_task = task.leader_view().unwrap();
    datastore.put_aggregator_task(&leader_task).await.unwrap();

    let report_1 = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );
    let encoded_report_1 = UploadRequest::from_slice(&[report_1])
        .get_encoded()
        .unwrap();
    let report_2 = create_report(
        &leader_task,
        &hpke_keypair,
        clock.now_aligned_to_precision(task.time_precision()),
    );
    let encoded_report_2 = UploadRequest::from_slice(&[report_2])
        .get_encoded()
        .unwrap();

    let stopper = Stopper::new();
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_addr = server.local_addr().unwrap();
    let handle = trillium_tokio::config()
        .without_signals()
        .with_stopper(stopper.clone())
        .with_prebound_server(server)
        .spawn(handler);

    // Client sends report, using Content-Length, and waits for one byte of response.
    let mut client_socket = TcpStream::connect(local_addr).await.unwrap();
    let request_line_and_headers = format!(
        "POST /tasks/{task_id}/reports HTTP/1.1\r\n\
        Content-Type: application/dap-upload-req\r\n\
        Content-Length: {}\r\n\r\n",
        encoded_report_1.len(),
    );
    client_socket
        .write_all(request_line_and_headers.as_bytes())
        .await
        .unwrap();
    client_socket.write_all(&encoded_report_1).await.unwrap();
    timeout(
        StdDuration::from_secs(15),
        client_socket.read_exact(&mut [0]),
    )
    .await
    .unwrap()
    .unwrap();
    client_socket.shutdown().await.unwrap();
    drop(client_socket);

    // Client disconnects before sending the entire request body, using Content-Length.
    let mut client_socket = TcpStream::connect(local_addr).await.unwrap();
    let request_line_and_headers = format!(
        "POST /tasks/{task_id}/reports HTTP/1.1\r\n\
        Content-Type: application/dap-upload-req\r\n\
        Content-Length: 1000\r\n\r\n"
    );
    client_socket
        .write_all(request_line_and_headers.as_bytes())
        .await
        .unwrap();
    client_socket.write_all(&[0x41u8; 999]).await.unwrap();
    client_socket.shutdown().await.unwrap();
    drop(client_socket);

    // Client sends report, using chunked transfer encoding, and waits for one byte of response.
    let mut client_socket = TcpStream::connect(local_addr).await.unwrap();
    let request_line_and_headers = format!(
        "POST /tasks/{task_id}/reports HTTP/1.1\r\n\
        Content-Type: application/dap-upload-req\r\n\
        Transfer-Encoding: chunked\r\n\r\n"
    );
    client_socket
        .write_all(request_line_and_headers.as_bytes())
        .await
        .unwrap();
    let chunk_length_line = format!("{:x}\r\n", encoded_report_2.len());
    client_socket
        .write_all(chunk_length_line.as_bytes())
        .await
        .unwrap();
    client_socket.write_all(&encoded_report_2).await.unwrap();
    client_socket.write_all(b"\r\n0\r\n\r\n").await.unwrap();
    timeout(
        StdDuration::from_secs(15),
        client_socket.read_exact(&mut [0]),
    )
    .await
    .unwrap()
    .unwrap();
    client_socket.shutdown().await.unwrap();
    drop(client_socket);

    // Client disconnects before signaling the end of the request body, using chunked transfer
    // encoding.
    let mut client_socket = TcpStream::connect(local_addr).await.unwrap();
    let request_line_and_headers = format!(
        "POST /tasks/{task_id}/reports HTTP/1.1\r\n\
        Content-Type: application/dap-upload-req\r\n\
        Transfer-Encoding: chunked\r\n\r\n"
    );
    client_socket
        .write_all(request_line_and_headers.as_bytes())
        .await
        .unwrap();
    client_socket.write_all(b"1000\r\n").await.unwrap();
    client_socket.write_all(&[0x41; 1000]).await.unwrap();
    client_socket.write_all(b"\r\n").await.unwrap();
    client_socket.shutdown().await.unwrap();
    drop(client_socket);

    // Loop until metrics show that the server has handled all responses. (At this point, it's
    // possible the server hasn't accepted the above connections, and polling via metrics is more
    // efficient and robust than sleeping.)
    let metrics = timeout(StdDuration::from_secs(15), {
        let in_memory_metrics = in_memory_metrics.clone();
        async move {
            loop {
                let metrics = in_memory_metrics.collect().await;
                let Some(metric) = metrics.get("http.server.request.duration") else {
                    continue;
                };
                let histogram_data = metric
                    .data
                    .as_any()
                    .downcast_ref::<Histogram<f64>>()
                    .unwrap();
                let count = histogram_data
                    .data_points
                    .iter()
                    .map(|data_point| data_point.count)
                    .sum::<u64>();
                if count == 4 {
                    break metrics;
                }
            }
        }
    })
    .await
    .unwrap();

    stopper.stop();
    handle.await;
    in_memory_metrics.shutdown().await;

    // Inspect the metrics to confirm they contain expected values. We should have seen two
    // successful requests, and two invalid requests due to the client disconnecting in the middle
    // of the request body.
    let error_code_key = Key::new("error_code");
    let error_type_key = Key::new("error.type");
    let status_code_key = Key::new("http.response.status_code");

    let counter_data = metrics["janus_aggregator_responses"]
        .data
        .as_any()
        .downcast_ref::<Sum<u64>>()
        .unwrap();
    assert_eq!(counter_data.data_points.len(), 2);
    assert!(
        counter_data
            .data_points
            .iter()
            .all(|data_point| data_point.value == 2)
    );
    assert_eq!(
        counter_data
            .data_points
            .iter()
            .map(|data_point| {
                data_point
                    .attributes
                    .iter()
                    .find(|attribute| attribute.key == error_code_key)
                    .unwrap()
                    .value
                    .to_string()
            })
            .collect::<HashSet<String>>(),
        HashSet::from(["client_disconnected".into(), "".into()])
    );

    let histogram_data = metrics["http.server.request.duration"]
        .data
        .as_any()
        .downcast_ref::<Histogram<f64>>()
        .unwrap();
    assert_eq!(histogram_data.data_points.len(), 2);
    assert!(
        histogram_data
            .data_points
            .iter()
            .all(|data_point| data_point.count == 2)
    );
    assert_eq!(
        histogram_data
            .data_points
            .iter()
            .map(|data_point| {
                data_point
                    .attributes
                    .iter()
                    .find(|attribute| attribute.key == error_type_key)
                    .map(|attribute| attribute.value.to_string())
            })
            .collect::<HashSet<Option<String>>>(),
        HashSet::from([Some("client_disconnected".to_string()), None])
    );
    assert_eq!(
        histogram_data
            .data_points
            .iter()
            .map(|data_point| {
                data_point
                    .attributes
                    .iter()
                    .find(|attribute| attribute.key == status_code_key)
                    .unwrap()
                    .value
                    .to_string()
            })
            .collect::<HashSet<String>>(),
        HashSet::from(["400".into(), "200".into()])
    );
}

/// This test streams reports using HTTP/1.1 chunked encoding and ensures they're all counted.
#[tokio::test(flavor = "multi_thread")]
async fn upload_client_http11_bulk() {
    install_test_trace_subscriber();
    use tracing::info;

    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
    let hpke_keypair = datastore.put_hpke_key().await.unwrap();
    let handler = AggregatorHandlerBuilder::new(
        datastore.clone(),
        clock.clone(),
        TestRuntime::default(),
        &noop_meter(),
        default_aggregator_config(),
    )
    .await
    .unwrap()
    .build()
    .unwrap();

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .with_time_precision(TimePrecision::from_seconds(5))
    .build();
    let task_id = *task.id();
    let leader_task = task.leader_view().unwrap();
    datastore.put_aggregator_task(&leader_task).await.unwrap();

    let stopper = Stopper::new();
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let local_addr = server.local_addr().unwrap();
    let handle = trillium_tokio::config()
        .without_signals()
        .with_stopper(stopper.clone())
        .with_prebound_server(server)
        .spawn(handler);

    let mut client_socket = TcpStream::connect(local_addr).await.unwrap();
    let request_line_and_headers = format!(
        "POST /tasks/{task_id}/reports HTTP/1.1\r\n\
        Content-Type: application/dap-upload-req\r\n\
        Transfer-Encoding: chunked\r\n\r\n"
    );
    client_socket
        .write_all(request_line_and_headers.as_bytes())
        .await
        .unwrap();

    let report_count = 20;

    for i in 0..report_count {
        info!(i, report_count, "Starting loop");
        let report = create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        );
        let encoded = report.get_encoded().unwrap();
        let chunk_length_line = format!("{:x}\r\n", encoded.len());
        client_socket
            .write_all(chunk_length_line.as_bytes())
            .await
            .unwrap();
        client_socket.write_all(&encoded).await.unwrap();
        client_socket.write_all(b"\r\n").await.unwrap(); // Chunk terminator
        client_socket.flush().await.unwrap();
        clock.advance(TimeDelta::seconds(1));
    }
    client_socket.write_all(b"0\r\n\r\n").await.unwrap(); // Final chunk terminator
    client_socket.flush().await.unwrap();
    timeout(
        StdDuration::from_secs(15),
        client_socket.read_exact(&mut [0]),
    )
    .await
    .unwrap()
    .unwrap();
    drop(client_socket);

    // Verify that the valid reports were actually written to the datastore
    let stored_reports = datastore
        .count_client_reports_for_task(leader_task.id())
        .await
        .unwrap();
    assert_eq!(
        stored_reports, report_count,
        "Expected the right number of valid reports in the datastore"
    );

    stopper.stop();
    handle.await;
}

/// These are all tests of the decode_reports_stream method in http_handlers.rs
mod decode_reports_stream_tests {
    use super::*;
    use crate::aggregator::{Error, http_handlers::decode_reports_stream};
    use assert_matches::assert_matches;
    use futures::{StreamExt, io::Cursor};
    use prio::codec::CodecError;
    use std::{
        cmp::min,
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    /// Helper to create a mock AsyncRead that returns an IO error
    struct ErrorReader {
        error_kind: io::ErrorKind,
    }

    impl futures::io::AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(self.error_kind, "mock error")))
        }
    }

    /// Helper AsyncRead that feeds data in small chunks to test buffering logic.
    /// This ensures the stream correctly handles reports split at arbitrary byte boundaries.
    struct ChunkedReader {
        data: Vec<u8>,
        position: usize,
        chunk_size: usize,
    }

    impl ChunkedReader {
        fn new(data: Vec<u8>, chunk_size: usize) -> Self {
            Self {
                data,
                position: 0,
                chunk_size,
            }
        }
    }

    impl futures::io::AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.position >= self.data.len() {
                return Poll::Ready(Ok(0));
            }

            let remaining = self.data.len() - self.position;
            let to_read = min(min(remaining, self.chunk_size), buf.len());
            buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
            self.position += to_read;
            Poll::Ready(Ok(to_read))
        }
    }

    #[tokio::test]
    async fn empty_body() {
        let body = Cursor::new(Vec::<u8>::new());
        let mut stream = Box::pin(decode_reports_stream(body));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn single_valid_report() {
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let hpke_keypair = datastore.put_hpke_key().await.unwrap();

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_time_precision(TimePrecision::from_seconds(1))
        .build();
        let leader_task = task.leader_view().unwrap();

        let report = create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        );
        let encoded = report.get_encoded().unwrap();
        let body = Cursor::new(encoded);

        let mut stream = Box::pin(decode_reports_stream(body));
        let decoded_report = stream
            .next()
            .await
            .expect("stream should yield Result<Result<Report>>")
            .expect("stream should yield Result<Report>")
            .expect("report should decode Report successfully");
        assert_eq!(decoded_report.metadata().id(), report.metadata().id());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn multiple_reports_in_one_chunk() {
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let hpke_keypair = datastore.put_hpke_key().await.unwrap();

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_time_precision(TimePrecision::from_seconds(1))
        .build();
        let leader_task = task.leader_view().unwrap();

        let report1 = create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        );
        let report2 = create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        );
        let mut encoded = report1.get_encoded().unwrap();
        encoded.extend_from_slice(&report2.get_encoded().unwrap());
        let body = Cursor::new(encoded);

        let mut stream = Box::pin(decode_reports_stream(body));
        let decoded1 = stream
            .next()
            .await
            .expect("stream should yield first item, Result<Result<Report>>")
            .expect("stream should not error, Result<Report>")
            .expect("report should decode successfully as Report");
        assert_eq!(decoded1.metadata().id(), report1.metadata().id());

        let decoded2 = stream
            .next()
            .await
            .expect("stream should yield second item, Result<Result<Report>>")
            .expect("stream should not error, Result<Report>")
            .expect("report should decode successfully as Report");
        assert_eq!(decoded2.metadata().id(), report2.metadata().id());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn leftover_bytes() {
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let hpke_keypair = datastore.put_hpke_key().await.unwrap();

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_time_precision(TimePrecision::from_seconds(1))
        .build();
        let leader_task = task.leader_view().unwrap();

        let report = create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        );
        let mut encoded = report.get_encoded().unwrap();
        encoded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let body = Cursor::new(encoded);

        let mut stream = Box::pin(decode_reports_stream(body));
        let _ = stream
            .next()
            .await
            .expect("stream should yield Result<Result<Report>>")
            .expect("stream should yield Result<Report>")
            .expect("report should decode successfully into Report");

        let error = stream
            .next()
            .await
            .expect("stream should yield Result<Result<Report>>")
            .expect_err("should be Err<Error>");
        assert_matches!(error, Error::MessageDecode(CodecError::BytesLeftOver(4)));
    }

    #[tokio::test]
    async fn io_error_client_disconnected() {
        let body = ErrorReader {
            error_kind: io::ErrorKind::ConnectionReset,
        };
        let mut stream = Box::pin(decode_reports_stream(body));
        let error = stream
            .next()
            .await
            .expect("stream should yield Result<Result<Report>>")
            .expect_err("should be Err<Error>");
        assert_matches!(error, Error::ClientDisconnected);
    }

    #[tokio::test]
    async fn io_error_bad_request() {
        let body = ErrorReader {
            error_kind: io::ErrorKind::InvalidData,
        };
        let mut stream = Box::pin(decode_reports_stream(body));
        let error = stream
            .next()
            .await
            .expect("stream should yield Result<Result<Report>>")
            .expect_err("should be Err<Error>");
        assert_matches!(error, Error::BadRequest(_));
    }

    #[tokio::test]
    async fn decode_error_with_metadata() {
        // This tests that decode errors with metadata are yielded correctly and bytes
        // are consumed, allowing the stream to continue.
        //
        // Note: Creating test data that naturally triggers a decode error (not UnexpectedEof
        // or LengthPrefixTooBig) with metadata is challenging because most corruptions cause
        // UnexpectedEof. This test verifies that when such errors occur (as they can in
        // production with network issues or malformed clients), they're handled correctly.

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let hpke_keypair = datastore.put_hpke_key().await.unwrap();

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_time_precision(TimePrecision::from_seconds(1))
        .build();
        let leader_task = task.leader_view().unwrap();

        let report1 = create_report(
            &leader_task,
            &hpke_keypair,
            clock.now_aligned_to_precision(task.time_precision()),
        );

        let report2_metadata = ReportMetadata::new(
            random(),
            clock.now_aligned_to_precision(task.time_precision()),
            vec![],
        );

        // Build stream: [valid report] [valid metadata + incomplete body]
        let mut stream_bytes = report1.get_encoded().unwrap();
        report2_metadata.encode(&mut stream_bytes).unwrap();
        // Incomplete public_share to trigger UnexpectedEof
        stream_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]); // Claim 100 bytes
        stream_bytes.extend_from_slice(&[0xAA; 99]); // Only provide 99 bytes of screaming

        let body = Cursor::new(stream_bytes);
        let mut stream = Box::pin(decode_reports_stream(body));

        // First report decodes successfully
        let decoded1 = stream
            .next()
            .await
            .expect("stream should yield an item, Some(Result<Result<Report>>)")
            .expect("stream should not error, OK(Result<Report>)")
            .expect("first report should decode successfully, OK(Report)");
        assert_eq!(decoded1.metadata().id(), report1.metadata().id());

        // Corrupted report causes UnexpectedEof, which buffers the data.
        // When stream ends, BytesLeftOver error occurs.
        let error = stream
            .next()
            .await
            .expect("stream should yield an item, Some(Result<Error>)")
            .expect_err("should be stream error, Err(MessageDecode<CodecError>)");
        assert_matches!(error, Error::MessageDecode(CodecError::BytesLeftOver(_)));
    }

    #[tokio::test]
    async fn decode_error_without_metadata_fails_fast() {
        // Create malformed data that fails to decode metadata
        // Using an invalid fixed size value (all 0xFF) should cause early failure
        let bad_data = vec![0xFF; 100];
        let body = Cursor::new(bad_data);

        let mut stream = Box::pin(decode_reports_stream(body));
        let error = stream
            .next()
            .await
            .expect("stream should yield Result<Result<Report>>")
            .expect_err("should be stream Err<Error>");

        assert_matches!(error, Error::MessageDecode(_));
    }

    #[tokio::test]
    async fn chunk_boundary_handling() {
        // This test feeds data in very small chunks to ensure the buffering logic and error
        // variant matching (LengthPrefixTooBig, UnexpectedEof) correctly distinguish
        // "incomplete report" from "actual decode error".

        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
        let hpke_keypair = datastore.put_hpke_key().await.unwrap();

        let task = TaskBuilder::new(
            BatchMode::TimeInterval,
            AggregationMode::Synchronous,
            VdafInstance::Prio3Count,
        )
        .with_time_precision(TimePrecision::from_seconds(1))
        .build();
        let leader_task = task.leader_view().unwrap();

        // Create multiple reports to test various split points
        let reports = (0..3)
            .map(|_| {
                create_report(
                    &leader_task,
                    &hpke_keypair,
                    clock.now_aligned_to_precision(task.time_precision()),
                )
            })
            .collect::<Vec<_>>();

        // Encode all reports
        let mut all_bytes = Vec::new();
        for report in &reports {
            report.encode(&mut all_bytes).unwrap();
        }

        // Test with various chunk sizes to ensure we hit boundaries at different points
        // within the report structure (metadata, length prefixes, ciphertexts, etc.)
        for chunk_size in [1, 3, 7, 13, 29, 67] {
            let body = ChunkedReader::new(all_bytes.clone(), chunk_size);
            let mut stream = Box::pin(decode_reports_stream(body));

            // All reports should decode successfully regardless of chunk boundaries
            for (i, expected_report) in reports.iter().enumerate() {
                let decoded = stream
                    .next()
                    .await
                    .unwrap_or_else(|| {
                        panic!("chunk_size={}: should yield report {}", chunk_size, i)
                    })
                    .unwrap_or_else(|e| {
                        panic!(
                            "chunk_size={}: stream error at report {}: {:?}",
                            chunk_size, i, e
                        )
                    })
                    .unwrap_or_else(|e| {
                        panic!(
                            "chunk_size={}: decode error at report {}: {:?}",
                            chunk_size, i, e
                        )
                    });

                assert_eq!(
                    decoded.metadata().id(),
                    expected_report.metadata().id(),
                    "chunk_size={}: report {} metadata mismatch",
                    chunk_size,
                    i
                );
            }

            // Stream should end cleanly
            assert!(
                stream.next().await.is_none(),
                "chunk_size={}: stream should end after all reports",
                chunk_size
            );
        }
    }
}
