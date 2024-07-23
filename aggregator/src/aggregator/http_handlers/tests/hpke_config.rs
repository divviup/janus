use crate::{
    aggregator::{
        http_handlers::{
            aggregator_handler, aggregator_handler_with_aggregator,
            test_util::{take_problem_details, take_response_body, HttpHandlerTest},
            HPKE_CONFIG_SIGNATURE_HEADER,
        },
        test_util::{
            default_aggregator_config, hpke_config_signing_key, hpke_config_verification_key,
        },
        Aggregator, Config,
    },
    config::TaskprovConfig,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use janus_aggregator_core::{
    datastore::{models::HpkeKeyState, test_util::ephemeral_datastore},
    task::{test_util::TaskBuilder, QueryType},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    test_util::{install_test_trace_subscriber, runtime::TestRuntime},
    time::MockClock,
    vdaf::VdafInstance,
};
use janus_messages::{HpkeConfigList, Role, TaskId};
use prio::codec::Decode as _;
use rand::random;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use trillium::{KnownHeaderName, Status};
use trillium_testing::{assert_headers, prelude::get, TestConn};

#[tokio::test]
async fn task_specific_hpke_config() {
    install_test_trace_subscriber();
    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);
    let mut config = default_aggregator_config();
    config.require_global_hpke_keys = false;
    let handler = aggregator_handler(
        datastore.clone(),
        clock.clone(),
        TestRuntime::default(),
        &noop_meter(),
        config,
    )
    .await
    .unwrap();

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
        .build()
        .leader_view()
        .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    let unknown_task_id: TaskId = random();
    let want_hpke_key = task.current_hpke_key().clone();

    // No task ID provided and no global keys are configured.
    let mut test_conn = get("/hpke_config").run_async(&handler).await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": 400u16,
            "type": "urn:ietf:params:ppm:dap:error:missingTaskID",
            "title": "HPKE configuration was requested without specifying a task ID.",
        })
    );

    // Unknown task ID provided
    let mut test_conn = get(format!("/hpke_config?task_id={unknown_task_id}"))
        .run_async(&handler)
        .await;
    // Expected status and problem type should be per the protocol
    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": 400u16,
            "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            "title": "An endpoint received a message with an unknown task ID.",
            "taskid": format!("{unknown_task_id}"),
        })
    );

    // Recognized task ID provided
    let mut test_conn = get(format!("/hpke_config?task_id={}", task.id()))
        .run_async(&handler)
        .await;

    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(
        &test_conn,
        "cache-control" => "max-age=86400",
        "content-type" => (HpkeConfigList::MEDIA_TYPE),
    );
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[want_hpke_key.config().clone()]
    );
    check_hpke_config_is_usable(&hpke_config_list, &want_hpke_key);
}

#[tokio::test]
async fn global_hpke_config() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        hpke_keypair: first_hpke_keypair,
        ..
    } = HttpHandlerTest::new().await;

    let aggregator = Arc::new(
        crate::aggregator::Aggregator::new(
            datastore.clone(),
            clock.clone(),
            TestRuntime::default(),
            &noop_meter(),
            Config {
                hpke_config_signing_key: Some(hpke_config_signing_key()),
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );
    let handler = aggregator_handler_with_aggregator(aggregator.clone(), &noop_meter())
        .await
        .unwrap();

    // No task ID provided
    let mut test_conn = get("/hpke_config").run_async(&handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    assert_headers!(
        &test_conn,
        "cache-control" => "max-age=86400",
        "content-type" => (HpkeConfigList::MEDIA_TYPE),
    );
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[first_hpke_keypair.config().clone()]
    );
    check_hpke_config_is_usable(&hpke_config_list, &first_hpke_keypair);

    // Insert an inactive HPKE config.
    let first_hpke_keypair_id = u8::from(*first_hpke_keypair.config().id());
    let second_hpke_keypair = HpkeKeypair::test_with_id(first_hpke_keypair_id.wrapping_add(1));
    datastore
        .run_unnamed_tx(|tx| {
            let keypair = second_hpke_keypair.clone();
            Box::pin(async move { tx.put_global_hpke_keypair(&keypair).await })
        })
        .await
        .unwrap();
    aggregator.refresh_caches().await.unwrap();
    let mut test_conn = get("/hpke_config").run_async(&handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[first_hpke_keypair.config().clone()]
    );

    // Set key active.
    datastore
        .run_unnamed_tx(|tx| {
            let keypair = second_hpke_keypair.clone();
            Box::pin(async move {
                tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                    .await
            })
        })
        .await
        .unwrap();
    aggregator.refresh_caches().await.unwrap();
    let mut test_conn = get("/hpke_config").run_async(&handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    // Unordered comparison.
    assert_eq!(
        HashMap::from_iter(
            hpke_config_list
                .hpke_configs()
                .iter()
                .map(|config| (config.id(), config))
        ),
        HashMap::from([
            (
                first_hpke_keypair.config().id(),
                &first_hpke_keypair.config().clone()
            ),
            (
                second_hpke_keypair.config().id(),
                &second_hpke_keypair.config().clone()
            ),
        ]),
    );

    // Expire a key.
    datastore
        .run_unnamed_tx(|tx| {
            let keypair = second_hpke_keypair.clone();
            Box::pin(async move {
                tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Expired)
                    .await
            })
        })
        .await
        .unwrap();
    aggregator.refresh_caches().await.unwrap();
    let mut test_conn = get("/hpke_config").run_async(&handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[first_hpke_keypair.config().clone()]
    );

    // Delete a key, no keys left.
    datastore
        .run_unnamed_tx(|tx| {
            let keypair = first_hpke_keypair.clone();
            Box::pin(async move { tx.delete_global_hpke_keypair(keypair.config().id()).await })
        })
        .await
        .unwrap();
    aggregator.refresh_caches().await.unwrap();
    let test_conn = get("/hpke_config").run_async(&handler).await;
    assert_eq!(test_conn.status(), Some(Status::InternalServerError));
}

#[tokio::test]
async fn global_hpke_config_with_taskprov() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        ..
    } = HttpHandlerTest::new().await;

    // Retrieve the global keypair from the test fixture.
    let first_hpke_keypair = datastore
        .run_unnamed_tx(|tx| {
            Box::pin(async move {
                Ok(tx.get_global_hpke_keypairs().await.unwrap()[0]
                    .hpke_keypair()
                    .clone())
            })
        })
        .await
        .unwrap();

    // Insert a taskprov task. This task won't have its task-specific HPKE key.
    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count).build();
    let taskprov_helper_task = task.taskprov_helper_view().unwrap();
    datastore
        .put_aggregator_task(&taskprov_helper_task)
        .await
        .unwrap();

    let cfg = Config {
        taskprov_config: TaskprovConfig {
            enabled: true,
            ignore_unknown_differential_privacy_mechanism: false,
        },
        hpke_config_signing_key: Some(hpke_config_signing_key()),
        ..Default::default()
    };

    let aggregator = Arc::new(
        crate::aggregator::Aggregator::new(
            datastore.clone(),
            clock.clone(),
            TestRuntime::default(),
            &noop_meter(),
            cfg,
        )
        .await
        .unwrap(),
    );
    let handler = aggregator_handler_with_aggregator(aggregator.clone(), &noop_meter())
        .await
        .unwrap();

    let mut test_conn = get(format!("/hpke_config?task_id={}", task.id()))
        .run_async(&handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[first_hpke_keypair.config().clone()]
    );
    check_hpke_config_is_usable(&hpke_config_list, &first_hpke_keypair);
}

fn check_hpke_config_is_usable(hpke_config_list: &HpkeConfigList, hpke_keypair: &HpkeKeypair) {
    let application_info =
        HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader);
    let message = b"this is a message";
    let associated_data = b"some associated data";

    let ciphertext = hpke::seal(
        &hpke_config_list.hpke_configs()[0],
        &application_info,
        message,
        associated_data,
    )
    .unwrap();
    let plaintext = hpke::open(
        hpke_keypair,
        &application_info,
        &ciphertext,
        associated_data,
    )
    .unwrap();
    assert_eq!(&plaintext, message);
}

#[tokio::test]
async fn hpke_config_cors_headers() {
    let HttpHandlerTest {
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
        .build()
        .leader_view()
        .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    // Check for appropriate CORS headers in response to a preflight request.
    let test_conn = TestConn::build(
        trillium::Method::Options,
        format!("/hpke_config?task_id={}", task.id()),
        (),
    )
    .with_request_header(KnownHeaderName::Origin, "https://example.com/")
    .with_request_header(KnownHeaderName::AccessControlRequestMethod, "GET")
    .run_async(&handler)
    .await;
    assert!(test_conn.status().unwrap().is_success());
    assert_headers!(
        &test_conn,
        "access-control-allow-origin" => "https://example.com/",
        "access-control-allow-methods"=> "GET",
        "access-control-max-age"=> "86400",
    );

    // Check for appropriate CORS headers with a simple GET request.
    let test_conn = get(format!("/hpke_config?task_id={}", task.id()))
        .with_request_header(KnownHeaderName::Origin, "https://example.com/")
        .run_async(&handler)
        .await;
    assert!(test_conn.status().unwrap().is_success());
    assert_headers!(
        &test_conn,
        "access-control-allow-origin" => "https://example.com/",
    );
}

async fn verify_and_decode_hpke_config_list(test_conn: &mut TestConn) -> HpkeConfigList {
    let response_body = take_response_body(test_conn).await;
    let signature = URL_SAFE_NO_PAD
        .decode(
            test_conn
                .response_headers()
                .get(HPKE_CONFIG_SIGNATURE_HEADER)
                .unwrap(),
        )
        .unwrap();
    hpke_config_verification_key()
        .verify(&response_body, &signature)
        .unwrap();
    HpkeConfigList::get_decoded(&response_body).unwrap()
}

#[tokio::test]
async fn require_global_hpke_keys() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        ..
    } = HttpHandlerTest::new().await;

    // Retrieve the global keypair from the test fixture.
    let keypair = datastore
        .run_unnamed_tx(|tx| {
            Box::pin(async move {
                Ok(tx.get_global_hpke_keypairs().await.unwrap()[0]
                    .hpke_keypair()
                    .clone())
            })
        })
        .await
        .unwrap();

    let cfg = Config {
        require_global_hpke_keys: true,
        hpke_config_signing_key: Some(hpke_config_signing_key()),
        ..Default::default()
    };

    let aggregator = Arc::new(
        Aggregator::new(
            Arc::clone(&datastore),
            clock.clone(),
            TestRuntime::default(),
            &noop_meter(),
            cfg,
        )
        .await
        .unwrap(),
    );

    let handler = aggregator_handler_with_aggregator(aggregator.clone(), &noop_meter())
        .await
        .unwrap();

    let mut test_conn = get(format!("/hpke_config?task_id={}", &random::<TaskId>()))
        .run_async(&handler)
        .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    assert_eq!(hpke_config_list.hpke_configs(), &[keypair.config().clone()]);
    check_hpke_config_is_usable(&hpke_config_list, &keypair);

    let mut test_conn = get("/hpke_config").run_async(&handler).await;
    assert_eq!(test_conn.status(), Some(Status::Ok));
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut test_conn).await;
    assert_eq!(hpke_config_list.hpke_configs(), &[keypair.config().clone()]);
    check_hpke_config_is_usable(&hpke_config_list, &keypair);
}
