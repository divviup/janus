use std::{collections::HashMap, sync::Arc};

use axum::body::Body;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{Request, StatusCode};
use janus_aggregator_core::{
    datastore::models::HpkeKeyState,
    task::{AggregationMode, BatchMode, test_util::TaskBuilder},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    test_util::runtime::TestRuntime,
    vdaf::VdafInstance,
};
use janus_messages::{HpkeConfigId, HpkeConfigList, MediaType, Role};
use prio::codec::Decode as _;
use tower::ServiceExt;

use crate::{
    aggregator::{
        Config,
        http_handlers::{
            AggregatorHandlerBuilder, HPKE_CONFIG_SIGNATURE_HEADER,
            test_util::{HttpHandlerTest, take_response_body},
        },
        test_util::{hpke_config_signing_key, hpke_config_verification_key},
    },
    config::TaskprovConfig,
};

#[tokio::test]
async fn hpke_config() {
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
    let router = AggregatorHandlerBuilder::from_aggregator(aggregator.clone(), &noop_meter())
        .build()
        .unwrap();

    // No task ID provided.
    let mut response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/hpke_config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "max-age=86400"
    );
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        HpkeConfigList::MEDIA_TYPE
    );
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut response).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[first_hpke_keypair.config().clone()]
    );
    check_hpke_config_is_usable(&hpke_config_list, &first_hpke_keypair);

    // Insert an inactive HPKE config.
    let first_hpke_keypair_id = u8::from(*first_hpke_keypair.config().id());
    let second_hpke_keypair =
        HpkeKeypair::test_with_id(HpkeConfigId::from(first_hpke_keypair_id.wrapping_add(1)));
    datastore
        .run_unnamed_tx(|tx| {
            let keypair = second_hpke_keypair.clone();
            Box::pin(async move { tx.put_hpke_keypair(&keypair).await })
        })
        .await
        .unwrap();
    aggregator.refresh_caches().await.unwrap();
    let mut response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/hpke_config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut response).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[first_hpke_keypair.config().clone()]
    );

    // Set key active.
    datastore
        .run_unnamed_tx(|tx| {
            let keypair = second_hpke_keypair.clone();
            Box::pin(async move {
                tx.set_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                    .await
            })
        })
        .await
        .unwrap();
    aggregator.refresh_caches().await.unwrap();
    let mut response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/hpke_config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut response).await;
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
                tx.set_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Expired)
                    .await
            })
        })
        .await
        .unwrap();
    aggregator.refresh_caches().await.unwrap();
    let mut response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/hpke_config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut response).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[first_hpke_keypair.config().clone()]
    );
}

#[tokio::test]
async fn hpke_config_with_taskprov() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        hpke_keypair,
        ..
    } = HttpHandlerTest::new().await;

    // Insert a taskprov task.
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .build();
    let taskprov_helper_task = task.taskprov_helper_view().unwrap();
    datastore
        .put_aggregator_task(&taskprov_helper_task)
        .await
        .unwrap();

    let cfg = Config {
        taskprov_config: TaskprovConfig { enabled: true },
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
    let router = AggregatorHandlerBuilder::from_aggregator(aggregator.clone(), &noop_meter())
        .build()
        .unwrap();

    let mut response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/hpke_config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let hpke_config_list = verify_and_decode_hpke_config_list(&mut response).await;
    assert_eq!(
        hpke_config_list.hpke_configs(),
        &[hpke_keypair.config().clone()]
    );
    check_hpke_config_is_usable(&hpke_config_list, &hpke_keypair);
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
        router,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Prio3Count,
    )
    .build()
    .leader_view()
    .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    // Check for appropriate CORS headers in response to a preflight request.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/hpke_config")
                .header("origin", "https://example.com/")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://example.com/"
    );
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-methods")
            .unwrap(),
        "GET"
    );
    assert_eq!(
        response.headers().get("access-control-max-age").unwrap(),
        "86400"
    );

    // Check for appropriate CORS headers with a simple GET request.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/hpke_config")
                .header("origin", "https://example.com/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://example.com/"
    );
}

async fn verify_and_decode_hpke_config_list(
    response: &mut axum::response::Response,
) -> HpkeConfigList {
    let response_body = take_response_body(response).await;
    let signature = URL_SAFE_NO_PAD
        .decode(
            response
                .headers()
                .get(HPKE_CONFIG_SIGNATURE_HEADER)
                .unwrap(),
        )
        .unwrap();
    hpke_config_verification_key()
        .verify(&response_body, &signature)
        .unwrap();
    HpkeConfigList::get_decoded(&response_body).unwrap()
}
