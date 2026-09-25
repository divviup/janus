use std::{collections::HashMap, sync::Arc};

use axum::body::Body;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hpke_dispatch::Kem;
use http::{Request, StatusCode};
use janus_aggregator_core::{
    datastore::models::{HpkeKeyState, HpkeKeypair as DatastoreHpkeKeypair},
    task::{AggregationMode, BatchMode, test_util::TaskBuilder},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeCiphersuite, HpkeKeypair, HpkePrivateKey, Label},
    test_util::runtime::TestRuntime,
    vdaf::VdafInstance,
};
use janus_messages::{
    HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeConfigList, HpkeKdfId, HpkeKemId, HpkePublicKey,
    MediaType, Role,
};
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
    let taskprov_helper_task = task
        .taskprov_helper_view_with_task_config(task.task_configuration())
        .unwrap();
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

#[tokio::test]
async fn hpke_config_list_order() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        ..
    } = HttpHandlerTest::new().await;

    let hpke_config_ciphersuite_priority = Vec::from([
        HpkeCiphersuite::new(
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        ),
        HpkeCiphersuite::new(
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        ),
    ]);

    // Set up old and new keypairs with ciphersuites that are high priority, low priority, and not
    // in the list.
    let p521_keypair = Kem::DhP521HkdfSha512.gen_keypair();
    let hpke_keypair_35 = DatastoreHpkeKeypair::new(
        HpkeKeypair::new(
            HpkeConfig::new(
                HpkeConfigId::from(35),
                HpkeKemId::P521HkdfSha512,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(p521_keypair.public_key),
            ),
            HpkePrivateKey::new(p521_keypair.private_key),
        ),
        HpkeKeyState::Active,
        DateTime::<Utc>::from_timestamp(1_600_000_100, 0).unwrap(),
    );
    let hpke_keypair_86 = DatastoreHpkeKeypair::new(
        HpkeKeypair::generate(
            HpkeConfigId::from(86),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap(),
        HpkeKeyState::Active,
        DateTime::<Utc>::from_timestamp(1_700_000_200, 0).unwrap(),
    );
    let hpke_keypair_95 = DatastoreHpkeKeypair::new(
        HpkeKeypair::generate(
            HpkeConfigId::from(95),
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap(),
        HpkeKeyState::Active,
        DateTime::<Utc>::from_timestamp(1_600_000_400, 0).unwrap(),
    );
    let p384_keypair = Kem::DhP384HkdfSha384.gen_keypair();
    let hpke_keypair_140 = DatastoreHpkeKeypair::new(
        HpkeKeypair::new(
            HpkeConfig::new(
                HpkeConfigId::from(140),
                HpkeKemId::P384HkdfSha384,
                HpkeKdfId::HkdfSha384,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(p384_keypair.public_key),
            ),
            HpkePrivateKey::new(p384_keypair.private_key),
        ),
        HpkeKeyState::Active,
        DateTime::<Utc>::from_timestamp(1_700_000_300, 0).unwrap(),
    );
    let hpke_keypair_157 = DatastoreHpkeKeypair::new(
        HpkeKeypair::generate(
            HpkeConfigId::from(157),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap(),
        HpkeKeyState::Active,
        DateTime::<Utc>::from_timestamp(1_600_000_200, 0).unwrap(),
    );
    let p384_keypair = Kem::DhP384HkdfSha384.gen_keypair();
    let hpke_keypair_158 = DatastoreHpkeKeypair::new(
        HpkeKeypair::new(
            HpkeConfig::new(
                HpkeConfigId::from(158),
                HpkeKemId::P384HkdfSha384,
                HpkeKdfId::HkdfSha384,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(p384_keypair.public_key),
            ),
            HpkePrivateKey::new(p384_keypair.private_key),
        ),
        HpkeKeyState::Active,
        DateTime::<Utc>::from_timestamp(1_600_000_300, 0).unwrap(),
    );
    let hpke_keypair_232 = DatastoreHpkeKeypair::new(
        HpkeKeypair::generate(
            HpkeConfigId::from(232),
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap(),
        HpkeKeyState::Active,
        DateTime::<Utc>::from_timestamp(1_700_000_100, 0).unwrap(),
    );

    let expected_order = [
        // X25519 keypairs
        hpke_keypair_86.hpke_keypair().config().clone(),
        hpke_keypair_157.hpke_keypair().config().clone(),
        // P256 keypairs
        hpke_keypair_232.hpke_keypair().config().clone(),
        hpke_keypair_95.hpke_keypair().config().clone(),
        // Other algorithms
        hpke_keypair_140.hpke_keypair().config().clone(),
        hpke_keypair_158.hpke_keypair().config().clone(),
        hpke_keypair_35.hpke_keypair().config().clone(),
    ];

    let hpke_keypairs = [
        hpke_keypair_35,
        hpke_keypair_86,
        hpke_keypair_95,
        hpke_keypair_140,
        hpke_keypair_157,
        hpke_keypair_158,
        hpke_keypair_232,
    ];

    datastore
        .run_unnamed_tx(|tx| {
            let hpke_keypairs = hpke_keypairs.clone();
            Box::pin(async move {
                // Delete the keypair added by `HttpHandlerTest::new()`.
                let keypairs = tx.get_hpke_keypairs().await.unwrap();
                for keypair in keypairs {
                    tx.delete_hpke_keypair(keypair.id()).await.unwrap();
                }

                // Add keypairs and set their metadata.
                for keypair in hpke_keypairs {
                    tx.put_hpke_keypair(keypair.hpke_keypair()).await.unwrap();
                    tx.set_hpke_keypair_state(keypair.id(), keypair.state())
                        .await
                        .unwrap();
                    tx.set_hpke_keypair_last_state_change_at(
                        keypair.id(),
                        *keypair.last_state_change_at(),
                    )
                    .await
                    .unwrap();
                }

                Ok(())
            })
        })
        .await
        .unwrap();

    let aggregator = Arc::new(
        crate::aggregator::Aggregator::new(
            datastore.clone(),
            clock.clone(),
            TestRuntime::default(),
            &noop_meter(),
            Config {
                hpke_config_ciphersuite_priority,
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );
    let router = AggregatorHandlerBuilder::from_aggregator(aggregator.clone(), &noop_meter())
        .build()
        .unwrap();

    // Check that the HpkeConfigList is sorted correctly.
    let mut response = router
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
        response.headers().get("content-type").unwrap(),
        HpkeConfigList::MEDIA_TYPE
    );
    let response_body = take_response_body(&mut response).await;
    let hpke_config_list = HpkeConfigList::get_decoded(&response_body).unwrap();
    assert_eq!(hpke_config_list.hpke_configs(), expected_order);
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
