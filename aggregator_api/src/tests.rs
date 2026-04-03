use std::{iter, sync::Arc};

use assert_matches::assert_matches;
use axum::body::Body;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::future::try_join_all;
use http::{Request, StatusCode};
use janus_aggregator_core::{
    SecretBytes,
    datastore::{
        Datastore,
        models::HpkeKeyState,
        task_counters::{TaskAggregationCounter, TaskUploadCounter},
        test_util::{EphemeralDatastore, ephemeral_datastore},
    },
    task::{
        AggregationMode, AggregatorTask, AggregatorTaskParameters, BatchMode,
        test_util::TaskBuilder,
    },
    taskprov::test_util::PeerAggregatorBuilder,
    test_util::noop_meter,
};
use janus_core::{
    auth_tokens::{AuthenticationToken, AuthenticationTokenHash},
    hpke::HpkeKeypair,
    test_util::install_test_trace_subscriber,
    time::MockClock,
    vdaf::{VERIFY_KEY_LENGTH_PRIO3, VdafInstance, vdaf_dp_strategies},
};
use janus_messages::{
    Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, HpkePublicKey, Role,
    TaskId, Time, TimePrecision,
};
use rand::{RngExt, distr::StandardUniform, random, rng};
use serde_test::{Token, assert_ser_tokens, assert_tokens};
use tower::ServiceExt;
use url::Url;

use crate::{
    CONTENT_TYPE, Config, aggregator_api_handler,
    models::{
        DeleteTaskprovPeerAggregatorReq, GetTaskAggregationMetricsResp, GetTaskIdsResp,
        GetTaskUploadMetricsResp, HpkeConfigResp, PatchHpkeConfigReq, PostTaskReq,
        PostTaskprovPeerAggregatorReq, PutHpkeConfigReq, TaskResp, TaskprovPeerAggregatorResp,
    },
};

const AUTH_TOKEN: &str = "Y29sbGVjdG9yLWFiY2RlZjAw";

async fn setup_api_test() -> (axum::Router, EphemeralDatastore, Arc<Datastore<MockClock>>) {
    install_test_trace_subscriber();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(MockClock::default()).await);
    let handler = aggregator_api_handler(
        Arc::clone(&datastore),
        Config {
            auth_tokens: Vec::from([
                AuthenticationToken::new_bearer_token_from_string(AUTH_TOKEN).unwrap(),
            ]),
            public_dap_url: "https://dap.url".parse().unwrap(),
        },
        &noop_meter(),
    );

    (handler, ephemeral_datastore, datastore)
}

#[tokio::test]
async fn get_config() {
    let (handler, ..) = setup_api_test().await;
    let response = handler
        .clone()
        .oneshot(
            Request::get("/")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains(concat!(
            r#""protocol":"DAP-18","dap_url":"https://dap.url/","role":"Either","vdafs":"#,
            r#"["Prio3Count","Prio3Sum","Prio3Histogram","Prio3SumVec"],"#,
            r#""batch_modes":["TimeInterval","LeaderSelected"],"#,
            r#""features":["TokenHash","UploadMetrics","TimeBucketedLeaderSelected","#,
            r#""PureDpDiscreteLaplace","AggregationJobMetrics"],"#,
            r#""software_name":"Janus","software_version":""#,
        )),
        "{body}"
    );
}

#[tokio::test]
async fn replace_mime_types_wrong_content_type() {
    let (handler, ..) = setup_api_test().await;
    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn replace_mime_types_wrong_accept() {
    let (handler, ..) = setup_api_test().await;
    let response = handler
        .clone()
        .oneshot(
            Request::get("/")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
}

#[tokio::test]
async fn replace_mime_types_response_content_type() {
    let (handler, ..) = setup_api_test().await;
    let response = handler
        .clone()
        .oneshot(
            Request::get("/")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        CONTENT_TYPE,
    );
}

#[tokio::test]
async fn get_task_ids() {
    // Setup: write a few tasks to the datastore.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let mut task_ids: Vec<_> = ds
        .run_unnamed_tx(|tx| {
            Box::pin(async move {
                let tasks: Vec<_> = iter::repeat_with(|| {
                    TaskBuilder::new(
                        BatchMode::TimeInterval,
                        AggregationMode::Synchronous,
                        VdafInstance::Fake { rounds: 1 },
                    )
                    .build()
                    .leader_view()
                    .unwrap()
                })
                .take(10)
                .collect();

                try_join_all(tasks.iter().map(|task| tx.put_aggregator_task(task))).await?;

                Ok(tasks.into_iter().map(|task| *task.id()).collect())
            })
        })
        .await
        .unwrap();
    task_ids.sort();

    fn response_for(task_ids: &[TaskId]) -> String {
        serde_json::to_string(&GetTaskIdsResp {
            task_ids: task_ids.to_vec(),
            pagination_token: task_ids.last().cloned(),
        })
        .unwrap()
    }

    // Verify: we can get the task IDs we wrote back from the API.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/task_ids")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, response_for(&task_ids).as_bytes());

    // Verify: the lower_bound is respected, if specified.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!(
                "/task_ids?pagination_token={}",
                task_ids.first().unwrap()
            ))
            .header("authorization", format!("Bearer {AUTH_TOKEN}"))
            .header("accept", CONTENT_TYPE)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, response_for(&task_ids[1..]).as_bytes());

    // Verify: if the lower bound is large enough, nothing is returned.
    // (also verifies the "last" response will not include a pagination token)
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!(
                "/task_ids?pagination_token={}",
                task_ids.last().unwrap()
            ))
            .header("authorization", format!("Bearer {AUTH_TOKEN}"))
            .header("accept", CONTENT_TYPE)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, response_for(&[]).as_bytes());

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/task_ids")
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Verify: requests without the Accept header are denied.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/task_ids")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
}

#[tokio::test]
async fn post_task_bad_role() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;
    let time_precision = TimePrecision::from_seconds(60);

    let vdaf_verify_key = SecretBytes::new(
        rng()
            .sample_iter(StandardUniform)
            .take(VERIFY_KEY_LENGTH_PRIO3)
            .collect(),
    );
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        batch_mode: BatchMode::TimeInterval,
        aggregation_mode: None,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Collector,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        task_start: Some(Time::from_seconds_since_epoch(12300, &time_precision)),
        task_end: Some(Time::from_seconds_since_epoch(12360, &time_precision)),
        min_batch_size: 223,
        time_precision,
        collector_hpke_config: HpkeKeypair::test().config().clone(),
        aggregator_auth_token: Some(aggregator_auth_token),
        collector_auth_token_hash: Some(AuthenticationTokenHash::from(&random())),
    };
    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_task_unauthorized() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;
    let time_precision = TimePrecision::from_seconds(60);

    let vdaf_verify_key = SecretBytes::new(
        rng()
            .sample_iter(StandardUniform)
            .take(VERIFY_KEY_LENGTH_PRIO3)
            .collect(),
    );
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        batch_mode: BatchMode::TimeInterval,
        aggregation_mode: Some(AggregationMode::Synchronous),
        vdaf: VdafInstance::Prio3Count,
        role: Role::Helper,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        task_start: None,
        task_end: Some(Time::from_seconds_since_epoch(12300, &time_precision)),
        min_batch_size: 223,
        time_precision,
        collector_hpke_config: HpkeKeypair::test().config().clone(),
        aggregator_auth_token: Some(aggregator_auth_token),
        collector_auth_token_hash: Some(AuthenticationTokenHash::from(&random())),
    };
    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                // no Authorization header
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Test the POST /tasks endpoint, with a helper task with no optional fields defined
#[tokio::test]
async fn post_task_helper_no_optional_fields() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let vdaf_verify_key = SecretBytes::new(
        rng()
            .sample_iter(StandardUniform)
            .take(VERIFY_KEY_LENGTH_PRIO3)
            .collect(),
    );

    // Verify: posting a task creates a new task which matches the request.
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        batch_mode: BatchMode::TimeInterval,
        aggregation_mode: Some(AggregationMode::Synchronous),
        vdaf: VdafInstance::Prio3Count,
        role: Role::Helper,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        task_start: None,
        task_end: None,
        min_batch_size: 223,
        time_precision: TimePrecision::from_seconds(60),
        collector_hpke_config: HpkeKeypair::test().config().clone(),
        aggregator_auth_token: None,
        collector_auth_token_hash: None,
    };
    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut got_task_resp: TaskResp = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    // Task creation response will include the aggregator auth token, but it won't be in the
    // datastore or subsequent TaskResps. The token should be a Bearer token.
    assert_matches!(
        got_task_resp.aggregator_auth_token,
        Some(AuthenticationToken::Bearer(_))
    );

    let got_task = ds
        .run_unnamed_tx(|tx| {
            let got_task_resp = got_task_resp.clone();
            Box::pin(async move { tx.get_aggregator_task(&got_task_resp.task_id).await })
        })
        .await
        .unwrap()
        .expect("task was not created");

    // Verify that the task written to the datastore matches the request...
    assert_eq!(
        &req.peer_aggregator_endpoint,
        got_task.peer_aggregator_endpoint()
    );
    assert_eq!(&req.batch_mode, got_task.batch_mode());
    assert_eq!(&req.vdaf, got_task.vdaf());
    assert_eq!(&req.role, got_task.role());
    assert_eq!(req.task_end.as_ref(), got_task.task_end());
    assert_eq!(req.min_batch_size, got_task.min_batch_size());
    assert_eq!(&req.time_precision, got_task.time_precision());
    assert!(got_task.aggregator_auth_token().is_none());
    assert!(got_task.collector_auth_token_hash().is_none());
    assert_eq!(
        &req.collector_hpke_config,
        got_task.collector_hpke_config().unwrap()
    );

    // ...and the response. Clear the aggregator auth token from got_task_resp or it won't match
    // what's in the datastore, as the helper only stores the auth token _hash_.
    got_task_resp.aggregator_auth_token = None;
    assert_eq!(got_task_resp, TaskResp::try_from(&got_task).unwrap());
}

#[tokio::test]
async fn post_task_helper_with_aggregator_auth_token() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;
    let time_precision = TimePrecision::from_seconds(60);

    let vdaf_verify_key = SecretBytes::new(
        rng()
            .sample_iter(StandardUniform)
            .take(VERIFY_KEY_LENGTH_PRIO3)
            .collect(),
    );
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    // Verify: posting a task with role = helper and an aggregator auth token fails
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        batch_mode: BatchMode::TimeInterval,
        aggregation_mode: Some(AggregationMode::Synchronous),
        vdaf: VdafInstance::Prio3Count,
        role: Role::Helper,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        task_start: None,
        task_end: Some(Time::from_seconds_since_epoch(12360, &time_precision)),
        min_batch_size: 223,
        time_precision,
        collector_hpke_config: HpkeKeypair::test().config().clone(),
        aggregator_auth_token: Some(aggregator_auth_token),
        collector_auth_token_hash: None,
    };
    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_task_idempotence() {
    // Setup: create a datastore & handler.
    let (handler, ephemeral_datastore, _) = setup_api_test().await;
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;
    let time_precision = TimePrecision::from_seconds(60);

    let vdaf_verify_key = SecretBytes::new(
        rng()
            .sample_iter(StandardUniform)
            .take(VERIFY_KEY_LENGTH_PRIO3)
            .collect(),
    );
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    // Verify: posting a task creates a new task which matches the request.
    let mut req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        batch_mode: BatchMode::TimeInterval,
        aggregation_mode: Some(AggregationMode::Synchronous),
        vdaf: VdafInstance::Prio3Count,
        role: Role::Leader,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        task_start: Some(Time::from_seconds_since_epoch(12300, &time_precision)),
        task_end: Some(Time::from_seconds_since_epoch(12360, &time_precision)),
        min_batch_size: 223,
        time_precision,
        collector_hpke_config: HpkeKeypair::test().config().clone(),
        aggregator_auth_token: Some(aggregator_auth_token.clone()),
        collector_auth_token_hash: Some(AuthenticationTokenHash::from(&random())),
    };

    let post_task = || async {
        let response = handler
            .clone()
            .oneshot(
                Request::post("/tasks")
                    .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                    .header("accept", CONTENT_TYPE)
                    .header("content-type", CONTENT_TYPE)
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice::<TaskResp>(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    };

    let first_task_resp = post_task().await;
    let second_task_resp = post_task().await;

    assert_eq!(first_task_resp.task_id, second_task_resp.task_id);
    assert_eq!(
        first_task_resp.vdaf_verify_key,
        second_task_resp.vdaf_verify_key
    );

    let got_tasks = ds
        .run_unnamed_tx(|tx| Box::pin(async move { tx.get_aggregator_tasks().await }))
        .await
        .unwrap();

    assert!(got_tasks.len() == 1);
    assert_eq!(got_tasks[0].id(), &first_task_resp.task_id);

    // Mutate the PostTaskReq and re-send it.
    req.min_batch_size = 332;
    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// Test the POST /tasks endpoint, with a leader task with all of the optional fields provided.
#[tokio::test]
async fn post_task_leader_all_optional_fields() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;
    let time_precision = TimePrecision::from_seconds(60);

    let vdaf_verify_key = SecretBytes::new(
        rng()
            .sample_iter(StandardUniform)
            .take(VERIFY_KEY_LENGTH_PRIO3)
            .collect(),
    );
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());
    let collector_auth_token_hash = AuthenticationTokenHash::from(&random());
    // Verify: posting a task creates a new task which matches the request.
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        batch_mode: BatchMode::TimeInterval,
        aggregation_mode: Some(AggregationMode::Synchronous),
        vdaf: VdafInstance::Prio3Count,
        role: Role::Leader,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        task_start: None,
        task_end: Some(Time::from_seconds_since_epoch(12360, &time_precision)),
        min_batch_size: 223,
        time_precision,
        collector_hpke_config: HpkeKeypair::test().config().clone(),
        aggregator_auth_token: Some(aggregator_auth_token.clone()),
        collector_auth_token_hash: Some(collector_auth_token_hash.clone()),
    };
    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got_task_resp: TaskResp = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    let got_task = ds
        .run_unnamed_tx(|tx| {
            let got_task_resp = got_task_resp.clone();
            Box::pin(async move { tx.get_aggregator_task(&got_task_resp.task_id).await })
        })
        .await
        .unwrap()
        .expect("task was not created");

    // Verify that the task written to the datastore matches the request...
    assert_eq!(
        &req.peer_aggregator_endpoint,
        got_task.peer_aggregator_endpoint()
    );
    assert_eq!(&req.batch_mode, got_task.batch_mode());
    assert_eq!(&req.vdaf, got_task.vdaf());
    assert_eq!(&req.role, got_task.role());
    assert_eq!(&vdaf_verify_key, got_task.opaque_vdaf_verify_key());
    assert_eq!(req.task_end.as_ref(), got_task.task_end());
    assert_eq!(req.min_batch_size, got_task.min_batch_size());
    assert_eq!(&req.time_precision, got_task.time_precision());
    assert_eq!(
        &req.collector_hpke_config,
        got_task.collector_hpke_config().unwrap()
    );
    assert_eq!(
        aggregator_auth_token.as_ref(),
        got_task.aggregator_auth_token().unwrap().as_ref()
    );
    assert_eq!(
        got_task.collector_auth_token_hash().unwrap(),
        &collector_auth_token_hash
    );

    // ...and the response.
    assert_eq!(got_task_resp, TaskResp::try_from(&got_task).unwrap());
}

/// Test the POST /tasks endpoint, with a leader task with all of the optional fields provided.
#[tokio::test]
async fn post_task_leader_no_aggregator_auth_token() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;
    let time_precision = TimePrecision::from_seconds(60);

    let vdaf_verify_key = SecretBytes::new(
        rng()
            .sample_iter(StandardUniform)
            .take(VERIFY_KEY_LENGTH_PRIO3)
            .collect(),
    );

    // Verify: posting a task with role = Leader and no aggregator auth token fails
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        batch_mode: BatchMode::TimeInterval,
        aggregation_mode: Some(AggregationMode::Synchronous),
        vdaf: VdafInstance::Prio3Count,
        role: Role::Leader,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        task_start: Some(Time::from_seconds_since_epoch(12300, &time_precision)),
        task_end: Some(Time::from_seconds_since_epoch(12360, &time_precision)),
        min_batch_size: 223,
        time_precision,
        collector_hpke_config: HpkeKeypair::test().config().clone(),
        aggregator_auth_token: None,
        collector_auth_token_hash: Some(AuthenticationTokenHash::from(&random())),
    };

    let response = handler
        .clone()
        .oneshot(
            Request::post("/tasks")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[rstest::rstest]
#[case::leader(Role::Leader)]
#[case::helper(Role::Helper)]
#[tokio::test]
async fn get_task(#[case] role: Role) {
    // Setup: write a task to the datastore.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .build()
    .view_for_role(role)
    .unwrap();

    ds.put_aggregator_task(&task).await.unwrap();

    // Verify: getting the task returns the expected result.
    let want_task_resp = TaskResp::try_from(&task).unwrap();
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{}", task.id()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got_task_resp = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(want_task_resp, got_task_resp);

    // Verify: getting a nonexistent task returns NotFound.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{}", random::<TaskId>()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{}", task.id()))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_task() {
    // Setup: write a task to the datastore.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let task_id = ds
        .run_unnamed_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    BatchMode::TimeInterval,
                    AggregationMode::Synchronous,
                    VdafInstance::Fake { rounds: 1 },
                )
                .build()
                .leader_view()
                .unwrap();

                tx.put_aggregator_task(&task).await?;

                Ok(*task.id())
            })
        })
        .await
        .unwrap();

    // Verify: deleting a task succeeds (and actually deletes the task).
    let response = handler
        .clone()
        .oneshot(
            Request::delete(format!("/tasks/{}", &task_id))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    ds.run_unnamed_tx(|tx| {
        Box::pin(async move {
            assert_eq!(tx.get_aggregator_task(&task_id).await.unwrap(), None);
            Ok(())
        })
    })
    .await
    .unwrap();

    // Verify: deleting a task twice returns NoContent.
    let response = handler
        .clone()
        .oneshot(
            Request::delete(format!("/tasks/{}", &task_id))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify: deleting an arbitrary nonexistent task ID returns NoContent.
    let response = handler
        .clone()
        .oneshot(
            Request::delete(format!("/tasks/{}", &random::<TaskId>()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::delete(format!("/tasks/{}", &task_id))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest::rstest]
#[case::leader(Role::Leader)]
#[case::helper(Role::Helper)]
#[tokio::test]
async fn patch_task(#[case] role: Role) {
    // Setup: write a task to the datastore.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let time_precision = TimePrecision::from_seconds(100);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_time_precision(time_precision)
    .with_task_end(Some(Time::from_time_precision_units(10)))
    .build()
    .view_for_role(role)
    .unwrap();

    ds.put_aggregator_task(&task).await.unwrap();
    let task_id = *task.id();

    // Verify: patching the task with empty body does nothing.
    let want_task_resp = TaskResp::try_from(&task).unwrap();
    let response = handler
        .clone()
        .oneshot(
            Request::patch(format!("/tasks/{}", task.id()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got_task_resp = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(want_task_resp, got_task_resp);
    let task = ds
        .run_unnamed_tx(|tx| Box::pin(async move { tx.get_aggregator_task(&task_id).await }))
        .await
        .unwrap();
    assert_eq!(
        task.unwrap().task_end(),
        Some(&Time::from_seconds_since_epoch(1000, &time_precision))
    );

    // Verify: patching the task with a null task end time returns the expected result.
    let response = handler
        .clone()
        .oneshot(
            Request::patch(format!("/tasks/{task_id}"))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(r#"{"task_end": null}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got_task_resp: TaskResp = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(got_task_resp.task_end, None);
    let task = ds
        .run_unnamed_tx(|tx| Box::pin(async move { tx.get_aggregator_task(&task_id).await }))
        .await
        .unwrap();
    assert_eq!(task.unwrap().task_end(), None);

    // Verify: patching the task with a task end time returns the expected result.
    let expected_time = Some(Time::from_seconds_since_epoch(2000, &time_precision));
    let response = handler
        .clone()
        .oneshot(
            Request::patch(format!("/tasks/{task_id}"))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(r#"{"task_end": 20}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got_task_resp: TaskResp = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(got_task_resp.task_end, expected_time);
    let task = ds
        .run_unnamed_tx(|tx| Box::pin(async move { tx.get_aggregator_task(&task_id).await }))
        .await
        .unwrap();
    assert_eq!(task.unwrap().task_end(), expected_time.as_ref());

    // Verify: patching a nonexistent task returns NotFound.
    let response = handler
        .clone()
        .oneshot(
            Request::patch(format!("/tasks/{}", random::<TaskId>()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::patch(format!("/tasks/{task_id}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_task_upload_metrics() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;
    let task_id = ds
        .run_unnamed_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    BatchMode::TimeInterval,
                    AggregationMode::Synchronous,
                    VdafInstance::Fake { rounds: 1 },
                )
                .build()
                .leader_view()
                .unwrap();
                let task_id = *task.id();
                tx.put_aggregator_task(&task).await.unwrap();

                Ok(task_id)
            })
        })
        .await
        .unwrap();

    // Verify: requesting metrics on a fresh task returns zeroes.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{}/metrics/uploads", &task_id))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body,
        serde_json::to_string(&GetTaskUploadMetricsResp(TaskUploadCounter::default()))
            .unwrap()
            .as_bytes()
    );

    // Verify: requesting metrics on a task returns the correct result.
    ds.run_unnamed_tx(|tx| {
        Box::pin(async move {
            TaskUploadCounter::new_with_values(0, 0, 2, 4, 6, 100, 25, 22, 12, 0)
                .flush(&task_id, tx, 1)
                .await
        })
    })
    .await
    .unwrap();
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{}/metrics/uploads", &task_id))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body,
        serde_json::to_string(&GetTaskUploadMetricsResp(
            TaskUploadCounter::new_with_values(0, 0, 2, 4, 6, 100, 25, 22, 12, 0)
        ))
        .unwrap()
        .as_bytes()
    );

    // Verify: requesting metrics on a nonexistent task returns NotFound.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{}/metrics/uploads", &random::<TaskId>()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{}/metrics/uploads", &task_id))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_task_aggregation_metrics() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;
    let task_id = ds
        .run_unnamed_tx(|tx| {
            Box::pin(async move {
                let task = TaskBuilder::new(
                    BatchMode::TimeInterval,
                    AggregationMode::Synchronous,
                    VdafInstance::Fake { rounds: 1 },
                )
                .build()
                .leader_view()
                .unwrap();
                let task_id = *task.id();
                tx.put_aggregator_task(&task).await.unwrap();

                Ok(task_id)
            })
        })
        .await
        .unwrap();

    // Verify: requesting metrics on a fresh task returns zeroes.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{task_id}/metrics/aggregations"))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body,
        serde_json::to_string(&GetTaskAggregationMetricsResp(
            TaskAggregationCounter::default()
        ))
        .unwrap()
        .as_bytes()
    );

    // Verify: requesting metrics on a task returns the correct result.
    ds.run_unnamed_tx(|tx| {
        Box::pin(async move {
            TaskAggregationCounter::default()
                .with_success(15)
                .with_helper_hpke_decrypt_failure(100)
                .flush(&task_id, tx, 5)
                .await
        })
    })
    .await
    .unwrap();
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{task_id}/metrics/aggregations"))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body,
        serde_json::to_string(&GetTaskAggregationMetricsResp(
            TaskAggregationCounter::default()
                .with_success(15)
                .with_helper_hpke_decrypt_failure(100)
        ))
        .unwrap()
        .as_bytes()
    );

    // Verify: requesting metrics on a nonexistent task returns NotFound.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!(
                "/tasks/{}/metrics/aggregations",
                &random::<TaskId>()
            ))
            .header("authorization", format!("Bearer {AUTH_TOKEN}"))
            .header("accept", CONTENT_TYPE)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::get(format!("/tasks/{task_id}/metrics/aggregations"))
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_hpke_configs() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let response = handler
        .clone()
        .oneshot(
            Request::get("/hpke_configs")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let resp: Vec<HpkeConfigResp> = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resp, vec![]);

    let keypair1_id: u8 = random();
    let keypair1 = HpkeKeypair::test_with_id(HpkeConfigId::from(keypair1_id));
    let keypair2 = HpkeKeypair::generate(
        HpkeConfigId::from(keypair1_id.wrapping_add(1)),
        HpkeKemId::P256HkdfSha256,
        HpkeKdfId::HkdfSha384,
        HpkeAeadId::Aes128Gcm,
    )
    .unwrap();
    ds.run_unnamed_tx(|tx| {
        let keypair1 = keypair1.clone();
        let keypair2 = keypair2.clone();
        Box::pin(async move {
            tx.put_hpke_keypair(&keypair1).await?;
            tx.put_hpke_keypair(&keypair2).await?;
            tx.set_hpke_keypair_state(keypair2.config().id(), &HpkeKeyState::Active)
                .await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    let response = handler
        .clone()
        .oneshot(
            Request::get("/hpke_configs")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut resp: Vec<HpkeConfigResp> = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    resp.sort_by(|a, b| a.config.id().cmp(b.config.id()));

    let mut expected = vec![
        HpkeConfigResp {
            config: keypair1.config().clone(),
            state: HpkeKeyState::Pending,
        },
        HpkeConfigResp {
            config: keypair2.config().clone(),
            state: HpkeKeyState::Active,
        },
    ];
    expected.sort_by(|a, b| a.config.id().cmp(b.config.id()));

    assert_eq!(resp, expected);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/hpke_configs")
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    // Verify: non-existent key.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/hpke_configs/123")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify: overflow u8.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/hpke_configs/1234310294")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/hpke_configs/123")
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let keypair1_id: u8 = random();
    let keypair1 = HpkeKeypair::test_with_id(HpkeConfigId::from(keypair1_id));
    let keypair2 = HpkeKeypair::generate(
        HpkeConfigId::from(keypair1_id.wrapping_add(1)),
        HpkeKemId::P256HkdfSha256,
        HpkeKdfId::HkdfSha384,
        HpkeAeadId::Aes128Gcm,
    )
    .unwrap();
    ds.run_unnamed_tx(|tx| {
        let keypair1 = keypair1.clone();
        let keypair2 = keypair2.clone();
        Box::pin(async move {
            tx.put_hpke_keypair(&keypair1).await?;
            tx.put_hpke_keypair(&keypair2).await?;
            tx.set_hpke_keypair_state(keypair2.config().id(), &HpkeKeyState::Active)
                .await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    for (key, state) in [
        (keypair1, HpkeKeyState::Pending),
        (keypair2, HpkeKeyState::Active),
    ] {
        let response = handler
            .clone()
            .oneshot(
                Request::get(format!("/hpke_configs/{}", key.config().id()))
                    .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                    .header("accept", CONTENT_TYPE)
                    .header("content-type", CONTENT_TYPE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp: HpkeConfigResp = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            resp,
            HpkeConfigResp {
                config: key.config().clone(),
                state,
            },
        );
    }
}

#[tokio::test]
async fn put_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    // No custom parameters.
    let key1_response = handler
        .clone()
        .oneshot(
            Request::put("/hpke_configs")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(key1_response.status(), StatusCode::CREATED);
    let key1: HpkeConfigResp = serde_json::from_slice(
        &axum::body::to_bytes(key1_response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    // Choose some custom non-default ciphers.
    let key2_req = PutHpkeConfigReq {
        kem_id: Some(HpkeKemId::X25519HkdfSha256),
        kdf_id: Some(HpkeKdfId::HkdfSha512),
        aead_id: Some(HpkeAeadId::ChaCha20Poly1305),
    };
    let key2_response = handler
        .clone()
        .oneshot(
            Request::put("/hpke_configs")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&key2_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(key2_response.status(), StatusCode::CREATED);
    let key2: HpkeConfigResp = serde_json::from_slice(
        &axum::body::to_bytes(key2_response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    let (got_key1, got_key2) = ds
        .run_unnamed_tx(|tx| {
            let key1 = key1.config.clone();
            let key2 = key2.config.clone();
            Box::pin(async move {
                Ok((
                    tx.get_hpke_keypair(key1.id()).await?,
                    tx.get_hpke_keypair(key2.id()).await?,
                ))
            })
        })
        .await
        .unwrap();

    assert_eq!(
        key1,
        HpkeConfigResp {
            config: got_key1.unwrap().hpke_keypair().config().clone(),
            state: HpkeKeyState::Pending,
        }
    );

    assert_eq!(
        key2,
        HpkeConfigResp {
            config: got_key2.unwrap().hpke_keypair().config().clone(),
            state: HpkeKeyState::Pending,
        }
    );

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::put("/hpke_configs")
                .header("accept", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let req = PatchHpkeConfigReq {
        state: HpkeKeyState::Active,
    };

    // Verify: non-existent key.
    let response = handler
        .clone()
        .oneshot(
            Request::patch("/hpke_configs/123")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify: overflow u8.
    let response = handler
        .clone()
        .oneshot(
            Request::patch("/hpke_configs/1234310294")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Verify: invalid body.
    let response = handler
        .clone()
        .oneshot(
            Request::patch("/hpke_configs/123")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::patch("/hpke_configs/123")
                .header("accept", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let keypair = HpkeKeypair::test();
    ds.run_unnamed_tx(|tx| {
        let keypair = keypair.clone();
        Box::pin(async move { tx.put_hpke_keypair(&keypair).await })
    })
    .await
    .unwrap();

    let response = handler
        .clone()
        .oneshot(
            Request::patch(format!("/hpke_configs/{}", keypair.config().id()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let got_key = ds
        .run_unnamed_tx(|tx| {
            let keypair = keypair.clone();
            Box::pin(async move { tx.get_hpke_keypair(keypair.config().id()).await })
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got_key.state(), &HpkeKeyState::Active);
}

#[tokio::test]
async fn delete_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let req = PatchHpkeConfigReq {
        state: HpkeKeyState::Active,
    };

    // Verify: non-existent key.
    let response = handler
        .clone()
        .oneshot(
            Request::delete("/hpke_configs/123")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify: overflow u8.
    let response = handler
        .clone()
        .oneshot(
            Request::delete("/hpke_configs/1234310294")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Verify: unauthorized requests are denied appropriately.
    let response = handler
        .clone()
        .oneshot(
            Request::delete("/hpke_configs/123")
                .header("accept", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let keypair = HpkeKeypair::test();
    ds.run_unnamed_tx(|tx| {
        let keypair = keypair.clone();
        Box::pin(async move { tx.put_hpke_keypair(&keypair).await })
    })
    .await
    .unwrap();

    let response = handler
        .clone()
        .oneshot(
            Request::delete(format!("/hpke_configs/{}", keypair.config().id()))
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        ds.run_unnamed_tx(|tx| Box::pin(async move { tx.get_hpke_keypairs().await }))
            .await
            .unwrap(),
        vec![]
    );
}

#[tokio::test]
async fn get_taskprov_peer_aggregator() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let leader = PeerAggregatorBuilder::new()
        .with_endpoint(Url::parse("https://leader.example.com/").unwrap())
        .with_peer_role(Role::Leader)
        .build()
        .unwrap();
    let helper = PeerAggregatorBuilder::new()
        .with_endpoint(Url::parse("https://helper.example.com/").unwrap())
        .with_peer_role(Role::Helper)
        .build()
        .unwrap();

    ds.run_unnamed_tx(|tx| {
        let leader = leader.clone();
        let helper = helper.clone();
        Box::pin(async move {
            tx.put_taskprov_peer_aggregator(&leader).await?;
            tx.put_taskprov_peer_aggregator(&helper).await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    // List all.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/taskprov/peer_aggregators")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut resp: Vec<TaskprovPeerAggregatorResp> = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    resp.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));

    let mut expected = vec![
        TaskprovPeerAggregatorResp {
            endpoint: leader.endpoint().clone(),
            peer_role: *leader.peer_role(),
            collector_hpke_config: leader.collector_hpke_config().clone(),
            report_expiry_age: leader.report_expiry_age().map(|d| d.num_seconds()),
        },
        TaskprovPeerAggregatorResp {
            endpoint: helper.endpoint().clone(),
            peer_role: *helper.peer_role(),
            collector_hpke_config: helper.collector_hpke_config().clone(),
            report_expiry_age: helper.report_expiry_age().map(|d| d.num_seconds()),
        },
    ];
    expected.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));

    assert_eq!(resp, expected);

    // Missing authorization.
    let response = handler
        .clone()
        .oneshot(
            Request::get("/taskprov/peer_aggregators")
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_taskprov_peer_aggregator() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let endpoint = Url::parse("https://leader.example.com/").unwrap();
    let leader = PeerAggregatorBuilder::new()
        .with_endpoint(endpoint.clone())
        .with_peer_role(Role::Leader)
        .build()
        .unwrap();

    let req = PostTaskprovPeerAggregatorReq {
        endpoint,
        peer_role: Role::Leader,
        aggregation_mode: Some(AggregationMode::Synchronous),
        collector_hpke_config: leader.collector_hpke_config().clone(),
        verify_key_init: *leader.verify_key_init(),
        report_expiry_age: leader.report_expiry_age().map(|d| d.num_seconds() as u64),
        aggregator_auth_tokens: Vec::from(leader.aggregator_auth_tokens()),
        collector_auth_tokens: Vec::from(leader.collector_auth_tokens()),
    };

    let response = handler
        .clone()
        .oneshot(
            Request::post("/taskprov/peer_aggregators")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        serde_json::from_slice::<TaskprovPeerAggregatorResp>(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap(),
        leader.clone().into()
    );

    assert_eq!(
        ds.run_unnamed_tx(|tx| {
            Box::pin(async move { tx.get_taskprov_peer_aggregators().await })
        })
        .await
        .unwrap(),
        vec![leader]
    );

    // Can't insert the same aggregator.
    let response = handler
        .clone()
        .oneshot(
            Request::post("/taskprov/peer_aggregators")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Missing authorization.
    let response = handler
        .clone()
        .oneshot(
            Request::post("/taskprov/peer_aggregators")
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_taskprov_peer_aggregator() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let endpoint = Url::parse("https://leader.example.com/").unwrap();
    let leader = PeerAggregatorBuilder::new()
        .with_endpoint(endpoint.clone())
        .with_peer_role(Role::Leader)
        .build()
        .unwrap();

    ds.run_unnamed_tx(|tx| {
        let leader = leader.clone();
        Box::pin(async move { tx.put_taskprov_peer_aggregator(&leader).await })
    })
    .await
    .unwrap();

    let req = DeleteTaskprovPeerAggregatorReq {
        endpoint,
        peer_role: Role::Leader,
    };

    // Delete target.
    let response = handler
        .clone()
        .oneshot(
            Request::delete("/taskprov/peer_aggregators")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        ds.run_unnamed_tx(|tx| {
            Box::pin(async move { tx.get_taskprov_peer_aggregators().await })
        })
        .await
        .unwrap(),
        vec![]
    );

    // Non-existent target.
    let response = handler
        .clone()
        .oneshot(
            Request::delete("/taskprov/peer_aggregators")
                .header("authorization", format!("Bearer {AUTH_TOKEN}"))
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::from(
                    serde_json::to_vec(&DeleteTaskprovPeerAggregatorReq {
                        endpoint: Url::parse("https://doesnt-exist.example.com/").unwrap(),
                        peer_role: Role::Leader,
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Missing authorization.
    let response = handler
        .clone()
        .oneshot(
            Request::delete("/taskprov/peer_aggregators")
                .header("accept", CONTENT_TYPE)
                .header("content-type", CONTENT_TYPE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn get_task_ids_resp_serialization() {
    assert_ser_tokens(
        &GetTaskIdsResp {
            task_ids: Vec::from([TaskId::from([0u8; 32])]),
            pagination_token: None,
        },
        &[
            Token::Struct {
                name: "GetTaskIdsResp",
                len: 1,
            },
            Token::Str("task_ids"),
            Token::Seq { len: Some(1) },
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::SeqEnd,
            Token::StructEnd,
        ],
    );
    assert_ser_tokens(
        &GetTaskIdsResp {
            task_ids: Vec::from([TaskId::from([0u8; 32])]),
            pagination_token: Some(TaskId::from([0u8; 32])),
        },
        &[
            Token::Struct {
                name: "GetTaskIdsResp",
                len: 2,
            },
            Token::Str("task_ids"),
            Token::Seq { len: Some(1) },
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::SeqEnd,
            Token::Str("pagination_token"),
            Token::Some,
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::StructEnd,
        ],
    );
}

#[test]
fn post_task_req_serialization() {
    let time_precision = TimePrecision::from_seconds(3600);
    // helper request with optional fields omitted
    assert_tokens(
        &PostTaskReq {
            peer_aggregator_endpoint: "https://example.com/".parse().unwrap(),
            batch_mode: BatchMode::LeaderSelected {
                batch_time_window_size: None,
            },
            aggregation_mode: Some(AggregationMode::Synchronous),
            vdaf: VdafInstance::Prio3SumVec {
                max_measurement: 4096,
                length: 5,
                chunk_length: 2,
                dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
            },
            role: Role::Helper,
            vdaf_verify_key: "encoded".to_owned(),
            task_start: None,
            task_end: None,
            min_batch_size: 100,
            time_precision,
            collector_hpke_config: HpkeConfig::new(
                HpkeConfigId::from(7),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
                HpkePublicKey::from([0u8; 32].to_vec()),
            ),
            aggregator_auth_token: None,
            collector_auth_token_hash: None,
        },
        &[
            Token::Struct {
                name: "PostTaskReq",
                len: 13,
            },
            Token::Str("peer_aggregator_endpoint"),
            Token::Str("https://example.com/"),
            Token::Str("batch_mode"),
            Token::StructVariant {
                name: "BatchMode",
                variant: "LeaderSelected",
                len: 1,
            },
            Token::Str("batch_time_window_size"),
            Token::None,
            Token::StructVariantEnd,
            Token::Str("aggregation_mode"),
            Token::Some,
            Token::UnitVariant {
                name: "AggregationMode",
                variant: "Synchronous",
            },
            Token::Str("vdaf"),
            Token::StructVariant {
                name: "VdafInstance",
                variant: "Prio3SumVec",
                len: 4,
            },
            Token::Str("max_measurement"),
            Token::U64(4096),
            Token::Str("length"),
            Token::U64(5),
            Token::Str("chunk_length"),
            Token::U64(2),
            Token::Str("dp_strategy"),
            Token::Struct {
                name: "Prio3SumVec",
                len: 1,
            },
            Token::Str("dp_strategy"),
            Token::Str("NoDifferentialPrivacy"),
            Token::StructEnd,
            Token::StructVariantEnd,
            Token::Str("role"),
            Token::UnitVariant {
                name: "Role",
                variant: "Helper",
            },
            Token::Str("vdaf_verify_key"),
            Token::Str("encoded"),
            Token::Str("task_start"),
            Token::None,
            Token::Str("task_end"),
            Token::None,
            Token::Str("min_batch_size"),
            Token::U64(100),
            Token::Str("time_precision"),
            Token::NewtypeStruct {
                name: "TimePrecision",
            },
            Token::U64(3600),
            Token::Str("collector_hpke_config"),
            Token::Struct {
                name: "HpkeConfig",
                len: 5,
            },
            Token::Str("id"),
            Token::NewtypeStruct {
                name: "HpkeConfigId",
            },
            Token::U8(7),
            Token::Str("kem_id"),
            Token::UnitVariant {
                name: "HpkeKemId",
                variant: "X25519HkdfSha256",
            },
            Token::Str("kdf_id"),
            Token::UnitVariant {
                name: "HpkeKdfId",
                variant: "HkdfSha256",
            },
            Token::Str("aead_id"),
            Token::UnitVariant {
                name: "HpkeAeadId",
                variant: "Aes128Gcm",
            },
            Token::Str("public_key"),
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::StructEnd,
            Token::Str("aggregator_auth_token"),
            Token::None,
            Token::Str("collector_auth_token_hash"),
            Token::None,
            Token::StructEnd,
        ],
    );

    // leader request with optional fields set
    assert_tokens(
        &PostTaskReq {
            peer_aggregator_endpoint: "https://example.com/".parse().unwrap(),
            batch_mode: BatchMode::LeaderSelected {
                batch_time_window_size: None,
            },
            aggregation_mode: None,
            vdaf: VdafInstance::Prio3SumVec {
                max_measurement: 4096,
                length: 5,
                chunk_length: 2,
                dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
            },
            role: Role::Leader,
            vdaf_verify_key: "encoded".to_owned(),
            task_start: Some(Time::from_time_precision_units(42)),
            task_end: Some(Time::from_time_precision_units(67)),
            min_batch_size: 100,
            time_precision,
            collector_hpke_config: HpkeConfig::new(
                HpkeConfigId::from(7),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
                HpkePublicKey::from([0u8; 32].to_vec()),
            ),
            aggregator_auth_token: Some(
                AuthenticationToken::new_dap_auth_token_from_string("ZW5jb2RlZA").unwrap(),
            ),
            collector_auth_token_hash: Some(AuthenticationTokenHash::from(
                &AuthenticationToken::new_dap_auth_token_from_string("ZW5jb2RlZA").unwrap(),
            )),
        },
        &[
            Token::Struct {
                name: "PostTaskReq",
                len: 13,
            },
            Token::Str("peer_aggregator_endpoint"),
            Token::Str("https://example.com/"),
            Token::Str("batch_mode"),
            Token::StructVariant {
                name: "BatchMode",
                variant: "LeaderSelected",
                len: 1,
            },
            Token::Str("batch_time_window_size"),
            Token::None,
            Token::StructVariantEnd,
            Token::Str("aggregation_mode"),
            Token::None,
            Token::Str("vdaf"),
            Token::StructVariant {
                name: "VdafInstance",
                variant: "Prio3SumVec",
                len: 4,
            },
            Token::Str("max_measurement"),
            Token::U64(4096),
            Token::Str("length"),
            Token::U64(5),
            Token::Str("chunk_length"),
            Token::U64(2),
            Token::Str("dp_strategy"),
            Token::Struct {
                name: "Prio3SumVec",
                len: 1,
            },
            Token::Str("dp_strategy"),
            Token::Str("NoDifferentialPrivacy"),
            Token::StructEnd,
            Token::StructVariantEnd,
            Token::Str("role"),
            Token::UnitVariant {
                name: "Role",
                variant: "Leader",
            },
            Token::Str("vdaf_verify_key"),
            Token::Str("encoded"),
            Token::Str("task_start"),
            Token::Some,
            Token::NewtypeStruct { name: "Time" },
            Token::U64(42),
            Token::Str("task_end"),
            Token::Some,
            Token::NewtypeStruct { name: "Time" },
            Token::U64(67),
            Token::Str("min_batch_size"),
            Token::U64(100),
            Token::Str("time_precision"),
            Token::NewtypeStruct {
                name: "TimePrecision",
            },
            Token::U64(3600),
            Token::Str("collector_hpke_config"),
            Token::Struct {
                name: "HpkeConfig",
                len: 5,
            },
            Token::Str("id"),
            Token::NewtypeStruct {
                name: "HpkeConfigId",
            },
            Token::U8(7),
            Token::Str("kem_id"),
            Token::UnitVariant {
                name: "HpkeKemId",
                variant: "X25519HkdfSha256",
            },
            Token::Str("kdf_id"),
            Token::UnitVariant {
                name: "HpkeKdfId",
                variant: "HkdfSha256",
            },
            Token::Str("aead_id"),
            Token::UnitVariant {
                name: "HpkeAeadId",
                variant: "Aes128Gcm",
            },
            Token::Str("public_key"),
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::StructEnd,
            Token::Str("aggregator_auth_token"),
            Token::Some,
            Token::Struct {
                name: "AuthenticationToken",
                len: 2,
            },
            Token::Str("type"),
            Token::UnitVariant {
                name: "AuthenticationToken",
                variant: "DapAuth",
            },
            Token::Str("token"),
            Token::Str("ZW5jb2RlZA"),
            Token::StructEnd,
            Token::Str("collector_auth_token_hash"),
            Token::Some,
            Token::Struct {
                name: "AuthenticationTokenHash",
                len: 2,
            },
            Token::Str("type"),
            Token::UnitVariant {
                name: "AuthenticationTokenHash",
                variant: "DapAuth",
            },
            Token::Str("hash"),
            Token::Str("hT_ixzv_X1CmJmHGT7jYSEBbdB-CN9H8WxAvjgv4rms"),
            Token::StructEnd,
            Token::StructEnd,
        ],
    );
}

#[test]
fn task_resp_serialization() {
    let time_precision = TimePrecision::from_seconds(3600);
    let task = AggregatorTask::new(
        TaskId::from([0u8; 32]),
        "https://helper.com/".parse().unwrap(),
        BatchMode::LeaderSelected {
            batch_time_window_size: None,
        },
        VdafInstance::Prio3SumVec {
            max_measurement: 4096,
            length: 5,
            chunk_length: 2,
            dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
        },
        SecretBytes::new(b"vdaf verify key!".to_vec()),
        None,
        None,
        None,
        100,
        time_precision,
        Duration::from_time_precision_units(11),
        AggregatorTaskParameters::Leader {
            aggregator_auth_token: AuthenticationToken::new_dap_auth_token_from_string(
                "Y29sbGVjdG9yLWFiY2RlZjAw",
            )
            .unwrap(),
            collector_auth_token_hash: AuthenticationTokenHash::from(
                &AuthenticationToken::new_dap_auth_token_from_string("Y29sbGVjdG9yLWFiY2RlZjAw")
                    .unwrap(),
            ),
            collector_hpke_config: HpkeConfig::new(
                HpkeConfigId::from(7),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
                HpkePublicKey::from([0u8; 32].to_vec()),
            ),
        },
    )
    .unwrap();
    assert_tokens(
        &TaskResp::try_from(&task).unwrap(),
        &[
            Token::Struct {
                name: "TaskResp",
                len: 14,
            },
            Token::Str("task_id"),
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::Str("peer_aggregator_endpoint"),
            Token::Str("https://helper.com/"),
            Token::Str("batch_mode"),
            Token::StructVariant {
                name: "BatchMode",
                variant: "LeaderSelected",
                len: 1,
            },
            Token::Str("batch_time_window_size"),
            Token::None,
            Token::StructVariantEnd,
            Token::Str("vdaf"),
            Token::StructVariant {
                name: "VdafInstance",
                variant: "Prio3SumVec",
                len: 4,
            },
            Token::Str("max_measurement"),
            Token::U64(4096),
            Token::Str("length"),
            Token::U64(5),
            Token::Str("chunk_length"),
            Token::U64(2),
            Token::Str("dp_strategy"),
            Token::Struct {
                name: "Prio3SumVec",
                len: 1,
            },
            Token::Str("dp_strategy"),
            Token::Str("NoDifferentialPrivacy"),
            Token::StructEnd,
            Token::StructVariantEnd,
            Token::Str("role"),
            Token::UnitVariant {
                name: "Role",
                variant: "Leader",
            },
            Token::Str("vdaf_verify_key"),
            Token::Str("dmRhZiB2ZXJpZnkga2V5IQ"),
            Token::Str("task_start"),
            Token::None,
            Token::Str("task_end"),
            Token::None,
            Token::Str("report_expiry_age"),
            Token::None,
            Token::Str("min_batch_size"),
            Token::U64(100),
            Token::Str("time_precision"),
            Token::NewtypeStruct {
                name: "TimePrecision",
            },
            Token::U64(3600),
            Token::Str("tolerable_clock_skew"),
            Token::NewtypeStruct { name: "Duration" },
            Token::U64(11),
            Token::Str("aggregator_auth_token"),
            Token::None,
            Token::Str("collector_hpke_config"),
            Token::Struct {
                name: "HpkeConfig",
                len: 5,
            },
            Token::Str("id"),
            Token::NewtypeStruct {
                name: "HpkeConfigId",
            },
            Token::U8(7),
            Token::Str("kem_id"),
            Token::UnitVariant {
                name: "HpkeKemId",
                variant: "X25519HkdfSha256",
            },
            Token::Str("kdf_id"),
            Token::UnitVariant {
                name: "HpkeKdfId",
                variant: "HkdfSha256",
            },
            Token::Str("aead_id"),
            Token::UnitVariant {
                name: "HpkeAeadId",
                variant: "Aes128Gcm",
            },
            Token::Str("public_key"),
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::StructEnd,
            Token::StructEnd,
        ],
    );
}

#[test]
fn get_task_upload_metrics_serialization() {
    assert_ser_tokens(
        &GetTaskUploadMetricsResp(TaskUploadCounter::new_with_values(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        )),
        &[
            Token::NewtypeStruct {
                name: "GetTaskUploadMetricsResp",
            },
            Token::Struct {
                name: "TaskUploadCounter",
                len: 10,
            },
            Token::Str("interval_collected"),
            Token::U64(0),
            Token::Str("report_decode_failure"),
            Token::U64(1),
            Token::Str("report_decrypt_failure"),
            Token::U64(2),
            Token::Str("report_expired"),
            Token::U64(3),
            Token::Str("report_outdated_key"),
            Token::U64(4),
            Token::Str("report_success"),
            Token::U64(5),
            Token::Str("report_too_early"),
            Token::U64(6),
            Token::Str("task_not_started"),
            Token::U64(7),
            Token::Str("task_ended"),
            Token::U64(8),
            Token::Str("duplicate_extension"),
            Token::U64(9),
            Token::StructEnd,
        ],
    )
}
