use crate::{
    aggregator_api_handler,
    models::{
        DeleteTaskprovPeerAggregatorReq, GetTaskIdsResp, GetTaskMetricsResp, GlobalHpkeConfigResp,
        PatchGlobalHpkeConfigReq, PostTaskReq, PostTaskprovPeerAggregatorReq,
        PutGlobalHpkeConfigReq, TaskResp, TaskprovPeerAggregatorResp,
    },
    Config, CONTENT_TYPE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::{
        models::{
            AggregationJob, AggregationJobState, HpkeKeyState, LeaderStoredReport,
            ReportAggregation, ReportAggregationState,
        },
        test_util::{ephemeral_datastore, EphemeralDatastore},
        Datastore,
    },
    task::{test_util::TaskBuilder, QueryType, Task},
    taskprov::test_util::PeerAggregatorBuilder,
    SecretBytes,
};
use janus_core::{
    auth_tokens::AuthenticationToken,
    hpke::{
        generate_hpke_config_and_private_key,
        test_util::{
            generate_test_hpke_config_and_private_key,
            generate_test_hpke_config_and_private_key_with_id,
        },
        HpkeKeypair, HpkePrivateKey,
    },
    test_util::{
        dummy_vdaf::{self, AggregationParam},
        install_test_trace_subscriber,
    },
    time::MockClock,
    vdaf::VdafInstance,
};
use janus_messages::{
    query_type::TimeInterval, AggregationJobStep, Duration, HpkeAeadId, HpkeConfig, HpkeConfigId,
    HpkeKdfId, HpkeKemId, HpkePublicKey, Interval, Role, TaskId, Time,
};
use rand::{distributions::Standard, random, thread_rng, Rng};
use serde_test::{assert_ser_tokens, assert_tokens, Token};
use std::{iter, sync::Arc};
use trillium::{Handler, Status};
use trillium_testing::{
    assert_response, assert_status,
    prelude::{delete, get, patch, post, put},
    Url,
};

const AUTH_TOKEN: &str = "Y29sbGVjdG9yLWFiY2RlZjAw";

async fn setup_api_test() -> (impl Handler, EphemeralDatastore, Arc<Datastore<MockClock>>) {
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
    );

    (handler, ephemeral_datastore, datastore)
}

#[tokio::test]
async fn get_config() {
    let (handler, ..) = setup_api_test().await;
    assert_response!(
        get("/")
            .with_request_header("Authorization", format!("Bearer {}", AUTH_TOKEN))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Ok,
        concat!(
            r#"{"protocol":"DAP-07","dap_url":"https://dap.url/","role":"Either","vdafs":"#,
            r#"["Prio3Count","Prio3Sum","Prio3Histogram","Prio3CountVec","Prio3SumVec"],"#,
            r#""query_types":["TimeInterval","FixedSize"]}"#
        )
    );
}

#[tokio::test]
async fn get_task_ids() {
    // Setup: write a few tasks to the datastore.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let mut task_ids: Vec<_> = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let tasks: Vec<_> = iter::repeat_with(|| {
                    TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                        .build()
                })
                .take(10)
                .collect();

                try_join_all(tasks.iter().map(|task| tx.put_task(task))).await?;

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
    assert_response!(
        get("/task_ids")
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Ok,
        response_for(&task_ids),
    );

    // Verify: the lower_bound is respected, if specified.
    assert_response!(
        get(&format!(
            "/task_ids?pagination_token={}",
            task_ids.first().unwrap()
        ))
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .run_async(&handler)
        .await,
        Status::Ok,
        response_for(&task_ids[1..]),
    );

    // Verify: if the lower bound is large enough, nothing is returned.
    // (also verifies the "last" response will not include a pagination token)
    assert_response!(
        get(&format!(
            "/task_ids?pagination_token={}",
            task_ids.last().unwrap()
        ))
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .run_async(&handler)
        .await,
        Status::Ok,
        response_for(&[]),
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        get("/task_ids")
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );

    // Verify: requests without the Accept header are denied.
    assert_response!(
        get("/task_ids")
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .run_async(&handler)
            .await,
        Status::NotAcceptable,
        ""
    );
}

#[tokio::test]
async fn post_task_bad_role() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;

    let vdaf_verify_key = SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        query_type: QueryType::TimeInterval,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Collector,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        max_batch_query_count: 12,
        task_expiration: Some(Time::from_seconds_since_epoch(12345)),
        min_batch_size: 223,
        time_precision: Duration::from_seconds(62),
        collector_hpke_config: generate_hpke_config_and_private_key(
            random(),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap()
        .config()
        .clone(),
        aggregator_auth_token: Some(aggregator_auth_token),
    };
    assert_response!(
        post("/tasks")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::BadRequest
    );
}

#[tokio::test]
async fn post_task_unauthorized() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;

    let vdaf_verify_key = SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        query_type: QueryType::TimeInterval,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Helper,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        max_batch_query_count: 12,
        task_expiration: Some(Time::from_seconds_since_epoch(12345)),
        min_batch_size: 223,
        time_precision: Duration::from_seconds(62),
        collector_hpke_config: generate_hpke_config_and_private_key(
            random(),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap()
        .config()
        .clone(),
        aggregator_auth_token: Some(aggregator_auth_token),
    };
    assert_response!(
        post("/tasks")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            // no Authorization header
            .run_async(&handler)
            .await,
        Status::Unauthorized
    );
}

/// Test the POST /tasks endpoint, with a helper task with no optional fields defined
#[tokio::test]
async fn post_task_helper_no_optional_fields() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let vdaf_verify_key = SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());

    // Verify: posting a task creates a new task which matches the request.
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        query_type: QueryType::TimeInterval,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Helper,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        max_batch_query_count: 12,
        task_expiration: Some(Time::from_seconds_since_epoch(12345)),
        min_batch_size: 223,
        time_precision: Duration::from_seconds(62),
        collector_hpke_config: generate_hpke_config_and_private_key(
            random(),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap()
        .config()
        .clone(),
        aggregator_auth_token: None,
    };
    let mut conn = post("/tasks")
        .with_request_body(serde_json::to_vec(&req).unwrap())
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_status!(conn, Status::Ok);
    let got_task_resp: TaskResp = serde_json::from_slice(
        &conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();

    let got_task = ds
        .run_tx(|tx| {
            let got_task_resp = got_task_resp.clone();
            Box::pin(async move { tx.get_task(&got_task_resp.task_id).await })
        })
        .await
        .unwrap()
        .expect("task was not created");

    // Verify that the task written to the datastore matches the request...
    assert_eq!(
        // The other aggregator endpoint in the datastore task is fake
        &req.peer_aggregator_endpoint,
        got_task.leader_aggregator_endpoint()
    );
    assert_eq!(&req.query_type, got_task.query_type());
    assert_eq!(&req.vdaf, got_task.vdaf());
    assert_eq!(&req.role, got_task.role());
    assert_eq!(req.max_batch_query_count, got_task.max_batch_query_count());
    assert_eq!(req.task_expiration.as_ref(), got_task.task_expiration());
    assert_eq!(req.min_batch_size, got_task.min_batch_size());
    assert_eq!(&req.time_precision, got_task.time_precision());
    assert!(got_task.aggregator_auth_token().is_some());
    assert!(got_task.collector_auth_token().is_none());
    assert_eq!(
        &req.collector_hpke_config,
        got_task.collector_hpke_config().unwrap()
    );

    // ...and the response.
    assert_eq!(got_task_resp, TaskResp::try_from(&got_task).unwrap());
}

#[tokio::test]
async fn post_task_helper_with_aggregator_auth_token() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;

    let vdaf_verify_key = SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    // Verify: posting a task with role = helper and an aggregator auth token fails
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        query_type: QueryType::TimeInterval,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Helper,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        max_batch_query_count: 12,
        task_expiration: Some(Time::from_seconds_since_epoch(12345)),
        min_batch_size: 223,
        time_precision: Duration::from_seconds(62),
        collector_hpke_config: generate_hpke_config_and_private_key(
            random(),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap()
        .config()
        .clone(),
        aggregator_auth_token: Some(aggregator_auth_token),
    };
    assert_response!(
        post("/tasks")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::BadRequest
    );
}

#[tokio::test]
async fn post_task_idempotence() {
    // Setup: create a datastore & handler.
    let (handler, ephemeral_datastore, _) = setup_api_test().await;
    let ds = ephemeral_datastore.datastore(MockClock::default()).await;

    let vdaf_verify_key = SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    // Verify: posting a task creates a new task which matches the request.
    let mut req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        query_type: QueryType::TimeInterval,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Leader,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        max_batch_query_count: 12,
        task_expiration: Some(Time::from_seconds_since_epoch(12345)),
        min_batch_size: 223,
        time_precision: Duration::from_seconds(62),
        collector_hpke_config: generate_hpke_config_and_private_key(
            random(),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap()
        .config()
        .clone(),
        aggregator_auth_token: Some(aggregator_auth_token.clone()),
    };

    let post_task = || async {
        let mut conn = post("/tasks")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await;
        assert_status!(conn, Status::Ok);
        serde_json::from_slice::<TaskResp>(
            &conn
                .take_response_body()
                .unwrap()
                .into_bytes()
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
        .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
        .await
        .unwrap();

    assert!(got_tasks.len() == 1);
    assert_eq!(got_tasks[0].id(), &first_task_resp.task_id);

    // Mutate the PostTaskReq and re-send it.
    req.max_batch_query_count = 10;
    let conn = post("/tasks")
        .with_request_body(serde_json::to_vec(&req).unwrap())
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_status!(conn, Status::Conflict);
}

/// Test the POST /tasks endpoint, with a leader task with all of the optional fields provided.
#[tokio::test]
async fn post_task_leader_all_optional_fields() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let vdaf_verify_key = SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());
    let aggregator_auth_token = AuthenticationToken::DapAuth(random());

    // Verify: posting a task creates a new task which matches the request.
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        query_type: QueryType::TimeInterval,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Leader,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        max_batch_query_count: 12,
        task_expiration: Some(Time::from_seconds_since_epoch(12345)),
        min_batch_size: 223,
        time_precision: Duration::from_seconds(62),
        collector_hpke_config: generate_hpke_config_and_private_key(
            random(),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap()
        .config()
        .clone(),
        aggregator_auth_token: Some(aggregator_auth_token.clone()),
    };
    let mut conn = post("/tasks")
        .with_request_body(serde_json::to_vec(&req).unwrap())
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_status!(conn, Status::Ok);
    let got_task_resp: TaskResp = serde_json::from_slice(
        &conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();

    let got_task = ds
        .run_tx(|tx| {
            let got_task_resp = got_task_resp.clone();
            Box::pin(async move { tx.get_task(&got_task_resp.task_id).await })
        })
        .await
        .unwrap()
        .expect("task was not created");

    // Verify that the task written to the datastore matches the request...
    assert_eq!(
        // The other aggregator endpoint in the datastore task is fake
        &req.peer_aggregator_endpoint,
        got_task.helper_aggregator_endpoint()
    );
    assert_eq!(&req.query_type, got_task.query_type());
    assert_eq!(&req.vdaf, got_task.vdaf());
    assert_eq!(&req.role, got_task.role());
    assert_eq!(&vdaf_verify_key, got_task.opaque_vdaf_verify_key());
    assert_eq!(req.max_batch_query_count, got_task.max_batch_query_count());
    assert_eq!(req.task_expiration.as_ref(), got_task.task_expiration());
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
    assert!(got_task.collector_auth_token().is_some());

    // ...and the response.
    assert_eq!(got_task_resp, TaskResp::try_from(&got_task).unwrap());
}

/// Test the POST /tasks endpoint, with a leader task with all of the optional fields provided.
#[tokio::test]
async fn post_task_leader_no_aggregator_auth_token() {
    // Setup: create a datastore & handler.
    let (handler, _ephemeral_datastore, _) = setup_api_test().await;

    let vdaf_verify_key = SecretBytes::new(thread_rng().sample_iter(Standard).take(16).collect());

    // Verify: posting a task with role = Leader and no aggregator auth token fails
    let req = PostTaskReq {
        peer_aggregator_endpoint: "http://aggregator.endpoint".try_into().unwrap(),
        query_type: QueryType::TimeInterval,
        vdaf: VdafInstance::Prio3Count,
        role: Role::Leader,
        vdaf_verify_key: URL_SAFE_NO_PAD.encode(&vdaf_verify_key),
        max_batch_query_count: 12,
        task_expiration: Some(Time::from_seconds_since_epoch(12345)),
        min_batch_size: 223,
        time_precision: Duration::from_seconds(62),
        collector_hpke_config: generate_hpke_config_and_private_key(
            random(),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        )
        .unwrap()
        .config()
        .clone(),
        aggregator_auth_token: None,
    };

    assert_response!(
        post("/tasks")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::BadRequest
    );
}

#[tokio::test]
async fn get_task() {
    // Setup: write a task to the datastore.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader).build();

    ds.run_tx(|tx| {
        let task = task.clone();
        Box::pin(async move {
            tx.put_task(&task).await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    // Verify: getting the task returns the expected result.
    let want_task_resp = TaskResp::try_from(&task).unwrap();
    let mut conn = get(&format!("/tasks/{}", task.id()))
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_status!(conn, Status::Ok);
    let got_task_resp = serde_json::from_slice(
        &conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(want_task_resp, got_task_resp);

    // Verify: getting a nonexistent task returns NotFound.
    assert_response!(
        get(&format!("/tasks/{}", random::<TaskId>()))
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NotFound,
        "",
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        get(&format!("/tasks/{}", task.id()))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );
}

#[tokio::test]
async fn delete_task() {
    // Setup: write a task to the datastore.
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let task_id = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let task =
                    TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                        .build();

                tx.put_task(&task).await?;

                Ok(*task.id())
            })
        })
        .await
        .unwrap();

    // Verify: deleting a task succeeds (and actually deletes the task).
    assert_response!(
        delete(&format!("/tasks/{}", &task_id))
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NoContent,
        "",
    );

    ds.run_tx(|tx| {
        Box::pin(async move {
            assert_eq!(tx.get_task(&task_id).await.unwrap(), None);
            Ok(())
        })
    })
    .await
    .unwrap();

    // Verify: deleting a task twice returns NoContent.
    assert_response!(
        delete(&format!("/tasks/{}", &task_id))
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NoContent,
        "",
    );

    // Verify: deleting an arbitrary nonexistent task ID returns NoContent.
    assert_response!(
        delete(&format!("/tasks/{}", &random::<TaskId>()))
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NoContent,
        "",
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        delete(&format!("/tasks/{}", &task_id))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        ""
    );
}

#[tokio::test]
async fn get_task_metrics() {
    // Setup: write a task, some reports, and some report aggregations to the datastore.
    const REPORT_COUNT: usize = 10;
    const REPORT_AGGREGATION_COUNT: usize = 4;

    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;
    let task_id = ds
        .run_tx(|tx| {
            Box::pin(async move {
                let task =
                    TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
                        .build();
                let task_id = *task.id();
                tx.put_task(&task).await?;

                let reports: Vec<_> = iter::repeat_with(|| {
                    LeaderStoredReport::new_dummy(task_id, Time::from_seconds_since_epoch(0))
                })
                .take(REPORT_COUNT)
                .collect();
                try_join_all(reports.iter().map(|report| async move {
                    tx.put_client_report(&dummy_vdaf::Vdaf::new(), report).await
                }))
                .await?;

                let aggregation_job_id = random();
                tx.put_aggregation_job(&AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                    task_id,
                    aggregation_job_id,
                    AggregationParam(0),
                    (),
                    Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1))
                        .unwrap(),
                    AggregationJobState::InProgress,
                    AggregationJobStep::from(0),
                ))
                .await?;

                try_join_all(
                    reports
                        .iter()
                        .take(REPORT_AGGREGATION_COUNT)
                        .enumerate()
                        .map(|(ord, report)| async move {
                            tx.put_report_aggregation(
                                &ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                                    task_id,
                                    aggregation_job_id,
                                    *report.metadata().id(),
                                    *report.metadata().time(),
                                    ord.try_into().unwrap(),
                                    None,
                                    ReportAggregationState::Start,
                                ),
                            )
                            .await
                        }),
                )
                .await?;

                Ok(task_id)
            })
        })
        .await
        .unwrap();

    // Verify: requesting metrics on a task returns the correct result.
    assert_response!(
        get(&format!("/tasks/{}/metrics", &task_id))
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Ok,
        serde_json::to_string(&GetTaskMetricsResp {
            reports: REPORT_COUNT.try_into().unwrap(),
            report_aggregations: REPORT_AGGREGATION_COUNT.try_into().unwrap(),
        })
        .unwrap(),
    );

    // Verify: requesting metrics on a nonexistent task returns NotFound.
    assert_response!(
        get(&format!("/tasks/{}/metrics", &random::<TaskId>()))
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NotFound,
        "",
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        get(&format!("/tasks/{}/metrics", &task_id))
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );
}

#[tokio::test]
async fn get_global_hpke_configs() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let mut conn = get("/hpke_configs")
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_response!(conn, Status::Ok);
    let resp: Vec<GlobalHpkeConfigResp> = serde_json::from_slice(
        &conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resp, vec![]);

    let keypair1_id = random();
    let keypair1 = generate_test_hpke_config_and_private_key_with_id(keypair1_id);
    let keypair2 = generate_hpke_config_and_private_key(
        HpkeConfigId::from(keypair1_id.wrapping_add(1)),
        HpkeKemId::P256HkdfSha256,
        HpkeKdfId::HkdfSha384,
        HpkeAeadId::Aes128Gcm,
    )
    .unwrap();
    ds.run_tx(|tx| {
        let keypair1 = keypair1.clone();
        let keypair2 = keypair2.clone();
        Box::pin(async move {
            tx.put_global_hpke_keypair(&keypair1).await?;
            tx.put_global_hpke_keypair(&keypair2).await?;
            tx.set_global_hpke_keypair_state(keypair2.config().id(), &HpkeKeyState::Active)
                .await?;
            Ok(())
        })
    })
    .await
    .unwrap();

    let mut conn = get("/hpke_configs")
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_response!(conn, Status::Ok);
    let mut resp: Vec<GlobalHpkeConfigResp> = serde_json::from_slice(
        &conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    resp.sort_by(|a, b| a.config.id().cmp(b.config.id()));

    let mut expected = vec![
        GlobalHpkeConfigResp {
            config: keypair1.config().clone(),
            state: HpkeKeyState::Pending,
        },
        GlobalHpkeConfigResp {
            config: keypair2.config().clone(),
            state: HpkeKeyState::Active,
        },
    ];
    expected.sort_by(|a, b| a.config.id().cmp(b.config.id()));

    assert_eq!(resp, expected);

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        put("/hpke_configs")
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );
}

#[tokio::test]
async fn get_global_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    // Verify: non-existent key.
    assert_response!(
        get("/hpke_configs/123")
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NotFound
    );

    // Verify: overflow u8.
    assert_response!(
        get("/hpke_configs/1234310294")
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::BadRequest
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        put("/hpke_configs/123")
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );

    let keypair1_id = random();
    let keypair1 = generate_test_hpke_config_and_private_key_with_id(keypair1_id);
    let keypair2 = generate_hpke_config_and_private_key(
        HpkeConfigId::from(keypair1_id.wrapping_add(1)),
        HpkeKemId::P256HkdfSha256,
        HpkeKdfId::HkdfSha384,
        HpkeAeadId::Aes128Gcm,
    )
    .unwrap();
    ds.run_tx(|tx| {
        let keypair1 = keypair1.clone();
        let keypair2 = keypair2.clone();
        Box::pin(async move {
            tx.put_global_hpke_keypair(&keypair1).await?;
            tx.put_global_hpke_keypair(&keypair2).await?;
            tx.set_global_hpke_keypair_state(keypair2.config().id(), &HpkeKeyState::Active)
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
        let mut conn = get(&format!("/hpke_configs/{}", key.config().id()))
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await;
        assert_response!(conn, Status::Ok);
        let resp: GlobalHpkeConfigResp = serde_json::from_slice(
            &conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            resp,
            GlobalHpkeConfigResp {
                config: key.config().clone(),
                state,
            },
        );
    }
}

#[tokio::test]
async fn put_global_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    // No custom parameters.
    let mut key1_resp = put("/hpke_configs")
        .with_request_body("{}")
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;

    assert_response!(key1_resp, Status::Created);
    let key1: GlobalHpkeConfigResp = serde_json::from_slice(
        &key1_resp
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();

    // Choose some custom non-default ciphers.
    let key2_req = PutGlobalHpkeConfigReq {
        kem_id: Some(HpkeKemId::X25519HkdfSha256),
        kdf_id: Some(HpkeKdfId::HkdfSha512),
        aead_id: Some(HpkeAeadId::ChaCha20Poly1305),
    };
    let mut key2_resp = put("/hpke_configs")
        .with_request_body(serde_json::to_vec(&key2_req).unwrap())
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;

    assert_response!(key1_resp, Status::Created);
    let key2: GlobalHpkeConfigResp = serde_json::from_slice(
        &key2_resp
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();

    let (got_key1, got_key2) = ds
        .run_tx(|tx| {
            let key1 = key1.config.clone();
            let key2 = key2.config.clone();
            Box::pin(async move {
                Ok((
                    tx.get_global_hpke_keypair(key1.id()).await?,
                    tx.get_global_hpke_keypair(key2.id()).await?,
                ))
            })
        })
        .await
        .unwrap();

    assert_eq!(
        key1,
        GlobalHpkeConfigResp {
            config: got_key1.unwrap().hpke_keypair().config().clone(),
            state: HpkeKeyState::Pending,
        }
    );

    assert_eq!(
        key2,
        GlobalHpkeConfigResp {
            config: got_key2.unwrap().hpke_keypair().config().clone(),
            state: HpkeKeyState::Pending,
        }
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        put("/hpke_configs")
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );
}

#[tokio::test]
async fn patch_global_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let req = PatchGlobalHpkeConfigReq {
        state: HpkeKeyState::Active,
    };

    // Verify: non-existent key.
    assert_response!(
        patch("/hpke_configs/123")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NotFound
    );

    // Verify: overflow u8.
    assert_response!(
        patch("/hpke_configs/1234310294")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::BadRequest
    );

    // Verify: invalid body.
    assert_response!(
        patch("/hpke_configs/1234310294")
            .with_request_body("{}")
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::UnprocessableEntity
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        patch("/hpke_configs/123")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );

    let keypair = generate_test_hpke_config_and_private_key();
    ds.run_tx(|tx| {
        let keypair = keypair.clone();
        Box::pin(async move { tx.put_global_hpke_keypair(&keypair).await })
    })
    .await
    .unwrap();

    let conn = patch(&format!("/hpke_configs/{}", keypair.config().id()))
        .with_request_body(serde_json::to_vec(&req).unwrap())
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_response!(conn, Status::Ok);

    let got_key = ds
        .run_tx(|tx| {
            let keypair = keypair.clone();
            Box::pin(async move { tx.get_global_hpke_keypair(keypair.config().id()).await })
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got_key.state(), &HpkeKeyState::Active);
}

#[tokio::test]
async fn delete_global_hpke_config() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let req = PatchGlobalHpkeConfigReq {
        state: HpkeKeyState::Active,
    };

    // Verify: non-existent key.
    assert_response!(
        delete("/hpke_configs/123")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NoContent
    );

    // Verify: overflow u8.
    assert_response!(
        delete("/hpke_configs/1234310294")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::BadRequest
    );

    // Verify: unauthorized requests are denied appropriately.
    assert_response!(
        delete("/hpke_configs/123")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Accept", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized,
        "",
    );

    let keypair = generate_test_hpke_config_and_private_key();
    ds.run_tx(|tx| {
        let keypair = keypair.clone();
        Box::pin(async move { tx.put_global_hpke_keypair(&keypair).await })
    })
    .await
    .unwrap();

    let conn = delete(&format!("/hpke_configs/{}", keypair.config().id()))
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_response!(conn, Status::NoContent);

    assert_eq!(
        ds.run_tx(|tx| Box::pin(async move { tx.get_global_hpke_keypairs().await }))
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
        .with_role(Role::Leader)
        .build();
    let helper = PeerAggregatorBuilder::new()
        .with_endpoint(Url::parse("https://helper.example.com/").unwrap())
        .with_role(Role::Helper)
        .build();

    ds.run_tx(|tx| {
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
    let mut conn = get("/taskprov/peer_aggregators")
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_response!(conn, Status::Ok);
    let mut resp: Vec<TaskprovPeerAggregatorResp> = serde_json::from_slice(
        &conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    resp.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));

    let mut expected = vec![
        TaskprovPeerAggregatorResp {
            endpoint: leader.endpoint().clone(),
            role: *leader.role(),
            collector_hpke_config: leader.collector_hpke_config().clone(),
            report_expiry_age: leader.report_expiry_age().cloned(),
            tolerable_clock_skew: *leader.tolerable_clock_skew(),
        },
        TaskprovPeerAggregatorResp {
            endpoint: helper.endpoint().clone(),
            role: *helper.role(),
            collector_hpke_config: helper.collector_hpke_config().clone(),
            report_expiry_age: helper.report_expiry_age().cloned(),
            tolerable_clock_skew: *helper.tolerable_clock_skew(),
        },
    ];
    expected.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));

    assert_eq!(resp, expected);

    // Missing authorization.
    assert_response!(
        get("/taskprov/peer_aggregators")
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized
    );
}

#[tokio::test]
async fn post_taskprov_peer_aggregator() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let endpoint = Url::parse("https://leader.example.com/").unwrap();
    let leader = PeerAggregatorBuilder::new()
        .with_endpoint(endpoint.clone())
        .with_role(Role::Leader)
        .build();

    let req = PostTaskprovPeerAggregatorReq {
        endpoint,
        role: Role::Leader,
        collector_hpke_config: leader.collector_hpke_config().clone(),
        verify_key_init: *leader.verify_key_init(),
        report_expiry_age: leader.report_expiry_age().cloned(),
        tolerable_clock_skew: *leader.tolerable_clock_skew(),
        aggregator_auth_tokens: Vec::from(leader.aggregator_auth_tokens()),
        collector_auth_tokens: Vec::from(leader.collector_auth_tokens()),
    };

    let mut conn = post("/taskprov/peer_aggregators")
        .with_request_body(serde_json::to_vec(&req).unwrap())
        .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
        .with_request_header("Accept", CONTENT_TYPE)
        .with_request_header("Content-Type", CONTENT_TYPE)
        .run_async(&handler)
        .await;
    assert_response!(conn, Status::Created);
    assert_eq!(
        serde_json::from_slice::<TaskprovPeerAggregatorResp>(
            &conn
                .take_response_body()
                .unwrap()
                .into_bytes()
                .await
                .unwrap(),
        )
        .unwrap(),
        leader.clone().into()
    );

    assert_eq!(
        ds.run_tx(|tx| { Box::pin(async move { tx.get_taskprov_peer_aggregators().await }) })
            .await
            .unwrap(),
        vec![leader]
    );

    // Can't insert the same aggregator.
    assert_response!(
        post("/taskprov/peer_aggregators")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Conflict
    );

    // Missing authorization.
    assert_response!(
        post("/taskprov/peer_aggregators")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized
    );
}

#[tokio::test]
async fn delete_taskprov_peer_aggregator() {
    let (handler, _ephemeral_datastore, ds) = setup_api_test().await;

    let endpoint = Url::parse("https://leader.example.com/").unwrap();
    let leader = PeerAggregatorBuilder::new()
        .with_endpoint(endpoint.clone())
        .with_role(Role::Leader)
        .build();

    ds.run_tx(|tx| {
        let leader = leader.clone();
        Box::pin(async move { tx.put_taskprov_peer_aggregator(&leader).await })
    })
    .await
    .unwrap();

    let req = DeleteTaskprovPeerAggregatorReq {
        endpoint,
        role: Role::Leader,
    };

    // Delete target.
    assert_response!(
        delete("/taskprov/peer_aggregators")
            .with_request_body(serde_json::to_vec(&req).unwrap())
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NoContent
    );

    assert_eq!(
        ds.run_tx(|tx| { Box::pin(async move { tx.get_taskprov_peer_aggregators().await }) })
            .await
            .unwrap(),
        vec![]
    );

    // Non-existent target.
    assert_response!(
        delete("/taskprov/peer_aggregators")
            .with_request_body(
                serde_json::to_vec(&DeleteTaskprovPeerAggregatorReq {
                    endpoint: Url::parse("https://doesnt-exist.example.com/").unwrap(),
                    role: Role::Leader,
                })
                .unwrap()
            )
            .with_request_header("Authorization", format!("Bearer {AUTH_TOKEN}"))
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::NoContent
    );

    // Missing authorization.
    assert_response!(
        delete("/taskprov/peer_aggregators")
            .with_request_header("Accept", CONTENT_TYPE)
            .with_request_header("Content-Type", CONTENT_TYPE)
            .run_async(&handler)
            .await,
        Status::Unauthorized
    );
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
    // helper request with optional fields omitted
    assert_tokens(
        &PostTaskReq {
            peer_aggregator_endpoint: "https://example.com/".parse().unwrap(),
            query_type: QueryType::FixedSize {
                max_batch_size: 999,
                batch_time_window_size: None,
            },
            vdaf: VdafInstance::Prio3CountVec {
                length: 5,
                chunk_length: 2,
            },
            role: Role::Helper,
            vdaf_verify_key: "encoded".to_owned(),
            max_batch_query_count: 1,
            task_expiration: None,
            min_batch_size: 100,
            time_precision: Duration::from_seconds(3600),
            collector_hpke_config: HpkeConfig::new(
                HpkeConfigId::from(7),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
                HpkePublicKey::from([0u8; 32].to_vec()),
            ),
            aggregator_auth_token: None,
        },
        &[
            Token::Struct {
                name: "PostTaskReq",
                len: 11,
            },
            Token::Str("peer_aggregator_endpoint"),
            Token::Str("https://example.com/"),
            Token::Str("query_type"),
            Token::StructVariant {
                name: "QueryType",
                variant: "FixedSize",
                len: 2,
            },
            Token::Str("max_batch_size"),
            Token::U64(999),
            Token::Str("batch_time_window_size"),
            Token::None,
            Token::StructVariantEnd,
            Token::Str("vdaf"),
            Token::StructVariant {
                name: "VdafInstance",
                variant: "Prio3CountVec",
                len: 2,
            },
            Token::Str("length"),
            Token::U64(5),
            Token::Str("chunk_length"),
            Token::U64(2),
            Token::StructVariantEnd,
            Token::Str("role"),
            Token::UnitVariant {
                name: "Role",
                variant: "Helper",
            },
            Token::Str("vdaf_verify_key"),
            Token::Str("encoded"),
            Token::Str("max_batch_query_count"),
            Token::U64(1),
            Token::Str("task_expiration"),
            Token::None,
            Token::Str("min_batch_size"),
            Token::U64(100),
            Token::Str("time_precision"),
            Token::NewtypeStruct { name: "Duration" },
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
            Token::StructEnd,
        ],
    );

    // leader request with optional fields set
    assert_tokens(
        &PostTaskReq {
            peer_aggregator_endpoint: "https://example.com/".parse().unwrap(),
            query_type: QueryType::FixedSize {
                max_batch_size: 999,
                batch_time_window_size: None,
            },
            vdaf: VdafInstance::Prio3CountVec {
                length: 5,
                chunk_length: 2,
            },
            role: Role::Leader,
            vdaf_verify_key: "encoded".to_owned(),
            max_batch_query_count: 1,
            task_expiration: Some(Time::from_seconds_since_epoch(1000)),
            min_batch_size: 100,
            time_precision: Duration::from_seconds(3600),
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
        },
        &[
            Token::Struct {
                name: "PostTaskReq",
                len: 11,
            },
            Token::Str("peer_aggregator_endpoint"),
            Token::Str("https://example.com/"),
            Token::Str("query_type"),
            Token::StructVariant {
                name: "QueryType",
                variant: "FixedSize",
                len: 2,
            },
            Token::Str("max_batch_size"),
            Token::U64(999),
            Token::Str("batch_time_window_size"),
            Token::None,
            Token::StructVariantEnd,
            Token::Str("vdaf"),
            Token::StructVariant {
                name: "VdafInstance",
                variant: "Prio3CountVec",
                len: 2,
            },
            Token::Str("length"),
            Token::U64(5),
            Token::Str("chunk_length"),
            Token::U64(2),
            Token::StructVariantEnd,
            Token::Str("role"),
            Token::UnitVariant {
                name: "Role",
                variant: "Leader",
            },
            Token::Str("vdaf_verify_key"),
            Token::Str("encoded"),
            Token::Str("max_batch_query_count"),
            Token::U64(1),
            Token::Str("task_expiration"),
            Token::Some,
            Token::NewtypeStruct { name: "Time" },
            Token::U64(1000),
            Token::Str("min_batch_size"),
            Token::U64(100),
            Token::Str("time_precision"),
            Token::NewtypeStruct { name: "Duration" },
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
            Token::StructEnd,
        ],
    );
}

#[test]
fn task_resp_serialization() {
    let task = Task::new(
        TaskId::from([0u8; 32]),
        "https://leader.com/".parse().unwrap(),
        "https://helper.com/".parse().unwrap(),
        QueryType::FixedSize {
            max_batch_size: 999,
            batch_time_window_size: None,
        },
        VdafInstance::Prio3CountVec {
            length: 5,
            chunk_length: 2,
        },
        Role::Leader,
        SecretBytes::new(b"vdaf verify key!".to_vec()),
        1,
        None,
        None,
        100,
        Duration::from_seconds(3600),
        Duration::from_seconds(60),
        HpkeConfig::new(
            HpkeConfigId::from(7),
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
            HpkePublicKey::from([0u8; 32].to_vec()),
        ),
        Some(
            AuthenticationToken::new_dap_auth_token_from_string("Y29sbGVjdG9yLWFiY2RlZjAw")
                .unwrap(),
        ),
        Some(
            AuthenticationToken::new_dap_auth_token_from_string("Y29sbGVjdG9yLWFiY2RlZjAw")
                .unwrap(),
        ),
        [(HpkeKeypair::new(
            HpkeConfig::new(
                HpkeConfigId::from(13),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::Aes128Gcm,
                HpkePublicKey::from([0u8; 32].to_vec()),
            ),
            HpkePrivateKey::new(b"unused".to_vec()),
        ))],
    )
    .unwrap();
    assert_tokens(
        &TaskResp::try_from(&task).unwrap(),
        &[
            Token::Struct {
                name: "TaskResp",
                len: 16,
            },
            Token::Str("task_id"),
            Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Token::Str("peer_aggregator_endpoint"),
            Token::Str("https://helper.com/"),
            Token::Str("query_type"),
            Token::StructVariant {
                name: "QueryType",
                variant: "FixedSize",
                len: 2,
            },
            Token::Str("max_batch_size"),
            Token::U64(999),
            Token::Str("batch_time_window_size"),
            Token::None,
            Token::StructVariantEnd,
            Token::Str("vdaf"),
            Token::StructVariant {
                name: "VdafInstance",
                variant: "Prio3CountVec",
                len: 2,
            },
            Token::Str("length"),
            Token::U64(5),
            Token::Str("chunk_length"),
            Token::U64(2),
            Token::StructVariantEnd,
            Token::Str("role"),
            Token::UnitVariant {
                name: "Role",
                variant: "Leader",
            },
            Token::Str("vdaf_verify_key"),
            Token::Str("dmRhZiB2ZXJpZnkga2V5IQ"),
            Token::Str("max_batch_query_count"),
            Token::U64(1),
            Token::Str("task_expiration"),
            Token::None,
            Token::Str("report_expiry_age"),
            Token::None,
            Token::Str("min_batch_size"),
            Token::U64(100),
            Token::Str("time_precision"),
            Token::NewtypeStruct { name: "Duration" },
            Token::U64(3600),
            Token::Str("tolerable_clock_skew"),
            Token::NewtypeStruct { name: "Duration" },
            Token::U64(60),
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
            Token::Str("Y29sbGVjdG9yLWFiY2RlZjAw"),
            Token::StructEnd,
            Token::Str("collector_auth_token"),
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
            Token::Str("Y29sbGVjdG9yLWFiY2RlZjAw"),
            Token::StructEnd,
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
            Token::Str("aggregator_hpke_configs"),
            Token::Seq { len: Some(1) },
            Token::Struct {
                name: "HpkeConfig",
                len: 5,
            },
            Token::Str("id"),
            Token::NewtypeStruct {
                name: "HpkeConfigId",
            },
            Token::U8(13),
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
            Token::SeqEnd,
            Token::StructEnd,
        ],
    );
}

#[test]
fn get_task_metrics_resp_serialization() {
    assert_ser_tokens(
        &GetTaskMetricsResp {
            reports: 87,
            report_aggregations: 348,
        },
        &[
            Token::Struct {
                name: "GetTaskMetricsResp",
                len: 2,
            },
            Token::Str("reports"),
            Token::U64(87),
            Token::Str("report_aggregations"),
            Token::U64(348),
            Token::StructEnd,
        ],
    )
}
