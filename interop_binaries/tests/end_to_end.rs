use base64::URL_SAFE_NO_PAD;
use futures::future::join_all;
use interop_binaries::{
    test_util::{await_http_server, generate_network_name, generate_unique_name},
    testcontainer::{Aggregator, Client, Collector},
};
use janus_core::{
    message::{Duration, TaskId},
    time::{Clock, RealClock},
};
use janus_server::task::PRIO3_AES128_VERIFY_KEY_LENGTH;
use lazy_static::lazy_static;
use portpicker::pick_unused_port;
use prio::codec::Encode;
use reqwest::{header::CONTENT_TYPE, StatusCode, Url};
use serde_json::{json, Value};
use std::{env, process::Command, time::Duration as StdDuration};
use testcontainers::{core::Port, RunnableImage};

const JSON_MEDIA_TYPE: &str = "application/json";
const MIN_BATCH_DURATION: u64 = 3600;

lazy_static! {
    static ref CONTAINER_CLIENT: testcontainers::clients::Cli =
        testcontainers::clients::Cli::default();
}

/// Take a VDAF description and a list of measurements, perform an entire aggregation using
/// interoperation test binaries, and return the aggregate result. This follows the outline of
/// section 4.7 of draft-dcook-ppm-dap-interop-test-design-00.
async fn run(
    vdaf_object: serde_json::Value,
    measurements: &[serde_json::Value],
    aggregation_parameter: &[u8],
) -> serde_json::Value {
    // Create and start containers.
    // We use std::process instead of tokio::process so that we can kill the child processes from
    // a Drop implementation. tokio::process::Child::kill() is async, and could not be called from
    // there.
    let network = generate_network_name();

    let client_port = pick_unused_port().expect("couldn't pick a port for the client");
    let client_name = generate_unique_name("client");
    let client_image = RunnableImage::from(Client::default())
        .with_network(network.clone())
        .with_container_name(client_name)
        .with_mapped_port(Port {
            local: client_port,
            internal: Client::INTERNAL_SERVING_PORT,
        });
    let _client_container = CONTAINER_CLIENT.run(client_image);

    let mut client_command = Command::new(env!("CARGO_BIN_EXE_janus_interop_client"));
    client_command.arg("--port").arg(format!("{}", client_port));

    let leader_port = pick_unused_port().expect("couldn't pick a port for the leader");
    let leader_name = generate_unique_name("leader");
    let leader_image = RunnableImage::from(Aggregator::default())
        .with_network(network.clone())
        .with_container_name(leader_name.clone())
        .with_mapped_port(Port {
            local: leader_port,
            internal: Aggregator::INTERNAL_SERVING_PORT,
        });
    let _leader_container = CONTAINER_CLIENT.run(leader_image);

    let helper_port = pick_unused_port().expect("couldn't pick a port for the helper");
    let helper_name = generate_unique_name("helper");
    let helper_image = RunnableImage::from(Aggregator::default())
        .with_network(network.clone())
        .with_container_name(helper_name.clone())
        .with_mapped_port(Port {
            local: helper_port,
            internal: Aggregator::INTERNAL_SERVING_PORT,
        });
    let _helper_container = CONTAINER_CLIENT.run(helper_image);

    let collector_port = pick_unused_port().expect("couldn't pick a port for the collector");
    let collector_name = generate_unique_name("collector");
    let collector_image = RunnableImage::from(Collector::default())
        .with_network(network)
        .with_container_name(collector_name)
        .with_mapped_port(Port {
            local: collector_port,
            internal: Collector::INTERNAL_SERVING_PORT,
        });
    let _collector_container = CONTAINER_CLIENT.run(collector_image);

    // Wait for all containers to sucessfully respond to HTTP requests.
    join_all(
        [client_port, leader_port, helper_port, collector_port]
            .into_iter()
            .map(await_http_server),
    )
    .await;

    // Generate a random TaskId, random authentication tokens, and a VDAF verification key.
    let task_id = TaskId::random();
    let aggregator_auth_token = base64::encode_config(rand::random::<[u8; 16]>(), URL_SAFE_NO_PAD);
    let collector_auth_token = base64::encode_config(rand::random::<[u8; 16]>(), URL_SAFE_NO_PAD);
    let verify_key = rand::random::<[u8; PRIO3_AES128_VERIFY_KEY_LENGTH]>();

    let task_id_encoded = base64::encode_config(&task_id.get_encoded(), URL_SAFE_NO_PAD);
    let verify_key_encoded = base64::encode_config(&verify_key, URL_SAFE_NO_PAD);

    // Endpoints, from the POV of this test (i.e. the Docker host).
    let local_client_endpoint = Url::parse(&format!("http://127.0.0.1:{client_port}/")).unwrap();
    let local_leader_endpoint = Url::parse(&format!("http://127.0.0.1:{leader_port}/")).unwrap();
    let local_helper_endpoint = Url::parse(&format!("http://127.0.0.1:{helper_port}/")).unwrap();
    let local_collector_endpoint =
        Url::parse(&format!("http://127.0.0.1:{collector_port}/")).unwrap();

    // Endpoints, from the POV of the containers (i.e. the Docker network).
    let internal_leader_endpoint = Url::parse(&format!("http://{leader_name}:8080/")).unwrap();
    let internal_helper_endpoint = Url::parse(&format!("http://{helper_name}:8080/")).unwrap();

    let http_client = reqwest::Client::new();

    // Send a /internal/test/endpoint_for_task request to the leader.
    let leader_endpoint_response = http_client
        .post(
            local_leader_endpoint
                .join("/internal/test/endpoint_for_task")
                .unwrap(),
        )
        .json(&json!({
            "taskId": task_id_encoded,
            "aggregatorId": 0,
            "hostnameAndPort": format!("{}:{}", local_leader_endpoint.host_str().unwrap(), local_leader_endpoint.port().unwrap()),
        }))
        .send()
        .await.unwrap();
    assert_eq!(leader_endpoint_response.status(), StatusCode::OK);
    assert_eq!(
        leader_endpoint_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let leader_endpoint_response_body = leader_endpoint_response.json::<Value>().await.unwrap();
    let leader_endpoint_response_object = leader_endpoint_response_body
        .as_object()
        .expect("endpoint_for_task response is not an object");
    assert_eq!(
        leader_endpoint_response_object
            .get("status")
            .expect("endpoint_for_task response is missing \"status\""),
        "success",
        "error: {:?}",
        leader_endpoint_response_object.get("error"),
    );
    assert_eq!(
        leader_endpoint_response_object
            .get("endpoint")
            .expect("endpoint_for_task response is missing \"endpoint\""),
        "/",
    );

    // Send a /internal/test/endpoint_for_task request to the helper.
    let helper_endpoint_response = http_client
        .post(
            local_helper_endpoint
                .join("/internal/test/endpoint_for_task")
                .unwrap(),
        )
        .json(&json!({
            "taskId": task_id_encoded,
            "aggregatorId": 1,
            "hostnameAndPort": format!("{}:{}", local_helper_endpoint.host_str().unwrap(), local_helper_endpoint.port().unwrap()),
        }))
        .send()
        .await.unwrap();
    assert_eq!(helper_endpoint_response.status(), StatusCode::OK);
    assert_eq!(
        helper_endpoint_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let helper_endpoint_response_body = helper_endpoint_response.json::<Value>().await.unwrap();
    let helper_endpoint_response_object = helper_endpoint_response_body
        .as_object()
        .expect("endpoint_for_task response is not an object");
    assert_eq!(
        helper_endpoint_response_object
            .get("status")
            .expect("endpoint_for_task response is missing \"status\""),
        "success",
        "error: {:?}",
        helper_endpoint_response_object.get("error"),
    );
    assert_eq!(
        helper_endpoint_response_object
            .get("endpoint")
            .expect("endpoint_for_task response is missing \"endpoint\""),
        "/",
    );

    // Send a /internal/test/add_task request to the collector.
    let collector_add_task_response = http_client
        .post(
            local_collector_endpoint
                .join("/internal/test/add_task")
                .unwrap(),
        )
        .json(&json!({
            "taskId": task_id_encoded,
            "leader": internal_leader_endpoint,
            "vdaf": vdaf_object,
            "collectorAuthenticationToken": collector_auth_token,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(collector_add_task_response.status(), StatusCode::OK);
    assert_eq!(
        collector_add_task_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let collector_add_task_response_body =
        collector_add_task_response.json::<Value>().await.unwrap();
    let collector_add_task_response_object = collector_add_task_response_body
        .as_object()
        .expect("collector add_task response is not an object");
    assert_eq!(
        collector_add_task_response_object
            .get("status")
            .expect("collector add_task response is missing \"status\""),
        "success",
        "error: {:?}",
        collector_add_task_response_object.get("error"),
    );
    let collector_hpke_config_encoded = collector_add_task_response_object
        .get("collectorHpkeConfig")
        .expect("collector add_task response is missing \"collectorHpkeConfig\"")
        .as_str()
        .expect("\"collectorHpkeConfig\" value is not a string");

    // Send a /internal/test/add_task request to the leader.
    let leader_add_task_response = http_client
        .post(
            local_leader_endpoint
                .join("/internal/test/add_task")
                .unwrap(),
        )
        .json(&json!({
            "taskId": task_id_encoded,
            "leader": internal_leader_endpoint,
            "helper": internal_helper_endpoint,
            "vdaf": vdaf_object,
            "leaderAuthenticationToken": aggregator_auth_token,
            "collectorAuthenticationToken": collector_auth_token,
            "aggregatorId": 0,
            "verifyKey": verify_key_encoded,
            "maxBatchLifetime": 1,
            "minBatchSize": 1,
            "minBatchDuration": MIN_BATCH_DURATION,
            "collectorHpkeConfig": collector_hpke_config_encoded,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(leader_add_task_response.status(), StatusCode::OK);
    assert_eq!(
        leader_add_task_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let leader_add_task_response_body = leader_add_task_response.json::<Value>().await.unwrap();
    let leader_add_task_response_object = leader_add_task_response_body
        .as_object()
        .expect("leader add_task response is not an object");
    assert_eq!(
        leader_add_task_response_object
            .get("status")
            .expect("leader add_task response is missing \"status\""),
        "success",
        "error: {:?}",
        leader_add_task_response_object.get("error"),
    );

    // Send a /internal/test/add_task request to the helper.
    let helper_add_task_response = http_client
        .post(
            local_helper_endpoint
                .join("/internal/test/add_task")
                .unwrap(),
        )
        .json(&json!({
            "taskId": task_id_encoded,
            "leader": internal_leader_endpoint,
            "helper": internal_helper_endpoint,
            "vdaf": vdaf_object,
            "leaderAuthenticationToken": aggregator_auth_token,
            "aggregatorId": 1,
            "verifyKey": verify_key_encoded,
            "maxBatchLifetime": 1,
            "minBatchSize": 1,
            "minBatchDuration": MIN_BATCH_DURATION,
            "collectorHpkeConfig": collector_hpke_config_encoded,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(helper_add_task_response.status(), StatusCode::OK);
    assert_eq!(
        helper_add_task_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let helper_add_task_response_body = helper_add_task_response.json::<Value>().await.unwrap();
    let helper_add_task_response_object = helper_add_task_response_body
        .as_object()
        .expect("helper add_task response is not an object");
    assert_eq!(
        helper_add_task_response_object
            .get("status")
            .expect("helper add_task response is missing \"status\""),
        "success",
        "error: {:?}",
        helper_add_task_response_object.get("error"),
    );

    // Record the time before generating reports, and round it down to
    // determine what batch time to start the aggregation at.
    let start_timestamp = RealClock::default().now();
    let batch_interval_start = start_timestamp
        .to_batch_unit_interval_start(Duration::from_seconds(MIN_BATCH_DURATION))
        .unwrap()
        .as_seconds_since_epoch();
    // Span the aggregation over two minimum batch durations, just in case our
    // measurements spilled over a batch boundary.
    let batch_interval_duration = MIN_BATCH_DURATION * 2;

    // Send one or more /internal/test/upload requests to the client.
    for measurement in measurements {
        let upload_response = http_client
            .post(local_client_endpoint.join("/internal/test/upload").unwrap())
            .json(&json!({
                "taskId": task_id_encoded,
                "leader": internal_leader_endpoint,
                "helper": internal_helper_endpoint,
                "vdaf": vdaf_object,
                "measurement": measurement,
                "minBatchDuration": MIN_BATCH_DURATION,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(upload_response.status(), StatusCode::OK);
        assert_eq!(
            upload_response.headers().get(CONTENT_TYPE).unwrap(),
            JSON_MEDIA_TYPE,
        );
        let upload_response_body = upload_response.json::<Value>().await.unwrap();
        let upload_response_object = upload_response_body
            .as_object()
            .expect("upload response is not an object");
        assert_eq!(
            upload_response_object
                .get("status")
                .expect("upload response is missing \"status\""),
            "success",
            "error: {:?}",
            upload_response_object.get("error"),
        );
    }

    // Send a /internal/test/collect_start request to the collector.
    let collect_start_response = http_client
        .post(
            local_collector_endpoint
                .join("/internal/test/collect_start")
                .unwrap(),
        )
        .json(&json!({
            "taskId": task_id_encoded,
            "aggParam": base64::encode_config(aggregation_parameter, URL_SAFE_NO_PAD),
            "batchIntervalStart": batch_interval_start,
            "batchIntervalDuration": batch_interval_duration,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(collect_start_response.status(), StatusCode::OK);
    assert_eq!(
        collect_start_response.headers().get(CONTENT_TYPE).unwrap(),
        JSON_MEDIA_TYPE,
    );
    let collect_start_response_body = collect_start_response.json::<Value>().await.unwrap();
    let collect_start_response_object = collect_start_response_body
        .as_object()
        .expect("collect_start response is not an object");
    assert_eq!(
        collect_start_response_object
            .get("status")
            .expect("collect_start response is missing \"status\""),
        "success",
        "error: {:?}",
        collect_start_response_object.get("error"),
    );
    let collect_job_handle = collect_start_response_object
        .get("handle")
        .expect("collect_start response is missing \"handle\"")
        .as_str()
        .expect("\"handle\" value is not a string");

    // Send /internal/test/collect_poll requests to the collector, polling until it is completed.
    for _ in 0..30 {
        let collect_poll_response = http_client
            .post(
                local_collector_endpoint
                    .join("/internal/test/collect_poll")
                    .unwrap(),
            )
            .json(&json!({
                "handle": collect_job_handle,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(collect_poll_response.status(), StatusCode::OK);
        assert_eq!(
            collect_poll_response.headers().get(CONTENT_TYPE).unwrap(),
            JSON_MEDIA_TYPE,
        );
        let collect_poll_response_body = collect_poll_response.json::<Value>().await.unwrap();
        let collect_poll_response_object = collect_poll_response_body
            .as_object()
            .expect("collect_poll response is not an object");
        let status = collect_poll_response_object
            .get("status")
            .expect("collect_poll response is missing \"status\"")
            .as_str()
            .expect("\"status\" value is not a string");
        if status == "in progress" {
            tokio::time::sleep(StdDuration::from_millis(500)).await;
            continue;
        }
        assert_eq!(
            status,
            "complete",
            "error: {:?}",
            collect_poll_response_object.get("error"),
        );
        return collect_poll_response_object
            .get("result")
            .expect("completed collect_poll response is missing \"result\"")
            .clone();
    }

    panic!("timed out fetching aggregation result");
}

#[tokio::test]
async fn e2e_prio3_count() {
    let result = run(
        json!({"type": "Prio3Aes128Count"}),
        &[
            json!(0),
            json!(1),
            json!(1),
            json!(0),
            json!(1),
            json!(0),
            json!(1),
            json!(0),
            json!(1),
            json!(1),
            json!(0),
            json!(1),
            json!(0),
            json!(1),
            json!(0),
            json!(0),
            json!(0),
            json!(0),
        ],
        b"",
    )
    .await;
    assert_eq!(result, json!(8));
}

#[tokio::test]
async fn e2e_prio3_sum() {
    let result = run(
        json!({"type": "Prio3Aes128Sum", "bits": 64}),
        &[
            json!(0),
            json!(10),
            json!(9),
            json!(21),
            json!(8),
            json!(12),
            json!(14),
        ],
        b"",
    )
    .await;
    assert_eq!(result, json!(74));
}

#[tokio::test]
async fn e2e_prio3_histogram() {
    let result = run(
        json!({"type": "Prio3Aes128Histogram", "buckets": [0, 1, 10, 100, 1_000, 10_000, 100_000]}),
        &[
            json!(1),
            json!(4),
            json!(16),
            json!(64),
            json!(256),
            json!(1024),
            json!(4096),
            json!(16384),
            json!(65536),
            json!(262144),
        ],
        b"",
    )
    .await;
    assert_eq!(result, json!([0, 1, 1, 2, 1, 2, 2, 1]));
}
