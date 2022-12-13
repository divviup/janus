use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use base64::{
    alphabet::URL_SAFE,
    engine::fast_portable::{FastPortable, NO_PAD},
};
use futures::future::join_all;
use janus_aggregator::task::PRIO3_AES128_VERIFY_KEY_LENGTH;
use janus_core::{
    test_util::{install_test_trace_subscriber, testcontainers::container_client},
    time::{Clock, RealClock, TimeExt},
};
use janus_interop_binaries::{
    test_util::{await_ready_ok, generate_network_name, generate_unique_name},
    testcontainer::{Aggregator, Client, Collector},
    ContainerLogsDropGuard,
};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    Duration, TaskId, Time,
};
use prio::codec::Encode;
use rand::random;
use reqwest::{header::CONTENT_TYPE, StatusCode, Url};
use serde_json::{json, Value};
use std::time::Duration as StdDuration;
use testcontainers::RunnableImage;
use tokio::time::sleep;

const JSON_MEDIA_TYPE: &str = "application/json";
const TIME_PRECISION: u64 = 3600;

enum QueryKind {
    TimeInterval,
    FixedSize,
}

/// Take a VDAF description and a list of measurements, perform an entire aggregation using
/// interoperation test binaries, and return the aggregate result. This follows the outline of
/// the "Test Runner Operation" section in draft-dcook-ppm-dap-interop-test-design.
async fn run(
    query_kind: QueryKind,
    vdaf_object: serde_json::Value,
    measurements: &[serde_json::Value],
    aggregation_parameter: &[u8],
) -> serde_json::Value {
    install_test_trace_subscriber();

    let (query_type_json, max_batch_size) = match query_kind {
        QueryKind::TimeInterval => {
            let query_type = json!(TimeInterval::CODE as u8);
            (query_type, None)
        }
        QueryKind::FixedSize => {
            let query_type = json!(FixedSize::CODE as u8);
            (query_type, Some(json!(10)))
        }
    };

    // Create and start containers.
    let container_client = container_client();
    let network = generate_network_name();

    let client_container = ContainerLogsDropGuard::new(
        container_client.run(
            RunnableImage::from(Client::default())
                .with_network(&network)
                .with_container_name(generate_unique_name("client")),
        ),
    );
    let client_port = client_container.get_host_port_ipv4(Client::INTERNAL_SERVING_PORT);

    let leader_name = generate_unique_name("leader");
    let leader_container = ContainerLogsDropGuard::new(
        container_client.run(
            RunnableImage::from(Aggregator::default())
                .with_network(&network)
                .with_container_name(leader_name.clone()),
        ),
    );
    let leader_port = leader_container.get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT);

    let helper_name = generate_unique_name("helper");
    let helper_container = ContainerLogsDropGuard::new(
        container_client.run(
            RunnableImage::from(Aggregator::default())
                .with_network(&network)
                .with_container_name(helper_name.clone()),
        ),
    );
    let helper_port = helper_container.get_host_port_ipv4(Aggregator::INTERNAL_SERVING_PORT);

    let collector_container = ContainerLogsDropGuard::new(
        container_client.run(
            RunnableImage::from(Collector::default())
                .with_network(&network)
                .with_container_name(generate_unique_name("collector")),
        ),
    );
    let collector_port = collector_container.get_host_port_ipv4(Collector::INTERNAL_SERVING_PORT);

    // Wait for all containers to sucessfully respond to HTTP requests.
    join_all(
        [client_port, leader_port, helper_port, collector_port]
            .into_iter()
            .map(await_ready_ok),
    )
    .await;

    // Generate a random TaskId, random authentication tokens, and a VDAF verification key.
    let task_id: TaskId = random();
    let aggregator_auth_token = base64::encode_engine(random::<[u8; 16]>(), &URL_SAFE_NO_PAD);
    let collector_auth_token = base64::encode_engine(random::<[u8; 16]>(), &URL_SAFE_NO_PAD);
    let verify_key = rand::random::<[u8; PRIO3_AES128_VERIFY_KEY_LENGTH]>();

    let task_id_encoded = base64::encode_engine(&task_id.get_encoded(), &URL_SAFE_NO_PAD);
    let verify_key_encoded = base64::encode_engine(verify_key, &URL_SAFE_NO_PAD);

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
            "task_id": task_id_encoded,
            "role": "leader",
            "hostname": local_leader_endpoint.host_str().unwrap(),
        }))
        .send()
        .await
        .unwrap();
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
            "task_id": task_id_encoded,
            "role": "helper",
            "hostname": local_helper_endpoint.host_str().unwrap(),
        }))
        .send()
        .await
        .unwrap();
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
            "task_id": task_id_encoded,
            "leader": internal_leader_endpoint,
            "vdaf": vdaf_object,
            "collector_authentication_token": collector_auth_token,
            "query_type": query_type_json,
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
        .get("collector_hpke_config")
        .expect("collector add_task response is missing \"collector_hpke_config\"")
        .as_str()
        .expect("\"collector_hpke_config\" value is not a string");

    // Send a /internal/test/add_task request to the leader.
    let mut leader_add_task_request_body = json!({
        "task_id": task_id_encoded,
        "leader": internal_leader_endpoint,
        "helper": internal_helper_endpoint,
        "vdaf": vdaf_object,
        "leader_authentication_token": aggregator_auth_token,
        "collector_authentication_token": collector_auth_token,
        "role": "leader",
        "verify_key": verify_key_encoded,
        "max_batch_query_count": 1,
        "query_type": query_type_json,
        "min_batch_size": 1,
        "time_precision": TIME_PRECISION,
        "collector_hpke_config": collector_hpke_config_encoded,
        "task_expiration": Time::distant_future().as_seconds_since_epoch(),
    });
    if let Some(max_batch_size) = &max_batch_size {
        leader_add_task_request_body
            .as_object_mut()
            .unwrap()
            .insert("max_batch_size".to_string(), max_batch_size.clone());
    }
    let leader_add_task_response = http_client
        .post(
            local_leader_endpoint
                .join("/internal/test/add_task")
                .unwrap(),
        )
        .json(&leader_add_task_request_body)
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
    let mut helper_add_task_request_body = json!({
        "task_id": task_id_encoded,
        "leader": internal_leader_endpoint,
        "helper": internal_helper_endpoint,
        "vdaf": vdaf_object,
        "leader_authentication_token": aggregator_auth_token,
        "role": "helper",
        "verify_key": verify_key_encoded,
        "max_batch_query_count": 1,
        "query_type": query_type_json,
        "min_batch_size": 1,
        "time_precision": TIME_PRECISION,
        "collector_hpke_config": collector_hpke_config_encoded,
        "task_expiration": Time::distant_future().as_seconds_since_epoch(),
    });
    if let Some(max_batch_size) = &max_batch_size {
        helper_add_task_request_body
            .as_object_mut()
            .unwrap()
            .insert("max_batch_size".to_string(), max_batch_size.clone());
    }
    let helper_add_task_response = http_client
        .post(
            local_helper_endpoint
                .join("/internal/test/add_task")
                .unwrap(),
        )
        .json(&helper_add_task_request_body)
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

    // Record the time before generating reports, for use in calculating time interval queries.
    let start_timestamp = RealClock::default().now();

    // Send one or more /internal/test/upload requests to the client.
    for measurement in measurements {
        let upload_response = http_client
            .post(local_client_endpoint.join("/internal/test/upload").unwrap())
            .json(&json!({
                "task_id": task_id_encoded,
                "leader": internal_leader_endpoint,
                "helper": internal_helper_endpoint,
                "vdaf": vdaf_object,
                "measurement": measurement,
                "time_precision": TIME_PRECISION,
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

    let query_json = match query_kind {
        QueryKind::TimeInterval => {
            let batch_interval_start = start_timestamp
                .to_batch_interval_start(&Duration::from_seconds(TIME_PRECISION))
                .unwrap()
                .as_seconds_since_epoch();
            // Span the aggregation over two time precisions, just in case our measurements spilled over a
            // batch boundary.
            let batch_interval_duration = TIME_PRECISION * 2;
            json!({
                "type": query_type_json,
                "batch_interval_start": batch_interval_start,
                "batch_interval_duration": batch_interval_duration,
            })
        }
        QueryKind::FixedSize => {
            // Make an additional request to the leader to fetch batch IDs.
            let batch_id_encoded;
            let mut requests = 0;
            loop {
                requests += 1;
                let fetch_batch_ids_response = http_client
                    .post(
                        local_leader_endpoint
                            .join("/internal/test/fetch_batch_ids")
                            .unwrap(),
                    )
                    .json(&json!({
                        "task_id": task_id_encoded,
                    }))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(fetch_batch_ids_response.status(), StatusCode::OK);
                assert_eq!(
                    fetch_batch_ids_response
                        .headers()
                        .get(CONTENT_TYPE)
                        .unwrap(),
                    JSON_MEDIA_TYPE,
                );
                let fetch_batch_ids_response_body =
                    fetch_batch_ids_response.json::<Value>().await.unwrap();
                let fetch_batch_ids_response_object = fetch_batch_ids_response_body
                    .as_object()
                    .expect("fetch_batch_ids response is not an object");
                assert_eq!(
                    fetch_batch_ids_response_object
                        .get("status")
                        .expect("fetch_batch_ids response is missing \"status\""),
                    "success",
                    "error: {:?}",
                    fetch_batch_ids_response_object.get("error"),
                );
                let batch_id_list = fetch_batch_ids_response_object
                    .get("batch_ids")
                    .expect("fetch_batch_ids response is missing \"batch_ids\"")
                    .as_array()
                    .expect("\"batch_ids\" value is not an array");

                if batch_id_list.is_empty() {
                    if requests >= 30 {
                        panic!("timed out polling for batch ID");
                    }
                    sleep(StdDuration::from_secs(1)).await
                } else {
                    assert_eq!(batch_id_list.len(), 1, "did not get exactly one batch ID");
                    batch_id_encoded = batch_id_list[0].clone();
                    assert!(batch_id_encoded.is_string());
                    break;
                }
            }

            json!({
                "type": query_type_json,
                "batch_id": batch_id_encoded,
            })
        }
    };

    // Send a /internal/test/collect_start request to the collector.
    let collect_start_response = http_client
        .post(
            local_collector_endpoint
                .join("/internal/test/collect_start")
                .unwrap(),
        )
        .json(&json!({
            "task_id": task_id_encoded,
            "agg_param": base64::encode_engine(aggregation_parameter, &URL_SAFE_NO_PAD),
            "query": query_json,
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
    let mut backoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(StdDuration::from_millis(500))
        .with_max_interval(StdDuration::from_millis(500))
        .with_max_elapsed_time(Some(StdDuration::from_secs(60)))
        .build();
    loop {
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
            if let Some(duration) = backoff.next_backoff() {
                tokio::time::sleep(duration).await;
                continue;
            } else {
                panic!("timed out fetching aggregation result");
            }
        }
        assert_eq!(
            status,
            "complete",
            "error: {:?}",
            collect_poll_response_object.get("error"),
        );
        assert_eq!(
            collect_poll_response_object
                .get("report_count")
                .expect("completed collect_poll response is missing \"report_count\""),
            measurements.len()
        );
        return collect_poll_response_object
            .get("result")
            .expect("completed collect_poll response is missing \"result\"")
            .clone();
    }
}

const URL_SAFE_NO_PAD: FastPortable = FastPortable::from(&URL_SAFE, NO_PAD);

#[tokio::test]
async fn e2e_prio3_count() {
    let result = run(
        QueryKind::TimeInterval,
        json!({"type": "Prio3Aes128Count"}),
        &[
            json!("0"),
            json!("1"),
            json!("1"),
            json!("0"),
            json!("1"),
            json!("0"),
            json!("1"),
            json!("0"),
            json!("1"),
            json!("1"),
            json!("0"),
            json!("1"),
            json!("0"),
            json!("1"),
            json!("0"),
            json!("0"),
            json!("0"),
            json!("0"),
        ],
        b"",
    )
    .await;
    assert!(result.is_string());
}

#[tokio::test]
async fn e2e_prio3_sum() {
    let result = run(
        QueryKind::TimeInterval,
        json!({"type": "Prio3Aes128Sum", "bits": "64"}),
        &[
            json!("0"),
            json!("10"),
            json!("9"),
            json!("21"),
            json!("8"),
            json!("12"),
            json!("14"),
        ],
        b"",
    )
    .await;
    assert!(result.is_string());
}

#[tokio::test]
async fn e2e_prio3_histogram() {
    let result = run(
        QueryKind::TimeInterval,
        json!({
            "type": "Prio3Aes128Histogram",
            "buckets": ["0", "1", "10", "100", "1000", "10000", "100000"],
        }),
        &[
            json!("1"),
            json!("4"),
            json!("16"),
            json!("64"),
            json!("256"),
            json!("1024"),
            json!("4096"),
            json!("16384"),
            json!("65536"),
            json!("262144"),
        ],
        b"",
    )
    .await;
    for element in result
        .as_array()
        .expect("Histogram result should be an array")
    {
        assert!(element.is_string());
    }
}

#[tokio::test]
async fn e2e_prio3_count_vec() {
    let result = run(
        QueryKind::TimeInterval,
        json!({"type": "Prio3Aes128CountVec", "length": "4"}),
        &[
            json!(["0", "0", "0", "1"]),
            json!(["0", "0", "1", "0"]),
            json!(["0", "1", "0", "0"]),
            json!(["1", "0", "0", "0"]),
        ],
        b"",
    )
    .await;
    for element in result
        .as_array()
        .expect("CountVec result should be an array")
    {
        assert!(element.is_string());
    }
}

#[tokio::test]
async fn e2e_prio3_count_fixed_size() {
    let result = run(
        QueryKind::FixedSize,
        json!({"type": "Prio3Aes128Count"}),
        &[
            json!("0"),
            json!("1"),
            json!("1"),
            json!("1"),
            json!("0"),
            json!("1"),
            json!("0"),
            json!("1"),
            json!("0"),
            json!("0"),
        ],
        b"",
    )
    .await;
    assert!(result.is_string());
}
