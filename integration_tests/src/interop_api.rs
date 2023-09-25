use janus_aggregator_core::task::Task;
use janus_interop_binaries::AggregatorAddTaskRequest;
use janus_messages::Role;
use std::collections::HashMap;
use url::Url;

/// Send an interop test API request to add a DAP task. This assumes the server is available on
/// some localhost port.
pub async fn aggregator_add_task(port: u16, task: Task, role: Role) {
    let http_client = reqwest::Client::default();
    let resp = http_client
        .post(Url::parse(&format!("http://127.0.0.1:{port}/internal/test/add_task")).unwrap())
        .json(&AggregatorAddTaskRequest::from_task(task, role))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp: HashMap<String, Option<String>> = resp.json().await.unwrap();
    assert_eq!(
        resp.get("status"),
        Some(&Some("success".to_string())),
        "error: {:?}",
        resp.get("error")
    );
}
