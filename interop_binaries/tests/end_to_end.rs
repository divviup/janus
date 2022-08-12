use anyhow::Context;
use base64::URL_SAFE_NO_PAD;
use janus_core::{
    message::{Duration, TaskId},
    time::{Clock, RealClock},
};
use janus_server::task::PRIO3_AES128_VERIFY_KEY_LENGTH;
use lazy_static::lazy_static;
use portpicker::pick_unused_port;
use prio::codec::Encode;
use reqwest::{header::CONTENT_TYPE, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    env, io,
    net::{Ipv4Addr, SocketAddr},
    process::{Child, Command, Stdio},
    time::Duration as StdDuration,
};
use testcontainers::{images::postgres::Postgres, RunnableImage};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
    process::{ChildStderr, ChildStdout},
    time::sleep,
};

static JSON_MEDIA_TYPE: &str = "application/json";
static MIN_BATCH_DURATION: u64 = 3600;

lazy_static! {
    static ref CONTAINER_CLIENT: testcontainers::clients::Cli =
        testcontainers::clients::Cli::default();
}

/// Wait for a TCP server to begin listening on the given port.
async fn wait_for_tcp_server(port: u16) -> anyhow::Result<()> {
    for _ in 0..100 {
        if TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .is_ok()
        {
            return Ok(());
        }
        sleep(StdDuration::from_millis(200)).await;
    }
    Err(anyhow::anyhow!(
        "timed out waiting for a server to accept on port {}",
        port,
    ))
}

/// RAII guard to ensure that child processes are cleaned up during test failures.
struct ChildProcessCleanupDropGuard(Child);

impl Drop for ChildProcessCleanupDropGuard {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
    }
}

/// Pass output from a child process's stdout pipe to print!(), so that it can be captured and
/// stored by the test harness.
async fn forward_stdout(stdout: ChildStdout) -> io::Result<()> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let count = reader.read_line(&mut line).await?;
        if count == 0 {
            return Ok(());
        }
        print!("{}", line);
    }
}

/// Pass output from a child process's stderr pipe to eprint!(), so that it can be captured and
/// stored by the test harness.
async fn forward_stderr(stdout: ChildStderr) -> io::Result<()> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let count = reader.read_line(&mut line).await?;
        if count == 0 {
            return Ok(());
        }
        eprint!("{}", line);
    }
}

/// Take a VDAF description and a list of measurements, perform an entire aggregation using
/// interoperation test binaries, and return the aggregate result. This follows the outline of
/// section 4.7 of draft-dcook-ppm-dap-interop-test-design-00.
async fn run(
    vdaf_object: serde_json::Value,
    measurements: &[serde_json::Value],
    aggregation_parameter: &[u8],
) -> anyhow::Result<serde_json::Value> {
    // Start up a database testcontainer for each aggregator directly, and don't set up the schema.
    let leader_db_container =
        CONTAINER_CLIENT.run(RunnableImage::from(Postgres::default()).with_tag("14-alpine"));
    let leader_postgres_port = leader_db_container.get_host_port_ipv4(5432);
    let helper_db_container =
        CONTAINER_CLIENT.run(RunnableImage::from(Postgres::default()).with_tag("14-alpine"));
    let helper_postgres_port = helper_db_container.get_host_port_ipv4(5432);

    // Pick four ports for HTTP servers.
    let client_port = pick_unused_port().context("couldn't pick a port for the client")?;
    let leader_port = pick_unused_port().context("couldn't pick a port for the leader")?;
    let helper_port = pick_unused_port().context("couldn't pick a port for the helper")?;
    let collector_port = pick_unused_port().context("couldn't pick a port for the collector")?;
    assert_eq!(
        BTreeSet::from([client_port, leader_port, helper_port, collector_port]).len(),
        4,
        "Ports selected for HTTP servers were not unique",
    );

    // Create and start containers. (here, we just run the binaries instead)
    // We use std::process instead of tokio::process so that we can kill the child processes from
    // a Drop implementation. tokio::process::Child::kill() is async, and could not be called from
    // there.
    let mut client_command = Command::new(env!("CARGO_BIN_EXE_janus_interop_client"));
    client_command.arg("--port").arg(format!("{}", client_port));
    let mut leader_command = Command::new(env!("CARGO_BIN_EXE_janus_interop_aggregator"));
    leader_command.arg("--port").arg(format!("{}", leader_port));
    leader_command.arg("--postgres-url").arg(format!(
        "postgres://postgres@127.0.0.1:{}/postgres",
        leader_postgres_port
    ));
    let mut helper_command = Command::new(env!("CARGO_BIN_EXE_janus_interop_aggregator"));
    helper_command.arg("--port").arg(format!("{}", helper_port));
    helper_command.arg("--postgres-url").arg(format!(
        "postgres://postgres@127.0.0.1:{}/postgres",
        helper_postgres_port
    ));
    let mut collector_command = Command::new(env!("CARGO_BIN_EXE_janus_interop_collector"));
    collector_command
        .arg("--port")
        .arg(format!("{}", collector_port));
    let commands = [
        client_command,
        leader_command,
        helper_command,
        collector_command,
    ];
    let mut drop_guards = Vec::with_capacity(commands.len());
    for mut command in commands {
        let mut drop_guard = ChildProcessCleanupDropGuard(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        tokio::spawn(forward_stdout(ChildStdout::from_std(
            drop_guard.0.stdout.take().unwrap(),
        )?));
        tokio::spawn(forward_stderr(ChildStderr::from_std(
            drop_guard.0.stderr.take().unwrap(),
        )?));
        drop_guards.push(drop_guard);
    }

    // Try opening a TCP connection to each container's port, and retry until it succeeds.
    for port in [client_port, leader_port, helper_port, collector_port] {
        wait_for_tcp_server(port).await?;
    }

    // Generate a random TaskId, random authentication tokens, and a VDAF verification key.
    let task_id = TaskId::random();
    let aggregator_auth_token = base64::encode_config(rand::random::<[u8; 16]>(), URL_SAFE_NO_PAD);
    let collector_auth_token = base64::encode_config(rand::random::<[u8; 16]>(), URL_SAFE_NO_PAD);
    let verify_key = rand::random::<[u8; PRIO3_AES128_VERIFY_KEY_LENGTH]>();

    let task_id_encoded = base64::encode_config(&task_id.get_encoded(), URL_SAFE_NO_PAD);
    let verify_key_encoded = base64::encode_config(&verify_key, URL_SAFE_NO_PAD);
    let leader_endpoint = format!("http://127.0.0.1:{}/", leader_port);
    let helper_endpoint = format!("http://127.0.0.1:{}/", helper_port);

    let http_client = reqwest::Client::new();

    // Send a /internal/test/endpoint_for_task request to the leader.
    let leader_endpoint_response = http_client
        .post(format!(
            "http://127.0.0.1:{}/internal/test/endpoint_for_task",
            leader_port,
        ))
        .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
        .json(&json!({
            "taskId": task_id_encoded,
            "aggregatorId": 0,
            "hostnameAndPort": format!("127.0.0.1:{}", leader_port),
        }))
        .send()
        .await?;
    assert_eq!(leader_endpoint_response.status(), StatusCode::OK);
    assert_eq!(
        leader_endpoint_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let leader_endpoint_response_body = leader_endpoint_response.json::<Value>().await?;
    let leader_endpoint_response_object = leader_endpoint_response_body
        .as_object()
        .context("endpoint_for_task response is not an object")?;
    assert_eq!(
        leader_endpoint_response_object
            .get("status")
            .context("endpoint_for_task response is missing \"status\"")?,
        "success",
        "error: {:?}",
        leader_endpoint_response_object.get("error"),
    );
    assert_eq!(
        leader_endpoint_response_object
            .get("endpoint")
            .context("endpoint_for_task response is missing \"endpoint\"")?,
        "/",
    );

    // Send a /internal/test/endpoint_for_task request to the helper.
    let helper_endpoint_response = http_client
        .post(format!(
            "http://127.0.0.1:{}/internal/test/endpoint_for_task",
            helper_port,
        ))
        .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
        .json(&json!({
            "taskId": task_id_encoded,
            "aggregatorId": 1,
            "hostnameAndPort": format!("127.0.0.1:{}", leader_port),
        }))
        .send()
        .await?;
    assert_eq!(helper_endpoint_response.status(), StatusCode::OK);
    assert_eq!(
        helper_endpoint_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let helper_endpoint_response_body = helper_endpoint_response.json::<Value>().await?;
    let helper_endpoint_response_object = helper_endpoint_response_body
        .as_object()
        .context("endpoint_for_task response is not an object")?;
    assert_eq!(
        helper_endpoint_response_object
            .get("status")
            .context("endpoint_for_task response is missing \"status\"")?,
        "success",
        "error: {:?}",
        helper_endpoint_response_object.get("error"),
    );
    assert_eq!(
        helper_endpoint_response_object
            .get("endpoint")
            .context("endpoint_for_task response is missing \"endpoint\"")?,
        "/",
    );

    // Send a /internal/test/add_task request to the collector.
    let collector_add_task_response = http_client
        .post(format!(
            "http://127.0.0.1:{}/internal/test/add_task",
            collector_port,
        ))
        .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
        .json(&json!({
            "taskId": task_id_encoded,
            "leader": leader_endpoint,
            "vdaf": vdaf_object,
            "collectorAuthenticationToken": collector_auth_token,
        }))
        .send()
        .await?;
    assert_eq!(collector_add_task_response.status(), StatusCode::OK);
    assert_eq!(
        collector_add_task_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let collector_add_task_response_body = collector_add_task_response.json::<Value>().await?;
    let collector_add_task_response_object = collector_add_task_response_body
        .as_object()
        .context("collector add_task response is not an object")?;
    assert_eq!(
        collector_add_task_response_object
            .get("status")
            .context("collector add_task response is missing \"status\"")?,
        "success",
        "error: {:?}",
        collector_add_task_response_object.get("error"),
    );
    let collector_hpke_config_encoded = collector_add_task_response_object
        .get("collectorHpkeConfig")
        .context("collector add_task response is missing \"collectorHpkeConfig\"")?
        .as_str()
        .context("\"collectorHpkeConfig\" value is not a string")?;

    // Send a /internal/test/add_task request to the leader.
    let leader_add_task_response = http_client
        .post(format!(
            "http://127.0.0.1:{}/internal/test/add_task",
            leader_port,
        ))
        .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
        .json(&json!({
            "taskId": task_id_encoded,
            "leader": leader_endpoint,
            "helper": helper_endpoint,
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
        .await?;
    assert_eq!(leader_add_task_response.status(), StatusCode::OK);
    assert_eq!(
        leader_add_task_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let leader_add_task_response_body = leader_add_task_response.json::<Value>().await?;
    let leader_add_task_response_object = leader_add_task_response_body
        .as_object()
        .context("leader add_task response is not an object")?;
    assert_eq!(
        leader_add_task_response_object
            .get("status")
            .context("leader add_task response is missing \"status\"")?,
        "success",
        "error: {:?}",
        leader_add_task_response_object.get("error"),
    );

    // Send a /internal/test/add_task request to the helper.
    let helper_add_task_response = http_client
        .post(format!(
            "http://127.0.0.1:{}/internal/test/add_task",
            helper_port,
        ))
        .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
        .json(&json!({
            "taskId": task_id_encoded,
            "leader": leader_endpoint,
            "helper": helper_endpoint,
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
        .await?;
    assert_eq!(helper_add_task_response.status(), StatusCode::OK);
    assert_eq!(
        helper_add_task_response
            .headers()
            .get(CONTENT_TYPE)
            .unwrap(),
        JSON_MEDIA_TYPE,
    );
    let helper_add_task_response_body = helper_add_task_response.json::<Value>().await?;
    let helper_add_task_response_object = helper_add_task_response_body
        .as_object()
        .context("helper add_task response is not an object")?;
    assert_eq!(
        helper_add_task_response_object
            .get("status")
            .context("helper add_task response is missing \"status\"")?,
        "success",
        "error: {:?}",
        helper_add_task_response_object.get("error"),
    );

    // Record the time before generating reports, and round it down to
    // determine what batch time to start the aggregation at.
    let start_timestamp = RealClock::default().now();
    let batch_interval_start = start_timestamp
        .to_batch_unit_interval_start(Duration::from_seconds(MIN_BATCH_DURATION))?
        .as_seconds_since_epoch();
    // Span the aggregation over two minimum batch durations, just in case our
    // measurements spilled over a batch boundary.
    let batch_interval_duration = MIN_BATCH_DURATION * 2;

    // Send one or more /internal/test/upload requests to the client.
    for measurement in measurements {
        let upload_response = http_client
            .post(format!(
                "http://127.0.0.1:{}/internal/test/upload",
                client_port,
            ))
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .json(&json!({
                "taskId": task_id_encoded,
                "leader": leader_endpoint,
                "helper": helper_endpoint,
                "vdaf": vdaf_object,
                "measurement": measurement,
                "minBatchDuration": MIN_BATCH_DURATION,
            }))
            .send()
            .await?;
        assert_eq!(upload_response.status(), StatusCode::OK);
        assert_eq!(
            upload_response.headers().get(CONTENT_TYPE).unwrap(),
            JSON_MEDIA_TYPE,
        );
        let upload_response_body = upload_response.json::<Value>().await?;
        let upload_response_object = upload_response_body
            .as_object()
            .context("upload response is not an object")?;
        assert_eq!(
            upload_response_object
                .get("status")
                .context("upload response is missing \"status\"")?,
            "success",
            "error: {:?}",
            upload_response_object.get("error"),
        );
    }

    // Send a /internal/test/collect_start request to the collector.
    let collect_start_response = http_client
        .post(format!(
            "http://127.0.0.1:{}/internal/test/collect_start",
            collector_port,
        ))
        .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
        .json(&json!({
            "taskId": task_id_encoded,
            "aggParam": base64::encode_config(aggregation_parameter, URL_SAFE_NO_PAD),
            "batchIntervalStart": batch_interval_start,
            "batchIntervalDuration": batch_interval_duration,
        }))
        .send()
        .await?;
    assert_eq!(collect_start_response.status(), StatusCode::OK);
    assert_eq!(
        collect_start_response.headers().get(CONTENT_TYPE).unwrap(),
        JSON_MEDIA_TYPE,
    );
    let collect_start_response_body = collect_start_response.json::<Value>().await?;
    let collect_start_response_object = collect_start_response_body
        .as_object()
        .context("collect_start response is not an object")?;
    assert_eq!(
        collect_start_response_object
            .get("status")
            .context("collect_start response is missing \"status\"")?,
        "success",
        "error: {:?}",
        collect_start_response_object.get("error"),
    );
    let collect_job_handle = collect_start_response_object
        .get("handle")
        .context("collect_start response is missing \"handle\"")?
        .as_str()
        .context("\"handle\" value is not a string")?;

    // Send /internal/test/collect_poll requests to the collector, polling until it is completed.
    for _ in 0..30 {
        let collect_poll_response = http_client
            .post(format!(
                "http://127.0.0.1:{}/internal/test/collect_poll",
                collector_port,
            ))
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .json(&json!({
                "handle": collect_job_handle,
            }))
            .send()
            .await?;
        assert_eq!(collect_poll_response.status(), StatusCode::OK);
        assert_eq!(
            collect_poll_response.headers().get(CONTENT_TYPE).unwrap(),
            JSON_MEDIA_TYPE,
        );
        let collect_poll_response_body = collect_poll_response.json::<Value>().await?;
        let collect_poll_response_object = collect_poll_response_body
            .as_object()
            .context("collect_poll response is not an object")?;
        let status = collect_poll_response_object
            .get("status")
            .context("collect_poll response is missing \"status\"")?
            .as_str()
            .context("\"status\" value is not a string")?;
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
            .context("completed collect_poll response is missing \"result\"")
            .cloned();
    }

    Err(anyhow::anyhow!("timed out fetching aggregation result"))
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
    .await
    .unwrap();
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
    .await
    .unwrap();
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
    .await
    .unwrap();
    assert_eq!(result, json!([0, 1, 1, 2, 1, 2, 2, 1]));
}
