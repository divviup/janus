//! This test starts each component, waits for it to become ready, according
//! to its health check endpoint, and then sends a SIGTERM signal to the
//! process. The process should promptly shut down, and this test will fail if
//! it times out waiting for the process to do so.

use janus_core::{
    message::{Role, TaskId},
    task::VdafInstance,
    test_util::install_test_trace_subscriber,
    time::RealClock,
};
use janus_server::{datastore::test_util::ephemeral_datastore, task::test_util::new_dummy_task};
use reqwest::Url;
use serde_yaml::Mapping;
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{ChildStderr, ChildStdout},
};
use wait_timeout::ChildExt;

/// Try to find an open port by binding to an ephemeral port, saving the port
/// number, and closing the listening socket. This may still fail due to race
/// conditions if another program grabs the same port number.
fn select_open_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address.port())
}

/// Attempt to connect to a server with retries. Returns `Ok(())` if connection
/// was successful, or `Err(())` if the retries were exhausted.
fn wait_for_server(addr: SocketAddr) -> Result<(), ()> {
    for _ in 0..30 {
        match TcpStream::connect(addr) {
            Ok(_) => return Ok(()),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
        }
    }
    Err(())
}

/// Start async tasks to forward a child process's output to `print!()`/`eprint!()`, which the
/// test harness can capture.
fn forward_stdout_stderr(process_name: &str, child: &mut Child) {
    let child_stdout = ChildStdout::from_std(child.stdout.take().unwrap()).unwrap();
    tokio::task::spawn({
        let process_name = process_name.to_string();
        let mut reader = BufReader::new(child_stdout);
        async move {
            let mut line = String::new();
            loop {
                line.clear();
                let count = reader.read_line(&mut line).await.unwrap();
                if count == 0 {
                    break;
                }
                print!("{} stdout: {}", process_name, line);
            }
        }
    });

    let child_stderr = ChildStderr::from_std(child.stderr.take().unwrap()).unwrap();
    tokio::task::spawn({
        let process_name = process_name.to_string();
        let mut reader = BufReader::new(child_stderr);
        async move {
            let mut line = String::new();
            loop {
                line.clear();
                let count = reader.read_line(&mut line).await.unwrap();
                if count == 0 {
                    break;
                }
                eprint!("{} stderr: {}", process_name, line);
            }
        }
    });
}

async fn graceful_shutdown(binary: &Path, mut config: Mapping) {
    install_test_trace_subscriber();

    // This datastore will be used indirectly by the child process, which
    // will connect to its backing database separately.
    let (datastore, db_handle) = ephemeral_datastore(RealClock::default()).await;

    let health_check_port = select_open_port().unwrap();
    let health_check_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, health_check_port));

    let mut db_config = Mapping::new();
    db_config.insert("url".into(), db_handle.connection_string().into());
    db_config.insert("connection_pool_timeout_secs".into(), "60".into());
    config.insert("database".into(), db_config.into());
    config.insert(
        "health_check_listen_address".into(),
        format!("{}", health_check_listen_address).into(),
    );

    let task_id = TaskId::random();
    let task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count.into(), Role::Leader);
    datastore
        .run_tx(|tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_task(&task).await })
        })
        .await
        .unwrap();

    // Save the above configuration to a temporary file, so that we can pass
    // the file's path to the binary under test on the command line.
    let mut config_temp_file = tempfile::NamedTempFile::new().unwrap();
    config_temp_file
        .write_all(serde_yaml::to_string(&config).unwrap().as_bytes())
        .unwrap();
    let config_path = config_temp_file.into_temp_path();

    // Start the binary under test, inside new PID and user namespaces. This will run it as PID 1,
    // which better emulates its behavior in a container. Note that PID 1's default signal
    // handling behaviors differ from other PIDs.
    let mut child = Command::new("unshare")
        .args([
            "--pid",
            "--user",
            "--map-root-user",
            "--fork",
            "--kill-child",
        ])
        .arg(binary)
        .args(["--config-file", config_path.to_str().unwrap()])
        .env("RUSTLOG", "trace")
        .env(
            "DATASTORE_KEYS",
            base64::encode_config(&db_handle.datastore_key_bytes(), base64::STANDARD_NO_PAD),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Kick off tasks to read from piped stdout/stderr
    forward_stdout_stderr(
        &format!("unshare/{}", binary.file_name().unwrap().to_str().unwrap()),
        &mut child,
    );

    // Try to connect to the health check HTTP server in a loop, until it is ready.
    let health_check_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, health_check_port));
    wait_for_server(health_check_listen_address)
        .expect("could not connect to health check server after starting it");

    let url = Url::parse(&format!("http://{}/healthz", health_check_listen_address)).unwrap();
    assert!(reqwest::get(url).await.unwrap().status().is_success());

    // Send SIGTERM to the server process, after entering its new namespaces.
    let unshare_pid: i32 = child.id().try_into().unwrap();
    let mut kill = Command::new("nsenter")
        .arg("--preserve-credentials")
        .arg("--user")
        .arg(format!("--pid=/proc/{}/ns/pid_for_children", unshare_pid))
        .arg("--target")
        .arg(format!("{}", unshare_pid))
        .args(["kill", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    forward_stdout_stderr("nsenter/kill", &mut kill);
    assert!(kill.wait().unwrap().success());

    // Confirm that the server shuts down promptly.
    let child_exit_status_opt = child
        .wait_timeout(std::time::Duration::from_secs(15))
        .unwrap();
    if child_exit_status_opt.is_none() {
        // We timed out waiting after sending a SIGTERM. Send a SIGKILL to unshare to clean up.
        // This will kill the server as well, due to the `--kill-child` flag.
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("Server did not shut down after SIGTERM");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn server_shutdown() {
    let aggregator_port = select_open_port().unwrap();
    let aggregator_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, aggregator_port));

    let mut config = Mapping::new();
    config.insert(
        "listen_address".into(),
        format!("{}", aggregator_listen_address).into(),
    );

    graceful_shutdown(trycmd::cargo::cargo_bin!("aggregator"), config).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn aggregation_job_creator_shutdown() {
    let mut config = Mapping::new();
    config.insert("tasks_update_frequency_secs".into(), 3600u64.into());
    config.insert(
        "aggregation_job_creation_interval_secs".into(),
        60u64.into(),
    );
    config.insert("min_aggregation_job_size".into(), 100u64.into());
    config.insert("max_aggregation_job_size".into(), 100u64.into());

    graceful_shutdown(trycmd::cargo::cargo_bin!("aggregation_job_creator"), config).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn aggregation_job_driver_shutdown() {
    let mut config = Mapping::new();
    config.insert("min_job_discovery_delay_secs".into(), 10u64.into());
    config.insert("max_job_discovery_delay_secs".into(), 60u64.into());
    config.insert("max_concurrent_job_workers".into(), 10u64.into());
    config.insert("worker_lease_duration_secs".into(), 600u64.into());
    config.insert(
        "worker_lease_clock_skew_allowance_secs".into(),
        60u64.into(),
    );
    config.insert("maximum_attempts_before_failure".into(), 5u64.into());

    graceful_shutdown(trycmd::cargo::cargo_bin!("aggregation_job_driver"), config).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn collect_job_driver_shutdown() {
    let mut config = Mapping::new();
    config.insert("min_job_discovery_delay_secs".into(), 10u64.into());
    config.insert("max_job_discovery_delay_secs".into(), 60u64.into());
    config.insert("max_concurrent_job_workers".into(), 10u64.into());
    config.insert("worker_lease_duration_secs".into(), 600u64.into());
    config.insert(
        "worker_lease_clock_skew_allowance_secs".into(),
        60u64.into(),
    );
    config.insert("maximum_attempts_before_failure".into(), 5u64.into());

    graceful_shutdown(trycmd::cargo::cargo_bin!("collect_job_driver"), config).await;
}
