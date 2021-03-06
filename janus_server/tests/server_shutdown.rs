//! This test starts the aggregator server, waits for it to become ready,
//! performs one request, and then sends a SIGTERM signal to the process.
//! The server should promptly shut down, and this test will fail if it times
//! out waiting for the server to do so.

use janus_core::{
    message::{Role, TaskId},
    task::VdafInstance,
    time::RealClock,
};
use janus_server::{
    datastore::test_util::ephemeral_datastore,
    task::test_util::new_dummy_task,
    trace::{install_trace_subscriber, TraceConfiguration},
};
use reqwest::{Client, Url};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::{Command, Stdio},
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

#[tokio::test]
async fn server_shutdown() {
    install_trace_subscriber(&TraceConfiguration {
        use_test_writer: true,
        ..Default::default()
    })
    .unwrap();

    // This datastore will be used indirectly by the aggregator process, which
    // will connect to its backing database separately.
    let (datastore, db_handle) = ephemeral_datastore(RealClock::default()).await;

    let aggregator_port = select_open_port().unwrap();
    let aggregator_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, aggregator_port));
    let health_check_port = select_open_port().unwrap();
    let health_check_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, health_check_port));
    assert_ne!(aggregator_port, health_check_port);

    let config = format!(
        r#"---
    listen_address: "{}"
    health_check_listen_address: "{}"
    database:
        url: "{}"
        connection_pool_timeouts_secs: 60
    "#,
        aggregator_listen_address,
        health_check_listen_address,
        db_handle.connection_string()
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
    // the file's path to the aggregator on the command line.
    let mut config_temp_file = tempfile::NamedTempFile::new().unwrap();
    config_temp_file.write_all(config.as_ref()).unwrap();
    let config_path = config_temp_file.into_temp_path();

    let mut child = Command::new(trycmd::cargo::cargo_bin!("aggregator"))
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
    let stdout_join_handle = tokio::task::spawn_blocking({
        let mut stdout = child.stdout.take().unwrap();
        move || {
            let mut output = String::new();
            stdout.read_to_string(&mut output).unwrap();
            output
        }
    });
    let stderr_join_handle = tokio::task::spawn_blocking({
        let mut stderr = child.stderr.take().unwrap();
        move || {
            let mut output = String::new();
            stderr.read_to_string(&mut output).unwrap();
            output
        }
    });

    // Try to connect to the HTTP servers in a loop, until they are ready.
    let aggregator_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, aggregator_port));
    wait_for_server(aggregator_listen_address)
        .expect("could not connect to aggregator server after starting it");
    let health_check_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, health_check_port));
    wait_for_server(health_check_listen_address)
        .expect("could not connect to health check server after starting it");

    // Make a test request to the server.
    // TODO(#220): expand this further once multi-process integration tests are fleshed out, to
    // catch more shutdown interactions throughout the codebase.
    let client = Client::new();
    let url = Url::parse(&format!(
        "http://{}/hpke_config?task_id={}",
        aggregator_listen_address, task_id
    ))
    .unwrap();
    assert!(client.get(url).send().await.unwrap().status().is_success());

    let url = Url::parse(&format!("http://{}/healthz", health_check_listen_address,)).unwrap();
    assert!(client.get(url).send().await.unwrap().status().is_success());

    // Send SIGTERM to the child process.
    let pid: i32 = child.id().try_into().unwrap();
    let status = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(status, 0);

    // Confirm that the server shuts down promptly.
    let child_exit_status_opt = child
        .wait_timeout(std::time::Duration::from_secs(15))
        .unwrap();
    if child_exit_status_opt.is_none() {
        // We timed out waiting after sending a SIGTERM. Send a SIGKILL to clean up.
        child.kill().unwrap();
        child.wait().unwrap();
        println!("===== child process stdout =====");
        println!("{}", stdout_join_handle.await.unwrap());
        println!("===== child process stderr =====");
        println!("{}", stderr_join_handle.await.unwrap());
        println!("===== end =====");
    }
    child_exit_status_opt.unwrap();
}
