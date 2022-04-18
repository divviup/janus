//! This test starts the aggregator server, waits for it to become ready,
//! performs one request, and then sends a SIGTERM signal to the process.
//! The server should promptly shut down, and this test will fail if it times
//! out waiting for the server to do so.

use janus_server::{
    config::{AggregatorConfig, DbConfig},
    datastore::test_util::ephemeral_datastore,
    trace::{install_trace_subscriber, TraceConfiguration},
};
use reqwest::{Client, Url};
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    process::Command,
};
use wait_timeout::ChildExt;

/// Try to find an open port by binding to an ephemeral port, saving the port
/// number, and closing the listening socket. This may still fail due to race
/// conditions if another program grabs the same port number.
fn select_open_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
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
    let aggregator_port = select_open_port().unwrap();

    let config = AggregatorConfig {
        listen_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, aggregator_port)),
        database: DbConfig {
            url: "postgres://postgres:postgres@localhost:5432/postgres"
                .parse()
                .unwrap(),
        },
        logging_config: TraceConfiguration {
            use_test_writer: true,
            ..Default::default()
        },
    };

    install_trace_subscriber(&config.logging_config).unwrap();

    // This datastore will be used indirectly by the aggregator process, which
    // will connect to its backing database separately.
    let (_datastore, _db_handle) = ephemeral_datastore().await;

    // Save the above configuration to a temporary file, so that we can pass
    // the file's path to the aggregator on the command line.
    let mut config_temp_file = tempfile::NamedTempFile::new().unwrap();
    serde_yaml::to_writer(&mut config_temp_file, &config).unwrap();
    let config_path = config_temp_file.into_temp_path();

    let mut child = Command::new(trycmd::cargo::cargo_bin!("aggregator"))
        .args([
            "--config-file",
            config_path.to_str().unwrap(),
            "--role",
            "leader",
        ])
        .env("RUSTLOG", "trace")
        .env("DATASTORE_KEYS", "VOQefstu2lDkkNulyqvDeA==")
        .spawn()
        .unwrap();

    // Try to connect to the server in a loop, until it's ready.
    wait_for_server(config.listen_address).expect("could not connect to server after starting it");

    // Make a test request to the server.
    // TODO: Expand this further once multi-process integration tests are fleshed out, to catch
    // more shutdown interactions throughout the codebase.
    let client = Client::new();
    let url = Url::parse(&format!("http://{}/hpke_config", &config.listen_address)).unwrap();
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
    }
    child_exit_status_opt.unwrap();
}
