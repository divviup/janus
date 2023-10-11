//! This test starts each component, waits for it to become ready, according
//! to its health check endpoint, and then sends a SIGTERM signal to the
//! process. The process should promptly shut down, and this test will fail if
//! it times out waiting for the process to do so.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator::{
    binaries::{
        aggregation_job_creator::Config as AggregationJobCreatorConfig,
        aggregation_job_driver::Config as AggregationJobDriverConfig,
        aggregator::{AggregatorApi, Config as AggregatorConfig},
        collection_job_driver::Config as CollectionJobDriverConfig,
    },
    config::{BinaryConfig, CommonConfig, DbConfig, JobDriverConfig, TaskprovConfig},
    metrics::MetricsConfiguration,
    trace::TraceConfiguration,
};
use janus_aggregator_core::{
    datastore::test_util::ephemeral_datastore,
    task::{test_util::TaskBuilder, QueryType},
};
use janus_core::{test_util::install_test_trace_subscriber, time::RealClock, vdaf::VdafInstance};
use reqwest::Url;
use serde::Serialize;
use std::{
    future::Future,
    io::{ErrorKind, Write},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    process::{Child, Command, Stdio},
    time::Instant,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    join,
    net::{TcpListener, TcpStream},
    process::{ChildStderr, ChildStdout},
    task::spawn_blocking,
    time::sleep,
};
use tracing::info;
use wait_timeout::ChildExt;

/// Try to find an open port by binding to an ephemeral port, saving the port
/// number, and closing the listening socket. This may still fail due to race
/// conditions if another program grabs the same port number.
async fn select_open_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address.port())
}

#[derive(Debug)]
struct Timeout;

/// Attempt to connect to a server with retries. Returns `Ok(())` if connection
/// was successful, or `Err(Timeout)` if the retries were exhausted.
async fn wait_for_server(addr: SocketAddr) -> Result<(), Timeout> {
    for _ in 0..30 {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) => sleep(std::time::Duration::from_millis(500)).await,
        }
    }
    Err(Timeout)
}

/// Start async tasks to forward a child process's output to `print!()`/`eprint!()`, which the
/// test harness can capture. Returns a future that waits for the end of both stdout and stderr.
fn forward_stdout_stderr(
    process_name: &str,
    child: &mut Child,
) -> impl Future<Output = ()> + 'static {
    let child_stdout = ChildStdout::from_std(child.stdout.take().unwrap()).unwrap();
    let handle_stdout = tokio::task::spawn({
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
                print!("{process_name} stdout: {line}");
            }
        }
    });

    let child_stderr = ChildStderr::from_std(child.stderr.take().unwrap()).unwrap();
    let handle_stderr = tokio::task::spawn({
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
                eprint!("{process_name} stderr: {line}");
            }
        }
    });

    async {
        let (result_stdout, result_stderr) = join!(handle_stdout, handle_stderr);
        result_stdout.unwrap();
        result_stderr.unwrap();
    }
}

async fn graceful_shutdown<C: BinaryConfig + Serialize>(binary: &Path, mut config: C) {
    let binary_name = binary.file_name().unwrap().to_str().unwrap();
    install_test_trace_subscriber();

    // This datastore will be used indirectly by the child process, which
    // will connect to its backing database separately.
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = ephemeral_datastore.datastore(RealClock::default()).await;

    let health_check_port = select_open_port().await.unwrap();
    let health_check_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, health_check_port));

    let common_config = config.common_config_mut();
    common_config.database.url = ephemeral_datastore.connection_string().parse().unwrap();
    common_config.database.connection_pool_timeouts_secs = 60;
    common_config.health_check_listen_address = health_check_listen_address;

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
        .build()
        .leader_view()
        .unwrap();
    datastore.put_aggregator_task(&task).await.unwrap();

    // Save the above configuration to a temporary file, so that we can pass
    // the file's path to the binary under test on the command line.
    let serialized = serde_yaml::to_string(&config).unwrap();
    let config_path = spawn_blocking(move || {
        let mut config_temp_file = tempfile::NamedTempFile::new().unwrap();
        config_temp_file.write_all(serialized.as_bytes()).unwrap();
        config_temp_file.into_temp_path()
    })
    .await
    .unwrap();

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
            URL_SAFE_NO_PAD.encode(ephemeral_datastore.datastore_key_bytes()),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Kick off tasks to read from piped stdout/stderr
    let binary_io_tasks = forward_stdout_stderr(&format!("unshare/{binary_name}"), &mut child);

    // Try to connect to the health check HTTP server in a loop, until it is ready.
    let health_check_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, health_check_port));
    wait_for_server(health_check_listen_address)
        .await
        .expect("could not connect to health check server after starting it");

    let url = Url::parse(&format!("http://{health_check_listen_address}/healthz")).unwrap();
    assert!(reqwest::get(url).await.unwrap().status().is_success());

    // Send SIGTERM to the binary under test, after entering its new namespaces.
    let unshare_pid: i32 = child.id().try_into().unwrap();
    let mut kill = Command::new("nsenter")
        .arg("--preserve-credentials")
        .arg("--user")
        .arg(format!("--pid=/proc/{unshare_pid}/ns/pid_for_children"))
        .arg("--target")
        .arg(format!("{unshare_pid}"))
        .args(["kill", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let kill_io_tasks = forward_stdout_stderr("nsenter/kill", &mut kill);
    // We ignore the exit status of nsenter/kill because there's a chance that the process under
    // test may receive the SIGTERM and exit before the kill process completes. Once PID 1 in the
    // PID namespace exits, all other processes in the namespace are sent SIGKILL, which in this
    // case includes `kill` itself.
    let _kill_exit_status = spawn_blocking(move || kill.wait()).await.unwrap().unwrap();
    kill_io_tasks.await;

    // Confirm that the binary under test shuts down promptly.
    let start = Instant::now();
    let (mut child, child_exit_status_res) = spawn_blocking(move || {
        let result = child.wait_timeout(std::time::Duration::from_secs(15));
        (child, result)
    })
    .await
    .unwrap();
    let end = Instant::now();
    let child_exit_status_opt = child_exit_status_res.unwrap();
    if child_exit_status_opt.is_none() {
        // We timed out waiting after sending a SIGTERM. Send a SIGKILL to unshare to clean up.
        // This will kill the server as well, due to the `--kill-child` flag.
        match child.kill() {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::InvalidInput => {}
            Err(e) => panic!("failed to kill unshare: {e:?}"),
        }
        child.wait().unwrap();
        binary_io_tasks.await;
        panic!("Binary did not shut down after SIGTERM");
    } else {
        binary_io_tasks.await;
        let elapsed = end - start;
        info!(?elapsed, %binary_name, "Graceful shutdown test succeeded");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn aggregator_shutdown() {
    let aggregator_port = select_open_port().await.unwrap();
    let aggregator_listen_address = SocketAddr::from((Ipv4Addr::LOCALHOST, aggregator_port));

    let aggregator_api_port = select_open_port().await.unwrap();
    let aggregator_api_listen_address =
        SocketAddr::from((Ipv4Addr::LOCALHOST, aggregator_api_port));

    let config = AggregatorConfig {
        common_config: CommonConfig {
            database: DbConfig {
                url: "postgres://localhost".parse().unwrap(),
                connection_pool_timeouts_secs: 60,
                check_schema_version: true,
            },
            logging_config: TraceConfiguration::default(),
            metrics_config: MetricsConfiguration::default(),
            health_check_listen_address: "127.0.0.1:9001".parse().unwrap(),
        },
        taskprov_config: TaskprovConfig { enabled: false },
        garbage_collection: None,
        listen_address: aggregator_listen_address,
        aggregator_api: Some(AggregatorApi {
            listen_address: Some(aggregator_api_listen_address),
            path_prefix: None,
            public_dap_url: "https://public.dap.url".parse().unwrap(),
        }),
        response_headers: Vec::new(),
        max_upload_batch_size: 100,
        max_upload_batch_write_delay_ms: 250,
        batch_aggregation_shard_count: 32,
        global_hpke_configs_refresh_interval: None,
    };

    graceful_shutdown(trycmd::cargo::cargo_bin!("aggregator"), config).await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn aggregation_job_creator_shutdown() {
    let config = AggregationJobCreatorConfig {
        common_config: CommonConfig {
            database: DbConfig {
                url: "postgres://localhost".parse().unwrap(),
                connection_pool_timeouts_secs: 60,
                check_schema_version: true,
            },
            logging_config: TraceConfiguration::default(),
            metrics_config: MetricsConfiguration::default(),
            health_check_listen_address: "127.0.0.1:9001".parse().unwrap(),
        },
        tasks_update_frequency_secs: 3600,
        aggregation_job_creation_interval_secs: 60,
        min_aggregation_job_size: 100,
        max_aggregation_job_size: 100,
    };

    graceful_shutdown(trycmd::cargo::cargo_bin!("aggregation_job_creator"), config).await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn aggregation_job_driver_shutdown() {
    let config = AggregationJobDriverConfig {
        common_config: CommonConfig {
            database: DbConfig {
                url: "postgres://localhost".parse().unwrap(),
                connection_pool_timeouts_secs: 60,
                check_schema_version: true,
            },
            logging_config: TraceConfiguration::default(),
            metrics_config: MetricsConfiguration::default(),
            health_check_listen_address: "127.0.0.1:9001".parse().unwrap(),
        },
        job_driver_config: JobDriverConfig {
            min_job_discovery_delay_secs: 10,
            max_job_discovery_delay_secs: 60,
            max_concurrent_job_workers: 10,
            worker_lease_duration_secs: 600,
            worker_lease_clock_skew_allowance_secs: 60,
            maximum_attempts_before_failure: 5,
        },
        taskprov_config: TaskprovConfig { enabled: false },
        batch_aggregation_shard_count: 32,
    };

    graceful_shutdown(trycmd::cargo::cargo_bin!("aggregation_job_driver"), config).await;
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn collection_job_driver_shutdown() {
    let config = CollectionJobDriverConfig {
        common_config: CommonConfig {
            database: DbConfig {
                url: "postgres://localhost".parse().unwrap(),
                connection_pool_timeouts_secs: 60,
                check_schema_version: true,
            },
            logging_config: TraceConfiguration::default(),
            metrics_config: MetricsConfiguration::default(),
            health_check_listen_address: "127.0.0.1:9001".parse().unwrap(),
        },
        job_driver_config: JobDriverConfig {
            min_job_discovery_delay_secs: 10,
            max_job_discovery_delay_secs: 60,
            max_concurrent_job_workers: 10,
            worker_lease_duration_secs: 600,
            worker_lease_clock_skew_allowance_secs: 60,
            maximum_attempts_before_failure: 5,
        },
        batch_aggregation_shard_count: 32,
    };

    graceful_shutdown(trycmd::cargo::cargo_bin!("collection_job_driver"), config).await;
}
