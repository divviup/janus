use anyhow::{anyhow, Context, Result};
use backoff::ExponentialBackoffBuilder;
use futures::Future;
use integration_tests::logs::CopyLogs;
use itertools::Itertools;
use janus_client::{Client, ClientParameters};
use janus_collector::{CollectJob, Collector, CollectorParameters};
use janus_core::{
    hpke::{test_util::generate_test_hpke_config_and_private_key, HpkePrivateKey},
    message::{Duration, HpkeConfig, Interval, Role, TaskId},
    retries::test_http_request_exponential_backoff,
    task::{AuthenticationToken, VdafInstance},
    time::{Clock, RealClock},
};
use janus_server::{
    task::{test_util::generate_auth_token, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    SecretBytes,
};
use prio::vdaf::prio3::Prio3;
use rand::{thread_rng, Rng};
use reqwest::Url;
use std::{
    self,
    env::{self, VarError},
    fs::create_dir_all,
    iter,
    path::PathBuf,
    str::FromStr,
};
use tempfile::tempdir;
use tokio::time;
use tracing::debug;

macro_rules! here {
    () => {
        concat!("at ", file!(), " line ", line!(), " column ", column!())
    };
}

// Returns (leader_task, helper_task).
pub fn create_test_tasks(collector_hpke_config: &HpkeConfig) -> (Task, Task) {
    // Generate parameters.
    let task_id = TaskId::random();
    let mut buf = [0; 4];
    thread_rng().fill(&mut buf);
    let endpoints = Vec::from([
        Url::parse(&format!("http://leader-{}:8080/", hex::encode(buf))).unwrap(),
        Url::parse(&format!("http://helper-{}:8080/", hex::encode(buf))).unwrap(),
    ]);
    let mut vdaf_verify_key = [0u8; PRIO3_AES128_VERIFY_KEY_LENGTH];
    thread_rng().fill(&mut vdaf_verify_key[..]);
    let vdaf_verify_keys = Vec::from([SecretBytes::new(vdaf_verify_key.to_vec())]);
    let aggregator_auth_tokens = Vec::from([generate_auth_token()]);

    // Create tasks & return.
    let leader_task = Task::new(
        task_id,
        endpoints.clone(),
        VdafInstance::Prio3Aes128Count.into(),
        Role::Leader,
        vdaf_verify_keys.clone(),
        1,
        46,
        Duration::from_hours(8).unwrap(),
        Duration::from_minutes(10).unwrap(),
        collector_hpke_config.clone(),
        aggregator_auth_tokens.clone(),
        Vec::from([generate_auth_token()]),
        Vec::from([generate_test_hpke_config_and_private_key()]),
    )
    .unwrap();
    let helper_task = Task::new(
        task_id,
        endpoints,
        VdafInstance::Prio3Aes128Count.into(),
        Role::Helper,
        vdaf_verify_keys,
        1,
        46,
        Duration::from_hours(8).unwrap(),
        Duration::from_minutes(10).unwrap(),
        collector_hpke_config.clone(),
        aggregator_auth_tokens,
        Vec::new(),
        Vec::from([generate_test_hpke_config_and_private_key()]),
    )
    .unwrap();

    (leader_task, helper_task)
}

pub fn translate_url_for_external_access(url: &Url, external_port: u16) -> Url {
    let mut translated = url.clone();
    translated.set_host(Some("127.0.0.1")).unwrap();
    translated.set_port(Some(external_port)).unwrap();
    translated
}

/// Run `test`, capturing logs from `helper` and `leader` if if fails.
pub async fn run_test_capturing_logs<
    Helper: CopyLogs,
    Leader: CopyLogs,
    Fut: Future<Output = Result<()>>,
    Test: FnMut() -> Fut,
>(
    test_name: &str,
    helper: &Helper,
    leader: &Leader,
    mut test: Test,
) {
    let result = test().await;
    if result.is_err() {
        let logs_destination = logs_host_path(test_name);

        leader.logs(&logs_destination);
        helper.logs(&logs_destination);
    }
    result.unwrap();
}

pub async fn submit_measurements_and_verify_aggregate(
    (leader_port, helper_port): (u16, u16),
    leader_task: &Task,
    collector_private_key: &HpkePrivateKey,
) -> Result<()> {
    // Translate aggregator endpoints for our perspective outside the container network.
    let aggregator_endpoints: Vec<_> = leader_task
        .aggregator_endpoints
        .iter()
        .zip([leader_port, helper_port])
        .map(|(url, port)| translate_url_for_external_access(url, port))
        .collect();

    // Create client.
    let task_id = leader_task.id;
    let vdaf = Prio3::new_aes128_count(2).unwrap();
    let client_parameters = ClientParameters::new(
        task_id,
        aggregator_endpoints.clone(),
        leader_task.min_batch_duration,
    );
    let http_client = janus_client::default_http_client().unwrap();
    let leader_report_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        Role::Leader,
        task_id,
        &http_client,
    )
    .await
    .unwrap();
    let helper_report_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        Role::Helper,
        task_id,
        &http_client,
    )
    .await
    .unwrap();
    let client = Client::new(
        client_parameters,
        vdaf.clone(),
        RealClock::default(),
        &http_client,
        leader_report_config,
        helper_report_config,
    );

    // Submit some measurements, recording a timestamp before measurement upload to allow us to
    // determine the correct collect interval.
    //
    // We generate exactly one batch's worth of measurement uploads to work around an issue in
    // Daphne at time of writing.
    let clock = RealClock::default();
    let total_measurements: usize = leader_task.min_batch_size.try_into().unwrap();
    let num_nonzero_measurements = total_measurements / 2;
    let num_zero_measurements = total_measurements - num_nonzero_measurements;
    assert!(num_nonzero_measurements > 0 && num_zero_measurements > 0);
    let before_timestamp = clock.now();
    for measurement in iter::repeat(1)
        .take(num_nonzero_measurements)
        .interleave(iter::repeat(0).take(num_zero_measurements))
    {
        client.upload(&measurement).await.context(here!())?;
    }

    // Send a collect request.
    let batch_interval = Interval::new(
        before_timestamp
            .to_batch_unit_interval_start(leader_task.min_batch_duration)
            .unwrap(),
        // Use two minimum batch durations as the interval duration in order to avoid a race
        // condition if this test happens to run very close to the end of a batch window.
        Duration::from_seconds(2 * leader_task.min_batch_duration.as_seconds()),
    )
    .unwrap();
    let collector_params = CollectorParameters::new_with_backoff(
        task_id,
        aggregator_endpoints[0].clone(),
        AuthenticationToken::from(
            leader_task
                .primary_collector_auth_token()
                .as_bytes()
                .to_vec(),
        ),
        leader_task.collector_hpke_config.clone(),
        collector_private_key.clone(),
        test_http_request_exponential_backoff(),
        ExponentialBackoffBuilder::new()
            .with_initial_interval(time::Duration::from_millis(500))
            .with_max_interval(time::Duration::from_millis(500))
            .with_max_elapsed_time(Some(time::Duration::from_secs(60)))
            .build(),
    );
    let collector = Collector::new(
        collector_params,
        vdaf,
        &janus_collector::default_http_client().unwrap(),
    );
    let job = collector
        .start_collection(batch_interval, &())
        .await
        .context(here!())?;

    // Rewrite the collect URL to access it outside of the container network.
    let job = CollectJob::new(
        translate_url_for_external_access(job.collect_job_url(), leader_port),
        job.batch_interval(),
        (),
    );

    // Poll until the collect job completes.
    let aggregate_result = collector.poll_until_complete(&job).await.context(here!())?;

    // Verify that the aggregate in the collect response is the correct value.
    if aggregate_result != num_nonzero_measurements as u64 {
        return Err(anyhow!(
            "unexpected aggregate result {aggregate_result} {}",
            here!()
        ));
    }

    Ok(())
}

/// Create a directory into which log files can be copied by tests and return its path.
fn logs_host_path(test_name: &str) -> PathBuf {
    let mut logs_directory = match env::var("JANUS_E2E_LOGS_PATH") {
        Ok(logs_path) => PathBuf::from_str(&logs_path).unwrap(),
        Err(VarError::NotPresent) => {
            let temp_logs_dir = tempdir().unwrap();
            // Calling TempDir::into_path means that the directory created by tempdir()
            // won't get deleted when either the TempDir or the PathBuf are dropped,
            // which is what we want since we want the log files to persist after the
            // test ends.
            temp_logs_dir.into_path()
        }
        Err(e) => panic!("failed to read environment variable {}", e),
    };

    logs_directory.push(test_name);
    create_dir_all(&logs_directory).unwrap();
    debug!(?logs_directory, "created temporary directory for logs");
    logs_directory
}
