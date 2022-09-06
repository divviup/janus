use anyhow::{anyhow, Context, Result};
use futures::Future;
use http::{
    header::{CONTENT_TYPE, LOCATION},
    StatusCode,
};
use integration_tests::logs::CopyLogs;
use itertools::Itertools;
use janus_client::{Client, ClientParameters};
use janus_core::{
    hpke::{
        self, associated_data_for_aggregate_share,
        test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo, HpkePrivateKey,
        Label,
    },
    message::{Duration, HpkeConfig, Interval, Role, TaskId},
    task::VdafInstance,
    time::{Clock, RealClock},
};
use janus_server::{
    message::{CollectReq, CollectResp},
    task::{test_util::generate_auth_token, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    SecretBytes,
};
use prio::{
    codec::{Decode, Encode},
    field::Field64,
    vdaf::{prio3::Prio3, AggregateShare, Collector},
};
use rand::{thread_rng, Rng};
use reqwest::{redirect, Url};
use std::{
    env::{self, VarError},
    fs::create_dir_all,
    iter,
    path::PathBuf,
    str::FromStr,
};
use tempfile::tempdir;
use tokio::time::{self, Instant};
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

    // Send a collect request, recording the collect job URL.
    let http_client = reqwest::Client::builder()
        .redirect(redirect::Policy::none()) // otherwise following SEE_OTHER is automatic
        .build()
        .unwrap();
    let collect_url = aggregator_endpoints
        .get(Role::Leader.index().unwrap())
        .unwrap()
        .join("collect")
        .unwrap();
    let batch_interval = Interval::new(
        before_timestamp
            .to_batch_unit_interval_start(leader_task.min_batch_duration)
            .unwrap(),
        // Use two minimum batch durations as the interval duration in order to avoid a race
        // condition if this test happens to run very close to the end of a batch window.
        Duration::from_seconds(2 * leader_task.min_batch_duration.as_seconds()),
    )
    .unwrap();
    let collect_req = CollectReq {
        task_id,
        batch_interval,
        agg_param: Vec::new(),
    };
    let collect_resp = http_client
        .post(collect_url)
        .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
        .header(
            "DAP-Auth-Token",
            leader_task.primary_collector_auth_token().as_bytes(),
        )
        .body(collect_req.get_encoded())
        .send()
        .await
        .context(here!())?;
    if collect_resp.status() != StatusCode::SEE_OTHER {
        return Err(anyhow!(
            "{} != StatusCode::SEE_OTHER {}",
            collect_resp.status(),
            here!()
        ));
    }
    let collect_job_url = Url::parse(
        collect_resp
            .headers()
            .get(LOCATION)
            .context(format!(
                "no Location header in collect request response {}",
                here!()
            ))?
            .to_str()?,
    )
    .context(here!())?;
    let collect_job_url = translate_url_for_external_access(&collect_job_url, leader_port);

    // Poll until the collect job completes.
    let collect_job_poll_timeout = Instant::now()
        .checked_add(time::Duration::from_secs(60))
        .unwrap();
    let mut poll_interval = time::interval(time::Duration::from_millis(500));
    let collect_resp = loop {
        if Instant::now() >= collect_job_poll_timeout {
            return Err(anyhow!("collect job poll timeout exceeded {}", here!()));
        }
        let collect_job_resp = http_client
            .get(collect_job_url.clone())
            .header(
                "DAP-Auth-Token",
                leader_task.primary_collector_auth_token().as_bytes(),
            )
            .send()
            .await?;
        let status = collect_job_resp.status();
        if status != StatusCode::OK && status != StatusCode::ACCEPTED {
            return Err(anyhow!("unexpected status {status} {}", here!()));
        }
        if status == StatusCode::ACCEPTED {
            poll_interval.tick().await;
            continue;
        }
        break CollectResp::get_decoded(&collect_job_resp.bytes().await?)?;
    };

    if collect_resp.encrypted_agg_shares.len() != 2 {
        return Err(anyhow!(
            "got {} encrypted aggregate shares, wanted 2 {}",
            collect_resp.encrypted_agg_shares.len(),
            here!(),
        ));
    }

    // Verify that the aggregate in the collect response is the correct value.
    let associated_data = associated_data_for_aggregate_share(task_id, batch_interval);
    let aggregate_result = vdaf
        .unshard(
            &(),
            collect_resp
                .encrypted_agg_shares
                .iter()
                .zip([Role::Leader, Role::Helper])
                .map(|(encrypted_agg_share, role)| {
                    let agg_share_bytes = hpke::open(
                        &leader_task.collector_hpke_config,
                        collector_private_key,
                        &HpkeApplicationInfo::new(Label::AggregateShare, role, Role::Collector),
                        encrypted_agg_share,
                        &associated_data,
                    )
                    .context(format!("failed to decrypt {}", here!()))?;
                    AggregateShare::<Field64>::try_from(agg_share_bytes.as_ref())
                        .context(format!("failed to decode into field {}", here!()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .unwrap();
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
