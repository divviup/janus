use backoff::ExponentialBackoffBuilder;
use itertools::Itertools;
use janus_client::{Client, ClientParameters};
use janus_collector::{test_util::collect_with_rewritten_url, Collector, CollectorParameters};
use janus_core::{
    hpke::{test_util::generate_test_hpke_config_and_private_key, HpkePrivateKey},
    retries::test_http_request_exponential_backoff,
    task::{AuthenticationToken, VdafInstance},
    time::{Clock, RealClock, TimeExt},
};
use janus_messages::{Duration, HpkeConfig, Interval, Role};
use janus_server::{
    messages::DurationExt,
    task::{test_util::generate_auth_token, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    SecretBytes,
};
use prio::vdaf::prio3::Prio3;
use rand::random;
use reqwest::Url;
use std::iter;
use tokio::time;

// Returns (leader_task, helper_task).
pub fn create_test_tasks(collector_hpke_config: &HpkeConfig) -> (Task, Task) {
    // Generate parameters.
    let task_id = random();
    let buf: [u8; 4] = random();
    let endpoints = Vec::from([
        Url::parse(&format!("http://leader-{}:8080/", hex::encode(buf))).unwrap(),
        Url::parse(&format!("http://helper-{}:8080/", hex::encode(buf))).unwrap(),
    ]);
    let vdaf_verify_key: [u8; PRIO3_AES128_VERIFY_KEY_LENGTH] = random();
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

pub async fn submit_measurements_and_verify_aggregate(
    (leader_port, helper_port): (u16, u16),
    leader_task: &Task,
    collector_private_key: &HpkePrivateKey,
) {
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
        client.upload(&measurement).await.unwrap();
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
    let collector_params = CollectorParameters::new(
        task_id,
        aggregator_endpoints[Role::Leader.index().unwrap()].clone(),
        AuthenticationToken::from(
            leader_task
                .primary_collector_auth_token()
                .as_bytes()
                .to_vec(),
        ),
        leader_task.collector_hpke_config.clone(),
        collector_private_key.clone(),
    )
    .with_http_request_backoff(test_http_request_exponential_backoff())
    .with_collect_poll_backoff(
        ExponentialBackoffBuilder::new()
            .with_initial_interval(time::Duration::from_millis(500))
            .with_max_interval(time::Duration::from_millis(500))
            .with_max_elapsed_time(Some(time::Duration::from_secs(60)))
            .build(),
    );
    let collector = Collector::new(
        collector_params,
        vdaf,
        janus_collector::default_http_client().unwrap(),
    );
    let aggregate_result =
        collect_with_rewritten_url(&collector, batch_interval, &(), "127.0.0.1", leader_port)
            .await
            .unwrap();

    // Verify that the aggregate in the collect response is the correct value.
    assert!(
        aggregate_result == num_nonzero_measurements as u64,
        "Unexpected aggregate result (want {num_nonzero_measurements}, got {aggregate_result})"
    );
}
