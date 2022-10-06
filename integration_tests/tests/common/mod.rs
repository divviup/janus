use backoff::ExponentialBackoffBuilder;
use itertools::Itertools;
use janus_client::{Client, ClientParameters};
use janus_collector::{
    test_util::collect_with_rewritten_url, Collection, Collector, CollectorParameters,
};
use janus_core::{
    hpke::{test_util::generate_test_hpke_config_and_private_key, HpkePrivateKey},
    retries::test_http_request_exponential_backoff,
    task::VdafInstance,
    time::{Clock, RealClock, TimeExt},
};
use janus_messages::{Duration, Interval, Role};
use janus_server::task::{test_util::TaskBuilder, QueryType, Task};
use prio::vdaf::prio3::Prio3;
use rand::random;
use reqwest::Url;
use std::iter;
use tokio::time;

// Returns (collector_private_key, leader_task, helper_task).
pub fn test_task_builders() -> (HpkePrivateKey, TaskBuilder, TaskBuilder) {
    let endpoint_random_value = hex::encode(random::<[u8; 4]>());
    let (collector_hpke_config, collector_private_key) =
        generate_test_hpke_config_and_private_key();
    let leader_task = TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3Aes128Count.into(),
        Role::Leader,
    )
    .with_aggregator_endpoints(Vec::from([
        Url::parse(&format!("http://leader-{endpoint_random_value}:8080/")).unwrap(),
        Url::parse(&format!("http://helper-{endpoint_random_value}:8080/")).unwrap(),
    ]))
    .with_min_batch_size(46)
    .with_collector_hpke_config(collector_hpke_config);
    let helper_task = leader_task.clone().with_role(Role::Helper);

    (collector_private_key, leader_task, helper_task)
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
        .aggregator_endpoints()
        .iter()
        .zip([leader_port, helper_port])
        .map(|(url, port)| translate_url_for_external_access(url, port))
        .collect();

    // Create client.
    let vdaf = Prio3::new_aes128_count(2).unwrap();
    let client_parameters = ClientParameters::new(
        *leader_task.task_id(),
        aggregator_endpoints.clone(),
        *leader_task.time_precision(),
    );
    let http_client = janus_client::default_http_client().unwrap();
    let leader_report_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        &Role::Leader,
        leader_task.task_id(),
        &http_client,
    )
    .await
    .unwrap();
    let helper_report_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        &Role::Helper,
        leader_task.task_id(),
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
    let total_measurements: usize = leader_task.min_batch_size().try_into().unwrap();
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
            .to_batch_unit_interval_start(leader_task.time_precision())
            .unwrap(),
        // Use two time precisions as the interval duration in order to avoid a race condition if
        // this test happens to run very close to the end of a batch window.
        Duration::from_seconds(2 * leader_task.time_precision().as_seconds()),
    )
    .unwrap();
    let collector_params = CollectorParameters::new(
        *leader_task.task_id(),
        aggregator_endpoints[Role::Leader.index().unwrap()].clone(),
        leader_task.primary_collector_auth_token().clone(),
        leader_task.collector_hpke_config().clone(),
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
    let collection =
        collect_with_rewritten_url(&collector, batch_interval, &(), "127.0.0.1", leader_port)
            .await
            .unwrap();

    // Verify that we got the correct result.
    assert_eq!(
        collection,
        Collection::new(total_measurements as u64, num_nonzero_measurements as u64)
    );
}
