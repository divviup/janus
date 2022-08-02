use http::{
    header::{CONTENT_TYPE, LOCATION},
    StatusCode,
};
use janus_client::{Client, ClientParameters};
use janus_core::{
    hpke::{
        self, associated_data_for_aggregate_share, test_util::generate_hpke_config_and_private_key,
        HpkeApplicationInfo, HpkePrivateKey, Label,
    },
    message::{Duration, HpkeConfig, Interval, Role, TaskId},
    task::VdafInstance,
    time::{Clock, RealClock},
};
use janus_server::{
    message::{CollectReq, CollectResp},
    task::{test_util::generate_aggregator_auth_token, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
};
use portpicker::pick_unused_port;
use prio::{
    codec::{Decode, Encode},
    field::Field64,
    vdaf::{prio3::Prio3, AggregateShare, Collector},
};
use rand::{thread_rng, Rng};
use reqwest::{redirect, Url};
use tokio::time::{self, Instant};

pub fn pick_two_unused_ports() -> (u16, u16) {
    let first_unused_port = pick_unused_port().unwrap();
    for _ in 0..10 {
        let second_unused_port = pick_unused_port().unwrap();
        if first_unused_port != second_unused_port {
            return (first_unused_port, second_unused_port);
        }
    }
    panic!("Couldn't find two unused ports");
}

// Returns (leader_task, helper_task).
pub fn create_test_tasks(
    leader_port: u16,
    helper_port: u16,
    collector_hpke_config: &HpkeConfig,
) -> (Task, Task) {
    // Generate parameters.
    let task_id = TaskId::random();
    let endpoints = Vec::from([
        Url::parse(&format!("http://localhost:{}", leader_port)).unwrap(),
        Url::parse(&format!("http://localhost:{}", helper_port)).unwrap(),
    ]);
    let mut verify_key = [0u8; PRIO3_AES128_VERIFY_KEY_LENGTH];
    thread_rng().fill(&mut verify_key[..]);
    let verify_key = verify_key.to_vec();
    let agg_auth_token = generate_aggregator_auth_token();
    let leader_hpke_key = generate_hpke_config_and_private_key();
    let helper_hpke_key = generate_hpke_config_and_private_key();

    // Create tasks & return.
    let leader_task = Task::new(
        task_id,
        endpoints.clone(),
        VdafInstance::Prio3Aes128Count.into(),
        Role::Leader,
        Vec::from([verify_key.clone()]),
        1,
        0,
        Duration::from_hours(8).unwrap(),
        Duration::from_minutes(10).unwrap(),
        collector_hpke_config.clone(),
        Vec::from([agg_auth_token.clone()]),
        Vec::from([leader_hpke_key]),
    )
    .unwrap();
    let helper_task = Task::new(
        task_id,
        endpoints,
        VdafInstance::Prio3Aes128Count.into(),
        Role::Helper,
        Vec::from([verify_key]),
        1,
        0,
        Duration::from_hours(8).unwrap(),
        Duration::from_minutes(10).unwrap(),
        collector_hpke_config.clone(),
        Vec::from([agg_auth_token]),
        Vec::from([helper_hpke_key]),
    )
    .unwrap();

    (leader_task, helper_task)
}

pub async fn submit_measurements_and_verify_aggregate(
    leader_task: &Task,
    collector_hpke_config: &HpkeConfig,
    collector_private_key: &HpkePrivateKey,
) {
    // Create client.
    let task_id = leader_task.id;
    let vdaf = Prio3::new_aes128_count(2).unwrap();
    let client_parameters = ClientParameters::new(
        task_id,
        leader_task.aggregator_endpoints.clone(),
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
    let clock = RealClock::default();
    const NUM_NONZERO_MEASUREMENTS: usize = 23;
    let before_timestamp = clock.now();
    for _ in 0..NUM_NONZERO_MEASUREMENTS {
        client.upload(&0).await.unwrap();
        client.upload(&1).await.unwrap();
    }

    // Send a collect request, recording the collect job URL.
    let http_client = reqwest::Client::builder()
        .redirect(redirect::Policy::none()) // otherwise following SEE_OTHER is automatic
        .build()
        .unwrap();
    let collect_url = leader_task
        .aggregator_url(Role::Leader)
        .unwrap()
        .join("/collect")
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
            leader_task.primary_aggregator_auth_token().as_bytes(),
        )
        .body(collect_req.get_encoded())
        .send()
        .await
        .unwrap();
    assert_eq!(collect_resp.status(), StatusCode::SEE_OTHER);
    let collect_job_url = Url::parse(
        collect_resp
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();

    // Poll until the collect job completes.
    let collect_job_poll_timeout = Instant::now()
        .checked_add(time::Duration::from_secs(20))
        .unwrap();
    let mut poll_interval = time::interval(time::Duration::from_millis(500));
    let collect_resp = loop {
        assert!(Instant::now() < collect_job_poll_timeout);
        let collect_job_resp = http_client
            .get(collect_job_url.clone())
            .send()
            .await
            .unwrap();
        let status = collect_job_resp.status();
        assert!(status == StatusCode::OK || status == StatusCode::ACCEPTED);
        if status == StatusCode::ACCEPTED {
            poll_interval.tick().await;
            continue;
        }
        break CollectResp::get_decoded(&collect_job_resp.bytes().await.unwrap()).unwrap();
    };

    // Verify that the aggregate in the collect response is the correct value.
    let associated_data = associated_data_for_aggregate_share(task_id, batch_interval);
    assert_eq!(collect_resp.encrypted_agg_shares.len(), 2);
    let aggregate_result = vdaf
        .unshard(
            &(),
            collect_resp
                .encrypted_agg_shares
                .iter()
                .zip([Role::Leader, Role::Helper])
                .map(|(encrypted_agg_share, role)| {
                    let agg_share_bytes = hpke::open(
                        collector_hpke_config,
                        collector_private_key,
                        &HpkeApplicationInfo::new(Label::AggregateShare, role, Role::Collector),
                        encrypted_agg_share,
                        &associated_data,
                    )
                    .unwrap();
                    AggregateShare::<Field64>::try_from(agg_share_bytes.as_ref()).unwrap()
                }),
        )
        .unwrap();
    assert_eq!(aggregate_result, NUM_NONZERO_MEASUREMENTS as u64);
}
