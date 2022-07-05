use janus_client::{self, Client, ClientParameters};
use janus_core::{
    hpke::{
        self, associated_data_for_aggregate_share, test_util::generate_hpke_config_and_private_key,
        HpkeApplicationInfo, HpkePrivateKey, Label,
    },
    message::{Duration, HpkeConfig, Interval, Role, TaskId},
    task::VdafInstance,
    time::{Clock, RealClock},
    TokioRuntime,
};
use janus_server::{
    aggregator::{
        aggregate_share::CollectJobDriver, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, aggregator_server,
    },
    binary_utils::job_driver::JobDriver,
    datastore::{Crypter, Datastore},
    message::{CollectReq, CollectResp},
    task::{test_util::generate_aggregator_auth_token, Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
};
use janus_test_util::install_test_trace_subscriber;
use prio::{
    codec::{Decode, Encode},
    field::Field64,
    vdaf::{
        prio3::{Prio3, Prio3Aes128Count},
        AggregateShare, Collector,
    },
};
use rand::{thread_rng, Rng};
use reqwest::{
    header::{self, CONTENT_TYPE},
    redirect, StatusCode,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{mpsc, Arc},
};
use tokio::{
    select,
    sync::oneshot,
    task,
    time::{self, Instant},
    try_join,
};
use url::Url;

janus_test_util::define_ephemeral_datastore!();

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end() {
    // Create a test case, and connect to the leader's database.
    let test_case = TestCase::new().await;

    // Upload some measurements, recording a timestamp before measurement upload to allow us to
    // determine the correct collect interval.
    let clock = RealClock::default();
    const NUM_NONZERO_MEASUREMENTS: usize = 23;
    let before_timestamp = clock.now();
    for _ in 0..NUM_NONZERO_MEASUREMENTS {
        test_case.client.upload(&0).await.unwrap();
        test_case.client.upload(&1).await.unwrap();
    }

    // Send a collect request, recording the collect job URL.
    let http_client = reqwest::Client::builder()
        .redirect(redirect::Policy::none()) // otherwise following SEE_OTHER is automatic
        .build()
        .unwrap();
    let collect_url = test_case
        .leader_task
        .aggregator_url(Role::Leader)
        .unwrap()
        .join("/collect")
        .unwrap();
    let batch_interval = Interval::new(
        before_timestamp
            .to_batch_unit_interval_start(test_case.leader_task.min_batch_duration)
            .unwrap(),
        // Use two minimum batch durations as the interval duration in order to avoid a race
        // condition if this test happens to run very close to the end of a batch window.
        Duration::from_seconds(2 * test_case.leader_task.min_batch_duration.as_seconds()),
    )
    .unwrap();
    let collect_req = CollectReq {
        task_id: test_case.leader_task.id,
        batch_interval,
        agg_param: Vec::new(),
    };
    let collect_resp = http_client
        .post(collect_url)
        .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
        .body(collect_req.get_encoded())
        .send()
        .await
        .unwrap();
    assert_eq!(collect_resp.status(), StatusCode::SEE_OTHER);
    let collect_job_url = Url::parse(
        collect_resp
            .headers()
            .get(header::LOCATION)
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
    let associated_data =
        associated_data_for_aggregate_share(test_case.leader_task.id, batch_interval);
    let aggregate_result = test_case
        .vdaf
        .unshard(
            &(),
            collect_resp
                .encrypted_agg_shares
                .iter()
                .zip([Role::Leader, Role::Helper])
                .map(|(encrypted_agg_share, role)| {
                    let agg_share_bytes = hpke::open(
                        &test_case.collector_hpke_config,
                        &test_case.collector_private_key,
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

struct TestCase {
    vdaf: Prio3Aes128Count,
    client: Client<Prio3Aes128Count, RealClock>,
    leader_task: Task,
    _leader_db_handle: DbHandle,
    _helper_db_handle: DbHandle,
    collector_hpke_config: HpkeConfig,
    collector_private_key: HpkePrivateKey,

    // Task lifetime management (logically private).
    start_shutdown_sender: Option<oneshot::Sender<()>>,
    shutdown_complete_receiver: Option<mpsc::Receiver<()>>,
}

impl TestCase {
    async fn new() -> Self {
        install_test_trace_subscriber();

        // Generate keys & configs.
        let task_id = TaskId::random();
        let mut verify_key = [0u8; PRIO3_AES128_VERIFY_KEY_LENGTH];
        thread_rng().fill(&mut verify_key[..]);
        let (collector_hpke_config, collector_private_key) = generate_hpke_config_and_private_key();
        let agg_auth_token = generate_aggregator_auth_token();
        let leader_hpke_key = generate_hpke_config_and_private_key();
        let helper_hpke_key = generate_hpke_config_and_private_key();

        // Start up datastores.
        let (leader_datastore, _leader_db_handle) = ephemeral_datastore(RealClock::default()).await;
        let leader_datastore = Arc::new(leader_datastore);
        let (helper_datastore, _helper_db_handle) = ephemeral_datastore(RealClock::default()).await;
        let helper_datastore = Arc::new(helper_datastore);

        // Start leader aggregator server.
        let (leader_shutdown_sender, leader_shutdown_receiver) = oneshot::channel();
        let (leader_address, leader_server) = aggregator_server(
            Arc::clone(&leader_datastore),
            RealClock::default(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            async move { leader_shutdown_receiver.await.unwrap() },
        )
        .unwrap();
        let leader_task_handle = task::spawn(leader_server);

        // Start helper aggregator server.
        let (helper_shutdown_sender, helper_shutdown_receiver) = oneshot::channel();
        let (helper_address, helper_server) = aggregator_server(
            Arc::clone(&helper_datastore),
            RealClock::default(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            async move { helper_shutdown_receiver.await.unwrap() },
        )
        .unwrap();
        let helper_task_handle = task::spawn(helper_server);

        // Insert tasks into leader & helper datastores.
        let leader_endpoint = endpoint_from_socket_addr(&leader_address);
        let helper_endpoint = endpoint_from_socket_addr(&helper_address);

        let leader_task = Task::new(
            task_id,
            vec![leader_endpoint.clone(), helper_endpoint.clone()],
            VdafInstance::Prio3Aes128Count.into(),
            Role::Leader,
            vec![Vec::from(verify_key)],
            1,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            collector_hpke_config.clone(),
            vec![agg_auth_token.clone()],
            vec![leader_hpke_key],
        )
        .unwrap();
        leader_datastore
            .run_tx(|tx| {
                let leader_task = leader_task.clone();
                Box::pin(async move { tx.put_task(&leader_task).await })
            })
            .await
            .unwrap();

        let helper_task = Task::new(
            task_id,
            vec![leader_endpoint.clone(), helper_endpoint.clone()],
            VdafInstance::Prio3Aes128Count.into(),
            Role::Helper,
            vec![Vec::from(verify_key)],
            1,
            0,
            Duration::from_hours(8).unwrap(),
            Duration::from_minutes(10).unwrap(),
            collector_hpke_config.clone(),
            vec![agg_auth_token],
            vec![helper_hpke_key],
        )
        .unwrap();
        helper_datastore
            .run_tx(|tx| {
                let helper_task = helper_task.clone();
                Box::pin(async move { tx.put_task(&helper_task).await })
            })
            .await
            .unwrap();

        // Start the leader's aggregation job creator.
        let (
            aggregation_job_creator_shutdown_sender,
            mut aggregation_job_creator_shutdown_receiver,
        ) = oneshot::channel();
        let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
            _leader_db_handle.datastore(RealClock::default()),
            RealClock::default(),
            time::Duration::from_secs(60),
            time::Duration::from_secs(1),
            1,
            100,
        ));
        let aggregation_job_creator_handle = task::spawn(async move {
            select! {
                _ = aggregation_job_creator.run() => unreachable!(),
                _ = &mut aggregation_job_creator_shutdown_receiver => (),
            }
        });

        // Start the leader's aggregation job driver.
        let (aggregation_job_driver_shutdown_sender, mut aggregation_job_driver_shutdown_receiver) =
            oneshot::channel();
        let datastore = Arc::new(_leader_db_handle.datastore(RealClock::default()));
        let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
        ));
        let aggregation_job_driver = Arc::new(JobDriver::new(
            RealClock::default(),
            TokioRuntime,
            Duration::from_seconds(1),
            Duration::from_seconds(1),
            10,
            Duration::ZERO,
            aggregation_job_driver
                .make_incomplete_job_acquirer_callback(&datastore, Duration::from_seconds(10)),
            aggregation_job_driver.make_job_stepper_callback(&datastore, 3),
        ));
        let aggregation_job_driver_handle = task::spawn(async move {
            select! {
                _ = aggregation_job_driver.run() => unreachable!(),
                _ = &mut aggregation_job_driver_shutdown_receiver => (),
            }
        });

        // Start the leader's collect job driver.
        let (collect_job_driver_shutdown_sender, mut collect_job_driver_shutdown_receiver) =
            oneshot::channel();
        let datastore = Arc::new(_leader_db_handle.datastore(RealClock::default()));
        let collect_job_driver = Arc::new(CollectJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
        ));
        let collect_job_driver = Arc::new(JobDriver::new(
            RealClock::default(),
            TokioRuntime,
            Duration::from_seconds(1),
            Duration::from_seconds(1),
            10,
            Duration::ZERO,
            collect_job_driver
                .make_incomplete_job_acquirer_callback(&datastore, Duration::from_seconds(10)),
            collect_job_driver.make_job_stepper_callback(&datastore, 3),
        ));
        let collect_job_driver_handle = task::spawn(async move {
            select! {
                _ = collect_job_driver.run() => unreachable!(),
                _ = &mut collect_job_driver_shutdown_receiver => (),
            }
        });

        // Start the "shutdown" task, allowing us to do asynchronous shutdown work in the
        // synchronous drop implementation. (We use an async oneshot channel for "start shutdown"
        // and a sync mpsc channel for "shutdown complete" to us to do the required operations from
        // a sync context.)
        let (start_shutdown_sender, start_shutdown_receiver) = oneshot::channel();
        let (shutdown_complete_sender, shutdown_complete_receiver) = mpsc::channel();
        task::spawn(async move {
            start_shutdown_receiver.await.unwrap();

            leader_shutdown_sender.send(()).unwrap();
            helper_shutdown_sender.send(()).unwrap();
            aggregation_job_creator_shutdown_sender.send(()).unwrap();
            aggregation_job_driver_shutdown_sender.send(()).unwrap();
            collect_job_driver_shutdown_sender.send(()).unwrap();

            try_join!(
                leader_task_handle,
                helper_task_handle,
                aggregation_job_creator_handle,
                aggregation_job_driver_handle,
                collect_job_driver_handle
            )
            .unwrap();

            shutdown_complete_sender.send(()).unwrap();
        });

        // Create client, retrieving HPKE configs.
        let client_parameters = ClientParameters::new(
            task_id,
            vec![leader_endpoint.clone(), helper_endpoint.clone()],
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
            Prio3::new_aes128_count(2).unwrap(),
            RealClock::default(),
            &http_client,
            leader_report_config,
            helper_report_config,
        );

        Self {
            vdaf: Prio3::new_aes128_count(2).unwrap(),
            client,
            leader_task,
            _leader_db_handle,
            _helper_db_handle,
            collector_hpke_config,
            collector_private_key,
            start_shutdown_sender: Some(start_shutdown_sender),
            shutdown_complete_receiver: Some(shutdown_complete_receiver),
        }
    }
}

impl Drop for TestCase {
    fn drop(&mut self) {
        let start_shutdown_sender = self.start_shutdown_sender.take().unwrap();
        let shutdown_complete_receiver = self.shutdown_complete_receiver.take().unwrap();

        start_shutdown_sender.send(()).unwrap();
        shutdown_complete_receiver.recv().unwrap();
    }
}

fn endpoint_from_socket_addr(addr: &SocketAddr) -> Url {
    assert!(addr.ip().is_loopback());
    Url::parse(&format!("http://{}", addr)).unwrap()
}
