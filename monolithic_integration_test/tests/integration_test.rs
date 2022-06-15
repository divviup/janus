use futures::channel::oneshot::Sender;
use janus::{
    hpke::test_util::generate_hpke_config_and_private_key,
    message::{Duration, Role, TaskId},
    time::{Clock, RealClock},
};
use janus_server::{
    aggregator::aggregator_server,
    client::{self, Client, ClientParameters},
    datastore::{Crypter, Datastore},
    task::{
        test_util::generate_aggregator_auth_token, Task, VdafInstance,
        PRIO3_AES128_VERIFY_KEY_LENGTH,
    },
    trace::{install_trace_subscriber, TraceConfiguration},
};
use prio::vdaf::prio3::{Prio3, Prio3Aes128Count};
use rand::{thread_rng, Rng};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::task::JoinHandle;
use url::Url;

janus_test_util::define_ephemeral_datastore!();

fn endpoint_from_socket_addr(addr: &SocketAddr) -> Url {
    assert!(addr.ip().is_loopback());
    let mut endpoint: Url = "http://localhost".parse().unwrap();
    endpoint.set_port(Some(addr.port())).unwrap();

    endpoint
}

struct TestCase {
    client: Client<Prio3Aes128Count, RealClock>,
    _leader_db_handle: DbHandle,
    _helper_db_handle: DbHandle,
    leader_shutdown_sender: Sender<()>,
    helper_shutdown_sender: Sender<()>,
    leader_task_handle: JoinHandle<()>,
    helper_task_handle: JoinHandle<()>,
}

async fn setup_test() -> TestCase {
    install_trace_subscriber(&TraceConfiguration {
        use_test_writer: true,
        ..Default::default()
    })
    .unwrap();

    let task_id = TaskId::random();

    let mut verify_key = [0u8; PRIO3_AES128_VERIFY_KEY_LENGTH];
    thread_rng().fill(&mut verify_key[..]);

    let (collector_hpke_config, _) = generate_hpke_config_and_private_key();
    let agg_auth_token = generate_aggregator_auth_token();
    let leader_hpke_key = generate_hpke_config_and_private_key();
    let helper_hpke_key = generate_hpke_config_and_private_key();

    let (leader_datastore, _leader_db_handle) = ephemeral_datastore(RealClock::default()).await;
    let leader_datastore = Arc::new(leader_datastore);
    let (helper_datastore, _helper_db_handle) = ephemeral_datastore(RealClock::default()).await;

    let (leader_shutdown_sender, leader_shutdown_receiver) = futures::channel::oneshot::channel();
    let (helper_shutdown_sender, helper_shutdown_receiver) = futures::channel::oneshot::channel();
    // `Receiver<T>` by itself yields a `Result<T, Cancelled>`, producing an error if the
    // corresponding sender has been dropped. We will remap values, so that our future returns the
    // unit type in either case. The effect of this is that the server can be cancelled by dropping
    // the channel's sender, or sending a message over it.
    let leader_shutdown_receiver =
        async move { leader_shutdown_receiver.await.unwrap_or_default() };
    let helper_shutdown_receiver =
        async move { helper_shutdown_receiver.await.unwrap_or_default() };

    let leader_task = Task::new(
        task_id,
        vec![
            Url::parse("http://leader_endpoint").unwrap(),
            Url::parse("http://helper_endpoint").unwrap(),
        ],
        VdafInstance::Prio3Aes128Count,
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
    let (leader_address, leader_server) = aggregator_server(
        leader_datastore.clone(),
        RealClock::default(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
        leader_shutdown_receiver,
    )
    .unwrap();

    let helper_task = Task::new(
        task_id,
        vec![
            Url::parse("http://leader_endpoint").unwrap(),
            Url::parse("http://helper_endpoint").unwrap(),
        ],
        VdafInstance::Prio3Aes128Count,
        Role::Helper,
        vec![Vec::from(verify_key)],
        1,
        0,
        Duration::from_hours(8).unwrap(),
        Duration::from_minutes(10).unwrap(),
        collector_hpke_config,
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
    let (helper_address, helper_server) = aggregator_server(
        Arc::new(helper_datastore),
        RealClock::default(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
        helper_shutdown_receiver,
    )
    .unwrap();

    let leader_task_handle = tokio::spawn(leader_server);
    let helper_task_handle = tokio::spawn(helper_server);

    let client_parameters = ClientParameters::new(
        task_id,
        vec![
            endpoint_from_socket_addr(&leader_address),
            endpoint_from_socket_addr(&helper_address),
        ],
    );

    let http_client = client::default_http_client().unwrap();
    let leader_report_config =
        client::aggregator_hpke_config(&client_parameters, Role::Leader, task_id, &http_client)
            .await
            .unwrap();

    let helper_report_config =
        client::aggregator_hpke_config(&client_parameters, Role::Helper, task_id, &http_client)
            .await
            .unwrap();

    let vdaf = Prio3::new_aes128_count(2).unwrap();

    let client = Client::new(
        client_parameters,
        vdaf,
        RealClock::default(),
        &http_client,
        leader_report_config,
        helper_report_config,
    );

    TestCase {
        client,
        _leader_db_handle,
        _helper_db_handle,
        leader_shutdown_sender,
        helper_shutdown_sender,
        leader_task_handle,
        helper_task_handle,
    }
}

async fn teardown_test(test_case: TestCase) {
    test_case.leader_shutdown_sender.send(()).unwrap();
    test_case.helper_shutdown_sender.send(()).unwrap();

    test_case.leader_task_handle.await.unwrap();
    test_case.helper_task_handle.await.unwrap();
}

#[tokio::test]
async fn upload() {
    let test_case = setup_test().await;
    test_case.client.upload(&1).await.unwrap();
    teardown_test(test_case).await
}
