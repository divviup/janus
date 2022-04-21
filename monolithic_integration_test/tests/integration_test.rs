use chrono::Duration;
use futures::channel::oneshot::Sender;
use janus_server::{
    aggregator::aggregator_server,
    client::{self, Client, ClientParameters},
    datastore::test_util::{ephemeral_datastore, DbHandle},
    hpke::test_util::generate_hpke_config_and_private_key,
    message::{Role, TaskId},
    task::{AggregatorAuthKey, Task, Vdaf},
    time::RealClock,
    trace::{install_trace_subscriber, TraceConfiguration},
};
use prio::{
    codec::Encode,
    vdaf::{prio3::Prio3Aes128Count, Vdaf as VdafTrait},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::task::JoinHandle;
use url::Url;

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

    let vdaf = Prio3Aes128Count::new(2).unwrap();
    let mut verify_params_iter = vdaf.setup().unwrap().1.into_iter();
    let leader_verify_param = verify_params_iter.next().unwrap();
    let helper_verify_param = verify_params_iter.next().unwrap();

    let (collector_hpke_config, _) = generate_hpke_config_and_private_key();
    let agg_auth_key = AggregatorAuthKey::generate();
    let leader_hpke_key = generate_hpke_config_and_private_key();
    let helper_hpke_key = generate_hpke_config_and_private_key();

    let (leader_datastore, _leader_db_handle) = ephemeral_datastore().await;
    let leader_datastore = Arc::new(leader_datastore);
    let (helper_datastore, _helper_db_handle) = ephemeral_datastore().await;

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
        Vdaf::Prio3Aes128Count,
        Role::Leader,
        leader_verify_param.get_encoded(),
        1,
        0,
        Duration::hours(8),
        Duration::minutes(10),
        collector_hpke_config.clone(),
        vec![agg_auth_key.clone()],
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
        Vdaf::Prio3Aes128Count,
        Role::Helper,
        helper_verify_param.get_encoded(),
        1,
        0,
        Duration::hours(8),
        Duration::minutes(10),
        collector_hpke_config,
        vec![agg_auth_key],
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

    let vdaf = Prio3Aes128Count::new(2).unwrap();

    let client = Client::new(
        client_parameters,
        vdaf,
        (), // no public parameter for prio3
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
