use chrono::Duration;
use janus_server::{
    aggregator::aggregator_server,
    client::Client,
    datastore::test_util::ephemeral_datastore,
    hpke::{HpkeRecipient, Label},
    message::{Role, TaskId},
    time::RealClock,
    trace::install_subscriber,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use url::Url;

fn endpoint_from_socket_addr(addr: &SocketAddr) -> Url {
    assert!(addr.ip().is_loopback());
    let mut endpoint: Url = "http://localhost".parse().unwrap();
    endpoint.set_port(Some(addr.port())).unwrap();

    endpoint
}

#[tokio::test]
async fn create_client() {
    install_subscriber().unwrap();

    let task_id = TaskId::random();

    let (leader_datastore, _leader_db_handle) = ephemeral_datastore().await;
    let leader_hpke_recipient =
        HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);
    let (leader_address, leader_server) = aggregator_server(
        Arc::new(leader_datastore),
        RealClock::default(),
        Duration::minutes(10),
        Role::Leader,
        leader_hpke_recipient,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
    )
    .unwrap();
    let leader_handle = tokio::spawn(leader_server);

    let (helper_datastore, _helper_db_handle) = ephemeral_datastore().await;
    let helper_hpke_recipient =
        HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Helper);
    let (helper_address, helper_server) = aggregator_server(
        Arc::new(helper_datastore),
        RealClock::default(),
        Duration::minutes(10),
        Role::Helper,
        helper_hpke_recipient,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
    )
    .unwrap();
    let helper_handle = tokio::spawn(helper_server);

    let http_client = Client::default_http_client().unwrap();
    let leader_report_sender = Client::aggregator_hpke_sender(
        &http_client,
        task_id,
        endpoint_from_socket_addr(&leader_address),
    )
    .await
    .unwrap();

    let helper_report_sender = Client::aggregator_hpke_sender(
        &http_client,
        task_id,
        endpoint_from_socket_addr(&helper_address),
    )
    .await
    .unwrap();

    let _client = Client::new(&http_client, leader_report_sender, helper_report_sender);

    leader_handle.abort();
    helper_handle.abort();

    leader_handle.await.unwrap_err().is_cancelled();
    helper_handle.await.unwrap_err().is_cancelled();
}
