use janus_server::{
    aggregator::aggregator_server,
    client::{self, Client, ClientParameters},
    datastore::test_util::{ephemeral_datastore, DbHandle},
    hpke::{HpkeRecipient, Label},
    message::{Duration, Role, TaskId},
    task::{AggregatorAuthKey, TaskParameters, Vdaf},
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

    let agg_auth_key = AggregatorAuthKey::generate().unwrap();

    let collector_hpke_recipient = HpkeRecipient::generate(
        task_id,
        Label::AggregateShare,
        Role::Leader,
        Role::Collector,
    );

    let (leader_datastore, _leader_db_handle) = ephemeral_datastore().await;
    let leader_datastore = Arc::new(leader_datastore);

    let (helper_datastore, _helper_db_handle) = ephemeral_datastore().await;
    let helper_datastore = Arc::new(helper_datastore);

    let leader_hpke_recipient =
        HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);
    let helper_hpke_recipient =
        HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Helper);

    // There's a chicken and egg problem here: we don't know the port that the
    // leader and helper will bind until we call `aggregator_server`, but we
    // can't call that without defining task parameters. We cheat here by
    // providing fake endpoints, then inserting the real endpoints later for the
    // client.
    let dummy_endpoints = vec![
        Url::parse("https://leader.fake").unwrap(),
        Url::parse("https://helper.fake").unwrap(),
    ];

    let mut leader_task_parameters = TaskParameters::new(
        task_id,
        dummy_endpoints.clone(),
        Vdaf::Prio3Aes128Count,
        Role::Leader,
        leader_verify_param.get_encoded(),
        0,                         // max_batch_lifetime
        0,                         // min_batch_size
        Duration::from_seconds(1), // min_batch_duration,
        Duration::from_seconds(1), // tolerable_clock_skew,
        collector_hpke_recipient.config(),
        agg_auth_key,
        &leader_hpke_recipient,
    );

    leader_datastore
        .run_tx(|tx| {
            let task_parameters = leader_task_parameters.clone();
            Box::pin(async move { tx.put_task(&task_parameters).await })
        })
        .await
        .unwrap();

    let helper_task_parameters = TaskParameters::new(
        task_id,
        dummy_endpoints,
        Vdaf::Prio3Aes128Count,
        Role::Helper,
        helper_verify_param.get_encoded(),
        0,                         // max_batch_lifetime
        0,                         // min_batch_size
        Duration::from_seconds(1), // min_batch_duration,
        Duration::from_seconds(1), // tolerable_clock_skew,
        collector_hpke_recipient.config(),
        agg_auth_key,
        &helper_hpke_recipient,
    );

    helper_datastore
        .run_tx(|tx| {
            let task_parameters = helper_task_parameters.clone();
            Box::pin(async move { tx.put_task(&task_parameters).await })
        })
        .await
        .unwrap();

    let (leader_address, leader_server) = aggregator_server(
        leader_datastore.clone(),
        RealClock::default(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
    )
    .await
    .unwrap();

    let (helper_address, helper_server) = aggregator_server(
        helper_datastore.clone(),
        RealClock::default(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
    )
    .await
    .unwrap();

    let leader_task_handle = tokio::spawn(leader_server);
    let helper_task_handle = tokio::spawn(helper_server);

    leader_task_parameters.set_aggregator_endpoints(vec![
        endpoint_from_socket_addr(&leader_address),
        endpoint_from_socket_addr(&helper_address),
    ]);

    let client_parameters = ClientParameters::from_task_parameters(&leader_task_parameters);

    let http_client = client::default_http_client().unwrap();
    let leader_report_sender =
        client::aggregator_hpke_sender(&client_parameters, Role::Leader, &http_client)
            .await
            .unwrap();

    let helper_report_sender =
        client::aggregator_hpke_sender(&client_parameters, Role::Helper, &http_client)
            .await
            .unwrap();

    let vdaf = Prio3Aes128Count::new(2).unwrap();

    let client = Client::new(
        client_parameters,
        vdaf,
        (), // no public parameter for prio3
        RealClock::default(),
        &http_client,
        leader_report_sender,
        helper_report_sender,
    );

    TestCase {
        client,
        _leader_db_handle,
        _helper_db_handle,
        leader_task_handle,
        helper_task_handle,
    }
}

async fn teardown_test(test_case: TestCase) {
    test_case.leader_task_handle.abort();
    test_case.helper_task_handle.abort();

    assert!(test_case
        .leader_task_handle
        .await
        .unwrap_err()
        .is_cancelled());
    assert!(test_case
        .helper_task_handle
        .await
        .unwrap_err()
        .is_cancelled());
}

#[tokio::test]
async fn upload() {
    let test_case = setup_test().await;

    test_case.client.upload(&1).await.unwrap();

    teardown_test(test_case).await
}
