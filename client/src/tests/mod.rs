use crate::{aggregator_hpke_config, default_http_client, Client, ClientParameters, Error};
use assert_matches::assert_matches;
use hex_literal::hex;
use http::{header::CONTENT_TYPE, StatusCode};
use janus_core::{
    hpke::HpkeKeypair, retries::test_util::test_http_request_exponential_backoff,
    test_util::install_test_trace_subscriber,
};
use janus_messages::{Duration, HpkeConfigList, Report, Role, Time};
use prio::{
    codec::Encode,
    vdaf::{self, prio3::Prio3},
};
use rand::random;
use url::Url;

#[cfg(feature = "ohttp")]
mod ohttp;

async fn setup_client<V: vdaf::Client<16>>(server: &mockito::Server, vdaf: V) -> Client<V> {
    let server_url = Url::parse(&server.url()).unwrap();
    Client::builder(
        random(),
        server_url.clone(),
        server_url,
        Duration::from_seconds(1),
        vdaf,
    )
    .with_backoff(test_http_request_exponential_backoff())
    .with_leader_hpke_config(HpkeKeypair::test().config().clone())
    .with_helper_hpke_config(HpkeKeypair::test().config().clone())
    .build()
    .await
    .unwrap()
}

#[test]
fn aggregator_endpoints_end_in_slash() {
    let client_parameters = ClientParameters::new(
        random(),
        "http://leader_endpoint/foo/bar".parse().unwrap(),
        "http://helper_endpoint".parse().unwrap(),
        Duration::from_seconds(1),
    );

    assert_eq!(
        client_parameters.leader_aggregator_endpoint,
        "http://leader_endpoint/foo/bar/".parse().unwrap()
    );
    assert_eq!(
        client_parameters.helper_aggregator_endpoint,
        "http://helper_endpoint/".parse().unwrap()
    );
}

#[tokio::test]
async fn upload_prio3_count() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;
    let client = setup_client(&server, Prio3::new_count(2).unwrap()).await;

    let mocked_upload = server
        .mock(
            "PUT",
            format!("/tasks/{}/reports", client.parameters.task_id).as_str(),
        )
        .match_header(CONTENT_TYPE.as_str(), Report::MEDIA_TYPE)
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    client.upload(&true).await.unwrap();

    mocked_upload.assert_async().await;
}

#[tokio::test]
async fn upload_prio3_invalid_measurement() {
    install_test_trace_subscriber();
    let server = mockito::Server::new_async().await;
    let vdaf = Prio3::new_sum(2, 16).unwrap();
    let client = setup_client(&server, vdaf).await;

    // 65536 is too big for a 16 bit sum and will be rejected by the VDAF.
    // Make sure we get the right error variant but otherwise we aren't
    // picky about its contents.
    assert_matches!(client.upload(&65536).await, Err(Error::Vdaf(_)));
}

#[tokio::test]
async fn upload_prio3_http_status_code() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;
    let client = setup_client(&server, Prio3::new_count(2).unwrap()).await;

    let mocked_upload = server
        .mock(
            "PUT",
            format!("/tasks/{}/reports", client.parameters.task_id).as_str(),
        )
        .match_header(CONTENT_TYPE.as_str(), Report::MEDIA_TYPE)
        .with_status(501)
        .expect(1)
        .create_async()
        .await;

    assert_matches!(
        client.upload(&true).await,
        Err(Error::Http(error_response)) => {
            assert_eq!(error_response.status(), StatusCode::NOT_IMPLEMENTED);
        }
    );

    mocked_upload.assert_async().await;
}

#[tokio::test]
async fn upload_problem_details() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;
    let client = setup_client(&server, Prio3::new_count(2).unwrap()).await;

    let mocked_upload = server
        .mock(
            "PUT",
            format!("/tasks/{}/reports", client.parameters.task_id).as_str(),
        )
        .match_header(CONTENT_TYPE.as_str(), Report::MEDIA_TYPE)
        .with_status(400)
        .with_header("Content-Type", "application/problem+json")
        .with_body(concat!(
            "{\"type\": \"urn:ietf:params:ppm:dap:error:invalidMessage\", ",
            "\"detail\": \"The message type for a response was incorrect or the payload was \
                 malformed.\"}",
        ))
        .expect(1)
        .create_async()
        .await;

    assert_matches!(
        client.upload(&true).await,
        Err(Error::Http(error_response)) => {
            assert_eq!(error_response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                error_response.type_uri().unwrap(),
                "urn:ietf:params:ppm:dap:error:invalidMessage"
            );
            assert_eq!(
                error_response.detail().unwrap(),
                "The message type for a response was incorrect or the payload was malformed."
            );
        }
    );

    mocked_upload.assert_async().await;
}

#[tokio::test]
async fn upload_bad_time_precision() {
    install_test_trace_subscriber();

    let client = Client::builder(
        random(),
        "https://leader.endpoint".parse().unwrap(),
        "https://helper.endpoint".parse().unwrap(),
        Duration::from_seconds(0),
        Prio3::new_count(2).unwrap(),
    )
    .with_leader_hpke_config(HpkeKeypair::test().config().clone())
    .with_helper_hpke_config(HpkeKeypair::test().config().clone())
    .build()
    .await
    .unwrap();
    let result = client.upload(&true).await;
    assert_matches!(result, Err(Error::InvalidParameter(_)));
}

#[tokio::test]
async fn report_timestamp() {
    install_test_trace_subscriber();
    let server = mockito::Server::new_async().await;
    let vdaf = Prio3::new_count(2).unwrap();
    let mut client = setup_client(&server, vdaf).await;

    client.parameters.time_precision = Duration::from_seconds(100);
    assert_eq!(
        client
            .prepare_report(&true, &Time::from_seconds_since_epoch(101))
            .unwrap()
            .metadata()
            .time(),
        &Time::from_seconds_since_epoch(100),
    );

    assert_eq!(
        client
            .prepare_report(&true, &Time::from_seconds_since_epoch(5200))
            .unwrap()
            .metadata()
            .time(),
        &Time::from_seconds_since_epoch(5200),
    );

    assert_eq!(
        client
            .prepare_report(&true, &Time::from_seconds_since_epoch(9814))
            .unwrap()
            .metadata()
            .time(),
        &Time::from_seconds_since_epoch(9800),
    );
}

#[tokio::test]
async fn aggregator_hpke() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = &default_http_client().unwrap();
    let mut client_parameters = ClientParameters::new(
        random(),
        server_url.clone(),
        server_url,
        Duration::from_seconds(1),
    );
    client_parameters.http_request_retry_parameters = test_http_request_exponential_backoff();

    let keypair = HpkeKeypair::test();
    let hpke_config_list = HpkeConfigList::new(Vec::from([keypair.config().clone()]));
    let mock = server
        .mock(
            "GET",
            format!("/hpke_config?task_id={}", &client_parameters.task_id).as_str(),
        )
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), HpkeConfigList::MEDIA_TYPE)
        .with_body(hpke_config_list.get_encoded().unwrap())
        .expect(1)
        .create_async()
        .await;

    let got_hpke_config =
        aggregator_hpke_config(None, &client_parameters, &Role::Leader, http_client)
            .await
            .unwrap();
    assert_eq!(&got_hpke_config, keypair.config());

    // Fetching HPKE config again should not hit the mock server
    let got_hpke_config = aggregator_hpke_config(
        Some(got_hpke_config),
        &client_parameters,
        &Role::Leader,
        http_client,
    )
    .await
    .unwrap();
    assert_eq!(&got_hpke_config, keypair.config());

    mock.assert_async().await;
}

#[tokio::test]
async fn unsupported_hpke_algorithms() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;
    let server_url = Url::parse(&server.url()).unwrap();
    let http_client = &default_http_client().unwrap();
    let mut client_parameters = ClientParameters::new(
        random(),
        server_url.clone(),
        server_url,
        Duration::from_seconds(1),
    );
    client_parameters.http_request_retry_parameters = test_http_request_exponential_backoff();

    let encoded_bad_hpke_config = hex!(
        "64" // HpkeConfigId
        "0064" // HpkeKemId
        "0064" // HpkeKdfId
        "0064" // HpkeAeadId
        "0008" // Length prefix from HpkePublicKey
        "4141414141414141" // Contents of HpkePublicKey
    );

    let good_hpke_config = HpkeKeypair::test().config().clone();
    let encoded_good_hpke_config = good_hpke_config.get_encoded().unwrap();

    let mut encoded_hpke_config_list = Vec::new();
    // HpkeConfigList length prefix
    encoded_hpke_config_list.extend_from_slice(
        &u16::try_from(encoded_bad_hpke_config.len() + encoded_good_hpke_config.len())
            .unwrap()
            .to_be_bytes(),
    );
    encoded_hpke_config_list.extend_from_slice(&encoded_bad_hpke_config);
    encoded_hpke_config_list.extend_from_slice(&encoded_good_hpke_config);

    let mock = server
        .mock(
            "GET",
            format!("/hpke_config?task_id={}", &client_parameters.task_id).as_str(),
        )
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), HpkeConfigList::MEDIA_TYPE)
        .with_body(encoded_hpke_config_list)
        .expect(1)
        .create_async()
        .await;

    let got_hpke_config =
        aggregator_hpke_config(None, &client_parameters, &Role::Leader, http_client)
            .await
            .unwrap();
    assert_eq!(got_hpke_config, good_hpke_config);

    mock.assert_async().await;
}
