use std::io::Cursor;

use crate::{
    Client, Error, OhttpConfig, OHTTP_KEYS_MEDIA_TYPE, OHTTP_REQUEST_MEDIA_TYPE,
    OHTTP_RESPONSE_MEDIA_TYPE,
};
use assert_matches::assert_matches;
use bhttp::{Message, Mode, StatusCode};
use http::header::{ACCEPT, CONTENT_TYPE};
use janus_core::{
    hpke::HpkeKeypair, http::HttpErrorResponse,
    retries::test_util::test_http_request_exponential_backoff,
    test_util::install_test_trace_subscriber,
};
use janus_messages::{Duration, Report};
use ohttp::{
    hpke::{Aead, Kdf},
    KeyConfig, SymmetricSuite,
};
use prio::{
    codec::Decode,
    vdaf::prio3::{Prio3, Prio3Count},
};
use rand::random;
use url::Url;

async fn build_client(server: &mockito::ServerGuard) -> Result<Client<Prio3Count>, Error> {
    let task_id = random();
    let server_url = Url::parse(&server.url()).unwrap();
    let keys_endpoint = Url::parse(format!("{}/ohttp-keys", server.url()).as_str()).unwrap();
    let relay = Url::parse(format!("{}/relay", server.url()).as_str()).unwrap();

    Client::builder(
        task_id,
        server_url.clone(),
        server_url.clone(),
        Duration::from_seconds(1),
        Prio3::new_count(2).unwrap(),
    )
    .with_backoff(test_http_request_exponential_backoff())
    .with_leader_hpke_config(HpkeKeypair::test().config().clone())
    .with_helper_hpke_config(HpkeKeypair::test().config().clone())
    .with_ohttp_config(OhttpConfig {
        key_configs: keys_endpoint,
        relay,
    })
    .build()
    .await
}

async fn mocked_ohttp_keys(server: &mut mockito::ServerGuard) -> (mockito::Mock, ohttp::Server) {
    let key_config = KeyConfig::new(
        0,
        ohttp::hpke::Kem::X25519Sha256,
        vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)],
    )
    .unwrap();
    let encoded_key_config = KeyConfig::encode_list(&[&key_config]).unwrap();

    let mocked_ohttp_keys = server
        .mock("GET", "/ohttp-keys")
        .match_header(ACCEPT.as_str(), OHTTP_KEYS_MEDIA_TYPE)
        .expect(1)
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), OHTTP_KEYS_MEDIA_TYPE)
        .with_body(encoded_key_config)
        .create_async()
        .await;

    (mocked_ohttp_keys, ohttp::Server::new(key_config).unwrap())
}

#[tokio::test]
async fn successful_upload() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;

    let (mocked_ohttp_keys, ohttp_server) = mocked_ohttp_keys(&mut server).await;
    let client = build_client(&server).await.unwrap();

    let mocked_ohttp_upload = server
        .mock("POST", "/relay")
        .match_header(ACCEPT.as_str(), OHTTP_RESPONSE_MEDIA_TYPE)
        .match_header(CONTENT_TYPE.as_str(), OHTTP_REQUEST_MEDIA_TYPE)
        .expect(1)
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), OHTTP_RESPONSE_MEDIA_TYPE)
        .with_body_from_request(move |request| {
            let encapsulated_req = request.body().unwrap();
            let (decapsulated_req, server_response) =
                ohttp_server.decapsulate(encapsulated_req.as_ref()).unwrap();
            let bin_request = Message::read_bhttp(&mut Cursor::new(&decapsulated_req[..])).unwrap();

            // Check that encapsulated request is a correct DAP upload
            assert_eq!(
                bin_request
                    .control()
                    .method()
                    .map(|a| String::from_utf8(a.to_vec()).unwrap()),
                Some("PUT".to_string()),
            );
            assert_eq!(
                bin_request
                    .control()
                    .scheme()
                    .map(|a| String::from_utf8(a.to_vec()).unwrap()),
                Some("http".to_string()),
            );
            assert_eq!(
                bin_request
                    .control()
                    .authority()
                    .map(|a| String::from_utf8(a.to_vec()).unwrap()),
                Some(Url::parse(&server.url()).unwrap().authority().to_string()),
            );
            assert_eq!(
                bin_request
                    .control()
                    .path()
                    .map(|a| String::from_utf8(a.to_vec()).unwrap()),
                Some(format!("/tasks/{}/reports", client.parameters.task_id)),
            );

            assert_eq!(
                bin_request
                    .header()
                    .get(b"content-type")
                    .map(|a| String::from_utf8(a.to_vec()).unwrap()),
                Some(Report::MEDIA_TYPE.to_string()),
            );

            Report::get_decoded(bin_request.content()).unwrap();

            // Construct a 200 OK response to the encapsulated request, then encapsulate that
            let mut response = Vec::new();
            Message::response(StatusCode::OK)
                .write_bhttp(Mode::KnownLength, &mut response)
                .unwrap();
            server_response.encapsulate(&response).unwrap()
        })
        .create_async()
        .await;

    client.upload(&true).await.unwrap();

    mocked_ohttp_keys.assert_async().await;
    mocked_ohttp_upload.assert_async().await;
}

#[tokio::test]
async fn ohttp_keyconfigs_http_error() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;

    let mocked_ohttp_keys = server
        .mock("GET", "/ohttp-keys")
        .match_header(ACCEPT.as_str(), OHTTP_KEYS_MEDIA_TYPE)
        .expect(1)
        .with_status(400)
        .with_header(CONTENT_TYPE.as_str(), OHTTP_KEYS_MEDIA_TYPE)
        .create_async()
        .await;

    let error = build_client(&server).await.unwrap_err();
    assert_matches!(error, Error::Http(_));

    mocked_ohttp_keys.assert_async().await;
}

#[tokio::test]
async fn ohttp_keyconfigs_malformed_response_body() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;

    let mocked_ohttp_keys = server
        .mock("GET", "/ohttp-keys")
        .match_header(ACCEPT.as_str(), OHTTP_KEYS_MEDIA_TYPE)
        .expect(1)
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), OHTTP_KEYS_MEDIA_TYPE)
        // Not a valid KeyConfigList
        .with_body(vec![0, 1, 2, 3])
        .create_async()
        .await;

    let error = build_client(&server).await.unwrap_err();

    assert_matches!(error, Error::Ohttp(_));

    mocked_ohttp_keys.assert_async().await;
}

#[tokio::test]
async fn ohttp_keyconfigs_wrong_content_type() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;

    let key_config = KeyConfig::new(
        0,
        ohttp::hpke::Kem::X25519Sha256,
        vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)],
    )
    .unwrap();
    let encoded_key_config = KeyConfig::encode_list(&[&key_config]).unwrap();

    let mocked_ohttp_keys = server
        .mock("GET", "/ohttp-keys")
        .match_header(ACCEPT.as_str(), OHTTP_KEYS_MEDIA_TYPE)
        .expect(1)
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), "application/wrong-type")
        .with_body(encoded_key_config)
        .create_async()
        .await;

    let error = build_client(&server).await.unwrap_err();

    assert_matches!(error, Error::UnexpectedServerResponse(_));

    mocked_ohttp_keys.assert_async().await;
}

#[tokio::test]
async fn http_client_error_from_relay() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;

    let (mocked_ohttp_keys, _) = mocked_ohttp_keys(&mut server).await;
    let client = build_client(&server).await.unwrap();

    let mocked_ohttp_upload = server
        .mock("POST", "/relay")
        .match_header(ACCEPT.as_str(), OHTTP_RESPONSE_MEDIA_TYPE)
        .match_header(CONTENT_TYPE.as_str(), OHTTP_REQUEST_MEDIA_TYPE)
        .expect(1)
        .with_status(400)
        .create_async()
        .await;

    let error = client.upload(&true).await.unwrap_err();

    assert_matches!(error, Error::Http(boxed) => {
        assert_matches!(boxed.as_ref(), HttpErrorResponse {..});
    });

    mocked_ohttp_keys.assert_async().await;
    mocked_ohttp_upload.assert_async().await;
}

#[tokio::test]
async fn http_client_error_from_target() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;

    let (mocked_ohttp_keys, ohttp_server) = mocked_ohttp_keys(&mut server).await;
    let client = build_client(&server).await.unwrap();

    let mocked_ohttp_upload = server
        .mock("POST", "/relay")
        .match_header(ACCEPT.as_str(), OHTTP_RESPONSE_MEDIA_TYPE)
        .match_header(CONTENT_TYPE.as_str(), OHTTP_REQUEST_MEDIA_TYPE)
        .expect(1)
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), OHTTP_RESPONSE_MEDIA_TYPE)
        .with_body_from_request(move |request| {
            let encapsulated_req = request.body().unwrap();
            let (_, server_response) = ohttp_server.decapsulate(encapsulated_req.as_ref()).unwrap();

            // Construct a 400 Client Error response to the encapsulated request, then encapsulate that
            let mut response = Vec::new();
            Message::response(StatusCode::try_from(400u16).unwrap())
                .write_bhttp(Mode::KnownLength, &mut response)
                .unwrap();
            server_response.encapsulate(&response).unwrap()
        })
        .create_async()
        .await;

    let error = client.upload(&true).await.unwrap_err();

    assert_matches!(error, Error::Http(boxed) => {
        assert_matches!(boxed.as_ref(), HttpErrorResponse {..});
    });

    mocked_ohttp_keys.assert_async().await;
    mocked_ohttp_upload.assert_async().await;
}

#[tokio::test]
async fn encapsulated_server_message_is_http_request() {
    install_test_trace_subscriber();
    let mut server = mockito::Server::new_async().await;

    let (mocked_ohttp_keys, ohttp_server) = mocked_ohttp_keys(&mut server).await;
    let client = build_client(&server).await.unwrap();

    let mocked_ohttp_upload = server
        .mock("POST", "/relay")
        .match_header(ACCEPT.as_str(), OHTTP_RESPONSE_MEDIA_TYPE)
        .match_header(CONTENT_TYPE.as_str(), OHTTP_REQUEST_MEDIA_TYPE)
        .expect(1)
        .with_status(200)
        .with_header(CONTENT_TYPE.as_str(), OHTTP_RESPONSE_MEDIA_TYPE)
        .with_body_from_request(move |request| {
            let encapsulated_req = request.body().unwrap();
            let (_, server_response) = ohttp_server.decapsulate(encapsulated_req.as_ref()).unwrap();

            // Construct an encapsulated *request*
            let mut response = Vec::new();
            Message::request(
                b"GET".to_vec(),
                b"http".to_vec(),
                b"example.com".to_vec(),
                b"/something".to_vec(),
            )
            .write_bhttp(Mode::KnownLength, &mut response)
            .unwrap();
            server_response.encapsulate(&response).unwrap()
        })
        .create_async()
        .await;

    let error = client.upload(&true).await.unwrap_err();

    assert_matches!(error, Error::UnexpectedServerResponse(_));

    mocked_ohttp_keys.assert_async().await;
    mocked_ohttp_upload.assert_async().await;
}
