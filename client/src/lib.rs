//! DAP protocol client

use backoff::ExponentialBackoff;
use derivative::Derivative;
use http::header::CONTENT_TYPE;
use http_api_problem::HttpApiProblem;
use itertools::Itertools;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label},
    http::response_to_problem_details,
    retries::{http_request_exponential_backoff, retry_http_request},
    task::url_ensure_trailing_slash,
    time::{Clock, TimeExt},
};
use janus_messages::{
    Duration, HpkeConfig, HpkeConfigList, InputShareAad, PlaintextInputShare, Report, ReportId,
    ReportMetadata, Role, TaskId,
};
use prio::{
    codec::{Decode, Encode},
    vdaf,
};
use rand::random;
use std::io::Cursor;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid parameter {0}")]
    InvalidParameter(&'static str),
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("codec error: {0}")]
    Codec(#[from] prio::codec::CodecError),
    #[error("HTTP response status {0}")]
    Http(Box<HttpApiProblem>),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("VDAF error: {0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("HPKE error: {0}")]
    Hpke(#[from] janus_core::hpke::Error),
    #[error("unexpected server response {0}")]
    UnexpectedServerResponse(&'static str),
}

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

/// The DAP client's view of task parameters.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct ClientParameters {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// URL relative to which the Leader's API endpoints are found.
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    leader_aggregator_endpoint: Url,
    /// URL relative to which the Helper's API endpoints are found.
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    helper_aggregator_endpoint: Url,
    /// The time precision of the task. This value is shared by all parties in the protocol, and is
    /// used to compute report timestamps.
    time_precision: Duration,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialBackoff,
}

impl ClientParameters {
    /// Creates a new set of client task parameters.
    pub fn new(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
    ) -> Self {
        Self::new_with_backoff(
            task_id,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            http_request_exponential_backoff(),
        )
    }

    /// Creates a new set of client task parameters with non-default HTTP request retry parameters.
    pub fn new_with_backoff(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
        http_request_retry_parameters: ExponentialBackoff,
    ) -> Self {
        Self {
            task_id,
            leader_aggregator_endpoint: url_ensure_trailing_slash(leader_aggregator_endpoint),
            helper_aggregator_endpoint: url_ensure_trailing_slash(helper_aggregator_endpoint),
            time_precision,
            http_request_retry_parameters,
        }
    }

    /// The URL relative to which the API endpoints for the aggregator may be found, if the role is
    /// an aggregator, or an error otherwise.
    fn aggregator_endpoint(&self, role: &Role) -> Result<&Url, Error> {
        match role {
            Role::Leader => Ok(&self.leader_aggregator_endpoint),
            Role::Helper => Ok(&self.helper_aggregator_endpoint),
            _ => Err(Error::InvalidParameter("role is not an aggregator")),
        }
    }

    /// URL from which the HPKE configuration for the server filling `role` may be fetched per
    /// draft-gpew-priv-ppm §4.3.1
    fn hpke_config_endpoint(&self, role: &Role) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(role)?.join("hpke_config")?)
    }

    // URI to which reports may be uploaded for the provided task.
    fn reports_resource_uri(&self, task_id: &TaskId) -> Result<Url, Error> {
        Ok(self
            .leader_aggregator_endpoint
            .join(&format!("tasks/{task_id}/reports"))?)
    }
}

/// Fetches HPKE configuration from the specified aggregator using the aggregator endpoints in the
/// provided [`ClientParameters`].
#[tracing::instrument(err)]
pub async fn aggregator_hpke_config(
    client_parameters: &ClientParameters,
    aggregator_role: &Role,
    task_id: &TaskId,
    http_client: &reqwest::Client,
) -> Result<HpkeConfig, Error> {
    let mut request_url = client_parameters.hpke_config_endpoint(aggregator_role)?;
    request_url.set_query(Some(&format!("task_id={task_id}")));
    let hpke_config_response = retry_http_request(
        client_parameters.http_request_retry_parameters.clone(),
        || async { http_client.get(request_url.clone()).send().await },
    )
    .await
    .or_else(|e| e)?;
    let status = hpke_config_response.status();
    if !status.is_success() {
        return Err(Error::Http(Box::new(
            response_to_problem_details(hpke_config_response).await,
        )));
    }

    let hpke_configs = HpkeConfigList::decode(&mut Cursor::new(
        hpke_config_response.bytes().await?.as_ref(),
    ))?;

    // TODO(#857): Pick one of the advertised HPKE configs. For now, just take the first one, since
    // we support any HpkeConfig we can decode, and it should be the server's preferred one.
    let hpke_config = hpke_configs
        .hpke_configs()
        .get(0)
        .ok_or(Error::UnexpectedServerResponse(
            "aggregator provided empty HpkeConfigList",
        ))?
        .clone();

    Ok(hpke_config)
}

/// Construct a [`reqwest::Client`] suitable for use in a DAP [`Client`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .user_agent(CLIENT_USER_AGENT)
        .build()?)
}

/// A DAP client.
#[derive(Debug)]
pub struct Client<V: vdaf::Client<16>, C> {
    parameters: ClientParameters,
    vdaf_client: V,
    clock: C,
    http_client: reqwest::Client,
    leader_hpke_config: HpkeConfig,
    helper_hpke_config: HpkeConfig,
}

impl<V: vdaf::Client<16>, C: Clock> Client<V, C> {
    pub fn new(
        parameters: ClientParameters,
        vdaf_client: V,
        clock: C,
        http_client: &reqwest::Client,
        leader_hpke_config: HpkeConfig,
        helper_hpke_config: HpkeConfig,
    ) -> Self {
        Self {
            parameters,
            vdaf_client,
            clock,
            http_client: http_client.clone(),
            leader_hpke_config,
            helper_hpke_config,
        }
    }

    /// Shard a measurement, encrypt its shares, and construct a [`janus_core::message::Report`]
    /// to be uploaded.
    fn prepare_report(&self, measurement: &V::Measurement) -> Result<Report, Error> {
        let report_id: ReportId = random();
        let (public_share, input_shares) =
            self.vdaf_client.shard(measurement, report_id.as_ref())?;
        assert_eq!(input_shares.len(), 2); // DAP only supports VDAFs using two aggregators.

        let time = self
            .clock
            .now()
            .to_batch_interval_start(&self.parameters.time_precision)
            .map_err(|_| Error::InvalidParameter("couldn't round time down to time_precision"))?;
        let report_metadata = ReportMetadata::new(report_id, time);
        let encoded_public_share = public_share.get_encoded();

        let (leader_encrypted_input_share, helper_encrypted_input_share) = [
            (&self.leader_hpke_config, &Role::Leader),
            (&self.helper_hpke_config, &Role::Helper),
        ]
        .into_iter()
        .zip(input_shares)
        .map(|((hpke_config, receiver_role), input_share)| {
            hpke::seal(
                hpke_config,
                &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, receiver_role),
                &PlaintextInputShare::new(
                    Vec::new(), // No extensions supported yet.
                    input_share.get_encoded(),
                )
                .get_encoded(),
                &InputShareAad::new(
                    self.parameters.task_id,
                    report_metadata.clone(),
                    encoded_public_share.clone(),
                )
                .get_encoded(),
            )
        })
        .collect_tuple()
        .expect("iterator to yield two items"); // expect safety: iterator contains two items.

        Ok(Report::new(
            report_metadata,
            encoded_public_share,
            leader_encrypted_input_share?,
            helper_encrypted_input_share?,
        ))
    }

    /// Upload a [`Report`] to the leader, per §4.3.2 of draft-gpew-priv-ppm.
    /// The provided measurement is sharded into one input share plus one proof share for each
    /// aggregator and then uploaded to the leader.
    #[tracing::instrument(skip(measurement), err)]
    pub async fn upload(&self, measurement: &V::Measurement) -> Result<(), Error> {
        let report = self.prepare_report(measurement)?;
        let upload_endpoint = self
            .parameters
            .reports_resource_uri(&self.parameters.task_id)?;
        let upload_response = retry_http_request(
            self.parameters.http_request_retry_parameters.clone(),
            || async {
                self.http_client
                    .put(upload_endpoint.clone())
                    .header(CONTENT_TYPE, Report::MEDIA_TYPE)
                    .body(report.get_encoded())
                    .send()
                    .await
            },
        )
        .await
        .or_else(|e| e)?;
        let status = upload_response.status();
        if !status.is_success() {
            return Err(Error::Http(Box::new(
                response_to_problem_details(upload_response).await,
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{default_http_client, Client, ClientParameters, Error};
    use assert_matches::assert_matches;
    use http::{header::CONTENT_TYPE, StatusCode};
    use janus_core::{
        hpke::test_util::generate_test_hpke_config_and_private_key,
        retries::test_http_request_exponential_backoff, test_util::install_test_trace_subscriber,
        time::MockClock,
    };
    use janus_messages::{Duration, Report, Time};
    use prio::vdaf::{self, prio3::Prio3};
    use rand::random;
    use url::Url;

    fn setup_client<V: vdaf::Client<16>>(
        server: &mockito::Server,
        vdaf_client: V,
    ) -> Client<V, MockClock> {
        let server_url = Url::parse(&server.url()).unwrap();
        Client::new(
            ClientParameters::new_with_backoff(
                random(),
                server_url.clone(),
                server_url,
                Duration::from_seconds(1),
                test_http_request_exponential_backoff(),
            ),
            vdaf_client,
            MockClock::default(),
            &default_http_client().unwrap(),
            generate_test_hpke_config_and_private_key().config().clone(),
            generate_test_hpke_config_and_private_key().config().clone(),
        )
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
        let client = setup_client(&server, Prio3::new_count(2).unwrap());

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

        client.upload(&1).await.unwrap();

        mocked_upload.assert_async().await;
    }

    #[tokio::test]
    async fn upload_prio3_invalid_measurement() {
        install_test_trace_subscriber();
        let server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_sum(2, 16).unwrap();
        let client = setup_client(&server, vdaf);

        // 65536 is too big for a 16 bit sum and will be rejected by the VDAF.
        // Make sure we get the right error variant but otherwise we aren't
        // picky about its contents.
        assert_matches!(client.upload(&65536).await, Err(Error::Vdaf(_)));
    }

    #[tokio::test]
    async fn upload_prio3_http_status_code() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let client = setup_client(&server, Prio3::new_count(2).unwrap());

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
            client.upload(&1).await,
            Err(Error::Http(problem)) => {
                assert_eq!(problem.status.unwrap(), StatusCode::NOT_IMPLEMENTED);
            }
        );

        mocked_upload.assert_async().await;
    }

    #[tokio::test]
    async fn upload_problem_details() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let client = setup_client(&server, Prio3::new_count(2).unwrap());

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
            client.upload(&1).await,
            Err(Error::Http(problem)) => {
                assert_eq!(problem.status.unwrap(), StatusCode::BAD_REQUEST);
                assert_eq!(
                    problem.type_url.unwrap(),
                    "urn:ietf:params:ppm:dap:error:invalidMessage"
                );
                assert_eq!(
                    problem.detail.unwrap(),
                    "The message type for a response was incorrect or the payload was malformed."
                );
            }
        );

        mocked_upload.assert_async().await;
    }

    #[tokio::test]
    async fn upload_bad_time_precision() {
        install_test_trace_subscriber();

        let client_parameters = ClientParameters::new(
            random(),
            "https://leader.endpoint".parse().unwrap(),
            "https://helper.endpoint".parse().unwrap(),
            Duration::from_seconds(0),
        );
        let client = Client::new(
            client_parameters,
            Prio3::new_count(2).unwrap(),
            MockClock::default(),
            &default_http_client().unwrap(),
            generate_test_hpke_config_and_private_key().config().clone(),
            generate_test_hpke_config_and_private_key().config().clone(),
        );
        let result = client.upload(&1).await;
        assert_matches!(result, Err(Error::InvalidParameter(_)));
    }

    #[test]
    fn report_timestamp() {
        install_test_trace_subscriber();
        let server = mockito::Server::new();
        let vdaf = Prio3::new_count(2).unwrap();
        let mut client = setup_client(&server, vdaf);

        client.parameters.time_precision = Duration::from_seconds(100);
        client.clock = MockClock::new(Time::from_seconds_since_epoch(101));
        assert_eq!(
            client.prepare_report(&1).unwrap().metadata().time(),
            &Time::from_seconds_since_epoch(100),
        );

        client.clock = MockClock::new(Time::from_seconds_since_epoch(5200));
        assert_eq!(
            client.prepare_report(&1).unwrap().metadata().time(),
            &Time::from_seconds_since_epoch(5200),
        );

        client.clock = MockClock::new(Time::from_seconds_since_epoch(9814));
        assert_eq!(
            client.prepare_report(&1).unwrap().metadata().time(),
            &Time::from_seconds_since_epoch(9800),
        );
    }
}
