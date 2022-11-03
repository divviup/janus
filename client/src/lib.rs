//! DAP protocol client

use backoff::ExponentialBackoff;
use derivative::Derivative;
use http::header::CONTENT_TYPE;
use http_api_problem::HttpApiProblem;
use janus_core::{
    hpke::associated_data_for_report_share,
    hpke::{self, HpkeApplicationInfo, Label},
    http::response_to_problem_details,
    retries::{http_request_exponential_backoff, retry_http_request},
    task::url_ensure_trailing_slash,
    time::{Clock, TimeExt},
};
use janus_messages::{Duration, HpkeCiphertext, HpkeConfig, Report, ReportMetadata, Role, TaskId};
use prio::{
    codec::{Decode, Encode},
    vdaf,
};
use rand::random;
use std::{
    fmt::{self, Formatter},
    io::Cursor,
};
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
    Http(HttpApiProblem),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("VDAF error: {0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("HPKE error: {0}")]
    Hpke(#[from] janus_core::hpke::Error),
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
    /// URLs relative to which aggregator API endpoints are found. The first
    /// entry is the leader's.
    #[derivative(Debug(format_with = "fmt_vector_of_urls"))]
    aggregator_endpoints: Vec<Url>,
    /// The time precision of the task. This value is shared by all parties in the protocol, and is
    /// used to compute report timestamps.
    time_precision: Duration,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialBackoff,
}

impl ClientParameters {
    /// Creates a new set of client task parameters.
    pub fn new(task_id: TaskId, aggregator_endpoints: Vec<Url>, time_precision: Duration) -> Self {
        Self::new_with_backoff(
            task_id,
            aggregator_endpoints,
            time_precision,
            http_request_exponential_backoff(),
        )
    }

    /// Creates a new set of client task parameters with non-default HTTP request retry parameters.
    pub fn new_with_backoff(
        task_id: TaskId,
        mut aggregator_endpoints: Vec<Url>,
        time_precision: Duration,
        http_request_retry_parameters: ExponentialBackoff,
    ) -> Self {
        // Ensure provided aggregator endpoints end with a slash, as we will be joining additional
        // path segments into these endpoints & the Url::join implementation is persnickety about
        // the slash at the end of the path.
        for url in &mut aggregator_endpoints {
            url_ensure_trailing_slash(url);
        }

        Self {
            task_id,
            aggregator_endpoints,
            time_precision,
            http_request_retry_parameters,
        }
    }

    /// The URL relative to which the API endpoints for the aggregator may be
    /// found, if the role is an aggregator, or an error otherwise.
    #[allow(clippy::result_large_err)]
    fn aggregator_endpoint(&self, role: &Role) -> Result<&Url, Error> {
        Ok(&self.aggregator_endpoints[role
            .index()
            .ok_or(Error::InvalidParameter("role is not an aggregator"))?])
    }

    /// URL from which the HPKE configuration for the server filling `role` may
    /// be fetched per draft-gpew-priv-ppm §4.3.1
    #[allow(clippy::result_large_err)]
    fn hpke_config_endpoint(&self, role: &Role) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(role)?.join("hpke_config")?)
    }

    /// URL to which reports may be uploaded by clients per draft-gpew-priv-ppm
    /// §4.3.2
    #[allow(clippy::result_large_err)]
    fn upload_endpoint(&self) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(&Role::Leader)?.join("upload")?)
    }
}

fn fmt_vector_of_urls(urls: &Vec<Url>, f: &mut Formatter<'_>) -> fmt::Result {
    let mut list = f.debug_list();
    for url in urls {
        list.entry(&format!("{}", url));
    }
    list.finish()
}

/// Fetches HPKE configuration from the specified aggregator using the
/// aggregator endpoints in the provided [`ClientParameters`].
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
        return Err(Error::Http(
            response_to_problem_details(hpke_config_response).await,
        ));
    }

    Ok(HpkeConfig::decode(&mut Cursor::new(
        hpke_config_response.bytes().await?.as_ref(),
    ))?)
}

/// Construct a [`reqwest::Client`] suitable for use in a DAP [`Client`].
#[allow(clippy::result_large_err)]
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .user_agent(CLIENT_USER_AGENT)
        .build()?)
}

/// A DAP client.
#[derive(Debug)]
pub struct Client<V: vdaf::Client, C>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    parameters: ClientParameters,
    vdaf_client: V,
    clock: C,
    http_client: reqwest::Client,
    leader_hpke_config: HpkeConfig,
    helper_hpke_config: HpkeConfig,
}

impl<V: vdaf::Client, C: Clock> Client<V, C>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
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
    #[allow(clippy::result_large_err)]
    fn prepare_report(&self, measurement: &V::Measurement) -> Result<Report, Error> {
        let (public_share, input_shares) = self.vdaf_client.shard(measurement)?;
        assert_eq!(input_shares.len(), 2); // DAP only supports VDAFs using two aggregators.

        let time = self
            .clock
            .now()
            .to_batch_unit_interval_start(&self.parameters.time_precision)
            .map_err(|_| Error::InvalidParameter("couldn't round time down to time_precision"))?;
        let report_metadata = ReportMetadata::new(
            random(),
            time,
            Vec::new(), // No extensions supported yet
        );
        let public_share = public_share.get_encoded();
        let associated_data = associated_data_for_report_share(
            &self.parameters.task_id,
            &report_metadata,
            &public_share,
        );

        let encrypted_input_shares: Vec<HpkeCiphertext> = [
            (&self.leader_hpke_config, &Role::Leader),
            (&self.helper_hpke_config, &Role::Helper),
        ]
        .into_iter()
        .zip(input_shares)
        .map(|((hpke_config, receiver_role), input_share)| {
            Ok(hpke::seal(
                hpke_config,
                &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, receiver_role),
                &input_share.get_encoded(),
                &associated_data,
            )?)
        })
        .collect::<Result<_, Error>>()?;

        Ok(Report::new(
            self.parameters.task_id,
            report_metadata,
            public_share,
            encrypted_input_shares,
        ))
    }

    /// Upload a [`Report`] to the leader, per §4.3.2 of draft-gpew-priv-ppm.
    /// The provided measurement is sharded into one input share plus one proof share for each
    /// aggregator and then uploaded to the leader.
    #[tracing::instrument(skip(measurement), err)]
    pub async fn upload(&self, measurement: &V::Measurement) -> Result<(), Error> {
        let report = self.prepare_report(measurement)?;
        let upload_endpoint = self.parameters.upload_endpoint()?;
        let upload_response = retry_http_request(
            self.parameters.http_request_retry_parameters.clone(),
            || async {
                self.http_client
                    .post(upload_endpoint.clone())
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
            return Err(Error::Http(
                response_to_problem_details(upload_response).await,
            ));
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
    use mockito::mock;
    use prio::vdaf::{self, prio3::Prio3};
    use rand::random;
    use url::Url;

    fn setup_client<V: vdaf::Client>(vdaf_client: V) -> Client<V, MockClock>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let server_url = Url::parse(&mockito::server_url()).unwrap();
        Client::new(
            ClientParameters::new_with_backoff(
                random(),
                Vec::from([server_url.clone(), server_url]),
                Duration::from_seconds(1),
                test_http_request_exponential_backoff(),
            ),
            vdaf_client,
            MockClock::default(),
            &default_http_client().unwrap(),
            generate_test_hpke_config_and_private_key().0,
            generate_test_hpke_config_and_private_key().0,
        )
    }

    #[test]
    fn aggregator_endpoints_end_in_slash() {
        let client_parameters = ClientParameters::new(
            random(),
            Vec::from([
                "http://leader_endpoint/foo/bar".parse().unwrap(),
                "http://helper_endpoint".parse().unwrap(),
            ]),
            Duration::from_seconds(1),
        );

        assert_eq!(
            client_parameters.aggregator_endpoints,
            Vec::from([
                "http://leader_endpoint/foo/bar/".parse().unwrap(),
                "http://helper_endpoint/".parse().unwrap()
            ])
        );
    }

    #[tokio::test]
    async fn upload_prio3_count() {
        install_test_trace_subscriber();
        let mocked_upload = mock("POST", "/upload")
            .match_header(CONTENT_TYPE.as_str(), Report::MEDIA_TYPE)
            .with_status(200)
            .expect(1)
            .create();

        let client = setup_client(Prio3::new_aes128_count(2).unwrap());
        client.upload(&1).await.unwrap();

        mocked_upload.assert();
    }

    #[tokio::test]
    async fn upload_prio3_invalid_measurement() {
        install_test_trace_subscriber();
        let vdaf = Prio3::new_aes128_sum(2, 16).unwrap();

        let client = setup_client(vdaf);
        // 65536 is too big for a 16 bit sum and will be rejected by the VDAF.
        // Make sure we get the right error variant but otherwise we aren't
        // picky about its contents.
        assert_matches!(client.upload(&65536).await, Err(Error::Vdaf(_)));
    }

    #[tokio::test]
    async fn upload_prio3_http_status_code() {
        install_test_trace_subscriber();

        let mocked_upload = mock("POST", "/upload")
            .match_header(CONTENT_TYPE.as_str(), Report::MEDIA_TYPE)
            .with_status(501)
            .expect(1)
            .create();

        let client = setup_client(Prio3::new_aes128_count(2).unwrap());
        assert_matches!(
            client.upload(&1).await,
            Err(Error::Http(problem)) => {
                assert_eq!(problem.status.unwrap(), StatusCode::NOT_IMPLEMENTED);
            }
        );

        mocked_upload.assert();
    }

    #[tokio::test]
    async fn upload_problem_details() {
        install_test_trace_subscriber();

        let mocked_upload = mock("POST", "/upload")
            .match_header(CONTENT_TYPE.as_str(), Report::MEDIA_TYPE)
            .with_status(400)
            .with_header("Content-Type", "application/problem+json")
            .with_body(
                concat!(
                    "{\"type\": \"urn:ietf:params:ppm:dap:error:unrecognizedMessage\", ",
                    "\"detail\": \"The message type for a response was incorrect or the payload was malformed.\"}",
                )
            )
            .expect(1)
            .create();

        let client = setup_client(Prio3::new_aes128_count(2).unwrap());
        assert_matches!(
            client.upload(&1).await,
            Err(Error::Http(problem)) => {
                assert_eq!(problem.status.unwrap(), StatusCode::BAD_REQUEST);
                assert_eq!(
                    problem.type_url.unwrap(),
                    "urn:ietf:params:ppm:dap:error:unrecognizedMessage"
                );
                assert_eq!(
                    problem.detail.unwrap(),
                    "The message type for a response was incorrect or the payload was malformed."
                );
            }
        );

        mocked_upload.assert();
    }

    #[tokio::test]
    async fn upload_bad_time_precision() {
        install_test_trace_subscriber();

        let client_parameters =
            ClientParameters::new(random(), Vec::new(), Duration::from_seconds(0));
        let client = Client::new(
            client_parameters,
            Prio3::new_aes128_count(2).unwrap(),
            MockClock::default(),
            &default_http_client().unwrap(),
            generate_test_hpke_config_and_private_key().0,
            generate_test_hpke_config_and_private_key().0,
        );
        let result = client.upload(&1).await;
        assert_matches!(result, Err(Error::InvalidParameter(_)));
    }

    #[test]
    fn report_timestamp() {
        install_test_trace_subscriber();
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let mut client = setup_client(vdaf);

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
