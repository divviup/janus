//! DAP protocol client

use backoff::ExponentialBackoff;
use derivative::Derivative;
use http::header::CONTENT_TYPE;
use itertools::Itertools;
use janus_core::{
    hpke::{self, is_hpke_config_supported, HpkeApplicationInfo, Label},
    http::HttpErrorResponse,
    retries::{http_request_exponential_backoff, retry_http_request},
    time::{Clock, RealClock, TimeExt},
    url_ensure_trailing_slash,
};
use janus_messages::{
    Duration, HpkeConfig, HpkeConfigList, InputShareAad, PlaintextInputShare, Report, ReportId,
    ReportMetadata, Role, TaskId, Time,
};
use prio::{
    codec::{Decode, Encode},
    vdaf,
};
use rand::random;
use std::{convert::Infallible, fmt::Debug, io::Cursor, time::SystemTimeError};
use tokio::try_join;
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
    Http(Box<HttpErrorResponse>),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("VDAF error: {0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("HPKE error: {0}")]
    Hpke(#[from] janus_core::hpke::Error),
    #[error("unexpected server response {0}")]
    UnexpectedServerResponse(&'static str),
    #[error("time conversion error: {0}")]
    TimeConversion(#[from] SystemTimeError),
}

impl From<Infallible> for Error {
    fn from(value: Infallible) -> Self {
        match value {}
    }
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
struct ClientParameters {
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
async fn aggregator_hpke_config(
    client_parameters: &ClientParameters,
    aggregator_role: &Role,
    http_client: &reqwest::Client,
) -> Result<HpkeConfig, Error> {
    let mut request_url = client_parameters.hpke_config_endpoint(aggregator_role)?;
    request_url.set_query(Some(&format!("task_id={}", client_parameters.task_id)));
    let hpke_config_response = retry_http_request(
        client_parameters.http_request_retry_parameters.clone(),
        || async { http_client.get(request_url.clone()).send().await },
    )
    .await
    .or_else(|e| e)?;
    let status = hpke_config_response.status();
    if !status.is_success() {
        return Err(Error::Http(Box::new(
            HttpErrorResponse::from_response(hpke_config_response).await,
        )));
    }

    let hpke_configs = HpkeConfigList::decode(&mut Cursor::new(
        hpke_config_response.bytes().await?.as_ref(),
    ))?;

    if hpke_configs.hpke_configs().is_empty() {
        return Err(Error::UnexpectedServerResponse(
            "aggregator provided empty HpkeConfigList",
        ));
    }

    // Take the first supported HpkeConfig from the list. Return the first error otherwise.
    let mut first_error = None;
    for config in hpke_configs.hpke_configs() {
        match is_hpke_config_supported(config) {
            Ok(()) => return Ok(config.clone()),
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    // Unwrap safety: we checked that the list is nonempty, and if we fell through to here, we must
    // have seen at least one error.
    Err(first_error.unwrap().into())
}

/// Construct a [`reqwest::Client`] suitable for use in a DAP [`Client`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .user_agent(CLIENT_USER_AGENT)
        .build()?)
}

/// Builder for configuring a [`Client`].
pub struct ClientBuilder<V: vdaf::Client<16>> {
    parameters: ClientParameters,
    vdaf: V,
    http_client: Option<reqwest::Client>,
}

impl<V: vdaf::Client<16>> ClientBuilder<V> {
    /// Construct a [`ClientBuilder`] from its required DAP task parameters.
    pub fn new(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
        vdaf: V,
    ) -> Self {
        Self {
            parameters: ClientParameters::new(
                task_id,
                leader_aggregator_endpoint,
                helper_aggregator_endpoint,
                time_precision,
            ),
            vdaf,
            http_client: None,
        }
    }

    /// Finalize construction of a [`Client`]. This will fetch HPKE configurations from each
    /// aggregator via HTTPS.
    pub async fn build(self) -> Result<Client<V>, Error> {
        let http_client = if let Some(http_client) = self.http_client {
            http_client
        } else {
            default_http_client()?
        };
        let (leader_hpke_config, helper_hpke_config) = try_join!(
            aggregator_hpke_config(&self.parameters, &Role::Leader, &http_client),
            aggregator_hpke_config(&self.parameters, &Role::Helper, &http_client)
        )?;
        Ok(Client {
            parameters: self.parameters,
            vdaf: self.vdaf,
            http_client,
            leader_hpke_config,
            helper_hpke_config,
        })
    }

    /// Finalize construction of a [`Client`], and provide aggregator HPKE configurations through an
    /// out-of-band mechanism.
    pub fn build_with_hpke_configs(
        self,
        leader_hpke_config: HpkeConfig,
        helper_hpke_config: HpkeConfig,
    ) -> Result<Client<V>, Error> {
        let http_client = if let Some(http_client) = self.http_client {
            http_client
        } else {
            default_http_client()?
        };
        Ok(Client {
            parameters: self.parameters,
            vdaf: self.vdaf,
            http_client,
            leader_hpke_config,
            helper_hpke_config,
        })
    }

    /// Override the HTTPS client configuration to be used.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Override the exponential backoff parameters used when retrying HTTPS requests.
    pub fn with_backoff(mut self, http_request_retry_parameters: ExponentialBackoff) -> Self {
        self.parameters.http_request_retry_parameters = http_request_retry_parameters;
        self
    }
}

/// A DAP client.
#[derive(Clone, Debug)]
pub struct Client<V: vdaf::Client<16>> {
    parameters: ClientParameters,
    vdaf: V,
    http_client: reqwest::Client,
    leader_hpke_config: HpkeConfig,
    helper_hpke_config: HpkeConfig,
}

impl<V: vdaf::Client<16>> Client<V> {
    /// Construct a new client from the required set of DAP task parameters.
    pub async fn new(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
        vdaf: V,
    ) -> Result<Self, Error> {
        ClientBuilder::new(
            task_id,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            vdaf,
        )
        .build()
        .await
    }

    /// Construct a new client, and provide the aggregator HPKE configurations through an
    /// out-of-band means.
    pub fn with_hpke_configs(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
        vdaf: V,
        leader_hpke_config: HpkeConfig,
        helper_hpke_config: HpkeConfig,
    ) -> Result<Self, Error> {
        ClientBuilder::new(
            task_id,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            vdaf,
        )
        .build_with_hpke_configs(leader_hpke_config, helper_hpke_config)
    }

    /// Creates a [`ClientBuilder`] for further configuration from the required set of DAP task
    /// parameters.
    pub fn builder(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
        vdaf: V,
    ) -> ClientBuilder<V> {
        ClientBuilder::new(
            task_id,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            vdaf,
        )
    }

    /// Shard a measurement, encrypt its shares, and construct a [`janus_core::message::Report`]
    /// to be uploaded.
    fn prepare_report(&self, measurement: &V::Measurement, time: &Time) -> Result<Report, Error> {
        let report_id: ReportId = random();
        let (public_share, input_shares) = self.vdaf.shard(measurement, report_id.as_ref())?;
        assert_eq!(input_shares.len(), 2); // DAP only supports VDAFs using two aggregators.

        let time = time
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

    /// Upload a [`Report`] to the leader, per §4.3.2 of draft-gpew-priv-ppm. The provided
    /// measurement is sharded into two shares and then uploaded to the leader.
    #[tracing::instrument(skip(measurement), err)]
    pub async fn upload(&self, measurement: &V::Measurement) -> Result<(), Error> {
        self.upload_with_time(measurement, Clock::now(&RealClock::default()))
            .await
    }

    /// Upload a [`Report`] to the leader, per §4.3.2 of draft-gpew-priv-ppm, and override the
    /// report's timestamp. The provided measurement is sharded into two shares and then uploaded to
    /// the leader.
    ///
    /// ```no_run
    /// # use janus_client::{Client, Error};
    /// # use janus_messages::Duration;
    /// # use prio::vdaf::prio3::Prio3;
    /// # use rand::random;
    /// #
    /// # async fn test() -> Result<(), Error> {
    /// # let measurement = 1;
    /// # let timestamp = 1_700_000_000;
    /// # let vdaf = Prio3::new_count(2).unwrap();
    /// let client = Client::new(
    ///     random(),
    ///     "https://example.com/".parse().unwrap(),
    ///     "https://example.net/".parse().unwrap(),
    ///     Duration::from_seconds(3600),
    ///     vdaf,
    /// ).await?;
    /// client.upload_with_time(&measurement, std::time::SystemTime::now()).await?;
    /// client.upload_with_time(&measurement, janus_messages::Time::from_seconds_since_epoch(timestamp)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(measurement), err)]
    pub async fn upload_with_time<T>(
        &self,
        measurement: &V::Measurement,
        time: T,
    ) -> Result<(), Error>
    where
        T: TryInto<Time> + Debug,
        Error: From<<T as TryInto<Time>>::Error>,
    {
        let report = self.prepare_report(measurement, &time.try_into()?)?;
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
                HttpErrorResponse::from_response(upload_response).await,
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{aggregator_hpke_config, default_http_client, Client, ClientParameters, Error};
    use assert_matches::assert_matches;
    use hex_literal::hex;
    use http::{header::CONTENT_TYPE, StatusCode};
    use janus_core::{
        hpke::test_util::generate_test_hpke_config_and_private_key,
        retries::test_http_request_exponential_backoff, test_util::install_test_trace_subscriber,
    };
    use janus_messages::{Duration, HpkeConfigList, Report, Role, Time};
    use prio::{
        codec::Encode,
        vdaf::{self, prio3::Prio3},
    };
    use rand::random;
    use url::Url;

    fn setup_client<V: vdaf::Client<16>>(server: &mockito::Server, vdaf: V) -> Client<V> {
        let server_url = Url::parse(&server.url()).unwrap();
        Client::builder(
            random(),
            server_url.clone(),
            server_url,
            Duration::from_seconds(1),
            vdaf,
        )
        .with_backoff(test_http_request_exponential_backoff())
        .build_with_hpke_configs(
            generate_test_hpke_config_and_private_key().config().clone(),
            generate_test_hpke_config_and_private_key().config().clone(),
        )
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
            Err(Error::Http(error_response)) => {
                assert_eq!(*error_response.status().unwrap(), StatusCode::NOT_IMPLEMENTED);
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
            Err(Error::Http(error_response)) => {
                assert_eq!(*error_response.status().unwrap(), StatusCode::BAD_REQUEST);
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
        .build_with_hpke_configs(
            generate_test_hpke_config_and_private_key().config().clone(),
            generate_test_hpke_config_and_private_key().config().clone(),
        )
        .unwrap();
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
        assert_eq!(
            client
                .prepare_report(&1, &Time::from_seconds_since_epoch(101))
                .unwrap()
                .metadata()
                .time(),
            &Time::from_seconds_since_epoch(100),
        );

        assert_eq!(
            client
                .prepare_report(&1, &Time::from_seconds_since_epoch(5200))
                .unwrap()
                .metadata()
                .time(),
            &Time::from_seconds_since_epoch(5200),
        );

        assert_eq!(
            client
                .prepare_report(&1, &Time::from_seconds_since_epoch(9814))
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
        let client_parameters = ClientParameters::new_with_backoff(
            random(),
            server_url.clone(),
            server_url,
            Duration::from_seconds(1),
            test_http_request_exponential_backoff(),
        );

        let keypair = generate_test_hpke_config_and_private_key();
        let hpke_config_list = HpkeConfigList::new(Vec::from([keypair.config().clone()]));
        let mock = server
            .mock(
                "GET",
                format!("/hpke_config?task_id={}", &client_parameters.task_id).as_str(),
            )
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), HpkeConfigList::MEDIA_TYPE)
            .with_body(hpke_config_list.get_encoded())
            .expect(1)
            .create_async()
            .await;

        let got_hpke_config =
            aggregator_hpke_config(&client_parameters, &Role::Leader, http_client)
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
        let client_parameters = ClientParameters::new_with_backoff(
            random(),
            server_url.clone(),
            server_url,
            Duration::from_seconds(1),
            test_http_request_exponential_backoff(),
        );

        let encoded_bad_hpke_config = hex!(
            "64" // HpkeConfigId
            "0064" // HpkeKemId
            "0064" // HpkeKdfId
            "0064" // HpkeAeadId
            "0008" // Length prefix from HpkePublicKey
            "4141414141414141" // Contents of HpkePublicKey
        );

        let good_hpke_config = generate_test_hpke_config_and_private_key().config().clone();
        let encoded_good_hpke_config = good_hpke_config.get_encoded();

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
            aggregator_hpke_config(&client_parameters, &Role::Leader, http_client)
                .await
                .unwrap();
        assert_eq!(got_hpke_config, good_hpke_config);

        mock.assert_async().await;
    }
}
