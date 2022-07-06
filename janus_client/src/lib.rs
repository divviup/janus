//! PPM protocol client

use http::{header::CONTENT_TYPE, StatusCode};
use janus_core::{
    hpke::associated_data_for_report_share,
    hpke::{self, HpkeApplicationInfo, Label},
    message::{Duration, HpkeCiphertext, HpkeConfig, Nonce, Report, Role, TaskId},
    time::Clock,
};
use prio::{
    codec::{Decode, Encode},
    vdaf,
};
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
    Http(StatusCode),
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

/// The PPM client's view of task parameters.
#[derive(Clone, Debug)]
pub struct ClientParameters {
    /// Unique identifier for the task
    task_id: TaskId,
    /// URLs relative to which aggregator API endpoints are found. The first
    /// entry is the leader's.
    aggregator_endpoints: Vec<Url>,
    /// The minimum batch duration of the task. This value is shared by all
    /// parties in the protocol, and is used to compute report nonces.
    min_batch_duration: Duration,
}

impl ClientParameters {
    /// Creates a new set of client task parameters.
    pub fn new(
        task_id: TaskId,
        aggregator_endpoints: Vec<Url>,
        min_batch_duration: Duration,
    ) -> Self {
        Self {
            task_id,
            aggregator_endpoints,
            min_batch_duration,
        }
    }

    /// The URL relative to which the API endpoints for the aggregator may be
    /// found, if the role is an aggregator, or an error otherwise.
    fn aggregator_endpoint(&self, role: Role) -> Result<&Url, Error> {
        Ok(&self.aggregator_endpoints[role
            .index()
            .ok_or(Error::InvalidParameter("role is not an aggregator"))?])
    }

    /// URL from which the HPKE configuration for the server filling `role` may
    /// be fetched per draft-gpew-priv-ppm §4.3.1
    fn hpke_config_endpoint(&self, role: Role) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(role)?.join("hpke_config")?)
    }

    /// URL to which reports may be uploaded by clients per draft-gpew-priv-ppm
    /// §4.3.2
    fn upload_endpoint(&self) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(Role::Leader)?.join("upload")?)
    }
}

/// Fetches HPKE configuration from the specified aggregator using the
/// aggregator endpoints in the provided [`ClientParameters`].
#[tracing::instrument(err)]
pub async fn aggregator_hpke_config(
    client_parameters: &ClientParameters,
    aggregator_role: Role,
    task_id: TaskId,
    http_client: &reqwest::Client,
) -> Result<HpkeConfig, Error> {
    let mut request_url = client_parameters.hpke_config_endpoint(aggregator_role)?;
    request_url.set_query(Some(&format!("task_id={}", task_id)));
    let hpke_config_response = http_client.get(request_url).send().await?;
    let status = hpke_config_response.status();
    if !status.is_success() {
        return Err(Error::Http(status));
    }

    Ok(HpkeConfig::decode(&mut Cursor::new(
        hpke_config_response.bytes().await?.as_ref(),
    ))?)
}

/// Construct a [`reqwest::Client`] suitable for use in a PPM [`Client`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .user_agent(CLIENT_USER_AGENT)
        .build()?)
}

/// A PPM client.
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
    ) -> Self
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
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
        let input_shares = self.vdaf_client.shard(measurement)?;
        assert_eq!(input_shares.len(), 2); // PPM only supports VDAFs using two aggregators.

        let nonce =
            Nonce::generate(&self.clock, self.parameters.min_batch_duration).map_err(|_| {
                Error::InvalidParameter("Error rounding time down to min_batch_duration")
            })?;
        let extensions = vec![]; // No extensions supported yet
        let associated_data =
            associated_data_for_report_share(self.parameters.task_id, nonce, &extensions);

        let encrypted_input_shares: Vec<HpkeCiphertext> = [
            (&self.leader_hpke_config, Role::Leader),
            (&self.helper_hpke_config, Role::Helper),
        ]
        .into_iter()
        .zip(input_shares)
        .map(|((hpke_config, receiver_role), input_share)| {
            Ok(hpke::seal(
                hpke_config,
                &HpkeApplicationInfo::new(Label::InputShare, Role::Client, receiver_role),
                &input_share.get_encoded(),
                &associated_data,
            )?)
        })
        .collect::<Result<_, Error>>()?;

        Ok(Report::new(
            self.parameters.task_id,
            nonce,
            extensions,
            encrypted_input_shares,
        ))
    }

    /// Upload a [`janus_core::message::Report`] to the leader, per §4.3.2 of
    /// draft-gpew-priv-ppm. The provided measurement is sharded into one input
    /// share plus one proof share for each aggregator and then uploaded to the
    /// leader.
    #[tracing::instrument(skip(measurement), err)]
    pub async fn upload(&self, measurement: &V::Measurement) -> Result<(), Error> {
        let report = self.prepare_report(measurement)?;

        let upload_response = self
            .http_client
            .post(self.parameters.upload_endpoint()?)
            .header(CONTENT_TYPE, Report::MEDIA_TYPE)
            .body(report.get_encoded())
            .send()
            .await?;
        let status = upload_response.status();
        if !status.is_success() {
            // TODO(#233): decode an RFC 7807 problem document once #25 / #31 land
            return Err(Error::Http(status));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use janus_core::{
        hpke::test_util::generate_hpke_config_and_private_key,
        message::{TaskId, Time},
        test_util::{install_test_trace_subscriber, MockClock},
    };
    use mockito::mock;
    use prio::vdaf::prio3::Prio3;
    use url::Url;

    fn setup_client<V: vdaf::Client>(vdaf_client: V) -> Client<V, MockClock>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let task_id = TaskId::random();

        let clock = MockClock::default();
        let (leader_hpke_config, _) = generate_hpke_config_and_private_key();
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();

        let server_url = Url::parse(&mockito::server_url()).unwrap();

        let client_parameters = ClientParameters {
            task_id,
            aggregator_endpoints: vec![server_url.clone(), server_url],
            min_batch_duration: Duration::from_seconds(1),
        };

        Client::new(
            client_parameters,
            vdaf_client,
            clock,
            &default_http_client().unwrap(),
            leader_hpke_config,
            helper_hpke_config,
        )
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
            Err(Error::Http(StatusCode::NOT_IMPLEMENTED))
        );

        mocked_upload.assert();
    }

    #[tokio::test]
    async fn upload_bad_min_batch_duration() {
        install_test_trace_subscriber();

        let client_parameters =
            ClientParameters::new(TaskId::random(), vec![], Duration::from_seconds(0));
        let client = Client::new(
            client_parameters,
            Prio3::new_aes128_count(2).unwrap(),
            MockClock::default(),
            &default_http_client().unwrap(),
            generate_hpke_config_and_private_key().0,
            generate_hpke_config_and_private_key().0,
        );
        let result = client.upload(&1).await;
        assert_matches!(result, Err(Error::InvalidParameter(_)));
    }

    #[test]
    fn report_nonce_time() {
        install_test_trace_subscriber();
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let mut client = setup_client(vdaf);

        client.parameters.min_batch_duration = Duration::from_seconds(100);
        client.clock = MockClock::new(Time::from_seconds_since_epoch(101));
        assert_eq!(
            client.prepare_report(&1).unwrap().nonce().time(),
            Time::from_seconds_since_epoch(100),
        );

        client.clock = MockClock::new(Time::from_seconds_since_epoch(5200));
        assert_eq!(
            client.prepare_report(&1).unwrap().nonce().time(),
            Time::from_seconds_since_epoch(5200),
        );

        client.clock = MockClock::new(Time::from_seconds_since_epoch(9814));
        assert_eq!(
            client.prepare_report(&1).unwrap().nonce().time(),
            Time::from_seconds_since_epoch(9800),
        );
    }
}
