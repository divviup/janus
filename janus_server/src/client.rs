//! PPM protocol client

use crate::{
    hpke::{HpkeSender, Label},
    message::{HpkeCiphertext, HpkeConfig, Nonce, Report, Role, Time},
    task::TaskParameters,
    time::Clock,
};
use http::StatusCode;
use prio::{
    codec::{Decode, Encode},
    vdaf::Client as VdafClient,
};
use std::io::Cursor;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("Codec error: {0}")]
    Codec(#[from] prio::codec::CodecError),
    #[error("HTTP response status {0}")]
    Http(StatusCode),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("VDAF error: {0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("HPKE error: {0}")]
    Hpke(#[from] crate::hpke::Error),
    #[error("invalid task parameters: {0}")]
    TaskParameters(#[from] crate::task::Error),
}

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

pub async fn aggregator_hpke_sender(
    task_parameters: &TaskParameters,
    aggregator_role: Role,
    http_client: &reqwest::Client,
) -> Result<HpkeSender, Error> {
    let hpke_config_response = http_client
        .get(task_parameters.hpke_config_endpoint(aggregator_role)?)
        .send()
        .await?;
    let status = hpke_config_response.status();
    if !status.is_success() {
        return Err(Error::Http(status));
    }

    let hpke_config = HpkeConfig::decode(&mut Cursor::new(
        hpke_config_response.bytes().await?.as_ref(),
    ))?;

    Ok(HpkeSender::new(
        task_parameters.id,
        hpke_config,
        Label::InputShare,
        Role::Client,
        Role::Leader,
    ))
}

/// Construct a [`reqwest::Client`] suitable for use in a PPM [`Client`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .user_agent(CLIENT_USER_AGENT)
        .build()?)
}

/// A PPM client.
#[derive(Debug)]
pub struct Client<V, P, C> {
    task_parameters: TaskParameters,
    vdaf_client: V,
    vdaf_public_parameter: P,
    clock: C,
    http_client: reqwest::Client,
    leader_report_sender: HpkeSender,
    helper_report_sender: HpkeSender,
}

impl<V: VdafClient, C: Clock> Client<V, V::PublicParam, C> {
    pub fn new(
        task_parameters: TaskParameters,
        vdaf_client: V,
        vdaf_public_parameter: V::PublicParam,
        clock: C,
        http_client: &reqwest::Client,
        leader_report_sender: HpkeSender,
        helper_report_sender: HpkeSender,
    ) -> Self {
        Self {
            task_parameters,
            vdaf_client,
            vdaf_public_parameter,
            clock,
            http_client: http_client.clone(),
            leader_report_sender,
            helper_report_sender,
        }
    }

    /// Upload a [`crate::message::Report`] to the leader, per §4.3.2 of
    /// draft-gpew-priv-ppm. The provided measurement is sharded into one input
    /// share plus one proof share for each aggregator and then uploaded to the
    /// leader.
    pub async fn upload(&self, measurement: &V::Measurement) -> Result<(), Error> {
        let input_shares = self
            .vdaf_client
            .shard(&self.vdaf_public_parameter, measurement)?;

        // All supported VDAFs use two aggregators
        assert_eq!(input_shares.len(), 2);

        let nonce = Nonce {
            time: Time::from_naive_date_time(self.clock.now()),
            rand: rand::random(),
        };

        // No extensions supported yet
        let extensions = vec![];

        let associated_data = Report::associated_data(nonce, &extensions);

        // Leader's share MUST be the first in the report. We assume/guess that
        // the first element in input_shares is the leader's. This is true for
        // all prio3 VDAFs, but not guaranteed generically.
        // https://github.com/cjpatton/vdaf/issues/40
        let encrypted_input_shares: Vec<HpkeCiphertext> =
            [&self.leader_report_sender, &self.helper_report_sender]
                .into_iter()
                .zip(input_shares)
                .map(|(hpke_sender, input_share)| {
                    Ok(hpke_sender.seal(&input_share.get_encoded(), &associated_data)?)
                })
                .collect::<Result<_, Error>>()?;

        let report = Report {
            task_id: self.task_parameters.id,
            nonce,
            extensions,
            encrypted_input_shares,
        };

        let upload_response = self
            .http_client
            .post(self.task_parameters.upload_endpoint()?)
            .body(report.get_encoded())
            .send()
            .await?;
        let status = upload_response.status();
        if !status.is_success() {
            // TODO: decode an RFC 7807 problem document once #25 / #31 land
            return Err(Error::Http(status));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpke::HpkeRecipient, message::TaskId, time::tests::MockClock,
        trace::test_util::install_test_trace_subscriber,
    };
    use assert_matches::assert_matches;
    use mockito::mock;
    use prio::vdaf::prio3::{Prio3Aes128Count, Prio3Aes128Sum};
    use url::Url;

    fn setup_client<V: VdafClient>(
        vdaf_client: V,
        public_parameter: V::PublicParam,
    ) -> Client<V, V::PublicParam, MockClock> {
        let task_id = TaskId::random();

        let clock = MockClock::default();
        let leader_hpke_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);
        let leader_hpke_sender = HpkeSender::from_recipient(&leader_hpke_recipient);
        let helper_hpke_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Helper);
        let helper_hpke_sender = HpkeSender::from_recipient(&helper_hpke_recipient);

        let server_url = Url::parse(&mockito::server_url()).unwrap();

        let task_parameters =
            TaskParameters::new_dummy(task_id, vec![server_url.clone(), server_url]);

        Client::new(
            task_parameters,
            vdaf_client,
            public_parameter,
            clock,
            &default_http_client().unwrap(),
            leader_hpke_sender,
            helper_hpke_sender,
        )
    }

    #[tokio::test]
    async fn upload_prio3_count() {
        install_test_trace_subscriber();
        let mocked_upload = mock("POST", "/upload").with_status(200).expect(1).create();

        let client = setup_client(Prio3Aes128Count::new(2).unwrap(), ());

        client.upload(&1).await.unwrap();

        mocked_upload.assert();
    }

    #[tokio::test]
    async fn upload_prio3_invalid_measurement() {
        install_test_trace_subscriber();
        let vdaf = Prio3Aes128Sum::new(2, 16).unwrap();

        let client = setup_client(vdaf, ());
        // 65536 is too big for a 16 bit sum and will be rejected by the VDAF.
        // Make sure we get the right error variant but otherwise we aren't
        // picky about its contents.
        assert_matches!(client.upload(&65536).await, Err(Error::Vdaf(_)));
    }

    #[tokio::test]
    async fn upload_prio3_http_status_code() {
        install_test_trace_subscriber();

        let mocked_upload = mock("POST", "/upload").with_status(501).expect(1).create();

        let client = setup_client(Prio3Aes128Count::new(2).unwrap(), ());
        assert_matches!(
            client.upload(&1).await,
            Err(Error::Http(StatusCode::NOT_IMPLEMENTED))
        );

        mocked_upload.assert();
    }
}
