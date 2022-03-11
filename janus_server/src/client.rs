//! PPM protocol client

use crate::{
    hpke::{HpkeSender, Label},
    message::{HpkeConfig, Role, TaskId},
};
use http::StatusCode;
use prio::codec::Decode;
use std::io::Cursor;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("Codec error")]
    Codec(#[from] prio::codec::CodecError),
    #[error("HTTP response status {0}")]
    Http(StatusCode),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
}

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

/// A PPM client.
#[derive(Debug)]
pub struct Client {
    http_client: reqwest::Client,
    leader_report_sender: HpkeSender,
    helper_report_sender: HpkeSender,
}

impl Client {
    pub fn new(
        http_client: &reqwest::Client,
        leader_report_sender: HpkeSender,
        helper_report_sender: HpkeSender,
    ) -> Self {
        Self {
            http_client: http_client.clone(),
            leader_report_sender,
            helper_report_sender,
        }
    }

    /// Construct a [`reqwest::Client`] suitable for use in a PPM [`Client`].
    //
    // TODO: To be particularly useful, this function should return
    // `Box<dyn JanusHttpClient>`, where `JanusHttpClient` is a trait we define
    // that captures exactly what our client needs (e.g., GET). Then tests could
    // provide an alternate implementation of it.
    pub fn default_http_client() -> Result<reqwest::Client, Error> {
        Ok(reqwest::Client::builder()
            .user_agent(CLIENT_USER_AGENT)
            .build()?)
    }

    pub async fn aggregator_hpke_sender(
        http_client: &reqwest::Client,
        task_id: TaskId,
        aggregator_endpoint: Url,
    ) -> Result<HpkeSender, Error> {
        let hpke_config_response = http_client
            .get(aggregator_endpoint.join("hpke_config")?)
            .send()
            .await?;
        let status = hpke_config_response.status();
        if !status.is_success() {
            return Err(Error::Http(status));
        }

        let hpke_config = HpkeConfig::decode(&mut Cursor::new(
            hpke_config_response.bytes().await?.as_ref(),
        ))?;

        Ok(HpkeSender {
            task_id,
            recipient_config: hpke_config,
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        })
    }
}
