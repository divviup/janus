//! A [DAP](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) client
//!
//! This library implements the client role of the DAP-PPM protocol. It uploads measurements to two
//! DAP aggregator servers which in turn compute a statistical aggregate over data from many
//! clients, while preserving the privacy of each client's data.
//!
//! # Examples
//!
//! ```no_run
//! use url::Url;
//! use prio::vdaf::prio3::Prio3Histogram;
//! use janus_messages::{Duration, TaskId};
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let leader_url = Url::parse("https://leader.example.com/").unwrap();
//!     let helper_url = Url::parse("https://helper.example.com/").unwrap();
//!     let vdaf = Prio3Histogram::new_histogram(
//!         2,
//!         12,
//!         4
//!     ).unwrap();
//!     let taskid = "rc0jgm1MHH6Q7fcI4ZdNUxas9DAYLcJFK5CL7xUl-gU";
//!     let task = TaskId::from_str(taskid).unwrap();
//!
//!     let client = janus_client::Client::new(
//!         task,
//!         leader_url,
//!         helper_url,
//!         Duration::from_seconds(300),
//!         vdaf
//!     )
//!     .await
//!     .unwrap();
//!     client.upload(&[5]).await.unwrap();
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

use backon::BackoffBuilder;
#[cfg(feature = "ohttp")]
use bhttp::{ControlData, Message, Mode};
use educe::Educe;
#[cfg(feature = "ohttp")]
use http::{HeaderValue, header::ACCEPT};
use http::{StatusCode, header::CONTENT_TYPE};
use itertools::Itertools;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label, is_hpke_config_supported},
    http::{HttpErrorResponse, cached_resource::CachedResource},
    retries::{
        ExponentialWithTotalDelayBuilder, http_request_exponential_backoff, retry_http_request,
    },
    time::{Clock, RealClock, TimeExt},
    url_ensure_trailing_slash,
    vdaf::vdaf_application_context,
};
use janus_messages::{
    Duration, HpkeConfig, HpkeConfigList, InputShareAad, PlaintextInputShare, Report, ReportId,
    ReportMetadata, Role, TaskId, Time, UploadRequest,
};
#[cfg(feature = "ohttp")]
use ohttp::{ClientRequest, KeyConfig};
#[cfg(feature = "ohttp")]
use ohttp_keys::OhttpKeys;
use prio::{codec::Encode, vdaf};
use rand::random;
#[cfg(feature = "ohttp")]
use std::io::Cursor;
use std::{convert::Infallible, fmt::Debug, sync::Arc, time::SystemTimeError};
use tokio::sync::Mutex;
use url::Url;

#[cfg(test)]
mod tests;

// TODO(timg): need way to convey per-report errors
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
    #[error("Cached resource error: {0}")]
    CachedResource(#[from] janus_core::http::cached_resource::Error),
    #[error("unexpected server response {0}")]
    UnexpectedServerResponse(&'static str),
    #[error("time conversion error: {0}")]
    TimeConversion(#[from] SystemTimeError),
    #[cfg(feature = "ohttp")]
    #[error("OHTTP error: {0}")]
    Ohttp(#[from] ohttp::Error),
    #[cfg(feature = "ohttp")]
    #[error("BHTTP error: {0}")]
    Bhttp(#[from] bhttp::Error),
    #[cfg(feature = "ohttp")]
    #[error("No supported key configurations advertised by OHTTP gateway")]
    OhttpNoSupportedKeyConfigs(Box<Vec<KeyConfig>>),
}

impl From<Infallible> for Error {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<Result<HttpErrorResponse, reqwest::Error>> for Error {
    fn from(result: Result<HttpErrorResponse, reqwest::Error>) -> Self {
        match result {
            Ok(http_error_response) => Error::Http(Box::new(http_error_response)),
            Err(error) => error.into(),
        }
    }
}

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

#[cfg(feature = "ohttp")]
const OHTTP_KEYS_MEDIA_TYPE: &str = "application/ohttp-keys";
#[cfg(feature = "ohttp")]
const OHTTP_REQUEST_MEDIA_TYPE: &str = "message/ohttp-req";
#[cfg(feature = "ohttp")]
const OHTTP_RESPONSE_MEDIA_TYPE: &str = "message/ohttp-res";

/// The DAP client's view of task parameters.
#[derive(Clone, Educe)]
#[educe(Debug)]
struct ClientParameters {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// URL relative to which the Leader's API endpoints are found.
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    leader_aggregator_endpoint: Url,
    /// URL relative to which the Helper's API endpoints are found.
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    helper_aggregator_endpoint: Url,
    /// The time precision of the task. This value is shared by all parties in the protocol, and is
    /// used to compute report timestamps.
    time_precision: Duration,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
}

impl ClientParameters {
    /// Creates a new set of client task parameters.
    pub fn new(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
    ) -> Self {
        Self {
            task_id,
            leader_aggregator_endpoint: url_ensure_trailing_slash(leader_aggregator_endpoint),
            helper_aggregator_endpoint: url_ensure_trailing_slash(helper_aggregator_endpoint),
            time_precision,
            http_request_retry_parameters: http_request_exponential_backoff(),
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

    /// URL from which the HPKE configuration for the server filling `role` may be fetched, per
    /// the [DAP specification][1].
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-hpke-configuration-request
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

/// Construct a [`reqwest::Client`] suitable for use in a DAP [`Client`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        // Clients wishing to override these timeouts may provide their own
        // values using ClientBuilder::with_http_client.
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent(CLIENT_USER_AGENT)
        .build()?)
}

/// Configuration for using Oblivious HTTP (RFC 9458).
#[derive(Clone, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "ohttp")))]
#[cfg(feature = "ohttp")]
pub struct OhttpConfig {
    /// Endpoint from which OHTTP gateway key configurations may be fetched. The key configurations
    /// must be in the format specified by [RFC 9458, section 3][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc9458#name-key-configuration
    pub key_configs: Url,

    /// The OHTTP relay which will relay encapsulated messages to the gateway.
    pub relay: Url,
}

/// Builder for configuring a [`Client`].
pub struct ClientBuilder<V: vdaf::Client<16>> {
    parameters: ClientParameters,
    vdaf: V,
    leader_hpke_config: Option<HpkeConfig>,
    helper_hpke_config: Option<HpkeConfig>,
    #[cfg(feature = "ohttp")]
    ohttp_config: Option<OhttpConfig>,
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
            leader_hpke_config: None,
            helper_hpke_config: None,
            #[cfg(feature = "ohttp")]
            ohttp_config: None,
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

        let fetch_hpke_config = async |hpke_config, role| match hpke_config {
            Some(hpke_config) => Ok(HpkeConfiguration::new_static(hpke_config)),
            None => HpkeConfiguration::new(&self.parameters, role, http_client.clone()).await,
        };

        let (leader_hpke_config, helper_hpke_config) = tokio::try_join!(
            fetch_hpke_config(self.leader_hpke_config, &Role::Leader),
            fetch_hpke_config(self.helper_hpke_config, &Role::Helper),
        )?;

        #[cfg(feature = "ohttp")]
        let ohttp_config = if let Some(ohttp_config) = self.ohttp_config {
            let key_configs =
                OhttpKeys::new(ohttp_config, &self.parameters, http_client.clone()).await?;
            Some(Arc::new(Mutex::new(key_configs)))
        } else {
            None
        };

        Ok(Client {
            #[cfg(feature = "ohttp")]
            ohttp_config,
            parameters: self.parameters,
            vdaf: self.vdaf,
            http_client,
            leader_hpke_config: Arc::new(Mutex::new(leader_hpke_config)),
            helper_hpke_config: Arc::new(Mutex::new(helper_hpke_config)),
        })
    }

    /// Finalize construction of a [`Client`], and provide aggregator HPKE configurations through an
    /// out-of-band mechanism.
    ///
    /// # Notes
    ///
    /// This method is not compatible with OHTTP . Use [`ClientBuilder::with_ohttp_config`] and then
    /// [`ClientBuilder::build`] to provide OHTTP configuration.
    #[deprecated(
        note = "Use `ClientBuilder::with_leader_hpke_config`, `ClientBuilder::with_helper_hpke_config` and `ClientBuilder::build` instead"
    )]
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
            #[cfg(feature = "ohttp")]
            ohttp_config: None,
            http_client,
            leader_hpke_config: Arc::new(Mutex::new(HpkeConfiguration::new_static(
                leader_hpke_config,
            ))),
            helper_hpke_config: Arc::new(Mutex::new(HpkeConfiguration::new_static(
                helper_hpke_config,
            ))),
        })
    }

    /// Override the HTTPS client configuration to be used.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Override the exponential backoff parameters used when retrying HTTPS requests.
    pub fn with_backoff(
        mut self,
        http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
    ) -> Self {
        self.parameters.http_request_retry_parameters = http_request_retry_parameters;
        self
    }

    /// Set the leader HPKE configuration to be used, preventing the client from fetching it from
    /// the aggregator over HTTPS.
    pub fn with_leader_hpke_config(mut self, hpke_config: HpkeConfig) -> Self {
        self.leader_hpke_config = Some(hpke_config);
        self
    }

    /// Set the helper HPKE configuration to be used, preventing the client from fetching it from
    /// the aggregator over HTTPS.
    pub fn with_helper_hpke_config(mut self, hpke_config: HpkeConfig) -> Self {
        self.helper_hpke_config = Some(hpke_config);
        self
    }

    /// Set the OHTTP configuration to be used when uploading reports, but not when fetching DAP
    /// HPKE configurations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use url::Url;
    /// # use prio::vdaf::prio3::Prio3Count;
    /// # use janus_messages::{Duration, TaskId};
    /// # use rand::random;
    /// # use std::str::FromStr;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let task_id = random();
    ///
    ///     let client = janus_client::Client::builder(
    ///         task_id,
    ///         Url::parse("https://leader.example.com/").unwrap(),
    ///         Url::parse("https://helper.example.com/").unwrap(),
    ///         Duration::from_seconds(1),
    ///         Prio3Count::new_count(2).unwrap(),
    ///     )
    ///     .with_ohttp_config(janus_client::OhttpConfig {
    ///         key_configs: Url::parse("https://ohttp-keys.example.com").unwrap(),
    ///         relay: Url::parse("https://ohttp-relay.example.com").unwrap(),
    ///     })
    ///     .build()
    ///     .await
    ///     .unwrap();
    ///
    ///     client.upload(&[true]).await.unwrap();
    /// }
    /// ```
    #[cfg(feature = "ohttp")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ohttp")))]
    pub fn with_ohttp_config(mut self, ohttp_config: OhttpConfig) -> Self {
        self.ohttp_config = Some(ohttp_config);
        self
    }
}

/// A DAP client.
#[derive(Clone, Debug)]
pub struct Client<V: vdaf::Client<16>> {
    parameters: ClientParameters,
    vdaf: V,
    #[cfg(feature = "ohttp")]
    ohttp_config: Option<Arc<Mutex<OhttpKeys>>>,
    http_client: reqwest::Client,
    leader_hpke_config: Arc<Mutex<HpkeConfiguration>>,
    helper_hpke_config: Arc<Mutex<HpkeConfiguration>>,
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
    ///
    /// # Notes
    ///
    /// This method is not compatible with OHTTP. Use [`ClientBuilder::with_ohttp_config`] and then
    /// [`ClientBuilder::build`] to provide OHTTP configuration.
    #[deprecated(
        note = "Use `ClientBuilder::with_leader_hpke_config`, `ClientBuilder::with_helper_hpke_config` and `ClientBuilder::build` instead"
    )]
    pub fn with_hpke_configs(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: Duration,
        vdaf: V,
        leader_hpke_config: HpkeConfig,
        helper_hpke_config: HpkeConfig,
    ) -> Result<Self, Error> {
        #[allow(deprecated)]
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

    /// Shard a measurement, encrypt its shares, and construct a [`janus_messages::Report`] to be
    /// uploaded.
    fn prepare_report(
        &self,
        measurement: &V::Measurement,
        time: &Time,
        leader_hpke_config: &HpkeConfig,
        helper_hpke_config: &HpkeConfig,
    ) -> Result<Report, Error> {
        let report_id: ReportId = random();
        let (public_share, input_shares) = self.vdaf.shard(
            &vdaf_application_context(&self.parameters.task_id),
            measurement,
            report_id.as_ref(),
        )?;
        assert_eq!(input_shares.len(), 2); // DAP only supports VDAFs using two aggregators.

        let time = time
            .to_batch_interval_start(&self.parameters.time_precision)
            .map_err(|_| Error::InvalidParameter("couldn't round time down to time_precision"))?;
        let report_metadata = ReportMetadata::new(
            report_id,
            time,
            Vec::new(), // No extensions supported yet.
        );
        let encoded_public_share = public_share.get_encoded()?;

        let (leader_encrypted_input_share, helper_encrypted_input_share) = [
            (leader_hpke_config, &Role::Leader),
            (helper_hpke_config, &Role::Helper),
        ]
        .into_iter()
        .zip(input_shares)
        .map(|((hpke_config, receiver_role), input_share)| {
            hpke::seal(
                hpke_config,
                &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, receiver_role),
                &PlaintextInputShare::new(
                    Vec::new(), // No extensions supported yet.
                    input_share.get_encoded()?,
                )
                .get_encoded()?,
                &InputShareAad::new(
                    self.parameters.task_id,
                    report_metadata.clone(),
                    encoded_public_share.clone(),
                )
                .get_encoded()?,
            )
            .map_err(Error::Hpke)
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

    /// Upload one or more measurements to the leader, per the [DAP specification][1]. The provided
    /// measurements are sharded into two shares and then uploaded to the leader.
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-uploading-reports
    #[tracing::instrument(skip(measurements), err)]
    pub async fn upload(&self, measurements: &[V::Measurement]) -> Result<(), Error> {
        let with_time: Vec<_> = measurements
            .iter()
            .map(|m| (m.clone(), Clock::now(&RealClock::default())))
            .collect();
        self.upload_with_time(&with_time).await
    }

    /// Upload a [`Report`] to the leader, per the [DAP specification][1], and override the report's
    /// timestamp. The provided measurement is sharded into two shares and then uploaded to the
    /// leader.
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-uploading-reports
    ///
    /// ```no_run
    /// # use janus_client::{Client, Error};
    /// # use janus_messages::{Duration, Time};
    /// # use prio::vdaf::prio3::Prio3;
    /// # use rand::random;
    /// #
    /// # async fn test() -> Result<(), Error> {
    /// # let measurement1 = true;
    /// # let measurement2 = false;
    /// # let vdaf = Prio3::new_count(2).unwrap();
    /// let client = Client::new(
    ///     random(),
    ///     "https://example.com/".parse().unwrap(),
    ///     "https://example.net/".parse().unwrap(),
    ///     Duration::from_seconds(3600),
    ///     vdaf,
    /// ).await?;
    ///
    /// // Upload multiple measurements with explicit timestamps.
    /// // Can use SystemTime for wall clock times:
    /// let now = std::time::SystemTime::now();
    /// let earlier = now - std::time::Duration::from_secs(3600);
    /// client.upload_with_time(&[
    ///     (measurement1, earlier),
    ///     (measurement2, now),
    /// ]).await?;
    ///
    /// // Or use janus_messages::Time for specific timestamps:
    /// client.upload_with_time(&[
    ///     (measurement1, Time::from_seconds_since_epoch(1_700_000_000)),
    ///     (measurement2, Time::from_seconds_since_epoch(1_700_003_600)),
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(measurements), err)]
    pub async fn upload_with_time<T>(
        &self,
        measurements: &[(V::Measurement, T)],
    ) -> Result<(), Error>
    where
        T: TryInto<Time> + Debug + Clone,
        Error: From<<T as TryInto<Time>>::Error>,
    {
        let mut reports = Vec::new();

        for (measurement, time) in measurements.iter() {
            reports.push(self.prepare_report(
                measurement,
                &time.clone().try_into()?,
                self.leader_hpke_config.lock().await.get().await?,
                self.helper_hpke_config.lock().await.get().await?,
            )?);
        }

        let upload_request = UploadRequest::new(reports).get_encoded()?;
        let upload_endpoint = self
            .parameters
            .reports_resource_uri(&self.parameters.task_id)?;

        #[cfg(feature = "ohttp")]
        let upload_status = self
            .upload_with_ohttp(&upload_endpoint, &upload_request)
            .await?;
        #[cfg(not(feature = "ohttp"))]
        let upload_status = self.put_report(&upload_endpoint, &upload_request).await?;

        if !upload_status.is_success() {
            return Err(Error::Http(Box::new(HttpErrorResponse::from(
                upload_status,
            ))));
        }

        Ok(())
    }

    async fn put_report(
        &self,
        upload_endpoint: &Url,
        request_body: &[u8],
    ) -> Result<StatusCode, Error> {
        Ok(retry_http_request(
            self.parameters.http_request_retry_parameters.build(),
            || async {
                self.http_client
                    .post(upload_endpoint.clone())
                    .header(CONTENT_TYPE, UploadRequest::MEDIA_TYPE)
                    .body(request_body.to_vec())
                    .send()
                    .await
            },
        )
        .await?
        .status())
    }

    /// Send a DAP upload request via OHTTP, if the client is configured to use it, or directly if
    /// not. This is only intended for DAP uploads and so does not handle response bodies.
    #[cfg(feature = "ohttp")]
    #[tracing::instrument(skip(self, request_body), err)]
    async fn upload_with_ohttp(
        &self,
        upload_endpoint: &Url,
        request_body: &[u8],
    ) -> Result<StatusCode, Error> {
        let ohttp_config = if let Some(ohttp_config) = &self.ohttp_config {
            ohttp_config
        } else {
            return self.put_report(upload_endpoint, request_body).await;
        };

        let mut ohttp_config = ohttp_config.lock().await;
        let key_configs = ohttp_config.get().await?;

        // Construct a Message representing the upload request...
        let mut message = Message::request(
            "POST".into(),
            upload_endpoint.scheme().into(),
            upload_endpoint.authority().into(),
            upload_endpoint.path().into(),
        );
        message.put_header(CONTENT_TYPE.as_str(), UploadRequest::MEDIA_TYPE);
        message.write_content(request_body);

        // ...get the BHTTP encoding of the message...
        let mut request_buf = Vec::new();
        message.write_bhttp(Mode::KnownLength, &mut request_buf)?;

        // ...and OHTTP encapsulate it to the gateway key config.
        let ohttp_request = key_configs
            .iter()
            .cloned()
            .find_map(|mut key_config| ClientRequest::from_config(&mut key_config).ok())
            .ok_or_else(|| Error::OhttpNoSupportedKeyConfigs(Box::new(key_configs.to_vec())))?;

        let (encapsulated_request, ohttp_response) = ohttp_request.encapsulate(&request_buf)?;

        let relay_response = retry_http_request(
            self.parameters.http_request_retry_parameters.build(),
            || async {
                self.http_client
                    .post(ohttp_config.relay.clone())
                    .header(CONTENT_TYPE, OHTTP_REQUEST_MEDIA_TYPE)
                    .header(ACCEPT, OHTTP_RESPONSE_MEDIA_TYPE)
                    .body(encapsulated_request.clone())
                    .send()
                    .await
            },
        )
        .await?;

        // Check whether request to the OHTTP relay was successful, and if so, decapsulate that
        // response to get the DAP aggregator's response.
        if !relay_response.status().is_success() {
            return Err(Error::Http(Box::new(HttpErrorResponse::from(
                relay_response.status(),
            ))));
        }

        if relay_response
            .headers()
            .get(CONTENT_TYPE)
            .map(HeaderValue::as_bytes)
            != Some(OHTTP_RESPONSE_MEDIA_TYPE.as_bytes())
        {
            return Err(Error::UnexpectedServerResponse(
                "content type wrong for OHTTP response",
            ));
        }

        let decapsulated_response = ohttp_response.decapsulate(relay_response.body().as_ref())?;
        let message = Message::read_bhttp(&mut Cursor::new(&decapsulated_response))?;
        let status = if let ControlData::Response(status) = message.control() {
            StatusCode::from_u16((*status).into()).map_err(|_| {
                Error::UnexpectedServerResponse(
                    "status in decapsulated response is not valid HTTP status",
                )
            })?
        } else {
            return Err(Error::UnexpectedServerResponse(
                "decapsulated response control data is not a response",
            ));
        };

        Ok(status)
    }
}

/// An HPKE configuration advertised by an aggregator.
#[derive(Debug, Clone)]
pub(crate) struct HpkeConfiguration {
    hpke_config_list: CachedResource<HpkeConfigList>,
}

impl HpkeConfiguration {
    pub(crate) async fn new(
        client_parameters: &ClientParameters,
        aggregator_role: &Role,
        http_client: reqwest::Client,
    ) -> Result<Self, Error> {
        let hpke_config_url = client_parameters.hpke_config_endpoint(aggregator_role)?;

        Ok(Self {
            hpke_config_list: CachedResource::new(
                hpke_config_url,
                http_client,
                client_parameters.http_request_retry_parameters,
            )
            .await?,
        })
    }

    pub(crate) fn new_static(hpke_configuration: HpkeConfig) -> Self {
        Self {
            hpke_config_list: CachedResource::Static(HpkeConfigList::new(vec![hpke_configuration])),
        }
    }

    pub(crate) async fn get(&mut self) -> Result<&HpkeConfig, Error> {
        let hpke_config_list = self.hpke_config_list.resource().await?;

        if hpke_config_list.hpke_configs().is_empty() {
            return Err(Error::UnexpectedServerResponse(
                "aggregator provided empty HpkeConfigList",
            ));
        }

        // Take the first supported HpkeConfig from the list. Return the first error otherwise.
        let mut first_error = None;
        for config in hpke_config_list.hpke_configs() {
            match is_hpke_config_supported(config) {
                Ok(()) => return Ok(config),
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
}

#[cfg(feature = "ohttp")]
pub mod ohttp_keys {
    use crate::{ClientParameters, Error, OHTTP_KEYS_MEDIA_TYPE, OhttpConfig};
    use janus_core::http::cached_resource::{CachedResource, FromBytes};
    use janus_messages::MediaType;
    use ohttp::KeyConfig;
    use url::Url;

    /// Shim around a vector of OHTTP key configs so that we can implement traits on it locally.
    #[derive(Debug, Clone)]
    pub(crate) struct OhttpKeyConfigs(pub Vec<KeyConfig>);

    impl FromBytes for OhttpKeyConfigs {
        fn from_bytes(
            bytes: &[u8],
        ) -> Result<Self, Box<dyn std::error::Error + 'static + Send + Sync>> {
            Ok(Self(KeyConfig::decode_list(bytes).map_err(|e| {
                janus_core::http::cached_resource::Error::Decode(Box::new(e))
            })?))
        }
    }

    impl MediaType for OhttpKeyConfigs {
        const MEDIA_TYPE: &'static str = OHTTP_KEYS_MEDIA_TYPE;
    }

    /// Key configurations advertised by an OHTTP relay.
    #[derive(Debug, Clone)]
    pub(crate) struct OhttpKeys {
        pub relay: Url,
        key_configs: CachedResource<OhttpKeyConfigs>,
    }

    impl OhttpKeys {
        pub(crate) async fn new(
            ohttp_config: OhttpConfig,
            client_parameters: &ClientParameters,
            http_client: reqwest::Client,
        ) -> Result<Self, Error> {
            Ok(Self {
                relay: ohttp_config.relay,
                key_configs: CachedResource::new(
                    ohttp_config.key_configs,
                    http_client,
                    client_parameters.http_request_retry_parameters,
                )
                .await?,
            })
        }

        #[tracing::instrument(err)]
        pub(crate) async fn get(&mut self) -> Result<&[KeyConfig], Error> {
            Ok(&self.key_configs.resource().await?.0)
        }
    }
}
