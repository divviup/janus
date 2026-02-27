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
//! use janus_messages::{taskprov::TimePrecision, TaskId};
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
//!         TimePrecision::from_seconds(300),
//!         vdaf
//!     )
//!     .await
//!     .unwrap();
//!     client.upload(5).await.unwrap();
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "ohttp")]
use std::io::Cursor;
use std::{convert::Infallible, fmt::Debug, sync::Arc, time::SystemTimeError};

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
    time::{Clock, DateTimeExt, RealClock},
    url_ensure_trailing_slash,
    vdaf::vdaf_application_context,
};
use janus_messages::{
    HpkeConfig, HpkeConfigList, InputShareAad, PlaintextInputShare, Report, ReportId,
    ReportMetadata, ReportUploadStatus, Role, TaskId, Time, UploadRequest, UploadResponse,
    taskprov::TimePrecision,
};
#[cfg(feature = "ohttp")]
use ohttp::{ClientRequest, KeyConfig};
#[cfg(feature = "ohttp")]
use ohttp_keys::OhttpKeys;
use prio::{
    codec::{Encode, ParameterizedDecode},
    vdaf,
};
use rand::random;
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use url::Url;

#[cfg(test)]
mod tests;

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
    #[error("upload failed for {} report(s)", .0.len())]
    Upload(Vec<ReportUploadStatus>),
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
    #[error("upload session closed unexpectedly")]
    SessionClosed,
    #[error("put called after close")]
    PutAfterClose,
    #[error("upload session task failed")]
    UploadTaskFailed,
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
    time_precision: TimePrecision,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
}

impl ClientParameters {
    /// Creates a new set of client task parameters.
    pub fn new(
        task_id: TaskId,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: TimePrecision,
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
        time_precision: TimePrecision,
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
    /// # use janus_messages::{taskprov::TimePrecision, TaskId};
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
    ///         TimePrecision::from_seconds(1),
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
    ///     client.upload(true).await.unwrap();
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
        time_precision: TimePrecision,
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
        time_precision: TimePrecision,
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
        time_precision: TimePrecision,
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

        let report_metadata = ReportMetadata::new(
            report_id,
            *time,
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

    /// Upload a [`Report`] to the leader, per the [DAP specification][1]. The provided measurement
    /// is sharded into two shares and then uploaded to the leader.
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-uploading-reports
    #[tracing::instrument(skip(measurement), err)]
    pub async fn upload(&self, measurement: V::Measurement) -> Result<(), Error> {
        self.upload_with_time(&[(
            measurement,
            Clock::now(&RealClock::default()).to_time(&self.parameters.time_precision),
        )])
        .await
    }

    /// Upload a [`Report`] to the leader, per the [DAP specification][1], and override the report's
    /// timestamp. The provided measurement is sharded into two shares and then uploaded to the
    /// leader.
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-uploading-reports
    ///
    /// ```no_run
    /// # use janus_client::{Client, Error};
    /// # use janus_messages::{taskprov::TimePrecision, Time};
    /// # use prio::vdaf::prio3::Prio3;
    /// # use rand::random;
    /// # use std::time::SystemTime;
    /// #
    /// # async fn test() -> Result<(), Error> {
    /// # let measurement1 = true;
    /// # let measurement2 = false;
    /// # let vdaf = Prio3::new_count(2).unwrap();
    /// let time_precision = TimePrecision::from_seconds(3600);
    /// let client = Client::new(
    ///     random(),
    ///     "https://example.com/".parse().unwrap(),
    ///     "https://example.net/".parse().unwrap(),
    ///     time_precision,
    ///     vdaf,
    /// ).await?;
    ///
    /// // Upload multiple measurements with explicit timestamps.
    /// // Can use SystemTime for wall clock times:
    /// let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    /// let earlier = now - 3600;
    ///
    /// client.upload_with_time(&[
    ///     (measurement1, Time::from_seconds_since_epoch(earlier, &time_precision)),
    ///     (measurement2, Time::from_seconds_since_epoch(now, &time_precision)),
    /// ]).await?;
    ///
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

        self.upload_reports(reports).await
    }

    /// Encode a batch of prepared [`Report`]s and upload them to the leader.
    async fn upload_reports(&self, reports: Vec<Report>) -> Result<(), Error> {
        let upload_request = UploadRequest::new(reports).get_encoded()?;
        let upload_endpoint = self
            .parameters
            .reports_resource_uri(&self.parameters.task_id)?;

        #[cfg(feature = "ohttp")]
        let (upload_status, upload_response) = self
            .upload_with_ohttp(&upload_endpoint, &upload_request)
            .await?;
        #[cfg(not(feature = "ohttp"))]
        let (upload_status, upload_response) =
            self.put_report(&upload_endpoint, &upload_request).await?;

        if !upload_status.is_success() {
            return Err(Error::Http(Box::new(HttpErrorResponse::from(
                upload_status,
            ))));
        }

        if let Some(upload_response) = upload_response {
            let failed_reports = upload_response.status();
            if !failed_reports.is_empty() {
                return Err(Error::Upload(failed_reports.to_vec()));
            }
        }

        Ok(())
    }

    async fn put_report(
        &self,
        upload_endpoint: &Url,
        request_body: &[u8],
    ) -> Result<(StatusCode, Option<UploadResponse>), Error> {
        let response = retry_http_request(
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
        .await?;

        let status = response.status();
        let upload_response = if response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            == Some(UploadResponse::MEDIA_TYPE)
        {
            let body = response.body();
            Some(UploadResponse::get_decoded_with_param(
                &body.len(),
                body.as_ref(),
            )?)
        } else {
            None
        };

        Ok((status, upload_response))
    }

    /// Send a DAP upload request via OHTTP, if the client is configured to use it, or directly if
    /// not.
    #[cfg(feature = "ohttp")]
    #[tracing::instrument(skip(self, request_body), err)]
    async fn upload_with_ohttp(
        &self,
        upload_endpoint: &Url,
        request_body: &[u8],
    ) -> Result<(StatusCode, Option<UploadResponse>), Error> {
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

        let upload_response = message
            .header()
            .iter()
            .find(|field| field.name() == CONTENT_TYPE.as_str().as_bytes())
            .and_then(|field| {
                if field.value() == UploadResponse::MEDIA_TYPE.as_bytes() {
                    let content = message.content();
                    UploadResponse::get_decoded_with_param(&content.len(), content).ok()
                } else {
                    None
                }
            });

        Ok((status, upload_response))
    }
}

/// Statistics from a completed [`UploadSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadStats {
    pub reports_uploaded: u64,
    pub requests_made: u64,
}

/// An active upload session that accepts measurements and uploads them in batches.
///
/// Created via [`Client::upload_session`]. Measurements sent through [`put`](Self::put) are
/// collected into batches of up to `batch_size` and uploaded concurrently with measurement
/// production.
///
/// Call [`close`](Self::close) when done to flush remaining measurements and retrieve upload
/// statistics.
pub struct UploadSession<V: vdaf::Client<16>> {
    sender: Option<mpsc::Sender<(V::Measurement, Time)>>,
    handle: JoinHandle<Result<UploadStats, Error>>,
}

impl<V: vdaf::Client<16>> UploadSession<V> {
    /// Enqueue a measurement for upload. Returns an error if the background upload task has
    /// failed or been dropped.
    pub async fn put(&self, measurement: V::Measurement, time: Time) -> Result<(), Error> {
        self.sender
            .as_ref()
            .ok_or(Error::PutAfterClose)?
            .send((measurement, time))
            .await
            .map_err(|_| Error::SessionClosed)
    }

    /// Signal that no more measurements will be sent, flush any pending batch, and wait for all
    /// uploads to complete. Returns upload statistics on success.
    pub async fn close(mut self) -> Result<UploadStats, Error> {
        // Drop the sender so the background task sees the channel close.
        self.sender.take();
        self.handle.await.map_err(|_| Error::UploadTaskFailed)?
    }
}

impl<V: vdaf::Client<16>> Client<V>
where
    V: Send + Sync + 'static,
    V::Measurement: Send,
{
    /// Create a streaming upload session. Measurements sent via [`UploadSession::put`] are
    /// split into groups of up to `group_size` and uploaded to the leader as each group fills.
    /// Any partial group remaining when [`UploadSession::close`] is called will be flushed.
    ///
    /// ```no_run
    /// # use janus_client::{Client, UploadStats};
    /// # use janus_messages::{taskprov::TimePrecision, Time};
    /// # use prio::vdaf::prio3::Prio3Count;
    /// # use rand::random;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// let time_precision = TimePrecision::from_seconds(300);
    /// let client = Client::new(
    ///     random(),
    ///     "https://leader.example.com/".parse().unwrap(),
    ///     "https://helper.example.com/".parse().unwrap(),
    ///     time_precision,
    ///     Prio3Count::new_count(2).unwrap(),
    /// ).await.unwrap();
    ///
    /// let session = client.upload_session(100);
    /// let now = Time::from_seconds_since_epoch(1_000_000, &time_precision);
    ///
    /// for _ in 0..250 {
    ///     session.put(true, now).await.unwrap();
    /// }
    ///
    /// let stats = session.close().await.unwrap();
    /// assert_eq!(stats.reports_uploaded, 250);
    /// # }
    /// ```
    pub fn upload_session(&self, group_size: usize) -> UploadSession<V> {
        let (sender, mut receiver) = mpsc::channel::<(V::Measurement, Time)>(group_size);
        let client = self.clone();

        let handle = tokio::spawn(async move {
            let mut stats = UploadStats {
                reports_uploaded: 0,
                requests_made: 0,
            };
            let mut batch = Vec::with_capacity(group_size);

            loop {
                // Block until at least one measurement arrives, or the channel closes.
                let count = receiver.recv_many(&mut batch, group_size).await;
                if count == 0 {
                    // Channel closed, no more measurements.
                    break;
                }

                let leader_hpke_config =
                    client.leader_hpke_config.lock().await.get().await?.clone();
                let helper_hpke_config =
                    client.helper_hpke_config.lock().await.get().await?.clone();

                let mut reports = Vec::with_capacity(batch.len());
                for (measurement, time) in batch.drain(..) {
                    reports.push(client.prepare_report(
                        &measurement,
                        &time,
                        &leader_hpke_config,
                        &helper_hpke_config,
                    )?);
                }

                let num_reports = reports.len() as u64;
                client.upload_reports(reports).await?;
                stats.reports_uploaded += num_reports;
                stats.requests_made += 1;
            }

            Ok(stats)
        });

        UploadSession {
            sender: Some(sender),
            handle,
        }
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
        // Unwrap safety: we checked that the list is nonempty, and if we fell through to here,
        // we must have seen at least one error.
        Err(first_error.unwrap().into())
    }
}

#[cfg(feature = "ohttp")]
pub mod ohttp_keys {
    use janus_core::http::cached_resource::{CachedResource, FromBytes};
    use janus_messages::MediaType;
    use ohttp::KeyConfig;
    use url::Url;

    use crate::{ClientParameters, Error, OHTTP_KEYS_MEDIA_TYPE, OhttpConfig};

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
