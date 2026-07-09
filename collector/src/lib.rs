//! A [DAP-PPM](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) collector
//!
//! This library implements the collector role of the DAP-PPM protocol. It works in concert with two
//! DAP-PPM aggregator servers to compute a statistical aggregate over data from many clients, while
//! preserving the privacy of each client's data.
//!
//! # Examples
//!
//! Initialize an instance of [`Collector`].
//!
//! ```no_run
//! use std::{fs::File, str::FromStr};
//!
//! use janus_collector::{Collector, PrivateCollectorCredential};
//! use janus_messages::{
//!     BatchConfig, Duration, Interval, Query, TaskId, Time, TimePrecision, Url, VdafConfig,
//! };
//! use prio::vdaf::prio3::Prio3;
//!
//! # async fn run() {
//! # const TIME_PRECISION: u64 = 3600;
//! let task_id = TaskId::from_str("[your DAP task ID here]").unwrap();
//! let time_precision = TimePrecision::from_seconds(TIME_PRECISION);
//!
//! let collector_credential: PrivateCollectorCredential =
//!     serde_json::from_reader(File::open("[path to JSON encoded collector credential]").unwrap())
//!         .unwrap();
//!
//! let leader_url =
//!     Url::from_str("[absolute URI to the DAP leader, e.g. https://leader.dap.example.com/]")
//!         .unwrap();
//! let helper_url =
//!     Url::from_str("[absolute URI to the DAP helper, e.g. https://helper.dap.example.com/]")
//!         .unwrap();
//!
//! // Supply a VDAF implementation, corresponding to this task.
//! let vdaf = Prio3::new_count(2).unwrap();
//!
//! // The task parameters below are bound into HPKE AADs and MUST match those provisioned to the
//! // aggregators byte-for-byte.
//! let collector = Collector::builder(
//!     task_id,
//!     leader_url,
//!     collector_credential.authentication_token(),
//!     collector_credential.hpke_keypair(),
//!     vdaf,
//!     time_precision,
//! )
//! .with_helper_endpoint(helper_url)
//! .with_task_info(b"[task info]".to_vec())
//! .with_min_batch_size(1000)
//! .with_batch_config(BatchConfig::TimeInterval)
//! .with_vdaf_config(VdafConfig::Prio3Count)
//! .build()
//! .unwrap();
//!
//! // If this is a time interval task, specify the time interval over which the aggregation
//! // should be calculated.
//! let interval = Interval::new(
//!     Time::from_seconds_since_epoch(1_656_000_000, &time_precision),
//!     Duration::from_seconds(3600, &time_precision),
//! )
//! .unwrap();
//!
//! // Make the requests and retrieve the aggregated statistic.
//! let aggregation_result = collector
//!     .collection(Query::new_time_interval(interval), &())
//!     .collect()
//!     .await
//!     .unwrap();
//!
//! // Or if this is a leader-selected task, make a leader-selected query.
//! let query = Query::new_leader_selected();
//! let aggregation_result = collector.collection(query, &()).collect().await.unwrap();
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

mod credential;

use std::{
    convert::TryFrom,
    time::{Duration as StdDuration, SystemTime},
};

pub use backon::{BackoffBuilder, ExponentialBackoff, ExponentialBuilder};
use chrono::{DateTime, Duration, Utc};
pub use credential::PrivateCollectorCredential;
use educe::Educe;
pub use janus_core::auth_tokens::AuthenticationToken;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair},
    http::{HttpErrorResponse, ReqwestAuthenticationToken, check_content_type},
    retries::{
        ExponentialWithTotalDelayBuilder, http_request_exponential_backoff, retry_http_request,
    },
    task_config::build_task_configuration,
    time::TimeExt,
    url_for_join,
};
use janus_messages::{
    AggregateShareAad, BatchConfig, BatchSelector, CollectionJobExtension, CollectionJobId,
    CollectionJobReq, CollectionJobResp, Interval, MediaType, PartialBatchSelector, Query, Role,
    TaskConfiguration, TaskId, TimePrecision, Url as DapUrl, VdafConfig,
    batch_mode::{BatchMode, TimeInterval},
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf,
};
use rand::random;
use reqwest::{
    StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, RETRY_AFTER, ToStrError},
};
pub use retry_after;
use retry_after::{FromHeaderValueError, RetryAfter};
use tokio::time::{Instant, sleep};
use tracing::debug;
use url::Url;

/// Errors that may occur when performing collections.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("HTTP response status {0}")]
    Http(Box<HttpErrorResponse>),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("missing Location header in See Other response")]
    MissingLocationHeader,
    #[error("invalid bytes in header")]
    InvalidHeader(#[from] ToStrError),
    #[error("wrong Content-Type header: {0:?}")]
    BadContentType(Option<HeaderValue>),
    #[error("invalid Retry-After header value: {0}")]
    InvalidRetryAfterHeader(#[from] FromHeaderValueError),
    #[error("codec error: {0}")]
    Codec(#[from] prio::codec::CodecError),
    #[error("aggregate share decoding error")]
    AggregateShareDecode,
    #[error("VDAF error: {0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("HPKE error: {0}")]
    Hpke(#[from] janus_core::hpke::Error),
    #[error("timed out waiting for collection to finish")]
    CollectPollTimeout,
    #[error("report count was too large")]
    ReportCountOverflow,
    #[error("message error: {0}")]
    Message(#[from] janus_messages::Error),
    #[error("the response from the server was invalid: {0}")]
    BadResponse(Box<dyn std::error::Error + Send + Sync>),
    #[error("invalid parameter {0}")]
    InvalidParameter(&'static str),
}

impl From<HttpErrorResponse> for Error {
    fn from(http_error_response: HttpErrorResponse) -> Self {
        Self::Http(Box::new(http_error_response))
    }
}

static COLLECTOR_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "collector"
);

/// Construct a [`reqwest::Client`] suitable for use in a DAP [`Collector`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        // Clients may override default timeouts using
        // CollectorBuilder::with_http_client
        .timeout(StdDuration::from_secs(30))
        .connect_timeout(StdDuration::from_secs(10))
        .user_agent(COLLECTOR_USER_AGENT)
        .build()?)
}

/// Collector state related to a collection job that is in progress.
#[derive(Educe)]
#[educe(Debug)]
pub struct CollectionJob<P, B>
where
    B: BatchMode,
{
    /// The collection job ID.
    collection_job_id: CollectionJobId,
    /// The collection request's query.
    query: Query<B>,
    /// The aggregation parameter used in this collection request.
    #[educe(Debug(ignore))]
    aggregation_parameter: P,
}

impl<P, B: BatchMode> CollectionJob<P, B> {
    /// Construct an in-progress collection job from its components.
    pub fn new(
        collection_job_id: CollectionJobId,
        query: Query<B>,
        aggregation_parameter: P,
    ) -> CollectionJob<P, B> {
        CollectionJob {
            collection_job_id,
            query,
            aggregation_parameter,
        }
    }

    /// Gets this collection job's identifier.
    pub fn collection_job_id(&self) -> &CollectionJobId {
        &self.collection_job_id
    }

    /// Gets the query used to create this collection job.
    pub fn query(&self) -> &Query<B> {
        &self.query
    }

    /// Gets the aggregation parameter used to create this collection job.
    pub fn aggregation_parameter(&self) -> &P {
        &self.aggregation_parameter
    }
}

/// A builder for a collection request, returned by [`Collector::collection`].
///
/// Configure the optional collection job ID ([`Self::with_id`]) and extensions
/// ([`Self::with_extensions`]), then send the request with [`Self::start`] or [`Self::collect`].
pub struct CollectionRequestBuilder<'a, V: vdaf::Collector, B: BatchMode> {
    collector: &'a Collector<V>,
    query: Query<B>,
    aggregation_parameter: &'a V::AggregationParam,
    collection_job_id: Option<CollectionJobId>,
    extensions: Vec<CollectionJobExtension>,
}

impl<'a, V: vdaf::Collector, B: BatchMode> CollectionRequestBuilder<'a, V, B> {
    /// Use a caller-chosen collection job ID instead of a randomly generated one.
    pub fn with_id(mut self, collection_job_id: CollectionJobId) -> Self {
        self.collection_job_id = Some(collection_job_id);
        self
    }

    /// Set the collection job extensions.
    pub fn with_extensions(mut self, extensions: Vec<CollectionJobExtension>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Send the collection request to the leader aggregator and return an in-progress
    /// [`CollectionJob`] that must be polled separately using [`Collector::poll_once`] or
    /// [`Collector::poll_until_complete`].
    pub async fn start(self) -> Result<CollectionJob<V::AggregationParam, B>, Error> {
        let collection_job_id = self.collection_job_id.unwrap_or_else(random);
        self.collector
            .send_collection_request(
                collection_job_id,
                self.query,
                self.aggregation_parameter,
                self.extensions,
            )
            .await
    }

    /// Send the collection request to the leader aggregator, wait for it to complete, and return
    /// the result of the aggregation.
    pub async fn collect(self) -> Result<Collection<V::AggregateResult, B>, Error> {
        let collector = self.collector;
        let job = self.start().await?;
        collector.poll_until_complete(&job).await
    }
}

#[derive(Educe)]
#[educe(Debug)]
/// The result of a collection request poll operation. This will either provide the collection
/// result or indicate that the collection is still being processed.
pub enum PollResult<T, B>
where
    B: BatchMode,
{
    /// The collection result from a completed collection request.
    CollectionResult(#[educe(Debug(ignore))] Collection<T, B>),
    /// The collection request is not yet ready. If present, the [`RetryAfter`] object is the time
    /// at which the leader recommends retrying the request.
    NotReady(Option<RetryAfter>),
}

/// The result of a collection operation.
#[derive(Debug, PartialEq, Eq)]
pub struct Collection<T, B>
where
    B: BatchMode,
{
    partial_batch_selector: PartialBatchSelector<B>,
    report_count: u64,
    interval: (DateTime<Utc>, Duration),
    aggregate_result: T,
}

impl<T, B> Collection<T, B>
where
    B: BatchMode,
{
    /// Retrieves the partial batch selector of this collection.
    pub fn partial_batch_selector(&self) -> &PartialBatchSelector<B> {
        &self.partial_batch_selector
    }

    /// Retrieves the number of client reports included in this collection.
    pub fn report_count(&self) -> u64 {
        self.report_count
    }

    /// Retrieves the interval of time spanned by the reports included in this collection.
    pub fn interval(&self) -> &(DateTime<Utc>, Duration) {
        &self.interval
    }

    /// Retrieves the aggregated result of the client reports included in this collection.
    pub fn aggregate_result(&self) -> &T {
        &self.aggregate_result
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
impl<T, B> Collection<T, B>
where
    B: BatchMode,
{
    /// Creates a new [`Collection`].
    pub fn new(
        partial_batch_selector: PartialBatchSelector<B>,
        report_count: u64,
        interval: (DateTime<Utc>, Duration),
        aggregate_result: T,
    ) -> Self {
        Self {
            partial_batch_selector,
            report_count,
            interval,
            aggregate_result,
        }
    }
}

/// Builder for configuring a [`Collector`].
pub struct CollectorBuilder<V: vdaf::Collector> {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// The base URL of the leader's aggregator API endpoints.
    leader_endpoint: DapUrl,
    /// The authentication information needed to communicate with the leader aggregator.
    authentication: AuthenticationToken,
    /// HPKE keypair used for decryption of aggregate shares.
    hpke_keypair: HpkeKeypair,
    /// An implementation of the task's VDAF.
    vdaf: V,
    /// The task's time precision.
    time_precision: TimePrecision,
    /// The base URL of the helper's aggregator API endpoints. Required before [`Self::build`]; set
    /// via [`Self::with_helper_endpoint`].
    helper_endpoint: Option<DapUrl>,
    /// Opaque task info bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`]; set via [`Self::with_task_info`].
    task_info: Option<Vec<u8>>,
    /// Minimum batch size bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`]; set via [`Self::with_min_batch_size`].
    min_batch_size: Option<u64>,
    /// Batch configuration bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`]; set via [`Self::with_batch_config`].
    batch_config: Option<BatchConfig>,
    /// VDAF configuration bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`]; set via [`Self::with_vdaf_config`].
    vdaf_config: Option<VdafConfig>,
    /// Optional task validity interval bound into the task's `TaskConfiguration`.
    task_interval: Option<Interval>,

    /// HTTPS client.
    http_client: Option<reqwest::Client>,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
    /// Parameters to use when waiting for a collection job to be processed.
    collect_poll_wait_parameters: ExponentialWithTotalDelayBuilder,
}

impl<V: vdaf::Collector> CollectorBuilder<V> {
    /// Construct a [`CollectorBuilder`] from required DAP task parameters and an implementation of
    /// the task's VDAF.
    pub fn new(
        task_id: TaskId,
        leader_endpoint: DapUrl,
        authentication: AuthenticationToken,
        hpke_keypair: HpkeKeypair,
        vdaf: V,
        time_precision: TimePrecision,
    ) -> Self {
        Self {
            task_id,
            leader_endpoint,
            authentication,
            hpke_keypair,
            vdaf,
            time_precision,
            helper_endpoint: None,
            task_info: None,
            min_batch_size: None,
            batch_config: None,
            vdaf_config: None,
            task_interval: None,
            http_client: None,
            http_request_retry_parameters: http_request_exponential_backoff(),
            collect_poll_wait_parameters: ExponentialWithTotalDelayBuilder::new()
                .with_min_delay(StdDuration::from_secs(15))
                .with_max_delay(StdDuration::from_secs(300))
                .with_factor(1.2),
        }
    }

    /// Finalize construction of a [`Collector`].
    pub fn build(self) -> Result<Collector<V>, Error> {
        let http_client = if let Some(http_client) = self.http_client {
            http_client
        } else {
            default_http_client()?
        };
        let collector = Collector {
            task_id: self.task_id,
            // Stored verbatim; the trailing slash is applied at join time via `url_for_join`, so
            // the bytes bound into HPKE AADs stay exactly as provisioned (DAP §4.1).
            leader_endpoint: self.leader_endpoint,
            helper_endpoint: self
                .helper_endpoint
                .ok_or(Error::InvalidParameter("helper_endpoint not set"))?,
            authentication: self.authentication,
            hpke_keypair: self.hpke_keypair,
            vdaf: self.vdaf,
            time_precision: self.time_precision,
            task_info: self
                .task_info
                .ok_or(Error::InvalidParameter("task_info not set"))?,
            min_batch_size: self
                .min_batch_size
                .ok_or(Error::InvalidParameter("min_batch_size not set"))?,
            batch_config: self
                .batch_config
                .ok_or(Error::InvalidParameter("batch_config not set"))?,
            vdaf_config: self
                .vdaf_config
                .ok_or(Error::InvalidParameter("vdaf_config not set"))?,
            task_interval: self.task_interval,
            http_client,
            http_request_retry_parameters: self.http_request_retry_parameters,
            collect_poll_wait_parameters: self.collect_poll_wait_parameters,
        };
        // Fail fast if the resolved parameters cannot form a valid TaskConfiguration (e.g. invalid
        // endpoint bytes), rather than deferring to the first collection's AAD construction.
        collector.task_configuration()?;
        Ok(collector)
    }

    /// Provide an HTTPS client for the collector.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Replace the exponential backoff settings used for HTTP requests.
    pub fn with_http_request_backoff(mut self, backoff: ExponentialWithTotalDelayBuilder) -> Self {
        self.http_request_retry_parameters = backoff;
        self
    }

    /// Replace the exponential backoff settings used while polling for aggregate shares.
    pub fn with_collect_poll_backoff(mut self, backoff: ExponentialWithTotalDelayBuilder) -> Self {
        self.collect_poll_wait_parameters = backoff;
        self
    }

    /// Set the base URL of the helper's aggregator API endpoints, bound into the task's
    /// `TaskConfiguration`. Required before [`Self::build`].
    pub fn with_helper_endpoint(mut self, helper_endpoint: DapUrl) -> Self {
        self.helper_endpoint = Some(helper_endpoint);
        self
    }

    /// Set the opaque task info bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`].
    pub fn with_task_info(mut self, task_info: Vec<u8>) -> Self {
        self.task_info = Some(task_info);
        self
    }

    /// Set the minimum batch size bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`].
    pub fn with_min_batch_size(mut self, min_batch_size: u64) -> Self {
        self.min_batch_size = Some(min_batch_size);
        self
    }

    /// Set the batch configuration bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`].
    pub fn with_batch_config(mut self, batch_config: BatchConfig) -> Self {
        self.batch_config = Some(batch_config);
        self
    }

    /// Set the VDAF configuration bound into the task's `TaskConfiguration`. Required before
    /// [`Self::build`].
    pub fn with_vdaf_config(mut self, vdaf_config: VdafConfig) -> Self {
        self.vdaf_config = Some(vdaf_config);
        self
    }

    /// Set the optional task validity interval bound into the task's `TaskConfiguration`.
    pub fn with_task_interval(mut self, task_interval: Option<Interval>) -> Self {
        self.task_interval = task_interval;
        self
    }
}

/// A DAP collector.
#[derive(Educe)]
#[educe(Debug)]
pub struct Collector<V: vdaf::Collector> {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// The base URL of the leader's aggregator API endpoints.
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    leader_endpoint: DapUrl,
    /// The base URL of the helper's aggregator API endpoints.
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    helper_endpoint: DapUrl,
    /// The authentication information needed to communicate with the leader aggregator.
    authentication: AuthenticationToken,
    /// HPKE keypair used for decryption of aggregate shares.
    #[educe(Debug(ignore))]
    hpke_keypair: HpkeKeypair,
    /// An implementation of the task's VDAF.
    vdaf: V,
    /// The task's time precision.
    time_precision: TimePrecision,
    /// Opaque task info bound into the task's `TaskConfiguration`.
    #[educe(Debug(ignore))]
    task_info: Vec<u8>,
    /// Minimum batch size bound into the task's `TaskConfiguration`.
    min_batch_size: u64,
    /// Batch configuration bound into the task's `TaskConfiguration`.
    batch_config: BatchConfig,
    /// VDAF configuration bound into the task's `TaskConfiguration`.
    vdaf_config: VdafConfig,
    /// Optional task validity interval bound into the task's `TaskConfiguration`.
    task_interval: Option<Interval>,

    /// HTTPS client.
    #[educe(Debug(ignore))]
    http_client: reqwest::Client,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
    /// Parameters to use when waiting for a collection job to be processed.
    collect_poll_wait_parameters: ExponentialWithTotalDelayBuilder,
}

impl<V: vdaf::Collector> Collector<V> {
    /// Construct a [`CollectorBuilder`] from required DAP task parameters and an implementation of
    /// the task's VDAF.
    pub fn builder(
        task_id: TaskId,
        leader_endpoint: DapUrl,
        authentication: AuthenticationToken,
        hpke_keypair: HpkeKeypair,
        vdaf: V,
        time_precision: TimePrecision,
    ) -> CollectorBuilder<V> {
        CollectorBuilder::new(
            task_id,
            leader_endpoint,
            authentication,
            hpke_keypair,
            vdaf,
            time_precision,
        )
    }

    /// Builds this task's canonical [`TaskConfiguration`] for binding into aggregate-share AADs.
    fn task_configuration(&self) -> Result<TaskConfiguration, Error> {
        Ok(build_task_configuration(
            self.task_info.clone(),
            self.leader_endpoint.clone(),
            self.helper_endpoint.clone(),
            self.time_precision,
            self.min_batch_size,
            self.batch_config.clone(),
            self.vdaf_config.clone(),
            self.task_interval,
        )?)
    }

    /// Construct a URI for a collection.
    fn collection_job_uri(&self, collection_job_id: CollectionJobId) -> Result<Url, Error> {
        Ok(url_for_join(&self.leader_endpoint)?.join(&format!(
            "tasks/{}/collection_jobs/{collection_job_id}",
            self.task_id
        ))?)
    }

    /// Construct a collection request to send to the leader aggregator.
    ///
    /// Returns a [`CollectionRequestBuilder`]; configure the optional collection job ID
    /// ([`CollectionRequestBuilder::with_id`]) and extensions
    /// ([`CollectionRequestBuilder::with_extensions`]), then send the request with
    /// [`CollectionRequestBuilder::start`] (returns a [`CollectionJob`] to poll) or
    /// [`CollectionRequestBuilder::collect`] (sends and waits for the result).
    pub fn collection<'a, B: BatchMode>(
        &'a self,
        query: Query<B>,
        aggregation_parameter: &'a V::AggregationParam,
    ) -> CollectionRequestBuilder<'a, V, B> {
        CollectionRequestBuilder {
            collector: self,
            query,
            aggregation_parameter,
            collection_job_id: None,
            extensions: Vec::new(),
        }
    }

    /// Send a collection request to the leader aggregator with the given [`CollectionJobId`],
    /// returning an in-progress [`CollectionJob`].
    #[tracing::instrument(skip(self, aggregation_parameter, extensions), err)]
    async fn send_collection_request<B: BatchMode>(
        &self,
        collection_job_id: CollectionJobId,
        query: Query<B>,
        aggregation_parameter: &V::AggregationParam,
        extensions: Vec<CollectionJobExtension>,
    ) -> Result<CollectionJob<V::AggregationParam, B>, Error> {
        let collect_request =
            CollectionJobReq::new(query.clone(), aggregation_parameter.get_encoded()?)
                .with_extensions(extensions)
                .get_encoded()?;
        let collection_job_url = self.collection_job_uri(collection_job_id)?;

        let response_res =
            retry_http_request(self.http_request_retry_parameters.build(), || async {
                self.http_client
                    .put(collection_job_url.clone())
                    .header(CONTENT_TYPE, CollectionJobReq::<TimeInterval>::MEDIA_TYPE)
                    .body(collect_request.clone())
                    .authentication_token(&self.authentication)
                    .send()
                    .await
            })
            .await;

        match response_res {
            // Successful response.
            Ok(response) => {
                let status = response.status();
                if status != StatusCode::CREATED {
                    // Incorrect success status code.
                    return Err(Error::Http(Box::new(status.into())));
                }
            }

            // HTTP-level error.
            Err(Ok(http_error_response)) => return Err(http_error_response.into()),

            // Network-level error.
            Err(Err(error)) => return Err(Error::HttpClient(error)),
        };

        Ok(CollectionJob::new(
            collection_job_id,
            query,
            aggregation_parameter.clone(),
        ))
    }

    /// Request the results of an in-progress collection from the leader aggregator.
    #[tracing::instrument(err)]
    pub async fn poll_once<B: BatchMode>(
        &self,
        job: &CollectionJob<V::AggregationParam, B>,
    ) -> Result<PollResult<V::AggregateResult, B>, Error> {
        let collection_job_url = self.collection_job_uri(job.collection_job_id)?;
        let response_res =
            retry_http_request(self.http_request_retry_parameters.build(), || async {
                self.http_client
                    .get(collection_job_url.clone())
                    // reqwest does not send Content-Length for requests with empty bodies. Some
                    // HTTP servers require this anyway, so explicitly set it.
                    .header(CONTENT_LENGTH, 0)
                    .authentication_token(&self.authentication)
                    .send()
                    .await
            })
            .await;

        let response = match response_res {
            // Successful response.
            Ok(response) => {
                if response.status() != StatusCode::OK {
                    return Err(Error::Http(Box::new(HttpErrorResponse::from(
                        response.status(),
                    ))));
                }
                response
            }

            // HTTP-level error.
            Err(Ok(http_error_response)) => return Err(http_error_response.into()),

            // Network-level error.
            Err(Err(error)) => return Err(Error::HttpClient(error)),
        };

        let body = response.body();
        if body.is_empty() {
            let retry_after_opt = response
                .headers()
                .get(RETRY_AFTER)
                .map(RetryAfter::try_from)
                .transpose()?;
            return Ok(PollResult::NotReady(retry_after_opt));
        }

        check_content_type::<CollectionJobResp<TimeInterval>>(response.headers())
            .map_err(|e| Error::BadResponse(e.into()))?;

        let collect_response = CollectionJobResp::<B>::get_decoded(body)?;

        let aggregate_shares = [
            (Role::Leader, collect_response.leader_encrypted_agg_share),
            (Role::Helper, collect_response.helper_encrypted_agg_share),
        ]
        .into_iter()
        .map(|(role, encrypted_aggregate_share)| {
            let bytes = hpke::open(
                &self.hpke_keypair,
                &HpkeApplicationInfo::new(&hpke::Label::AggregateShare, &role, &Role::Collector),
                &encrypted_aggregate_share,
                &AggregateShareAad::new(
                    self.task_id,
                    job.aggregation_parameter.get_encoded()?,
                    BatchSelector::<B>::new(B::batch_identifier_for_collection(
                        &job.query,
                        collect_response.partial_batch_selector.batch_identifier(),
                    )),
                )
                .get_encoded()?,
            )?;
            V::AggregateShare::get_decoded_with_param(
                &(&self.vdaf, &job.aggregation_parameter),
                &bytes,
            )
            .map_err(|_err| Error::AggregateShareDecode)
        })
        .collect::<Result<Vec<_>, Error>>()?;

        let aggregate_result = self.vdaf.unshard(
            &job.aggregation_parameter,
            aggregate_shares,
            usize::try_from(collect_response.report_count)
                .map_err(|_| Error::ReportCountOverflow)?,
        )?;

        Ok(PollResult::CollectionResult(Collection {
            partial_batch_selector: collect_response.partial_batch_selector.clone(),
            report_count: collect_response.report_count,
            interval: (
                collect_response
                    .interval
                    .start()
                    .as_date_time(self.time_precision)?,
                collect_response
                    .interval
                    .duration()
                    .to_chrono(&self.time_precision)?,
            ),
            aggregate_result,
        }))
    }

    /// A convenience method to repeatedly request the result of an in-progress collection job until
    /// it completes.
    ///
    /// This uses the parameters provided via [`CollectorBuilder::with_collect_poll_backoff`]
    /// to control how frequently to poll for completion.
    ///
    /// This could be accomplished using Backon's retry mechanism, but it's cumbersome to do with
    /// the current version. See <https://github.com/Xuanwo/backon/issues/150>.
    pub async fn poll_until_complete<B: BatchMode>(
        &self,
        job: &CollectionJob<V::AggregationParam, B>,
    ) -> Result<Collection<V::AggregateResult, B>, Error> {
        let starttime = Instant::now();
        let deadline = self
            .collect_poll_wait_parameters
            .total_delay
            .map(|duration| starttime + duration);
        let mut backoff = self.collect_poll_wait_parameters.build();

        loop {
            // poll_once() already retries upon server and connection errors, so propagate any error
            // received from it and return immediately.
            let retry_after = match self.poll_once(job).await? {
                PollResult::CollectionResult(aggregate_result) => {
                    debug!(
                        job_id = %job.collection_job_id(),
                        elapsed = ?Instant::now() - starttime,
                        "collection job complete"
                    );
                    return Ok(aggregate_result);
                }
                PollResult::NotReady(retry_after) => retry_after,
            };

            // Compute a sleep duration based on the Retry-After header, if available.
            let retry_after_duration = match retry_after {
                Some(RetryAfter::DateTime(system_time)) => {
                    system_time.duration_since(SystemTime::now()).ok()
                }
                Some(RetryAfter::Delay(duration)) => Some(duration),
                None => None,
            };

            let backoff_duration = if let Some(duration) = backoff.next() {
                duration
            } else {
                // Either the maximum retries or the maximum delay has been reached
                // so return a timeout.
                debug!(
                    ?deadline,
                    ?starttime,
                    "backoff limits reached, returning timeout"
                );
                return Err(Error::CollectPollTimeout);
            };

            // Sleep for the time indicated in the Retry-After header or the time from our
            // exponential backoff, whichever is longer.
            let sleep_duration = if let Some(retry_after_duration) = retry_after_duration {
                // Check if sleeping for as long as the Retry-After header recommends would result
                // in exceeding the maximum elapsed time, and return a timeout error if so.
                if let Some(deadline) = deadline {
                    let recommendation_is_past_deadline = Instant::now()
                        .checked_add(retry_after_duration)
                        .is_none_or(|recommendation| recommendation > deadline);

                    if recommendation_is_past_deadline {
                        debug!(
                            ?deadline,
                            ?starttime,
                            ?recommendation_is_past_deadline,
                            "retry-after would exceed deadline, returning timeout"
                        );
                        return Err(Error::CollectPollTimeout);
                    }
                }

                std::cmp::max(retry_after_duration, backoff_duration)
            } else {
                backoff_duration
            };

            debug!(
                job_id = %job.collection_job_id(),
                ?backoff_duration,
                retry_after_header = ?retry_after,
                "collection job not ready, backing off",
            );
            sleep(sleep_duration).await;
        }
    }

    /// Tell the leader aggregator to abandon an in-progress collection job, and delete all related
    /// state.
    pub async fn delete_collection_job<B: BatchMode>(
        &self,
        collection_job: &CollectionJob<V::AggregationParam, B>,
    ) -> Result<(), Error> {
        let collection_job_url = self.collection_job_uri(collection_job.collection_job_id)?;
        let response_res =
            retry_http_request(self.http_request_retry_parameters.build(), || async {
                self.http_client
                    .delete(collection_job_url.clone())
                    .authentication_token(&self.authentication)
                    .send()
                    .await
            })
            .await;

        match response_res {
            // Successful response.
            Ok(response) => {
                // Accept any success status code -- DAP is not prescriptive about status codes
                // for this response.
                let status = response.status();
                if !status.is_success() {
                    return Err(Error::Http(Box::new(status.into())));
                }
                Ok(())
            }

            // HTTP-level error.
            Err(Ok(http_error_response)) => Err(http_error_response.into()),

            // Network-level error.
            Err(Err(error)) => Err(Error::HttpClient(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use assert_matches::assert_matches;
    use chrono::{DateTime, TimeZone, Utc};
    use janus_core::{
        auth_tokens::{AuthenticationToken, test_util::MatchAuthenticationToken},
        hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
        initialize_rustls,
        retries::test_util::test_http_request_exponential_backoff,
        test_util::{VdafTranscript, install_test_trace_subscriber, run_vdaf},
    };
    use janus_messages::{
        AggregateShareAad, BatchConfig, BatchId, BatchSelector, CollectionJobId, CollectionJobReq,
        CollectionJobResp, Duration, HpkeCiphertext, Interval, MediaType, PartialBatchSelector,
        Query, Role, TaskId, Time, TimePrecision, Url as DapUrl, VdafConfig,
        batch_mode::{LeaderSelected, TimeInterval},
        problem_type::DapProblemType,
    };
    use mockito::Matcher;
    use prio::{
        codec::Encode,
        field::Field64,
        vdaf::{self, AggregateShare, OutputShare, dummy, prio3::Prio3},
    };
    use rand::random;
    use reqwest::{
        StatusCode,
        header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE},
    };
    use retry_after::RetryAfter;

    use crate::{Collection, CollectionJob, Collector, Error, PollResult};

    const TEST_TIME_PRECISION: TimePrecision = TimePrecision::from_seconds(100);

    fn setup_collector<V: vdaf::Collector>(server: &mut mockito::Server, vdaf: V) -> Collector<V> {
        let server_url = DapUrl::try_from(server.url().as_str()).unwrap();
        let hpke_keypair = HpkeKeypair::test();
        Collector::builder(
            random(),
            server_url.clone(),
            AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
            hpke_keypair,
            vdaf,
            TEST_TIME_PRECISION,
        )
        .with_helper_endpoint(server_url)
        .with_task_info(b"test task".to_vec())
        .with_min_batch_size(1)
        .with_batch_config(BatchConfig::TimeInterval)
        .with_vdaf_config(VdafConfig::Prio3Count)
        .with_http_request_backoff(test_http_request_exponential_backoff())
        .with_collect_poll_backoff(test_http_request_exponential_backoff())
        .build()
        .unwrap()
    }

    fn collection_uri_regex_matcher(task_id: &TaskId) -> Matcher {
        // Matches on the relative path for a collection job resource. The Base64 URL-safe encoding
        // of a collection ID is always 22 characters.
        Matcher::Regex(format!(
            "^/tasks/{task_id}/collection_jobs/[A-Za-z0-9-_]{{22}}$"
        ))
    }

    fn build_collect_response_time<const SEED_SIZE: usize, V>(
        transcript: &VdafTranscript<SEED_SIZE, V>,
        collector: &Collector<V>,
        aggregation_parameter: &V::AggregationParam,
        batch_interval: Interval,
    ) -> CollectionJobResp<TimeInterval>
    where
        V: vdaf::Aggregator<SEED_SIZE, 16> + vdaf::Collector,
        V::OutputShare: Eq,
    {
        let associated_data = AggregateShareAad::new(
            collector.task_id,
            aggregation_parameter.get_encoded().unwrap(),
            BatchSelector::new_time_interval(batch_interval),
        );
        CollectionJobResp {
            partial_batch_selector: PartialBatchSelector::new_time_interval(),
            report_count: 1,
            interval: batch_interval,
            leader_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                &transcript.leader_aggregate_share.get_encoded().unwrap(),
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
            helper_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                &transcript.helper_aggregate_share.get_encoded().unwrap(),
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
        }
    }

    fn build_collect_response_fixed<const SEED_SIZE: usize, V>(
        transcript: &VdafTranscript<SEED_SIZE, V>,
        collector: &Collector<V>,
        aggregation_parameter: &V::AggregationParam,
        batch_id: BatchId,
    ) -> CollectionJobResp<LeaderSelected>
    where
        V: vdaf::Aggregator<SEED_SIZE, 16> + vdaf::Collector,
        V::OutputShare: Eq,
    {
        let associated_data = AggregateShareAad::new(
            collector.task_id,
            aggregation_parameter.get_encoded().unwrap(),
            BatchSelector::new_leader_selected(batch_id),
        );
        CollectionJobResp {
            partial_batch_selector: PartialBatchSelector::new_leader_selected(batch_id),
            report_count: 1,
            interval: Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
            leader_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                &transcript.leader_aggregate_share.get_encoded().unwrap(),
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
            helper_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                &transcript.helper_aggregate_share.get_encoded().unwrap(),
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn leader_endpoint_preserved_and_joined() {
        install_test_trace_subscriber();
        initialize_rustls();
        let hpke_keypair = HpkeKeypair::test();
        let collection_job_id: CollectionJobId = random();

        for (endpoint, joined_base) in [
            ("http://example.com/dap", "http://example.com/dap/"),
            ("http://example.com", "http://example.com/"),
        ] {
            let collector = Collector::builder(
                random(),
                endpoint.try_into().unwrap(),
                AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
                hpke_keypair.clone(),
                dummy::Vdaf::new(1),
                TEST_TIME_PRECISION,
            )
            .with_helper_endpoint("http://helper.example.com".try_into().unwrap())
            .with_task_info(b"test task".to_vec())
            .with_min_batch_size(1)
            .with_batch_config(BatchConfig::TimeInterval)
            .with_vdaf_config(VdafConfig::Prio3Count)
            .build()
            .unwrap();

            // Stored verbatim (no trailing slash added) for byte-identical HPKE AADs (DAP §4.1),
            // while the request URI is still joined against a slash-terminated base.
            assert_eq!(collector.leader_endpoint.as_str(), endpoint);
            assert_eq!(
                collector
                    .collection_job_uri(collection_job_id)
                    .unwrap()
                    .as_str(),
                format!(
                    "{joined_base}tasks/{}/collection_jobs/{collection_job_id}",
                    collector.task_id
                ),
            );
        }
    }

    #[tokio::test]
    async fn successful_collect_prio3_count() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &random(), &(), &random(), &true);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_error = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_authentication_token(&collector.authentication)
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await;

        mocked_collect_start_error.assert_async().await;
        mocked_collect_start_success.assert_async().await;

        let job = job.unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_error = server
            .mock("GET", collection_job_path.as_str())
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mocked_collect_accepted = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .expect(2)
            .create_async()
            .await;
        let mocked_collect_complete = server
            .mock("GET", collection_job_path.as_str())
            .match_authentication_token(&collector.authentication)
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect(1)
            .create_async()
            .await;

        let poll_result = collector.poll_once(&job).await.unwrap();
        assert_matches!(poll_result, PollResult::NotReady(None));

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(
                PartialBatchSelector::new_time_interval(),
                1,
                (
                    DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap(),
                    chrono::Duration::try_seconds(3600).unwrap(),
                ),
                1,
            ),
        );

        mocked_collect_error.assert_async().await;
        mocked_collect_accepted.assert_async().await;
        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_prio3_sum() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_sum(2, 255).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &random(), &(), &random(), &144);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await
            .unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);
        mocked_collect_start_success.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect(1)
            .create_async()
            .await;

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(
                PartialBatchSelector::new_time_interval(),
                1,
                (
                    DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap(),
                    chrono::Duration::try_seconds(3600).unwrap(),
                ),
                144
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_prio3_histogram() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_histogram(2, 4, 2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &random(), &(), &random(), &3);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await
            .unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        mocked_collect_start_success.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect(1)
            .create_async()
            .await;

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(
                PartialBatchSelector::new_time_interval(),
                1,
                (
                    DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap(),
                    chrono::Duration::try_seconds(3600).unwrap(),
                ),
                Vec::from([0, 0, 0, 1])
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_leader_selected() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &random(), &(), &random(), &true);
        let collector = setup_collector(&mut server, vdaf);

        let batch_id = random();
        let collect_resp = build_collect_response_fixed(&transcript, &collector, &(), batch_id);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<LeaderSelected>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .collection(Query::new_leader_selected(), &())
            .start()
            .await
            .unwrap();

        mocked_collect_start_success.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<LeaderSelected>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect(1)
            .create_async()
            .await;

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(
                PartialBatchSelector::new_leader_selected(batch_id),
                1,
                (
                    DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
                    TEST_TIME_PRECISION.to_chrono().unwrap(),
                ),
                1
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_authentication_bearer() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &random(), &(), &random(), &true);
        let server_url = DapUrl::try_from(server.url().as_str()).unwrap();
        let hpke_keypair = HpkeKeypair::test();
        let collector = Collector::builder(
            random(),
            server_url.clone(),
            AuthenticationToken::new_bearer_token_from_bytes(Vec::from([0x41u8; 16])).unwrap(),
            hpke_keypair,
            vdaf,
            TEST_TIME_PRECISION,
        )
        .with_helper_endpoint(server_url)
        .with_task_info(b"test task".to_vec())
        .with_min_batch_size(1)
        .with_batch_config(BatchConfig::TimeInterval)
        .with_vdaf_config(VdafConfig::Prio3Count)
        .with_http_request_backoff(test_http_request_exponential_backoff())
        .with_collect_poll_backoff(test_http_request_exponential_backoff())
        .build()
        .unwrap();

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_header(AUTHORIZATION.as_str(), "Bearer AAAAAAAAAAAAAAAA")
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await;

        mocked_collect_start_success.assert_async().await;
        let job = job.unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("GET", collection_job_path.as_str())
            .match_header(AUTHORIZATION.as_str(), "Bearer AAAAAAAAAAAAAAAA")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect(1)
            .create_async()
            .await;

        let agg_result = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            agg_result,
            Collection::new(
                PartialBatchSelector::new_time_interval(),
                1,
                (
                    DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap(),
                    chrono::Duration::try_seconds(3600).unwrap(),
                ),
                1,
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn failed_collect_start() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_server_error = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let error = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_server_error.assert_async().await;

        let mock_server_error_details = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"http://example.com/test_server_error\"}")
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error_response.type_uri().unwrap(), "http://example.com/test_server_error");
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_server_error_details.assert_async().await;

        let mock_bad_request = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(400)
            .with_header("Content-Type", "application/problem+json")
            .with_body(concat!(
                "{\"type\": \"urn:ietf:params:ppm:dap:error:invalidMessage\", ",
                "\"detail\": \"The message type for a response was incorrect or the payload was \
                 malformed.\"}"
            ))
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(error_response.type_uri().unwrap(), "urn:ietf:params:ppm:dap:error:invalidMessage");
            assert_eq!(error_response.detail().unwrap(), "The message type for a response was incorrect or the payload was malformed.");
            assert_eq!(*error_response.dap_problem_type().unwrap(), DapProblemType::InvalidMessage);
        });

        mock_bad_request.assert_async().await;
    }

    #[tokio::test]
    async fn failed_collect_poll() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_collect_start = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;
        let mock_collection_job_server_error = server
            .mock("GET", matcher)
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let job = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await
            .unwrap();
        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_collect_start.assert_async().await;
        mock_collection_job_server_error.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mock_collection_job_server_error_details = server
            .mock("GET", collection_job_path.as_str())
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"http://example.com/test_server_error\"}")
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error_response.type_uri().unwrap(), "http://example.com/test_server_error");
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_collection_job_server_error_details
            .assert_async()
            .await;

        let mock_collection_job_bad_request = server
            .mock("GET", collection_job_path.as_str())
            .with_status(400)
            .with_header("Content-Type", "application/problem+json")
            .with_body(concat!(
                "{\"type\": \"urn:ietf:params:ppm:dap:error:invalidMessage\", ",
                "\"detail\": \"The message type for a response was incorrect or the payload was \
                 malformed.\"}"
            ))
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(error_response.type_uri().unwrap(), "urn:ietf:params:ppm:dap:error:invalidMessage");
            assert_eq!(error_response.detail().unwrap(), "The message type for a response was incorrect or the payload was malformed.");
            assert_eq!(*error_response.dap_problem_type().unwrap(), DapProblemType::InvalidMessage);
        });

        mock_collection_job_bad_request.assert_async().await;

        let mock_collection_job_empty_body_no_retry = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .expect_at_least(1)
            .create_async()
            .await;

        let poll_result = collector.poll_once(&job).await.unwrap();
        assert_matches!(poll_result, PollResult::NotReady(None));

        mock_collection_job_empty_body_no_retry.assert_async().await;

        let mock_collection_job_empty_body_with_retry = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", "65535")
            .expect_at_least(1)
            .create_async()
            .await;

        let poll_result = collector.poll_once(&job).await.unwrap();
        assert_matches!(
            poll_result,
            PollResult::NotReady(Some(RetryAfter::Delay(duration))) => {
                assert_eq!(duration, std::time::Duration::from_secs(65535));
            }
        );

        mock_collection_job_empty_body_with_retry
            .assert_async()
            .await;

        let mock_collection_job_bad_ciphertext = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(
                CollectionJobResp {
                    partial_batch_selector: PartialBatchSelector::new_time_interval(),
                    report_count: 1,
                    interval: batch_interval,
                    leader_encrypted_agg_share: HpkeCiphertext::new(
                        *collector.hpke_keypair.config().id(),
                        Vec::new(),
                        Vec::new(),
                    ),
                    helper_encrypted_agg_share: HpkeCiphertext::new(
                        *collector.hpke_keypair.config().id(),
                        Vec::new(),
                        Vec::new(),
                    ),
                }
                .get_encoded()
                .unwrap(),
            )
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Hpke(_));

        mock_collection_job_bad_ciphertext.assert_async().await;

        let associated_data = AggregateShareAad::new(
            collector.task_id,
            ().get_encoded().unwrap(),
            BatchSelector::new_time_interval(batch_interval),
        );
        let collect_resp = CollectionJobResp {
            partial_batch_selector: PartialBatchSelector::new_time_interval(),
            report_count: 1,
            interval: batch_interval,
            leader_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                b"bad",
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
            helper_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                b"bad",
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
        };
        let mock_collection_job_bad_shares = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareDecode);

        mock_collection_job_bad_shares.assert_async().await;

        let collect_resp = CollectionJobResp {
            partial_batch_selector: PartialBatchSelector::new_time_interval(),
            report_count: 1,
            interval: batch_interval,
            leader_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                &AggregateShare::from(OutputShare::from(Vec::from([Field64::from(0)])))
                    .get_encoded()
                    .unwrap(),
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
            helper_encrypted_agg_share: hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                &AggregateShare::from(OutputShare::from(Vec::from([
                    Field64::from(0),
                    Field64::from(0),
                ])))
                .get_encoded()
                .unwrap(),
                &associated_data.get_encoded().unwrap(),
            )
            .unwrap(),
        };
        let mock_collection_job_wrong_length = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareDecode);

        mock_collection_job_wrong_length.assert_async().await;

        let mock_collection_job_always_fail = server
            .mock("GET", collection_job_path.as_str())
            .with_status(500)
            .expect_at_least(3)
            .create_async()
            .await;
        let error = collector.poll_until_complete(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(error_response.dap_problem_type().is_none());
        });
        mock_collection_job_always_fail.assert_async().await;
    }

    #[tokio::test]
    async fn collect_poll_retry_after() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_collect_start = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionJobReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let job = collector
            .collection(Query::new_time_interval(batch_interval), &())
            .start()
            .await
            .unwrap();
        mock_collect_start.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );

        let mock_collect_poll_no_retry_after = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NotReady(None)
        );
        mock_collect_poll_no_retry_after.assert_async().await;

        let mock_collect_poll_retry_after_60s = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", "60")
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NotReady(Some(RetryAfter::Delay(duration))) => {
                assert_eq!(duration, std::time::Duration::from_secs(60));
            }
        );
        mock_collect_poll_retry_after_60s.assert_async().await;

        let mock_collect_poll_retry_after_date_time = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")
            .expect(1)
            .create_async()
            .await;
        let ref_date_time = Utc.with_ymd_and_hms(2015, 10, 21, 7, 28, 0).unwrap();
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NotReady(Some(RetryAfter::DateTime(system_time))) => {
                assert_eq!(system_time, SystemTime::from(ref_date_time));
            }
        );
        mock_collect_poll_retry_after_date_time.assert_async().await;
    }

    #[tokio::test]
    async fn poll_timing() {
        // This test exercises handling of the different Retry-After header forms. It does not test
        // the amount of time that poll_until_complete() sleeps. `tokio::time::pause()` cannot be
        // used for this because hyper uses `tokio::time::Interval` internally, see issue #234.
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let mut collector = setup_collector(&mut server, vdaf);
        collector.collect_poll_wait_parameters = collector
            .collect_poll_wait_parameters
            .without_max_times()
            .with_total_delay(Some(std::time::Duration::from_secs(3)));

        let collection_job_id: CollectionJobId = random();
        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{collection_job_id}",
            collector.task_id
        );

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let job = CollectionJob::new(
            collection_job_id,
            Query::new_time_interval(batch_interval),
            (),
        );

        let mock_collect_poll_retry_after_1s = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", "1")
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_10s = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", "10")
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_until_complete(&job).await.unwrap_err(),
            Error::CollectPollTimeout
        );
        mock_collect_poll_retry_after_1s.assert_async().await;
        mock_collect_poll_retry_after_10s.assert_async().await;

        let near_future =
            Utc::now() + chrono::Duration::from_std(std::time::Duration::from_secs(1)).unwrap();
        let near_future_formatted = near_future.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mock_collect_poll_retry_after_near_future = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", &near_future_formatted)
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_past = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", "Mon, 01 Jan 1900 00:00:00 GMT")
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_far_future = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .with_header("Retry-After", "Wed, 01 Jan 3000 00:00:00 GMT")
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_until_complete(&job).await.unwrap_err(),
            Error::CollectPollTimeout
        );
        mock_collect_poll_retry_after_near_future
            .assert_async()
            .await;
        mock_collect_poll_retry_after_past.assert_async().await;
        mock_collect_poll_retry_after_far_future
            .assert_async()
            .await;

        // Manipulate backoff settings so that we make one or two requests and time out.
        collector.http_request_retry_parameters = collector
            .http_request_retry_parameters
            .with_total_delay(Some(std::time::Duration::from_millis(3)))
            .with_min_delay(std::time::Duration::from_millis(2))
            .with_max_delay(std::time::Duration::from_millis(2));
        collector.collect_poll_wait_parameters = collector
            .collect_poll_wait_parameters
            .with_total_delay(Some(std::time::Duration::from_millis(15)))
            .with_min_delay(std::time::Duration::from_millis(10))
            .with_max_delay(std::time::Duration::from_millis(10));
        let mock_collect_poll_no_retry_after = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .expect_at_least(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_until_complete(&job).await.unwrap_err(),
            Error::CollectPollTimeout
        );
        mock_collect_poll_no_retry_after.assert_async().await;
    }

    #[tokio::test]
    async fn successful_delete() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = dummy::Vdaf::new(1);
        let collector = setup_collector(&mut server, vdaf);

        let collection_job_id = random();
        let collection_job = CollectionJob::new(
            collection_job_id,
            Query::new_leader_selected(),
            dummy::AggregationParam(1),
        );
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_error = server
            .mock("DELETE", matcher.clone())
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mock_success = server
            .mock("DELETE", matcher)
            .with_status(204)
            .expect(1)
            .create_async()
            .await;

        collector
            .delete_collection_job(&collection_job)
            .await
            .unwrap();

        mock_error.assert_async().await;
        mock_success.assert_async().await;
    }

    #[tokio::test]
    async fn failed_delete() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = dummy::Vdaf::new(1);
        let collector = setup_collector(&mut server, vdaf);

        let collection_job_id = random();
        let collection_job = CollectionJob::new(
            collection_job_id,
            Query::new_leader_selected(),
            dummy::AggregationParam(1),
        );
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_error = server
            .mock("DELETE", matcher.clone())
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector
            .delete_collection_job(&collection_job)
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(error_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        });

        mock_error.assert_async().await;
    }

    #[tokio::test]
    async fn poll_content_length_header() {
        install_test_trace_subscriber();
        initialize_rustls();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &random(), &(), &random(), &true);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000, &TEST_TIME_PRECISION),
            Duration::from_seconds(3600, &TEST_TIME_PRECISION),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);

        let job = CollectionJob {
            collection_job_id: random(),
            query: Query::new_time_interval(batch_interval),
            aggregation_parameter: (),
        };

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_error = server
            .mock("GET", collection_job_path.as_str())
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mocked_collect_accepted = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .match_header(CONTENT_LENGTH.as_str(), "0")
            .expect(2)
            .create_async()
            .await;
        let mocked_collect_complete = server
            .mock("GET", collection_job_path.as_str())
            .with_status(200)
            .match_authentication_token(&collector.authentication)
            .match_header(CONTENT_LENGTH.as_str(), "0")
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionJobResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded().unwrap())
            .expect(1)
            .create_async()
            .await;

        let poll_result = collector.poll_once(&job).await.unwrap();
        assert_matches!(poll_result, PollResult::NotReady(None));

        collector.poll_until_complete(&job).await.unwrap();
        mocked_collect_error.assert_async().await;
        mocked_collect_accepted.assert_async().await;
        mocked_collect_complete.assert_async().await;
    }
}
