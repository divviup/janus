//! A [DAP-PPM](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) collector
//!
//! This library implements the collector role of the DAP-PPM protocol. It works in concert with
//! two DAP-PPM aggregator servers to compute a statistical aggregate over data from many clients,
//! while preserving the privacy of each client's data.
//!
//! # Examples
//!
//! ```no_run
//! use janus_collector::{AuthenticationToken, Collector};
//! use janus_core::{hpke::generate_hpke_config_and_private_key};
//! use janus_messages::{
//!     Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, Interval, TaskId,
//!     Time, Query,
//! };
//! use prio::vdaf::prio3::Prio3;
//! use rand::random;
//! use url::Url;
//!
//! # async fn run() {
//! // Supply DAP task parameters.
//! let task_id = random();
//! let hpke_keypair = janus_core::hpke::generate_hpke_config_and_private_key(
//!     HpkeConfigId::from(0),
//!     HpkeKemId::X25519HkdfSha256,
//!     HpkeKdfId::HkdfSha256,
//!     HpkeAeadId::Aes128Gcm,
//! ).unwrap();
//!
//! // Supply a VDAF implementation, corresponding to this task.
//! let vdaf = Prio3::new_count(2).unwrap();
//! let collector = Collector::new(
//!     task_id,
//!     "https://example.com/dap/".parse().unwrap(),
//!     AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
//!     hpke_keypair,
//!     vdaf,
//! )
//! .unwrap();
//!
//! // Specify the time interval over which the aggregation should be calculated.
//! let interval = Interval::new(
//!     Time::from_seconds_since_epoch(1_656_000_000),
//!     Duration::from_seconds(3600),
//! )
//! .unwrap();
//! // Make the requests and retrieve the aggregated statistic.
//! let aggregation_result = collector.collect(Query::new_time_interval(interval), &()).await.unwrap();
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

use backoff::{backoff::Backoff, ExponentialBackoff};
use chrono::{DateTime, Duration, TimeZone, Utc};
use derivative::Derivative;
pub use janus_core::auth_tokens::AuthenticationToken;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair},
    http::HttpErrorResponse,
    retries::{http_request_exponential_backoff, retry_http_request},
    time::{DurationExt, TimeExt},
    url_ensure_trailing_slash,
};
use janus_messages::{
    query_type::{QueryType, TimeInterval},
    AggregateShareAad, BatchSelector, Collection as CollectionMessage, CollectionJobId,
    CollectionReq, PartialBatchSelector, Query, Role, TaskId,
};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf,
};
use rand::random;
use reqwest::{
    header::{HeaderValue, ToStrError, CONTENT_TYPE, RETRY_AFTER},
    Response, StatusCode,
};
pub use retry_after;
use retry_after::{FromHeaderValueError, RetryAfter};
use std::{
    convert::TryFrom,
    time::{Duration as StdDuration, SystemTime},
};
use tokio::time::{sleep, Instant};
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
}

impl Error {
    /// Construct an error from an HTTP response's status and problem details document, if present
    /// in the body.
    async fn from_http_response(response: Response) -> Error {
        Error::Http(Box::new(HttpErrorResponse::from_response(response).await))
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
        .user_agent(COLLECTOR_USER_AGENT)
        .build()?)
}

/// Collector state related to a collection job that is in progress.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct CollectionJob<P, Q>
where
    Q: QueryType,
{
    /// The collection job ID.
    collection_job_id: CollectionJobId,
    /// The collection request's query.
    query: Query<Q>,
    /// The aggregation parameter used in this collection request.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: P,
}

impl<P, Q: QueryType> CollectionJob<P, Q> {
    /// Construct an in-progress collection job from its components.
    pub fn new(
        collection_job_id: CollectionJobId,
        query: Query<Q>,
        aggregation_parameter: P,
    ) -> CollectionJob<P, Q> {
        CollectionJob {
            collection_job_id,
            query,
            aggregation_parameter,
        }
    }

    /// Destructure a collection job into its fields.
    pub fn into_fields(self) -> (CollectionJobId, Query<Q>, P) {
        (
            self.collection_job_id,
            self.query,
            self.aggregation_parameter,
        )
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
/// The result of a collection request poll operation. This will either provide the collection
/// result or indicate that the collection is still being processed.
pub enum PollResult<T, Q>
where
    Q: QueryType,
{
    /// The collection result from a completed collection request.
    CollectionResult(#[derivative(Debug = "ignore")] Collection<T, Q>),
    /// The collection request is not yet ready. If present, the [`RetryAfter`] object is the time
    /// at which the leader recommends retrying the request.
    NotReady(Option<RetryAfter>),
}

/// The result of a collection operation.
#[derive(Debug)]
pub struct Collection<T, Q>
where
    Q: QueryType,
{
    partial_batch_selector: PartialBatchSelector<Q>,
    report_count: u64,
    interval: (DateTime<Utc>, Duration),
    aggregate_result: T,
}

impl<T, Q> Collection<T, Q>
where
    Q: QueryType,
{
    /// Retrieves the partial batch selector of this collection.
    pub fn partial_batch_selector(&self) -> &PartialBatchSelector<Q> {
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
impl<T, Q> Collection<T, Q>
where
    Q: QueryType,
{
    /// Creates a new [`Collection`].
    pub fn new(
        partial_batch_selector: PartialBatchSelector<Q>,
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

impl<T, Q> PartialEq for Collection<T, Q>
where
    T: PartialEq,
    Q: QueryType,
{
    fn eq(&self, other: &Self) -> bool {
        self.partial_batch_selector == other.partial_batch_selector
            && self.report_count == other.report_count
            && self.interval == other.interval
            && self.aggregate_result == other.aggregate_result
    }
}

impl<T, Q> Eq for Collection<T, Q>
where
    T: Eq,
    Q: QueryType,
{
}

/// Builder for configuring a [`Collector`].
pub struct CollectorBuilder<V: vdaf::Collector> {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// The base URL of the leader's aggregator API endpoints.
    leader_endpoint: Url,
    /// The authentication information needed to communicate with the leader aggregator.
    authentication: AuthenticationToken,
    /// HPKE keypair used for decryption of aggregate shares.
    hpke_keypair: HpkeKeypair,
    /// An implementation of the task's VDAF.
    vdaf: V,

    /// HTTPS client.
    http_client: Option<reqwest::Client>,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialBackoff,
    /// Parameters to use when waiting for a collection job to be processed.
    collect_poll_wait_parameters: ExponentialBackoff,
}

impl<V: vdaf::Collector> CollectorBuilder<V> {
    /// Construct a [`CollectorBuilder`] from required DAP task parameters and an implementation of
    /// the task's VDAF.
    pub fn new(
        task_id: TaskId,
        leader_endpoint: Url,
        authentication: AuthenticationToken,
        hpke_keypair: HpkeKeypair,
        vdaf: V,
    ) -> Self {
        Self {
            task_id,
            leader_endpoint,
            authentication,
            hpke_keypair,
            vdaf,
            http_client: None,
            http_request_retry_parameters: http_request_exponential_backoff(),
            collect_poll_wait_parameters: ExponentialBackoff {
                initial_interval: StdDuration::from_secs(15),
                max_interval: StdDuration::from_secs(300),
                multiplier: 1.2,
                max_elapsed_time: None,
                ..Default::default()
            },
        }
    }

    /// Finalize construction of a [`Collector`].
    pub fn build(self) -> Result<Collector<V>, Error> {
        let http_client = if let Some(http_client) = self.http_client {
            http_client
        } else {
            default_http_client()?
        };
        Ok(Collector {
            task_id: self.task_id,
            leader_endpoint: url_ensure_trailing_slash(self.leader_endpoint),
            authentication: self.authentication,
            hpke_keypair: self.hpke_keypair,
            vdaf: self.vdaf,
            http_client,
            http_request_retry_parameters: self.http_request_retry_parameters,
            collect_poll_wait_parameters: self.collect_poll_wait_parameters,
        })
    }

    /// Provide an HTTPS client for the collector.
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Replace the exponential backoff settings used for HTTP requests.
    pub fn with_http_request_backoff(mut self, backoff: ExponentialBackoff) -> Self {
        self.http_request_retry_parameters = backoff;
        self
    }

    /// Replace the exponential backoff settings used while polling for aggregate shares.
    pub fn with_collect_poll_backoff(mut self, backoff: ExponentialBackoff) -> Self {
        self.collect_poll_wait_parameters = backoff;
        self
    }
}

/// A DAP collector.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Collector<V: vdaf::Collector> {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// The base URL of the leader's aggregator API endpoints.
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    leader_endpoint: Url,
    /// The authentication information needed to communicate with the leader aggregator.
    authentication: AuthenticationToken,
    /// HPKE keypair used for decryption of aggregate shares.
    #[derivative(Debug = "ignore")]
    hpke_keypair: HpkeKeypair,
    /// An implementation of the task's VDAF.
    vdaf: V,
    #[derivative(Debug = "ignore")]

    /// HTTPS client.
    http_client: reqwest::Client,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialBackoff,
    /// Parameters to use when waiting for a collection job to be processed.
    collect_poll_wait_parameters: ExponentialBackoff,
}

impl<V: vdaf::Collector> Collector<V> {
    /// Construct a new collector. This requires certain DAP task parameters and an implementation of
    /// the task's VDAF.
    pub fn new(
        task_id: TaskId,
        leader_endpoint: Url,
        authentication: AuthenticationToken,
        hpke_keypair: HpkeKeypair,
        vdaf: V,
    ) -> Result<Collector<V>, Error> {
        Self::builder(task_id, leader_endpoint, authentication, hpke_keypair, vdaf).build()
    }

    /// Construct a [`CollectorBuilder`] from required DAP task parameters and an implementation of
    /// the task's VDAF.
    pub fn builder(
        task_id: TaskId,
        leader_endpoint: Url,
        authentication: AuthenticationToken,
        hpke_keypair: HpkeKeypair,
        vdaf: V,
    ) -> CollectorBuilder<V> {
        CollectorBuilder::new(task_id, leader_endpoint, authentication, hpke_keypair, vdaf)
    }

    /// Construct a URI for a collection.
    fn collection_job_uri(&self, collection_job_id: CollectionJobId) -> Result<Url, Error> {
        Ok(self.leader_endpoint.join(&format!(
            "tasks/{}/collection_jobs/{collection_job_id}",
            self.task_id
        ))?)
    }

    /// Send a collection request to the leader aggregator, wait for it to complete, and return the
    /// result of the aggregation.
    pub async fn collect<Q: QueryType>(
        &self,
        query: Query<Q>,
        aggregation_parameter: &V::AggregationParam,
    ) -> Result<Collection<V::AggregateResult, Q>, Error> {
        let job = self.start_collection(query, aggregation_parameter).await?;
        self.poll_until_complete(&job).await
    }

    /// Send a collection request to the leader aggregator.
    ///
    /// This returns a [`CollectionJob`] that must be polled separately using [`Self::poll_once`] or
    /// [`Self::poll_until_complete`].
    #[tracing::instrument(skip(aggregation_parameter), err)]
    pub async fn start_collection<Q: QueryType>(
        &self,
        query: Query<Q>,
        aggregation_parameter: &V::AggregationParam,
    ) -> Result<CollectionJob<V::AggregationParam, Q>, Error> {
        let collect_request =
            CollectionReq::new(query.clone(), aggregation_parameter.get_encoded());
        let collection_job_id = random();
        let collection_job_url = self.collection_job_uri(collection_job_id)?;

        let response_res =
            retry_http_request(self.http_request_retry_parameters.clone(), || async {
                let (auth_header, auth_value) = self.authentication.request_authentication();
                self.http_client
                    .put(collection_job_url.clone())
                    .header(CONTENT_TYPE, CollectionReq::<TimeInterval>::MEDIA_TYPE)
                    .body(collect_request.get_encoded())
                    .header(auth_header, auth_value)
                    .send()
                    .await
            })
            .await;

        match response_res {
            // Successful response or unretryable error status code:
            Ok(response) => {
                let status = response.status();
                if status.is_client_error() || status.is_server_error() {
                    return Err(Error::from_http_response(response).await);
                } else if status != StatusCode::CREATED {
                    // Incorrect success status code:
                    return Err(Error::Http(Box::new(status.into())));
                }
            }
            // Retryable error status code, but ran out of retries:
            Err(Ok(response)) => return Err(Error::from_http_response(response).await),
            // Lower level errors, either unretryable or ran out of retries:
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
    pub async fn poll_once<Q: QueryType>(
        &self,
        job: &CollectionJob<V::AggregationParam, Q>,
    ) -> Result<PollResult<V::AggregateResult, Q>, Error> {
        let collection_job_url = self.collection_job_uri(job.collection_job_id)?;
        let response_res =
            retry_http_request(self.http_request_retry_parameters.clone(), || async {
                let (auth_header, auth_value) = self.authentication.request_authentication();
                self.http_client
                    .post(collection_job_url.clone())
                    .header(auth_header, auth_value)
                    .send()
                    .await
            })
            .await;

        let response = match response_res {
            // Successful response or unretryable error status code:
            Ok(response) => {
                let status = response.status();
                match status {
                    StatusCode::OK => response,
                    StatusCode::ACCEPTED => {
                        let retry_after_opt = response
                            .headers()
                            .get(RETRY_AFTER)
                            .map(RetryAfter::try_from)
                            .transpose()?;
                        return Ok(PollResult::NotReady(retry_after_opt));
                    }
                    _ if status.is_client_error() || status.is_server_error() => {
                        return Err(Error::from_http_response(response).await);
                    }
                    _ => {
                        return Err(Error::Http(Box::new(HttpErrorResponse::from(status))));
                    }
                }
            }
            // Retryable error status code, but ran out of retries:
            Err(Ok(response)) => return Err(Error::from_http_response(response).await),
            // Lower level errors, either unretryable or ran out of retries:
            Err(Err(error)) => return Err(Error::HttpClient(error)),
        };

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .ok_or(Error::BadContentType(None))?;
        if content_type != CollectionMessage::<TimeInterval>::MEDIA_TYPE {
            return Err(Error::BadContentType(Some(content_type.clone())));
        }

        let collect_response = CollectionMessage::<Q>::get_decoded(&response.bytes().await?)?;

        let aggregate_shares = [
            (
                Role::Leader,
                collect_response.leader_encrypted_aggregate_share(),
            ),
            (
                Role::Helper,
                collect_response.helper_encrypted_aggregate_share(),
            ),
        ]
        .into_iter()
        .map(|(role, encrypted_aggregate_share)| {
            let bytes = hpke::open(
                &self.hpke_keypair,
                &HpkeApplicationInfo::new(&hpke::Label::AggregateShare, &role, &Role::Collector),
                encrypted_aggregate_share,
                &AggregateShareAad::new(
                    self.task_id,
                    job.aggregation_parameter.get_encoded(),
                    BatchSelector::<Q>::new(Q::batch_identifier_for_collection(
                        &job.query,
                        &collect_response,
                    )),
                )
                .get_encoded(),
            )?;
            V::AggregateShare::get_decoded_with_param(
                &(&self.vdaf, &job.aggregation_parameter),
                &bytes,
            )
            .map_err(|_err| Error::AggregateShareDecode)
        })
        .collect::<Result<Vec<_>, Error>>()?;

        let report_count = collect_response
            .report_count()
            .try_into()
            .map_err(|_| Error::ReportCountOverflow)?;
        let aggregate_result =
            self.vdaf
                .unshard(&job.aggregation_parameter, aggregate_shares, report_count)?;

        Ok(PollResult::CollectionResult(Collection {
            partial_batch_selector: collect_response.partial_batch_selector().clone(),
            report_count: collect_response.report_count(),
            interval: (
                Utc.from_utc_datetime(&collect_response.interval().start().as_naive_date_time()?),
                collect_response
                    .interval()
                    .duration()
                    .as_chrono_duration()?,
            ),
            aggregate_result,
        }))
    }

    /// A convenience method to repeatedly request the result of an in-progress collection job until
    /// it completes.
    ///
    /// This uses the parameters provided via [`CollectorBuilder.with_collect_poll_wait_parameters`]
    /// to control how frequently to poll for completion.
    pub async fn poll_until_complete<Q: QueryType>(
        &self,
        job: &CollectionJob<V::AggregationParam, Q>,
    ) -> Result<Collection<V::AggregateResult, Q>, Error> {
        let mut backoff = self.collect_poll_wait_parameters.clone();
        backoff.reset();
        let deadline = backoff
            .max_elapsed_time
            .map(|duration| Instant::now() + duration);
        loop {
            // poll_once() already retries upon server and connection errors, so propagate any error
            // received from it and return immediately.
            let retry_after = match self.poll_once(job).await? {
                PollResult::CollectionResult(aggregate_result) => return Ok(aggregate_result),
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

            let backoff_duration = if let Some(duration) = backoff.next_backoff() {
                duration
            } else {
                // The maximum elapsed time has expired, so return a timeout error.
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
                        .map_or(true, |recommendation| recommendation > deadline);

                    if recommendation_is_past_deadline {
                        return Err(Error::CollectPollTimeout);
                    }
                }

                std::cmp::max(retry_after_duration, backoff_duration)
            } else {
                backoff_duration
            };
            sleep(sleep_duration).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Collection, CollectionJob, Collector, Error, PollResult};
    use assert_matches::assert_matches;
    use chrono::{NaiveDateTime, TimeZone, Utc};
    #[cfg(feature = "fpvec_bounded_l2")]
    use fixed_macro::fixed;
    use janus_core::{
        auth_tokens::AuthenticationToken,
        hpke::{
            self, test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo, Label,
        },
        retries::test_http_request_exponential_backoff,
        test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf, VdafTranscript},
    };
    use janus_messages::{
        problem_type::DapProblemType,
        query_type::{FixedSize, TimeInterval},
        AggregateShareAad, BatchId, BatchSelector, Collection as CollectionMessage,
        CollectionJobId, CollectionReq, Duration, FixedSizeQuery, HpkeCiphertext, Interval,
        PartialBatchSelector, Query, Role, TaskId, Time,
    };
    use mockito::Matcher;
    use prio::{
        codec::Encode,
        field::Field64,
        vdaf::{self, prio3::Prio3, AggregateShare, OutputShare},
    };
    use rand::random;
    use reqwest::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        StatusCode, Url,
    };
    use retry_after::RetryAfter;

    fn setup_collector<V: vdaf::Collector>(server: &mut mockito::Server, vdaf: V) -> Collector<V> {
        let server_url = Url::parse(&server.url()).unwrap();
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        Collector::builder(
            random(),
            server_url,
            AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
            hpke_keypair,
            vdaf,
        )
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

    fn build_collect_response_time<
        const SEED_SIZE: usize,
        V: vdaf::Aggregator<SEED_SIZE, 16> + vdaf::Collector,
    >(
        transcript: &VdafTranscript<SEED_SIZE, V>,
        collector: &Collector<V>,
        aggregation_parameter: &V::AggregationParam,
        batch_interval: Interval,
    ) -> CollectionMessage<TimeInterval> {
        let associated_data = AggregateShareAad::new(
            collector.task_id,
            aggregation_parameter.get_encoded(),
            BatchSelector::new_time_interval(batch_interval),
        );
        CollectionMessage::new(
            PartialBatchSelector::new_time_interval(),
            1,
            batch_interval,
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                &transcript.leader_aggregate_share.get_encoded(),
                &associated_data.get_encoded(),
            )
            .unwrap(),
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                &transcript.helper_aggregate_share.get_encoded(),
                &associated_data.get_encoded(),
            )
            .unwrap(),
        )
    }

    fn build_collect_response_fixed<
        const SEED_SIZE: usize,
        V: vdaf::Aggregator<SEED_SIZE, 16> + vdaf::Collector,
    >(
        transcript: &VdafTranscript<SEED_SIZE, V>,
        collector: &Collector<V>,
        aggregation_parameter: &V::AggregationParam,
        batch_id: BatchId,
    ) -> CollectionMessage<FixedSize> {
        let associated_data = AggregateShareAad::new(
            collector.task_id,
            aggregation_parameter.get_encoded(),
            BatchSelector::new_fixed_size(batch_id),
        );
        CollectionMessage::new(
            PartialBatchSelector::new_fixed_size(batch_id),
            1,
            Interval::new(Time::from_seconds_since_epoch(0), Duration::from_seconds(1)).unwrap(),
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                &transcript.leader_aggregate_share.get_encoded(),
                &associated_data.get_encoded(),
            )
            .unwrap(),
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                &transcript.helper_aggregate_share.get_encoded(),
                &associated_data.get_encoded(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn leader_endpoint_end_in_slash() {
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let collector = Collector::new(
            random(),
            "http://example.com/dap".parse().unwrap(),
            AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
            hpke_keypair.clone(),
            dummy_vdaf::Vdaf::new(),
        )
        .unwrap();

        assert_eq!(
            collector.leader_endpoint.as_str(),
            "http://example.com/dap/",
        );

        let collector = Collector::new(
            random(),
            "http://example.com".parse().unwrap(),
            AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
            hpke_keypair,
            dummy_vdaf::Vdaf::new(),
        )
        .unwrap();

        assert_eq!(collector.leader_endpoint.as_str(), "http://example.com/");
    }

    #[tokio::test]
    async fn successful_collect_prio3_count() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &1);
        let collector = setup_collector(&mut server, vdaf);
        let (auth_header, auth_value) = collector.authentication.request_authentication();

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_error = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_header(auth_header, auth_value.as_str())
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
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
            .mock("POST", collection_job_path.as_str())
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mocked_collect_accepted = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .expect(2)
            .create_async()
            .await;
        let mocked_collect_complete = server
            .mock("POST", collection_job_path.as_str())
            .match_header(auth_header, auth_value.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
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
                    Utc.from_utc_datetime(
                        &NaiveDateTime::from_timestamp_opt(1_000_000, 0).unwrap(),
                    ),
                    chrono::Duration::seconds(3600),
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
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_sum(2, 8).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &144);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);
        mocked_collect_start_success.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
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
                    Utc.from_utc_datetime(
                        &NaiveDateTime::from_timestamp_opt(1_000_000, 0).unwrap(),
                    ),
                    chrono::Duration::seconds(3600),
                ),
                144
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_prio3_histogram() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_histogram(2, 4, 2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &3);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        mocked_collect_start_success.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
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
                    Utc.from_utc_datetime(
                        &NaiveDateTime::from_timestamp_opt(1_000_000, 0).unwrap(),
                    ),
                    chrono::Duration::seconds(3600),
                ),
                Vec::from([0, 0, 0, 1])
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_prio3_fixedpoint_boundedl2_vec_sum() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, 3).unwrap();
        let fp32_4_inv = fixed!(0.25: I1F31);
        let fp32_8_inv = fixed!(0.125: I1F31);
        let fp32_16_inv = fixed!(0.0625: I1F31);
        let transcript = run_vdaf(
            &vdaf,
            &random(),
            &(),
            &random(),
            &vec![fp32_16_inv, fp32_8_inv, fp32_4_inv],
        );
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        mocked_collect_start_success.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
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
                    Utc.from_utc_datetime(
                        &NaiveDateTime::from_timestamp_opt(1_000_000, 0).unwrap(),
                    ),
                    chrono::Duration::seconds(3600),
                ),
                Vec::from([0.0625, 0.125, 0.25])
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_fixed_size() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &1);
        let collector = setup_collector(&mut server, vdaf);

        let batch_id = random();
        let collect_resp = build_collect_response_fixed(&transcript, &collector, &(), batch_id);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<FixedSize>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(
                Query::new_fixed_size(FixedSizeQuery::ByBatchId { batch_id }),
                &(),
            )
            .await
            .unwrap();
        assert_eq!(
            job.query.fixed_size_query(),
            &FixedSizeQuery::ByBatchId { batch_id }
        );

        mocked_collect_start_success.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<FixedSize>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create_async()
            .await;

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(
                PartialBatchSelector::new_fixed_size(batch_id),
                1,
                (
                    Utc.from_utc_datetime(&NaiveDateTime::from_timestamp_opt(0, 0).unwrap()),
                    chrono::Duration::seconds(1),
                ),
                1
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_authentication_bearer() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &1);
        let server_url = Url::parse(&server.url()).unwrap();
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let collector = Collector::builder(
            random(),
            server_url,
            AuthenticationToken::new_bearer_token_from_bytes(Vec::from([0x41u8; 16])).unwrap(),
            hpke_keypair,
            vdaf,
        )
        .with_http_request_backoff(test_http_request_exponential_backoff())
        .with_collect_poll_backoff(test_http_request_exponential_backoff())
        .build()
        .unwrap();

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector, &(), batch_interval);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mocked_collect_start_success = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_header(AUTHORIZATION.as_str(), "Bearer AAAAAAAAAAAAAAAA")
            .with_status(201)
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await;

        mocked_collect_start_success.assert_async().await;
        let job = job.unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mocked_collect_complete = server
            .mock("POST", collection_job_path.as_str())
            .match_header(AUTHORIZATION.as_str(), "Bearer AAAAAAAAAAAAAAAA")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
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
                    Utc.from_utc_datetime(
                        &NaiveDateTime::from_timestamp_opt(1_000_000, 0).unwrap(),
                    ),
                    chrono::Duration::seconds(3600),
                ),
                1,
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn failed_collect_start() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_server_error = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let error = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(*error_response.status().unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_server_error.assert_async().await;

        let mock_server_error_details = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"http://example.com/test_server_error\"}")
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(*error_response.status().unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error_response.type_uri().unwrap(), "http://example.com/test_server_error");
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_server_error_details.assert_async().await;

        let mock_bad_request = server
            .mock("PUT", matcher)
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
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
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(*error_response.status().unwrap(), StatusCode::BAD_REQUEST);
            assert_eq!(error_response.type_uri().unwrap(), "urn:ietf:params:ppm:dap:error:invalidMessage");
            assert_eq!(error_response.detail().unwrap(), "The message type for a response was incorrect or the payload was malformed.");
            assert_eq!(*error_response.dap_problem_type().unwrap(), DapProblemType::InvalidMessage);
        });

        mock_bad_request.assert_async().await;
    }

    #[tokio::test]
    async fn failed_collect_poll() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_collect_start = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;
        let mock_collection_job_server_error = server
            .mock("POST", matcher)
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(*error_response.status().unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_collect_start.assert_async().await;
        mock_collection_job_server_error.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mock_collection_job_server_error_details = server
            .mock("POST", collection_job_path.as_str())
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"http://example.com/test_server_error\"}")
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(*error_response.status().unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error_response.type_uri().unwrap(), "http://example.com/test_server_error");
            assert!(error_response.dap_problem_type().is_none());
        });

        mock_collection_job_server_error_details
            .assert_async()
            .await;

        let mock_collection_job_bad_request = server
            .mock("POST", collection_job_path.as_str())
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
            assert_eq!(*error_response.status().unwrap(), StatusCode::BAD_REQUEST);
            assert_eq!(error_response.type_uri().unwrap(), "urn:ietf:params:ppm:dap:error:invalidMessage");
            assert_eq!(error_response.detail().unwrap(), "The message type for a response was incorrect or the payload was malformed.");
            assert_eq!(*error_response.dap_problem_type().unwrap(), DapProblemType::InvalidMessage);
        });

        mock_collection_job_bad_request.assert_async().await;

        let mock_collection_job_bad_message_bytes = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(b"")
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Codec(_));

        mock_collection_job_bad_message_bytes.assert_async().await;

        let mock_collection_job_bad_ciphertext = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(
                CollectionMessage::new(
                    PartialBatchSelector::new_time_interval(),
                    1,
                    batch_interval,
                    HpkeCiphertext::new(
                        *collector.hpke_keypair.config().id(),
                        Vec::new(),
                        Vec::new(),
                    ),
                    HpkeCiphertext::new(
                        *collector.hpke_keypair.config().id(),
                        Vec::new(),
                        Vec::new(),
                    ),
                )
                .get_encoded(),
            )
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Hpke(_));

        mock_collection_job_bad_ciphertext.assert_async().await;

        let associated_data = AggregateShareAad::new(
            collector.task_id,
            ().get_encoded(),
            BatchSelector::new_time_interval(batch_interval),
        );
        let collect_resp = CollectionMessage::new(
            PartialBatchSelector::new_time_interval(),
            1,
            batch_interval,
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                b"bad",
                &associated_data.get_encoded(),
            )
            .unwrap(),
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                b"bad",
                &associated_data.get_encoded(),
            )
            .unwrap(),
        );
        let mock_collection_job_bad_shares = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareDecode);

        mock_collection_job_bad_shares.assert_async().await;

        let collect_resp = CollectionMessage::new(
            PartialBatchSelector::new_time_interval(),
            1,
            batch_interval,
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Leader, &Role::Collector),
                &AggregateShare::from(OutputShare::from(Vec::from([Field64::from(0)])))
                    .get_encoded(),
                &associated_data.get_encoded(),
            )
            .unwrap(),
            hpke::seal(
                collector.hpke_keypair.config(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                &AggregateShare::from(OutputShare::from(Vec::from([
                    Field64::from(0),
                    Field64::from(0),
                ])))
                .get_encoded(),
                &associated_data.get_encoded(),
            )
            .unwrap(),
        );
        let mock_collection_job_wrong_length = server
            .mock("POST", collection_job_path.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectionMessage::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareDecode);

        mock_collection_job_wrong_length.assert_async().await;

        let mock_collection_job_always_fail = server
            .mock("POST", collection_job_path.as_str())
            .with_status(500)
            .expect_at_least(3)
            .create_async()
            .await;
        let error = collector.poll_until_complete(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(error_response) => {
            assert_eq!(*error_response.status().unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(error_response.dap_problem_type().is_none());
        });
        mock_collection_job_always_fail.assert_async().await;
    }

    #[tokio::test]
    async fn collect_poll_retry_after() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);
        let matcher = collection_uri_regex_matcher(&collector.task_id);

        let mock_collect_start = server
            .mock("PUT", matcher.clone())
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectionReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(201)
            .expect(1)
            .create_async()
            .await;
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        mock_collect_start.assert_async().await;

        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{}",
            collector.task_id, job.collection_job_id
        );
        let mock_collect_poll_no_retry_after = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NotReady(None)
        );
        mock_collect_poll_no_retry_after.assert_async().await;

        let mock_collect_poll_retry_after_60s = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", "60")
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NotReady(Some(RetryAfter::Delay(duration))) => assert_eq!(duration, std::time::Duration::from_secs(60))
        );
        mock_collect_poll_retry_after_60s.assert_async().await;

        let mock_collect_poll_retry_after_date_time = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")
            .expect(1)
            .create_async()
            .await;
        let ref_date_time = Utc.with_ymd_and_hms(2015, 10, 21, 7, 28, 0).unwrap();
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NotReady(Some(RetryAfter::DateTime(system_time))) => assert_eq!(system_time, ref_date_time.into())
        );
        mock_collect_poll_retry_after_date_time.assert_async().await;
    }

    #[tokio::test]
    async fn poll_timing() {
        // This test exercises handling of the different Retry-After header forms. It does not test
        // the amount of time that poll_until_complete() sleeps. `tokio::time::pause()` cannot be
        // used for this because hyper uses `tokio::time::Interval` internally, see issue #234.
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_count(2).unwrap();
        let mut collector = setup_collector(&mut server, vdaf);
        collector.collect_poll_wait_parameters.max_elapsed_time =
            Some(std::time::Duration::from_secs(3));

        let collection_job_id: CollectionJobId = random();
        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{collection_job_id}",
            collector.task_id
        );

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let job = CollectionJob::new(
            collection_job_id,
            Query::new_time_interval(batch_interval),
            (),
        );

        let mock_collect_poll_retry_after_1s = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", "1")
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_10s = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
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
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", &near_future_formatted)
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_past = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", "Mon, 01 Jan 1900 00:00:00 GMT")
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_far_future = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
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
        collector.collect_poll_wait_parameters.max_elapsed_time =
            Some(std::time::Duration::from_millis(15));
        collector.collect_poll_wait_parameters.initial_interval =
            std::time::Duration::from_millis(10);
        let mock_collect_poll_no_retry_after = server
            .mock("POST", collection_job_path.as_str())
            .with_status(202)
            .expect_at_least(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_until_complete(&job).await.unwrap_err(),
            Error::CollectPollTimeout
        );
        mock_collect_poll_no_retry_after.assert_async().await;
    }
}
