//! A [DAP-PPM](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) collector
//!
//! This library implements the collector role of the DAP-PPM protocol. It works in concert with
//! two DAP-PPM aggregator servers to compute a statistical aggregate over data from many clients,
//! while preserving the privacy of each client's data.
//!
//! # Examples
//!
//! ```no_run
//! use janus_collector::{AuthenticationToken, Collector, CollectorParameters, default_http_client};
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
//! );
//! let parameters = CollectorParameters::new(
//!     task_id,
//!     "https://example.com/dap/".parse().unwrap(),
//!     AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
//!     hpke_keypair.config().clone(),
//!     hpke_keypair.private_key().clone(),
//! );
//!
//! // Supply a VDAF implementation, corresponding to this task.
//! let vdaf = Prio3::new_aes128_count(2).unwrap();
//! // Use the default HTTP client as-is.
//! let http_client = default_http_client().unwrap();
//! let collector = Collector::new(parameters, vdaf, http_client);
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
use derivative::Derivative;
use http_api_problem::HttpApiProblem;
pub use janus_core::task::AuthenticationToken;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkePrivateKey},
    http::response_to_problem_details,
    retries::{http_request_exponential_backoff, retry_http_request},
    task::url_ensure_trailing_slash,
};
use janus_messages::{
    problem_type::DapProblemType,
    query_type::{QueryType, TimeInterval},
    BatchSelector, CollectReq, CollectResp, HpkeConfig, PartialBatchSelector, Query, Role, TaskId,
};
use prio::{
    codec::{Decode, Encode},
    vdaf,
};
use reqwest::{
    header::{HeaderValue, ToStrError, CONTENT_TYPE, LOCATION, RETRY_AFTER},
    Response, StatusCode,
};
use retry_after::FromHeaderValueError;
use retry_after::RetryAfter;
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
    #[error("HTTP response status {problem_details}")]
    Http {
        problem_details: Box<HttpApiProblem>,
        dap_problem_type: Option<DapProblemType>,
    },
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
    #[error("expected two aggregate shares, got {0}")]
    AggregateShareCount(usize),
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
        let problem_details = response_to_problem_details(response).await;
        let dap_problem_type = problem_details
            .type_url
            .as_ref()
            .and_then(|str| str.parse::<DapProblemType>().ok());
        Error::Http {
            problem_details: Box::new(problem_details),
            dap_problem_type,
        }
    }
}

static COLLECTOR_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "collector"
);

/// The DAP collector's view of task parameters.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct CollectorParameters {
    /// Unique identifier for the task.
    task_id: TaskId,
    /// The base URL of the leader's aggregator API endpoints.
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    leader_endpoint: Url,
    /// The authentication information needed to communicate with the leader aggregator.
    authentication: AuthenticationToken,
    /// HPKE configuration and public key used for encryption of aggregate shares.
    #[derivative(Debug = "ignore")]
    hpke_config: HpkeConfig,
    /// HPKE private key used to decrypt aggregate shares.
    #[derivative(Debug = "ignore")]
    hpke_private_key: HpkePrivateKey,
    /// Parameters to use when retrying HTTP requests.
    #[derivative(Debug = "ignore")]
    http_request_retry_parameters: ExponentialBackoff,
    /// Parameters to use when waiting for a collection job to be processed.
    #[derivative(Debug = "ignore")]
    collect_poll_wait_parameters: ExponentialBackoff,
}

impl CollectorParameters {
    /// Creates a new set of collector task parameters.
    pub fn new(
        task_id: TaskId,
        mut leader_endpoint: Url,
        authentication: AuthenticationToken,
        hpke_config: HpkeConfig,
        hpke_private_key: HpkePrivateKey,
    ) -> CollectorParameters {
        // Ensure the provided leader endpoint ends with a slash.
        url_ensure_trailing_slash(&mut leader_endpoint);

        CollectorParameters {
            task_id,
            leader_endpoint,
            authentication,
            hpke_config,
            hpke_private_key,
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

    /// Replace the exponential backoff settings used for HTTP requests.
    pub fn with_http_request_backoff(mut self, backoff: ExponentialBackoff) -> CollectorParameters {
        self.http_request_retry_parameters = backoff;
        self
    }

    /// Replace the exponential backoff settings used while polling for aggregate shares.
    pub fn with_collect_poll_backoff(mut self, backoff: ExponentialBackoff) -> CollectorParameters {
        self.collect_poll_wait_parameters = backoff;
        self
    }

    /// Construct a URI to start a collection.
    fn collect_uri(&self) -> Result<Url, Error> {
        Ok(self.leader_endpoint.join("collect")?)
    }

    /// Construct a URI to poll for collection completion, given the value of the Location header in
    /// the response to collection creation.
    fn collect_poll_uri(&self, collection_location: &str) -> Result<Url, Error> {
        Ok(self.leader_endpoint.join(collection_location)?)
    }
}

/// Construct a [`reqwest::Client`] suitable for use in a DAP [`Collector`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(COLLECTOR_USER_AGENT)
        .build()?)
}

/// Collector state related to a collection job that is in progress.
#[derive(Derivative)]
#[derivative(Debug)]
struct CollectionJob<P, Q>
where
    Q: QueryType,
{
    /// The URL provided by the leader aggregator, where the collect response will be available
    /// upon completion.
    #[derivative(Debug(format_with = "std::fmt::Display::fmt"))]
    collect_poll_url: Url,
    /// The collect request's query.
    query: Query<Q>,
    /// The aggregation parameter used in this collect request.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: P,
}

impl<P, Q: QueryType> CollectionJob<P, Q> {
    fn new(
        collect_poll_url: Url,
        query: Query<Q>,
        aggregation_parameter: P,
    ) -> CollectionJob<P, Q> {
        CollectionJob {
            collect_poll_url,
            query,
            aggregation_parameter,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
/// The result of a collect request poll operation. This will either provide the collection result
/// or indicate that the collection is still being processed.
enum PollResult<T, Q>
where
    Q: QueryType,
{
    /// The collection result from a completed collect request.
    CollectionResult(#[derivative(Debug = "ignore")] Collection<T, Q>),
    /// The collect request is not yet ready. If present, the [`RetryAfter`] object is the time at
    /// which the leader recommends retrying the request.
    NextAttempt(Option<RetryAfter>),
}

/// The result of a collection operation.
#[derive(Debug)]
pub struct Collection<T, Q>
where
    Q: QueryType,
{
    partial_batch_selector: PartialBatchSelector<Q>,
    report_count: u64,
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
        aggregate_result: T,
    ) -> Self {
        Self {
            partial_batch_selector,
            report_count,
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
            && self.aggregate_result == other.aggregate_result
    }
}

impl<T, Q> Eq for Collection<T, Q>
where
    T: Eq,
    Q: QueryType,
{
}

/// A DAP collector.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Collector<V: vdaf::Collector>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    parameters: CollectorParameters,
    vdaf_collector: V,
    #[derivative(Debug = "ignore")]
    http_client: reqwest::Client,
}

impl<V: vdaf::Collector> Collector<V>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    /// Construct a new collector. This requires certain DAP task parameters, an implementation of
    /// the task's VDAF, and a [`reqwest::Client`], configured to never follow redirects, that will
    /// be used to communicate with the leader aggregator.
    pub fn new(
        parameters: CollectorParameters,
        vdaf_collector: V,
        http_client: reqwest::Client,
    ) -> Collector<V> {
        Collector {
            parameters,
            vdaf_collector,
            http_client,
        }
    }

    /// Send a collect request to the leader aggregator.
    #[tracing::instrument(skip(aggregation_parameter), err)]
    async fn start_collection<Q: QueryType>(
        &self,
        query: Query<Q>,
        aggregation_parameter: &V::AggregationParam,
    ) -> Result<CollectionJob<V::AggregationParam, Q>, Error> {
        let collect_request = CollectReq::new(
            self.parameters.task_id,
            query.clone(),
            aggregation_parameter.get_encoded(),
        );
        let collection_job_url = self.parameters.collect_uri()?;

        let response_res = retry_http_request(
            self.parameters.http_request_retry_parameters.clone(),
            || async {
                let (auth_header, auth_value) =
                    self.parameters.authentication.request_authentication();
                self.http_client
                    .post(collection_job_url.clone())
                    .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
                    .body(collect_request.get_encoded())
                    .header(auth_header, auth_value)
                    .send()
                    .await
            },
        )
        .await;

        let collect_poll_url = match response_res {
            // Successful response or unretryable error status code:
            Ok(response) => {
                let status = response.status();
                if status.is_client_error() || status.is_server_error() {
                    return Err(Error::from_http_response(response).await);
                } else if status != StatusCode::SEE_OTHER {
                    // Incorrect success/redirect status code:
                    return Err(Error::Http {
                        problem_details: Box::new(HttpApiProblem::new(status)),
                        dap_problem_type: None,
                    });
                }

                let collection_location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| Error::MissingLocationHeader)?
                    .to_str()?;
                self.parameters.collect_poll_uri(collection_location)?
            }
            // Retryable error status code, but ran out of retries:
            Err(Ok(response)) => return Err(Error::from_http_response(response).await),
            // Lower level errors, either unretryable or ran out of retries:
            Err(Err(error)) => return Err(Error::HttpClient(error)),
        };

        Ok(CollectionJob::new(
            collect_poll_url,
            query,
            aggregation_parameter.clone(),
        ))
    }

    /// Request the results of an in-progress collection from the leader aggregator. This may
    /// return `Ok(None)` if the aggregation is not done yet.
    #[tracing::instrument(err)]
    async fn poll_once<Q: QueryType>(
        &self,
        job: &CollectionJob<V::AggregationParam, Q>,
    ) -> Result<PollResult<V::AggregateResult, Q>, Error> {
        let response_res = retry_http_request(
            self.parameters.http_request_retry_parameters.clone(),
            || async {
                let (auth_header, auth_value) =
                    self.parameters.authentication.request_authentication();
                self.http_client
                    .get(job.collect_poll_url.clone())
                    .header(auth_header, auth_value)
                    .send()
                    .await
            },
        )
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
                        return Ok(PollResult::NextAttempt(retry_after_opt));
                    }
                    _ if status.is_client_error() || status.is_server_error() => {
                        return Err(Error::from_http_response(response).await);
                    }
                    _ => {
                        return Err(Error::Http {
                            problem_details: Box::new(HttpApiProblem::new(status)),
                            dap_problem_type: None,
                        })
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
        if content_type != CollectResp::<TimeInterval>::MEDIA_TYPE {
            return Err(Error::BadContentType(Some(content_type.clone())));
        }

        let collect_response = CollectResp::<Q>::get_decoded(&response.bytes().await?)?;
        if collect_response.encrypted_aggregate_shares().len() != 2 {
            return Err(Error::AggregateShareCount(
                collect_response.encrypted_aggregate_shares().len(),
            ));
        }

        let mut aad = Vec::new();
        aad.extend(self.parameters.task_id.as_ref());
        aad.extend(
            &BatchSelector::<Q>::new(Q::batch_identifier_for_collection(
                &job.query,
                &collect_response,
            ))
            .get_encoded(),
        );

        let aggregate_shares_bytes = collect_response
            .encrypted_aggregate_shares()
            .iter()
            .zip(&[Role::Leader, Role::Helper])
            .map(|(encrypted_aggregate_share, role)| {
                hpke::open(
                    &self.parameters.hpke_config,
                    &self.parameters.hpke_private_key,
                    &HpkeApplicationInfo::new(&hpke::Label::AggregateShare, role, &Role::Collector),
                    encrypted_aggregate_share,
                    &aad,
                )
            });
        let aggregate_shares = aggregate_shares_bytes
            .map(|bytes| {
                V::AggregateShare::try_from(&bytes?).map_err(|_err| Error::AggregateShareDecode)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let report_count = collect_response
            .report_count()
            .try_into()
            .map_err(|_| Error::ReportCountOverflow)?;
        let aggregate_result = self.vdaf_collector.unshard(
            &job.aggregation_parameter,
            aggregate_shares,
            report_count,
        )?;

        Ok(PollResult::CollectionResult(Collection {
            partial_batch_selector: collect_response.partial_batch_selector().clone(),
            report_count: collect_response.report_count(),
            aggregate_result,
        }))
    }

    /// A convenience method to repeatedly request the result of an in-progress collection until it
    /// completes.
    async fn poll_until_complete<Q: QueryType>(
        &self,
        job: &CollectionJob<V::AggregationParam, Q>,
    ) -> Result<Collection<V::AggregateResult, Q>, Error> {
        let mut backoff = self.parameters.collect_poll_wait_parameters.clone();
        backoff.reset();
        let deadline = backoff
            .max_elapsed_time
            .map(|duration| Instant::now() + duration);
        loop {
            // poll_once() already retries upon server and connection errors, so propagate any error
            // received from it and return immediately.
            let retry_after = match self.poll_once(job).await? {
                PollResult::CollectionResult(aggregate_result) => return Ok(aggregate_result),
                PollResult::NextAttempt(retry_after) => retry_after,
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

    /// Send a collect request to the leader aggregator, wait for it to complete, and return the
    /// result of the aggregation.
    pub async fn collect<Q: QueryType>(
        &self,
        query: Query<Q>,
        aggregation_parameter: &V::AggregationParam,
    ) -> Result<Collection<V::AggregateResult, Q>, Error> {
        let job = self.start_collection(query, aggregation_parameter).await?;
        self.poll_until_complete(&job).await
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use crate::{Collection, Collector, Error};
    use janus_messages::{query_type::QueryType, Query};
    use prio::vdaf;

    pub async fn collect_with_rewritten_url<V: vdaf::Collector, Q: QueryType>(
        collector: &Collector<V>,
        query: Query<Q>,
        aggregation_parameter: &V::AggregationParam,
        host: &str,
        port: u16,
    ) -> Result<Collection<V::AggregateResult, Q>, Error>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let mut job = collector
            .start_collection(query, aggregation_parameter)
            .await?;
        job.collect_poll_url.set_host(Some(host))?;
        job.collect_poll_url.set_port(Some(port)).unwrap();
        collector.poll_until_complete(&job).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        default_http_client, Collection, CollectionJob, Collector, CollectorParameters, Error,
        PollResult,
    };
    use assert_matches::assert_matches;
    use chrono::{TimeZone, Utc};
    use janus_core::{
        hpke::{
            self, test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo, Label,
        },
        retries::test_http_request_exponential_backoff,
        task::AuthenticationToken,
        test_util::{install_test_trace_subscriber, run_vdaf, VdafTranscript},
    };
    use janus_messages::{
        problem_type::DapProblemType,
        query_type::{FixedSize, TimeInterval},
        BatchId, BatchSelector, CollectReq, CollectResp, CollectionJobId, Duration, HpkeCiphertext,
        Interval, PartialBatchSelector, Query, Role, Time,
    };
    use prio::{
        codec::Encode,
        field::Field64,
        vdaf::{self, prio3::Prio3, AggregateShare, OutputShare, VdafError},
    };
    use rand::random;
    use reqwest::{
        header::{AUTHORIZATION, CONTENT_TYPE, LOCATION},
        StatusCode, Url,
    };
    use retry_after::RetryAfter;

    fn setup_collector<V: vdaf::Collector>(
        server: &mut mockito::Server,
        vdaf_collector: V,
    ) -> Collector<V>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let server_url = Url::parse(&server.url()).unwrap();
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let parameters = CollectorParameters::new(
            random(),
            server_url,
            AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
            hpke_keypair.config().clone(),
            hpke_keypair.private_key().clone(),
        )
        .with_http_request_backoff(test_http_request_exponential_backoff())
        .with_collect_poll_backoff(test_http_request_exponential_backoff());
        Collector::new(parameters, vdaf_collector, default_http_client().unwrap())
    }

    fn build_collect_response_time<const SEED_SIZE: usize, V: vdaf::Aggregator<SEED_SIZE>>(
        transcript: &VdafTranscript<SEED_SIZE, V>,
        parameters: &CollectorParameters,
        batch_interval: Interval,
    ) -> CollectResp<TimeInterval>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let mut aad = Vec::new();
        aad.extend(parameters.task_id.as_ref());
        aad.extend(&BatchSelector::new_time_interval(batch_interval).get_encoded());

        CollectResp::new(
            PartialBatchSelector::new_time_interval(),
            1,
            Vec::<HpkeCiphertext>::from([
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Leader,
                        &Role::Collector,
                    ),
                    &(&transcript.aggregate_shares[0]).into(),
                    &aad,
                )
                .unwrap(),
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &(&transcript.aggregate_shares[1]).into(),
                    &aad,
                )
                .unwrap(),
            ]),
        )
    }

    fn build_collect_response_fixed<const SEED_SIZE: usize, V: vdaf::Aggregator<SEED_SIZE>>(
        transcript: &VdafTranscript<SEED_SIZE, V>,
        parameters: &CollectorParameters,
        batch_id: BatchId,
    ) -> CollectResp<FixedSize>
    where
        for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
    {
        let mut aad = Vec::new();
        aad.extend(parameters.task_id.as_ref());
        aad.extend(&BatchSelector::new_fixed_size(batch_id).get_encoded());

        CollectResp::new(
            PartialBatchSelector::new_fixed_size(batch_id),
            1,
            Vec::<HpkeCiphertext>::from([
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Leader,
                        &Role::Collector,
                    ),
                    &(&transcript.aggregate_shares[0]).into(),
                    &aad,
                )
                .unwrap(),
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &(&transcript.aggregate_shares[1]).into(),
                    &aad,
                )
                .unwrap(),
            ]),
        )
    }

    #[test]
    fn leader_endpoint_end_in_slash() {
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let collector_parameters = CollectorParameters::new(
            random(),
            "http://example.com/dap".parse().unwrap(),
            AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
            hpke_keypair.config().clone(),
            hpke_keypair.private_key().clone(),
        );

        assert_eq!(
            collector_parameters.leader_endpoint.as_str(),
            "http://example.com/dap/",
        );

        let collector_parameters = CollectorParameters::new(
            random(),
            "http://example.com".parse().unwrap(),
            AuthenticationToken::new_bearer_token_from_string("Y29sbGVjdG9yIHRva2Vu").unwrap(),
            hpke_keypair.config().clone(),
            hpke_keypair.private_key().clone(),
        );

        assert_eq!(
            collector_parameters.leader_endpoint.as_str(),
            "http://example.com/",
        );
    }

    #[tokio::test]
    async fn successful_collect_prio3_count() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &1);
        let collector = setup_collector(&mut server, vdaf);
        let (auth_header, auth_value) =
            collector.parameters.authentication.request_authentication();

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector.parameters, batch_interval);

        let mocked_collect_start_error = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mocked_collect_start_success = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_header(auth_header, auth_value.as_str())
            .with_status(303)
            .with_header(
                LOCATION.as_str(),
                &format!(
                    "/collect/{}/{}",
                    collector.parameters.task_id,
                    random::<CollectionJobId>()
                ),
            )
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

        let mocked_collect_error = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        let mocked_collect_accepted = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(202)
            .expect(2)
            .create_async()
            .await;
        let mocked_collect_complete = server
            .mock("GET", job.collect_poll_url.path())
            .match_header(auth_header, auth_value.as_str())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create_async()
            .await;

        let poll_result = collector.poll_once(&job).await.unwrap();
        assert_matches!(poll_result, PollResult::NextAttempt(None));

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(PartialBatchSelector::new_time_interval(), 1, 1,),
        );

        mocked_collect_error.assert_async().await;
        mocked_collect_accepted.assert_async().await;
        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_prio3_sum() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_sum(2, 8).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &144);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector.parameters, batch_interval);

        let mocked_collect_start_success = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(
                LOCATION.as_str(),
                &format!(
                    "/collect/{}/{}",
                    collector.parameters.task_id,
                    random::<CollectionJobId>()
                ),
            )
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);
        mocked_collect_start_success.assert_async().await;

        let mocked_collect_complete: mockito::Mock = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create_async()
            .await;

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(PartialBatchSelector::new_time_interval(), 1, 144)
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_prio3_histogram() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_histogram(2, &[25, 50, 75, 100]).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &80);
        let collector = setup_collector(&mut server, vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector.parameters, batch_interval);

        let mocked_collect_start_success = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(
                LOCATION.as_str(),
                &format!(
                    "/collect/{}/{}",
                    collector.parameters.task_id,
                    random::<CollectionJobId>()
                ),
            )
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        mocked_collect_start_success.assert_async().await;

        let mocked_collect_complete = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
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
                Vec::from([0, 0, 0, 1, 0])
            )
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_fixed_size() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &1);
        let collector = setup_collector(&mut server, vdaf);

        let batch_id = random();
        let collect_resp =
            build_collect_response_fixed(&transcript, &collector.parameters, batch_id);

        let mocked_collect_start_success = server
            .mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::<FixedSize>::MEDIA_TYPE)
            .with_status(303)
            .with_header(
                LOCATION.as_str(),
                &format!(
                    "/collect/{}/{}",
                    collector.parameters.task_id,
                    random::<CollectionJobId>()
                ),
            )
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_fixed_size(batch_id), &())
            .await
            .unwrap();
        assert_eq!(job.query.batch_id(), &batch_id);

        mocked_collect_start_success.assert_async().await;

        let mocked_collect_complete = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::<FixedSize>::MEDIA_TYPE)
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create_async()
            .await;

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            collection,
            Collection::new(PartialBatchSelector::new_fixed_size(batch_id), 1, 1)
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn successful_collect_authentication_bearer() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random(), &(), &random(), &1);
        let server_url = Url::parse(&server.url()).unwrap();
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let parameters = CollectorParameters::new(
            random(),
            server_url,
            AuthenticationToken::new_bearer_token_from_bytes(Vec::from([0x41u8; 16])).unwrap(),
            hpke_keypair.config().clone(),
            hpke_keypair.private_key().clone(),
        )
        .with_http_request_backoff(test_http_request_exponential_backoff())
        .with_collect_poll_backoff(test_http_request_exponential_backoff());
        let collector = Collector::new(parameters, vdaf, default_http_client().unwrap());

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector.parameters, batch_interval);

        let mocked_collect_start_success = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_header(AUTHORIZATION.as_str(), "Bearer AAAAAAAAAAAAAAAA")
            .with_status(303)
            .with_header(
                LOCATION.as_str(),
                &format!(
                    "/collect/{}/{}",
                    collector.parameters.task_id,
                    random::<CollectionJobId>()
                ),
            )
            .expect(1)
            .create_async()
            .await;

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await;

        mocked_collect_start_success.assert_async().await;
        let job = job.unwrap();
        assert_eq!(job.query.batch_interval(), &batch_interval);

        let mocked_collect_complete = server
            .mock("GET", job.collect_poll_url.path())
            .match_header(AUTHORIZATION.as_str(), "Bearer AAAAAAAAAAAAAAAA")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create_async()
            .await;

        let agg_result = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(
            agg_result,
            Collection::new(PartialBatchSelector::new_time_interval(), 1, 1,)
        );

        mocked_collect_complete.assert_async().await;
    }

    #[tokio::test]
    async fn failed_collect_start() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);

        let mock_server_error = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
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
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(dap_problem_type, None);
        });

        mock_server_error.assert_async().await;

        let mock_server_error_details = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
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
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(problem_details.type_url.unwrap(), "http://example.com/test_server_error");
            assert_eq!(dap_problem_type, None);
        });

        mock_server_error_details.assert_async().await;

        let mock_bad_request = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(400)
            .with_header("Content-Type", "application/problem+json")
            .with_body(concat!(
                "{\"type\": \"urn:ietf:params:ppm:dap:error:unrecognizedMessage\", ",
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
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::BAD_REQUEST);
            assert_eq!(problem_details.type_url.unwrap(), "urn:ietf:params:ppm:dap:error:unrecognizedMessage");
            assert_eq!(problem_details.detail.unwrap(), "The message type for a response was incorrect or the payload was malformed.");
            assert_eq!(dap_problem_type, Some(DapProblemType::UnrecognizedMessage));
        });

        mock_bad_request.assert_async().await;
    }

    #[tokio::test]
    async fn failed_collect_poll() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);

        let mock_collect_start = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(
                LOCATION.as_str(),
                &format!(
                    "/collect/{}/{}",
                    collector.parameters.task_id,
                    random::<CollectionJobId>()
                ),
            )
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

        let mock_collection_job_server_error = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(dap_problem_type, None);
        });

        mock_collect_start.assert_async().await;
        mock_collection_job_server_error.assert_async().await;

        let mock_collection_job_server_error_details = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"http://example.com/test_server_error\"}")
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(problem_details.type_url.unwrap(), "http://example.com/test_server_error");
            assert_eq!(dap_problem_type, None);
        });

        mock_collection_job_server_error_details
            .assert_async()
            .await;

        let mock_collection_job_bad_request = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(400)
            .with_header("Content-Type", "application/problem+json")
            .with_body(concat!(
                "{\"type\": \"urn:ietf:params:ppm:dap:error:unrecognizedMessage\", ",
                "\"detail\": \"The message type for a response was incorrect or the payload was \
                 malformed.\"}"
            ))
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::BAD_REQUEST);
            assert_eq!(problem_details.type_url.unwrap(), "urn:ietf:params:ppm:dap:error:unrecognizedMessage");
            assert_eq!(problem_details.detail.unwrap(), "The message type for a response was incorrect or the payload was malformed.");
            assert_eq!(dap_problem_type, Some(DapProblemType::UnrecognizedMessage));
        });

        mock_collection_job_bad_request.assert_async().await;

        let mock_collection_job_bad_message_bytes = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(b"")
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Codec(_));

        mock_collection_job_bad_message_bytes.assert_async().await;

        let mock_collection_job_bad_share_count = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(
                CollectResp::new(PartialBatchSelector::new_time_interval(), 0, Vec::new())
                    .get_encoded(),
            )
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareCount(0));

        mock_collection_job_bad_share_count.assert_async().await;

        let mock_collection_job_bad_ciphertext = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(
                CollectResp::new(
                    PartialBatchSelector::new_time_interval(),
                    1,
                    Vec::from([
                        HpkeCiphertext::new(
                            *collector.parameters.hpke_config.id(),
                            Vec::new(),
                            Vec::new(),
                        ),
                        HpkeCiphertext::new(
                            *collector.parameters.hpke_config.id(),
                            Vec::new(),
                            Vec::new(),
                        ),
                    ]),
                )
                .get_encoded(),
            )
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Hpke(_));

        mock_collection_job_bad_ciphertext.assert_async().await;

        let mut aad = Vec::new();
        aad.extend(collector.parameters.task_id.as_ref());
        aad.extend(&BatchSelector::new_time_interval(batch_interval).get_encoded());

        let collect_resp = CollectResp::new(
            PartialBatchSelector::new_time_interval(),
            1,
            Vec::from([
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Leader,
                        &Role::Collector,
                    ),
                    b"bad",
                    &aad,
                )
                .unwrap(),
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    b"bad",
                    &aad,
                )
                .unwrap(),
            ]),
        );
        let mock_collection_job_bad_shares = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareDecode);

        mock_collection_job_bad_shares.assert_async().await;

        let collect_resp = CollectResp::new(
            PartialBatchSelector::new_time_interval(),
            1,
            Vec::from([
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Leader,
                        &Role::Collector,
                    ),
                    &Vec::<u8>::from(&AggregateShare::from(OutputShare::from(Vec::from([
                        Field64::from(0),
                    ])))),
                    &aad,
                )
                .unwrap(),
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &Vec::<u8>::from(&AggregateShare::from(OutputShare::from(Vec::from([
                        Field64::from(0),
                        Field64::from(0),
                    ])))),
                    &aad,
                )
                .unwrap(),
            ]),
        );
        let mock_collection_job_wrong_length = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect_at_least(1)
            .create_async()
            .await;

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Vdaf(VdafError::Uncategorized(_)));

        mock_collection_job_wrong_length.assert_async().await;

        let mock_collection_job_always_fail = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(500)
            .expect_at_least(3)
            .create_async()
            .await;
        let error = collector.poll_until_complete(&job).await.unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(dap_problem_type, None);
        });
        mock_collection_job_always_fail.assert_async().await;
    }

    #[tokio::test]
    async fn collect_poll_retry_after() {
        install_test_trace_subscriber();
        let mut server = mockito::Server::new_async().await;
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(&mut server, vdaf);

        let mock_collect_start = server
            .mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(
                LOCATION.as_str(),
                &format!(
                    "/collect/{}/{}",
                    collector.parameters.task_id,
                    random::<CollectionJobId>()
                ),
            )
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

        let mock_collect_poll_no_retry_after = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(202)
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NextAttempt(None)
        );
        mock_collect_poll_no_retry_after.assert_async().await;

        let mock_collect_poll_retry_after_60s = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(202)
            .with_header("Retry-After", "60")
            .expect(1)
            .create_async()
            .await;
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NextAttempt(Some(RetryAfter::Delay(duration))) => assert_eq!(duration, std::time::Duration::from_secs(60))
        );
        mock_collect_poll_retry_after_60s.assert_async().await;

        let mock_collect_poll_retry_after_date_time = server
            .mock("GET", job.collect_poll_url.path())
            .with_status(202)
            .with_header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")
            .expect(1)
            .create_async()
            .await;
        let ref_date_time = Utc.with_ymd_and_hms(2015, 10, 21, 7, 28, 0).unwrap();
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NextAttempt(Some(RetryAfter::DateTime(system_time))) => assert_eq!(system_time, ref_date_time.into())
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
        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let mut collector = setup_collector(&mut server, vdaf);
        collector
            .parameters
            .collect_poll_wait_parameters
            .max_elapsed_time = Some(std::time::Duration::from_secs(3));

        let collection_job_id: CollectionJobId = random();
        let collection_job_path = format!(
            "/tasks/{}/collection_jobs/{collection_job_id}",
            collector.parameters.task_id
        );

        let collection_job_url = format!("{}{collection_job_path}", server.url());
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let job = CollectionJob::new(
            collection_job_url.parse().unwrap(),
            Query::new_time_interval(batch_interval),
            (),
        );

        let mock_collect_poll_retry_after_1s = server
            .mock("GET", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", "1")
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_10s = server
            .mock("GET", collection_job_path.as_str())
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
            .mock("GET", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", &near_future_formatted)
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_past = server
            .mock("GET", collection_job_path.as_str())
            .with_status(202)
            .with_header("Retry-After", "Mon, 01 Jan 1900 00:00:00 GMT")
            .expect(1)
            .create_async()
            .await;
        let mock_collect_poll_retry_after_far_future = server
            .mock("GET", collection_job_path.as_str())
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
        collector
            .parameters
            .collect_poll_wait_parameters
            .max_elapsed_time = Some(std::time::Duration::from_millis(15));
        collector
            .parameters
            .collect_poll_wait_parameters
            .initial_interval = std::time::Duration::from_millis(10);
        let mock_collect_poll_no_retry_after = server
            .mock("GET", collection_job_path.as_str())
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
