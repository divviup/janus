//! A [DAP-PPM](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/) collector
//!
//! This library implements the collector role of the DAP-PPM protocol. It works in concert with
//! two DAP-PPM aggregator servers to compute a statistical aggregate over data from many clients,
//! while preserving the privacy of each client's data.
//!
//! # Examples
//!
//! ```no_run
//! use janus_collector::{Collector, CollectorParameters, default_http_client};
//! use janus_core::{hpke::generate_hpke_config_and_private_key, task::AuthenticationToken};
//! use janus_messages::{
//!     Duration, HpkeAeadId, HpkeConfig, HpkeConfigId, HpkeKdfId, HpkeKemId, Interval, TaskId,
//!     Time, Query,
//! };
//! use prio::vdaf::prio3::Prio3;
//! use rand::random;
//! use url::Url;
//!
//! # async fn run() {
//! // Supply DAP task paramenters.
//! let task_id = random();
//! let (hpke_config, private_key) = janus_core::hpke::generate_hpke_config_and_private_key(
//!     HpkeConfigId::from(0),
//!     HpkeKemId::X25519HkdfSha256,
//!     HpkeKdfId::HkdfSha256,
//!     HpkeAeadId::Aes128Gcm,
//! );
//! let authentication_token = AuthenticationToken::from(b"my-authentication-token".to_vec());
//! let parameters = CollectorParameters::new(
//!     task_id,
//!     "https://example.com/dap/".parse().unwrap(),
//!     authentication_token,
//!     hpke_config,
//!     private_key,
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

use backoff::{backoff::Backoff, ExponentialBackoff};
use derivative::Derivative;
use http_api_problem::HttpApiProblem;
use janus_core::{
    hpke::{self, associated_data_for_aggregate_share, HpkeApplicationInfo, HpkePrivateKey},
    http::response_to_problem_details,
    retries::{http_request_exponential_backoff, retry_http_request},
    task::{url_ensure_trailing_slash, AuthenticationToken, DAP_AUTH_HEADER},
};
use janus_messages::{
    problem_type::DapProblemType,
    query_type::{QueryType, TimeInterval},
    CollectReq, CollectResp, HpkeConfig, Query, Role, TaskId,
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

/// Authentication configuration for communication with the leader aggregator.
#[derive(Derivative)]
#[derivative(Debug)]
#[non_exhaustive]
pub enum Authentication {
    /// Bearer token authentication, via the `DAP-Auth-Token` header.
    DapAuthToken(#[derivative(Debug = "ignore")] AuthenticationToken),
}

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
    authentication: Authentication,
    /// HPKE configuration and public key used for encryption of aggregate shares.
    hpke_config: HpkeConfig,
    /// HPKE private key used to decrypt aggregate shares.
    #[derivative(Debug = "ignore")]
    hpke_private_key: HpkePrivateKey,
    /// Parameters to use when retrying HTTP requests.
    http_request_retry_parameters: ExponentialBackoff,
    /// Parameters to use when waiting for a collect job to be processed.
    collect_poll_wait_parameters: ExponentialBackoff,
}

impl CollectorParameters {
    /// Creates a new set of collector task parameters.
    pub fn new(
        task_id: TaskId,
        mut leader_endpoint: Url,
        authentication_token: AuthenticationToken,
        hpke_config: HpkeConfig,
        hpke_private_key: HpkePrivateKey,
    ) -> CollectorParameters {
        // Ensure the provided leader endpoint ends with a slash.
        url_ensure_trailing_slash(&mut leader_endpoint);

        CollectorParameters {
            task_id,
            leader_endpoint,
            authentication: Authentication::DapAuthToken(authentication_token),
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

    /// URL for collect requests.
    fn collect_endpoint(&self) -> Result<Url, Error> {
        Ok(self.leader_endpoint.join("collect")?)
    }
}

/// Construct a [`reqwest::Client`] suitable for use in a DAP [`Collector`].
pub fn default_http_client() -> Result<reqwest::Client, Error> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(COLLECTOR_USER_AGENT)
        .build()?)
}

/// Collector state related to a collect job that is in progress.
#[derive(Derivative)]
#[derivative(Debug)]
struct CollectJob<P, Q>
where
    Q: QueryType,
{
    /// The URL provided by the leader aggregator, where the collect response will be available
    /// upon completion.
    collect_job_url: Url,
    /// The collect request's query.
    query: Query<Q>,
    /// The aggregation parameter used in this collect request.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: P,
}

impl<P, Q: QueryType> CollectJob<P, Q> {
    fn new(collect_job_url: Url, query: Query<Q>, aggregation_parameter: P) -> CollectJob<P, Q> {
        CollectJob {
            collect_job_url,
            query,
            aggregation_parameter,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
/// The result of a collect request poll operation. This will either provide the collection result
/// or indicate that the collection is still being processed.
enum PollResult<T> {
    /// The collection result from a completed collect request.
    CollectionResult(#[derivative(Debug = "ignore")] Collection<T>),
    /// The collect request is not yet ready. If present, the [`RetryAfter`] object is the time at
    /// which the leader recommends retrying the request.
    NextAttempt(Option<RetryAfter>),
}

/// The result of a collection operation.
#[derive(Debug)]
pub struct Collection<T> {
    report_count: u64,
    aggregate_result: T,
}

impl<T> Collection<T> {
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
impl<T> Collection<T> {
    /// Creates a new [`Collection`].
    pub fn new(report_count: u64, aggregate_result: T) -> Self {
        Self {
            report_count,
            aggregate_result,
        }
    }
}

impl<T: PartialEq> PartialEq for Collection<T> {
    fn eq(&self, other: &Self) -> bool {
        self.report_count == other.report_count && self.aggregate_result == other.aggregate_result
    }
}

impl<T: Eq> Eq for Collection<T> {}

/// A DAP collector.
#[derive(Debug)]
pub struct Collector<V: vdaf::Collector>
where
    for<'a> Vec<u8>: From<&'a <V as vdaf::Vdaf>::AggregateShare>,
{
    parameters: CollectorParameters,
    vdaf_collector: V,
    http_client: reqwest::Client,
}

impl<V: vdaf::Collector> Collector<V>
where
    for<'a> Vec<u8>: From<&'a V::AggregateShare>,
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
    #[tracing::instrument(err)]
    async fn start_collection<Q: QueryType>(
        &self,
        query: Query<Q>,
        aggregation_parameter: &V::AggregationParam,
    ) -> Result<CollectJob<V::AggregationParam, Q>, Error> {
        let collect_request = CollectReq::new(
            self.parameters.task_id,
            query.clone(),
            aggregation_parameter.get_encoded(),
        );
        let url = self.parameters.collect_endpoint()?;

        let response_res = retry_http_request(
            self.parameters.http_request_retry_parameters.clone(),
            || async {
                let mut request = self
                    .http_client
                    .post(url.clone())
                    .header(CONTENT_TYPE, CollectReq::<TimeInterval>::MEDIA_TYPE)
                    .body(collect_request.get_encoded());
                match &self.parameters.authentication {
                    Authentication::DapAuthToken(token) => {
                        request = request.header(DAP_AUTH_HEADER, token.as_bytes())
                    }
                }
                request.send().await
            },
        )
        .await;

        let response = match response_res {
            // Successful response or unretryable error status code:
            Ok(response) => {
                let status = response.status();
                if status == StatusCode::SEE_OTHER {
                    response
                } else if status.is_client_error() || status.is_server_error() {
                    return Err(Error::from_http_response(response).await);
                } else {
                    // Incorrect success/redirect status code:
                    return Err(Error::Http {
                        problem_details: Box::new(HttpApiProblem::new(status)),
                        dap_problem_type: None,
                    });
                }
            }
            // Retryable error status code, but ran out of retries:
            Err(Ok(response)) => return Err(Error::from_http_response(response).await),
            // Lower level errors, either unretryable or ran out of retries:
            Err(Err(error)) => return Err(Error::HttpClient(error)),
        };

        let location_header_value = response
            .headers()
            .get(LOCATION)
            .ok_or(Error::MissingLocationHeader)?
            .to_str()?;
        let collect_job_url = location_header_value.parse()?;

        Ok(CollectJob::new(
            collect_job_url,
            query,
            aggregation_parameter.clone(),
        ))
    }

    /// Request the results of an in-progress collection from the leader aggregator. This may
    /// return `Ok(None)` if the aggregation is not done yet.
    #[tracing::instrument(err)]
    async fn poll_once<Q: QueryType>(
        &self,
        job: &CollectJob<V::AggregationParam, Q>,
    ) -> Result<PollResult<V::AggregateResult>, Error> {
        let response_res = retry_http_request(
            self.parameters.http_request_retry_parameters.clone(),
            || async {
                let mut request = self.http_client.get(job.collect_job_url.clone());
                match &self.parameters.authentication {
                    Authentication::DapAuthToken(token) => {
                        request = request.header(DAP_AUTH_HEADER, token.as_bytes())
                    }
                }
                request.send().await
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

        let associated_data = associated_data_for_aggregate_share::<Q>(
            &self.parameters.task_id,
            job.query.batch_identifier(),
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
                    &associated_data,
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
            report_count: collect_response.report_count(),
            aggregate_result,
        }))
    }

    /// A convenience method to repeatedly request the result of an in-progress collection until it
    /// completes.
    async fn poll_until_complete<Q: QueryType>(
        &self,
        job: &CollectJob<V::AggregationParam, Q>,
    ) -> Result<Collection<V::AggregateResult>, Error> {
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
                    if Instant::now() + retry_after_duration > deadline {
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
    ) -> Result<Collection<V::AggregateResult>, Error> {
        let job = self.start_collection(query, aggregation_parameter).await?;
        self.poll_until_complete(&job).await
    }
}

#[cfg(feature = "test-util")]
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
    ) -> Result<Collection<V::AggregateResult>, Error>
    where
        for<'a> Vec<u8>: From<&'a <V as vdaf::Vdaf>::AggregateShare>,
    {
        let mut job = collector
            .start_collection(query, aggregation_parameter)
            .await?;
        job.collect_job_url.set_host(Some(host))?;
        job.collect_job_url.set_port(Some(port)).unwrap();
        collector.poll_until_complete(&job).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        default_http_client, CollectJob, Collection, Collector, CollectorParameters, Error,
        PollResult,
    };
    use assert_matches::assert_matches;
    use chrono::{TimeZone, Utc};
    use janus_core::{
        hpke::{
            self, associated_data_for_aggregate_share,
            test_util::generate_test_hpke_config_and_private_key, HpkeApplicationInfo, Label,
        },
        retries::test_http_request_exponential_backoff,
        task::AuthenticationToken,
        test_util::{install_test_trace_subscriber, run_vdaf, VdafTranscript},
    };
    use janus_messages::{
        problem_type::DapProblemType,
        query_type::{FixedSize, TimeInterval},
        BatchId, CollectReq, CollectResp, Duration, HpkeCiphertext, Interval, PartialBatchSelector,
        Query, Role, Time,
    };
    use mockito::mock;
    use prio::{
        codec::Encode,
        field::Field64,
        vdaf::{self, prio3::Prio3, AggregateShare},
    };
    use rand::random;
    use reqwest::{
        header::{CONTENT_TYPE, LOCATION},
        StatusCode, Url,
    };
    use retry_after::RetryAfter;

    fn setup_collector<V: vdaf::Collector>(vdaf_collector: V) -> Collector<V>
    where
        for<'a> Vec<u8>: From<&'a V::AggregateShare>,
    {
        let server_url = Url::parse(&mockito::server_url()).unwrap();
        let (hpke_config, hpke_private_key) = generate_test_hpke_config_and_private_key();
        let parameters = CollectorParameters::new(
            random(),
            server_url,
            AuthenticationToken::from(b"token".to_vec()),
            hpke_config,
            hpke_private_key,
        )
        .with_http_request_backoff(test_http_request_exponential_backoff())
        .with_collect_poll_backoff(test_http_request_exponential_backoff());
        Collector::new(parameters, vdaf_collector, default_http_client().unwrap())
    }

    fn random_verify_key() -> [u8; 16] {
        random()
    }

    fn build_collect_response_time<const L: usize, V: vdaf::Aggregator<L>>(
        transcript: &VdafTranscript<L, V>,
        parameters: &CollectorParameters,
        batch_interval: Interval,
    ) -> CollectResp<TimeInterval>
    where
        for<'a> Vec<u8>: From<&'a V::AggregateShare>,
    {
        let associated_data = associated_data_for_aggregate_share::<TimeInterval>(
            &parameters.task_id,
            &batch_interval,
        );
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
                    &<Vec<u8>>::from(&transcript.aggregate_shares[0]),
                    &associated_data,
                )
                .unwrap(),
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &<Vec<u8>>::from(&transcript.aggregate_shares[1]),
                    &associated_data,
                )
                .unwrap(),
            ]),
        )
    }

    fn build_collect_response_fixed<const L: usize, V: vdaf::Aggregator<L>>(
        transcript: &VdafTranscript<L, V>,
        parameters: &CollectorParameters,
        batch_id: BatchId,
    ) -> CollectResp<FixedSize>
    where
        for<'a> Vec<u8>: From<&'a V::AggregateShare>,
    {
        let associated_data =
            associated_data_for_aggregate_share::<FixedSize>(&parameters.task_id, &batch_id);
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
                    &<Vec<u8>>::from(&transcript.aggregate_shares[0]),
                    &associated_data,
                )
                .unwrap(),
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &<Vec<u8>>::from(&transcript.aggregate_shares[1]),
                    &associated_data,
                )
                .unwrap(),
            ]),
        )
    }

    #[test]
    fn leader_endpoint_end_in_slash() {
        let (hpke_config, hpke_private_key) = generate_test_hpke_config_and_private_key();
        let collector_parameters = CollectorParameters::new(
            random(),
            "http://example.com/dap".parse().unwrap(),
            AuthenticationToken::from(b"token".to_vec()),
            hpke_config.clone(),
            hpke_private_key.clone(),
        );

        assert_eq!(
            collector_parameters.leader_endpoint.as_str(),
            "http://example.com/dap/",
        );

        let collector_parameters = CollectorParameters::new(
            random(),
            "http://example.com".parse().unwrap(),
            AuthenticationToken::from(b"token".to_vec()),
            hpke_config,
            hpke_private_key,
        );

        assert_eq!(
            collector_parameters.leader_endpoint.as_str(),
            "http://example.com/",
        );
    }

    #[tokio::test]
    async fn successful_collect_prio3_count() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random_verify_key(), &(), &random(), &1);
        let collector = setup_collector(vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector.parameters, batch_interval);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mocked_collect_start_error = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .expect(3)
            .create();
        let mocked_collect_start_success = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let mocked_collect_error = mock("GET", "/collect_job/1")
            .with_status(500)
            .expect(3)
            .create();
        let mocked_collect_accepted = mock("GET", "/collect_job/1")
            .with_status(202)
            .expect(2)
            .create();
        let mocked_collect_complete = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create();

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.collect_job_url.as_str(), collect_job_url);
        assert_eq!(job.query.batch_identifier(), &batch_interval);

        let poll_result = collector.poll_once(&job).await.unwrap();
        assert_matches!(poll_result, PollResult::NextAttempt(None));

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(collection, Collection::new(1, 1));

        mocked_collect_start_error.assert();
        mocked_collect_start_success.assert();
        mocked_collect_error.assert();
        mocked_collect_accepted.assert();
        mocked_collect_complete.assert();
    }

    #[tokio::test]
    async fn successful_collect_prio3_sum() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_sum(2, 8).unwrap();
        let transcript = run_vdaf(&vdaf, &random_verify_key(), &(), &random(), &144);
        let collector = setup_collector(vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector.parameters, batch_interval);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mocked_collect_start_success = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let mocked_collect_complete = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create();

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.collect_job_url.as_str(), collect_job_url);
        assert_eq!(job.query.batch_identifier(), &batch_interval);

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(collection, Collection::new(1, 144));

        mocked_collect_start_success.assert();
        mocked_collect_complete.assert();
    }

    #[tokio::test]
    async fn successful_collect_prio3_histogram() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_histogram(2, &[25, 50, 75, 100]).unwrap();
        let transcript = run_vdaf(&vdaf, &random_verify_key(), &(), &random(), &80);
        let collector = setup_collector(vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response_time(&transcript, &collector.parameters, batch_interval);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mocked_collect_start_success = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let mocked_collect_complete = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create();

        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        assert_eq!(job.collect_job_url.as_str(), collect_job_url);
        assert_eq!(job.query.batch_identifier(), &batch_interval);

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(collection, Collection::new(1, Vec::from([0, 0, 0, 1, 0])));

        mocked_collect_start_success.assert();
        mocked_collect_complete.assert();
    }

    #[tokio::test]
    async fn successful_collect_fixed_size() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let transcript = run_vdaf(&vdaf, &random_verify_key(), &(), &random(), &1);
        let collector = setup_collector(vdaf);

        let batch_id = random();
        let collect_resp =
            build_collect_response_fixed(&transcript, &collector.parameters, batch_id);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mocked_collect_start_success = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::<FixedSize>::MEDIA_TYPE)
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let mocked_collect_complete = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::<FixedSize>::MEDIA_TYPE)
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create();

        let job = collector
            .start_collection(Query::new_fixed_size(batch_id), &())
            .await
            .unwrap();
        assert_eq!(job.collect_job_url.as_str(), collect_job_url);
        assert_eq!(job.query.batch_identifier(), &batch_id);

        let collection = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(collection, Collection::new(1, 1));

        mocked_collect_start_success.assert();
        mocked_collect_complete.assert();
    }

    #[tokio::test]
    async fn failed_collect_start() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(vdaf);

        let mock_server_error = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .expect_at_least(1)
            .create();

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

        mock_server_error.assert();

        let mock_server_error_details = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"http://example.com/test_server_error\"}")
            .expect_at_least(1)
            .create();

        let error = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(problem_details.type_url.unwrap(), "http://example.com/test_server_error");
            assert_eq!(dap_problem_type, None);
        });

        mock_server_error_details.assert();

        let mock_server_no_location = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .expect_at_least(1)
            .create();

        let error = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap_err();
        assert_matches!(error, Error::MissingLocationHeader);

        mock_server_no_location.assert();

        let mock_bad_request = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(400)
            .with_header("Content-Type", "application/problem+json")
            .with_body(
                concat!(
                    "{\"type\": \"urn:ietf:params:ppm:dap:error:unrecognizedMessage\", ",
                    "\"detail\": \"The message type for a response was incorrect or the payload was malformed.\"}"
                )
            )
            .expect_at_least(1)
            .create();

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

        mock_bad_request.assert();
    }

    #[tokio::test]
    async fn failed_collect_poll() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(vdaf);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mock_collect_start = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let mock_collect_job_server_error = mock("GET", "/collect_job/1")
            .with_status(500)
            .expect_at_least(1)
            .create();

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
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(dap_problem_type, None);
        });

        mock_collect_start.assert();
        mock_collect_job_server_error.assert();

        let mock_collect_job_server_error_details = mock("GET", "/collect_job/1")
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"http://example.com/test_server_error\"}")
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(problem_details.type_url.unwrap(), "http://example.com/test_server_error");
            assert_eq!(dap_problem_type, None);
        });

        mock_collect_job_server_error_details.assert();

        let mock_collect_job_bad_request = mock("GET", "/collect_job/1")
            .with_status(400)
            .with_header("Content-Type", "application/problem+json")
            .with_body(concat!(
                "{\"type\": \"urn:ietf:params:ppm:dap:error:unrecognizedMessage\", ",
                "\"detail\": \"The message type for a response was incorrect or the payload was malformed.\"}"
            ))
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::BAD_REQUEST);
            assert_eq!(problem_details.type_url.unwrap(), "urn:ietf:params:ppm:dap:error:unrecognizedMessage");
            assert_eq!(problem_details.detail.unwrap(), "The message type for a response was incorrect or the payload was malformed.");
            assert_eq!(dap_problem_type, Some(DapProblemType::UnrecognizedMessage));
        });

        mock_collect_job_bad_request.assert();

        let mock_collect_job_bad_message_bytes = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(b"")
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Codec(_));

        mock_collect_job_bad_message_bytes.assert();

        let mock_collect_job_bad_share_count = mock("GET", "/collect_job/1")
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
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareCount(0));

        mock_collect_job_bad_share_count.assert();

        let mock_collect_job_bad_ciphertext = mock("GET", "/collect_job/1")
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
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Hpke(_));

        mock_collect_job_bad_ciphertext.assert();

        let associated_data = associated_data_for_aggregate_share::<TimeInterval>(
            &collector.parameters.task_id,
            &batch_interval,
        );
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
                    &associated_data,
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
                    &associated_data,
                )
                .unwrap(),
            ]),
        );
        let mock_collect_job_bad_shares = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareDecode);

        mock_collect_job_bad_shares.assert();

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
                    &<Vec<u8>>::from(&AggregateShare::from(Vec::from([Field64::from(0)]))),
                    &associated_data,
                )
                .unwrap(),
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Helper,
                        &Role::Collector,
                    ),
                    &<Vec<u8>>::from(&AggregateShare::from(Vec::from([
                        Field64::from(0),
                        Field64::from(0),
                    ]))),
                    &associated_data,
                )
                .unwrap(),
            ]),
        );
        let mock_collect_job_unshard_failure = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(
                CONTENT_TYPE.as_str(),
                CollectResp::<TimeInterval>::MEDIA_TYPE,
            )
            .with_body(collect_resp.get_encoded())
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Vdaf(_));

        mock_collect_job_unshard_failure.assert();

        let mock_collect_job_always_fail = mock("GET", "/collect_job/1")
            .with_status(500)
            .expect_at_least(3)
            .create();
        let error = collector.poll_until_complete(&job).await.unwrap_err();
        assert_matches!(error, Error::Http { problem_details, dap_problem_type } => {
            assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(dap_problem_type, None);
        });
        mock_collect_job_always_fail.assert();
    }

    #[tokio::test]
    async fn collect_poll_retry_after() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(vdaf);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mock_collect_start = mock("POST", "/collect")
            .match_header(
                CONTENT_TYPE.as_str(),
                CollectReq::<TimeInterval>::MEDIA_TYPE,
            )
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let job = collector
            .start_collection(Query::new_time_interval(batch_interval), &())
            .await
            .unwrap();
        mock_collect_start.assert();

        let mock_collect_poll_no_retry_after = mock("GET", "/collect_job/1")
            .with_status(202)
            .expect(1)
            .create();
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NextAttempt(None)
        );
        mock_collect_poll_no_retry_after.assert();

        let mock_collect_poll_retry_after_60s = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", "60")
            .expect(1)
            .create();
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NextAttempt(Some(RetryAfter::Delay(duration))) => assert_eq!(duration, std::time::Duration::from_secs(60))
        );
        mock_collect_poll_retry_after_60s.assert();

        let mock_collect_poll_retry_after_date_time = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")
            .expect(1)
            .create();
        let ref_date_time = Utc.with_ymd_and_hms(2015, 10, 21, 7, 28, 0).unwrap();
        assert_matches!(
            collector.poll_once(&job).await.unwrap(),
            PollResult::NextAttempt(Some(RetryAfter::DateTime(system_time))) => assert_eq!(system_time, ref_date_time.into())
        );
        mock_collect_poll_retry_after_date_time.assert();
    }

    #[tokio::test]
    async fn poll_timing() {
        // This test exercises handling of the different Retry-After header forms. It does not test
        // the amount of time that poll_until_complete() sleeps. `tokio::time::pause()` cannot be
        // used for this because hyper uses `tokio::time::Interval` internally, see issue #234.
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let mut collector = setup_collector(vdaf);
        collector
            .parameters
            .collect_poll_wait_parameters
            .max_elapsed_time = Some(std::time::Duration::from_secs(3));

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let job = CollectJob::new(
            collect_job_url.parse().unwrap(),
            Query::new_time_interval(batch_interval),
            (),
        );

        let mock_collect_poll_retry_after_1s = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", "1")
            .expect(1)
            .create();
        let mock_collect_poll_retry_after_10s = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", "10")
            .expect(1)
            .create();
        assert_matches!(
            collector.poll_until_complete(&job).await.unwrap_err(),
            Error::CollectPollTimeout
        );
        mock_collect_poll_retry_after_1s.assert();
        mock_collect_poll_retry_after_10s.assert();

        let near_future =
            Utc::now() + chrono::Duration::from_std(std::time::Duration::from_secs(1)).unwrap();
        let near_future_formatted = near_future.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mock_collect_poll_retry_after_near_future = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", &near_future_formatted)
            .expect(1)
            .create();
        let mock_collect_poll_retry_after_past = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", "Mon, 01 Jan 1900 00:00:00 GMT")
            .expect(1)
            .create();
        let mock_collect_poll_retry_after_far_future = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", "Wed, 01 Jan 3000 00:00:00 GMT")
            .expect(1)
            .create();
        assert_matches!(
            collector.poll_until_complete(&job).await.unwrap_err(),
            Error::CollectPollTimeout
        );
        mock_collect_poll_retry_after_near_future.assert();
        mock_collect_poll_retry_after_past.assert();
        mock_collect_poll_retry_after_far_future.assert();

        // Manipulate backoff settings so that we make one or two requests and time out.
        collector
            .parameters
            .collect_poll_wait_parameters
            .max_elapsed_time = Some(std::time::Duration::from_millis(15));
        collector
            .parameters
            .collect_poll_wait_parameters
            .initial_interval = std::time::Duration::from_millis(10);
        let mock_collect_poll_no_retry_after = mock("GET", "/collect_job/1")
            .with_status(202)
            .expect_at_least(1)
            .create();
        assert_matches!(
            collector.poll_until_complete(&job).await.unwrap_err(),
            Error::CollectPollTimeout
        );
        mock_collect_poll_no_retry_after.assert();
    }
}
