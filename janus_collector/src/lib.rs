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
//!     Time,
//! };
//! use prio::vdaf::prio3::Prio3;
//! use url::Url;
//!
//! # async fn run() {
//! // Supply DAP task paramenters.
//! let task_id = TaskId::random();
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
//! let collector = Collector::new(parameters, vdaf, &http_client);
//!
//! // Specify the time interval over which the aggregation should be calculated.
//! let interval = Interval::new(
//!     Time::from_seconds_since_epoch(1_656_000_000),
//!     Duration::from_seconds(3600),
//! )
//! .unwrap();
//! // Make the requests and retrieve the aggregated statistic.
//! let aggregation_result = collector.collect(interval, &()).await.unwrap();
//! # }
//! ```

use backoff::{backoff::Backoff, ExponentialBackoff};
use derivative::Derivative;
use janus_core::{
    hpke::{self, associated_data_for_aggregate_share, HpkeApplicationInfo, HpkePrivateKey},
    retries::{http_request_exponential_backoff, retry_http_request},
    task::{url_ensure_trailing_slash, AuthenticationToken, DAP_AUTH_HEADER},
};
use janus_messages::{CollectReq, CollectResp, HpkeConfig, Interval, Role, TaskId};
use prio::{
    codec::{Decode, Encode},
    vdaf,
};
use reqwest::{
    header::{HeaderValue, ToStrError, CONTENT_TYPE, LOCATION, RETRY_AFTER},
    StatusCode,
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
    #[error("HTTP response status {0}")]
    Http(StatusCode),
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
struct CollectJob<P> {
    /// The URL provided by the leader aggregator, where the collect response will be available
    /// upon completion.
    collect_job_url: Url,
    /// The collect request's batch time interval.
    batch_interval: Interval,
    /// The aggregation parameter used in this collect request.
    #[derivative(Debug = "ignore")]
    aggregation_parameter: P,
}

impl<P> CollectJob<P> {
    fn new(
        collect_job_url: Url,
        batch_interval: Interval,
        aggregation_parameter: P,
    ) -> CollectJob<P> {
        CollectJob {
            collect_job_url,
            batch_interval,
            aggregation_parameter,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
/// The result of a collect request poll operation. This will either provide the aggregate result
/// or indicate that the collection is still being processed.
enum PollResult<T> {
    /// The aggregate result from a completed collect request.
    AggregateResult(#[derivative(Debug = "ignore")] T),
    /// The collect request is not yet ready. If present, the [`RetryAfter`] object is the time at
    /// which the leader recommends retrying the request.
    NextAttempt(Option<RetryAfter>),
}

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
        http_client: &reqwest::Client,
    ) -> Collector<V> {
        Collector {
            parameters,
            vdaf_collector,
            http_client: http_client.clone(),
        }
    }

    /// Send a collect request to the leader aggregator.
    #[tracing::instrument(err)]
    async fn start_collection(
        &self,
        batch_interval: Interval,
        aggregation_parameter: &V::AggregationParam,
    ) -> Result<CollectJob<V::AggregationParam>, Error> {
        let collect_request = CollectReq {
            task_id: self.parameters.task_id,
            batch_interval,
            agg_param: aggregation_parameter.get_encoded(),
        };
        let url = self.parameters.collect_endpoint()?;

        let response = retry_http_request(
            self.parameters.http_request_retry_parameters.clone(),
            || async {
                let mut request = self
                    .http_client
                    .post(url.clone())
                    .header(CONTENT_TYPE, CollectReq::MEDIA_TYPE)
                    .body(collect_request.get_encoded());
                match &self.parameters.authentication {
                    Authentication::DapAuthToken(token) => {
                        request = request.header(DAP_AUTH_HEADER, token.as_bytes())
                    }
                }
                request.send().await
            },
        )
        .await
        .map_err(|res| match res {
            Ok(response) => Error::Http(response.status()),
            Err(error) => Error::HttpClient(error),
        })?;

        let status = response.status();
        if status != StatusCode::SEE_OTHER {
            return Err(Error::Http(status));
        }
        let location_header_value = response
            .headers()
            .get(LOCATION)
            .ok_or(Error::MissingLocationHeader)?
            .to_str()?;
        let collect_job_url = location_header_value.parse()?;

        Ok(CollectJob::new(
            collect_job_url,
            batch_interval,
            aggregation_parameter.clone(),
        ))
    }

    /// Request the results of an in-progress collection from the leader aggregator. This may
    /// return `Ok(None)` if the aggregation is not done yet.
    #[tracing::instrument(err)]
    async fn poll_once(
        &self,
        job: &CollectJob<V::AggregationParam>,
    ) -> Result<PollResult<V::AggregateResult>, Error> {
        let response = retry_http_request(
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
        .await
        .map_err(|res| match res {
            Ok(response) => Error::Http(response.status()),
            Err(error) => Error::HttpClient(error),
        })?;

        let status = response.status();
        match status {
            StatusCode::ACCEPTED => {
                let retry_after_opt = response
                    .headers()
                    .get(RETRY_AFTER)
                    .map(RetryAfter::try_from)
                    .transpose()?;
                return Ok(PollResult::NextAttempt(retry_after_opt));
            }
            StatusCode::OK => {}
            _ => return Err(Error::Http(status)),
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .ok_or(Error::BadContentType(None))?;
        if content_type != CollectResp::MEDIA_TYPE {
            return Err(Error::BadContentType(Some(content_type.clone())));
        }

        let collect_response = CollectResp::get_decoded(&response.bytes().await?)?;
        if collect_response.encrypted_agg_shares.len() != 2 {
            return Err(Error::AggregateShareCount(
                collect_response.encrypted_agg_shares.len(),
            ));
        }

        let associated_data =
            associated_data_for_aggregate_share(self.parameters.task_id, job.batch_interval);
        let aggregate_shares_bytes = collect_response
            .encrypted_agg_shares
            .iter()
            .zip([Role::Leader, Role::Helper])
            .map(|(encrypted_aggregate_share, role)| {
                hpke::open(
                    &self.parameters.hpke_config,
                    &self.parameters.hpke_private_key,
                    &HpkeApplicationInfo::new(hpke::Label::AggregateShare, role, Role::Collector),
                    encrypted_aggregate_share,
                    &associated_data,
                )
            });
        let aggregate_shares = aggregate_shares_bytes
            .map(|bytes| {
                V::AggregateShare::try_from(&bytes?).map_err(|_err| Error::AggregateShareDecode)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let aggregate_result = self
            .vdaf_collector
            .unshard(&job.aggregation_parameter, aggregate_shares)?;

        Ok(PollResult::AggregateResult(aggregate_result))
    }

    /// A convenience method to repeatedly request the result of an in-progress collection until it
    /// completes.
    async fn poll_until_complete(
        &self,
        job: &CollectJob<V::AggregationParam>,
    ) -> Result<V::AggregateResult, Error> {
        let mut backoff = self.parameters.collect_poll_wait_parameters.clone();
        backoff.reset();
        let deadline = backoff
            .max_elapsed_time
            .map(|duration| Instant::now() + duration);
        loop {
            // poll_once() already retries upon server and connection errors, so propagate any error
            // received from it and return immediately.
            let retry_after = match self.poll_once(job).await? {
                PollResult::AggregateResult(aggregate_result) => return Ok(aggregate_result),
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
    pub async fn collect(
        &self,
        batch_interval: Interval,
        aggregation_parameter: &V::AggregationParam,
    ) -> Result<V::AggregateResult, Error> {
        let job = self
            .start_collection(batch_interval, aggregation_parameter)
            .await?;
        self.poll_until_complete(&job).await
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use crate::{Collector, Error};
    use janus_messages::Interval;
    use prio::vdaf;

    pub async fn collect_with_rewritten_url<V: vdaf::Collector>(
        collector: &Collector<V>,
        batch_interval: Interval,
        aggregation_parameter: &V::AggregationParam,
        host: &str,
        port: u16,
    ) -> Result<V::AggregateResult, Error>
    where
        for<'a> Vec<u8>: From<&'a <V as vdaf::Vdaf>::AggregateShare>,
    {
        let mut job = collector
            .start_collection(batch_interval, aggregation_parameter)
            .await?;
        job.collect_job_url.set_host(Some(host))?;
        job.collect_job_url.set_port(Some(port)).unwrap();
        collector.poll_until_complete(&job).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use chrono::{TimeZone, Utc};
    use janus_core::{
        hpke::{test_util::generate_test_hpke_config_and_private_key, Label},
        nonce::NonceExt,
        retries::test_http_request_exponential_backoff,
        test_util::{install_test_trace_subscriber, run_vdaf, VdafTranscript},
        time::RealClock,
    };
    use janus_messages::{Duration, HpkeCiphertext, Nonce, Time};
    use mockito::mock;
    use prio::{
        field::Field64,
        vdaf::{prio3::Prio3, AggregateShare},
    };
    use rand::{thread_rng, Rng};

    fn setup_collector<V: vdaf::Collector>(vdaf_collector: V) -> Collector<V>
    where
        for<'a> Vec<u8>: From<&'a V::AggregateShare>,
    {
        let server_url = Url::parse(&mockito::server_url()).unwrap();
        let (hpke_config, hpke_private_key) = generate_test_hpke_config_and_private_key();
        let parameters = CollectorParameters::new(
            TaskId::random(),
            server_url,
            AuthenticationToken::from(b"token".to_vec()),
            hpke_config,
            hpke_private_key,
        )
        .with_http_request_backoff(test_http_request_exponential_backoff())
        .with_collect_poll_backoff(test_http_request_exponential_backoff());
        Collector::new(parameters, vdaf_collector, &default_http_client().unwrap())
    }

    fn random_verify_key() -> [u8; 16] {
        let mut verify_key = [0u8; 16];
        thread_rng().fill(&mut verify_key[..]);
        verify_key
    }

    fn build_collect_response<const L: usize, V: vdaf::Aggregator<L>>(
        transcript: &VdafTranscript<L, V>,
        parameters: &CollectorParameters,
        batch_interval: Interval,
    ) -> CollectResp
    where
        for<'a> Vec<u8>: From<&'a V::AggregateShare>,
    {
        let associated_data =
            associated_data_for_aggregate_share(parameters.task_id, batch_interval);
        CollectResp {
            encrypted_agg_shares: vec![
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Leader, Role::Collector),
                    &<Vec<u8>>::from(&transcript.aggregate_shares[0]),
                    &associated_data,
                )
                .unwrap(),
                hpke::seal(
                    &parameters.hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
                    &<Vec<u8>>::from(&transcript.aggregate_shares[1]),
                    &associated_data,
                )
                .unwrap(),
            ],
        }
    }

    #[test]
    fn leader_endpoint_end_in_slash() {
        let (hpke_config, hpke_private_key) = generate_test_hpke_config_and_private_key();
        let collector_parameters = CollectorParameters::new(
            TaskId::random(),
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
            TaskId::random(),
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
        let transcript = run_vdaf(
            &vdaf,
            &random_verify_key(),
            &(),
            Nonce::generate(&RealClock::default(), Duration::from_seconds(3600)).unwrap(),
            &1,
        );
        let collector = setup_collector(vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response(&transcript, &collector.parameters, batch_interval);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mocked_collect_start_error = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
            .with_status(500)
            .expect(3)
            .create();
        let mocked_collect_start_success = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
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
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create();

        let job = collector
            .start_collection(batch_interval, &())
            .await
            .unwrap();
        assert_eq!(job.collect_job_url.as_str(), collect_job_url);
        assert_eq!(job.batch_interval, batch_interval);

        let poll_result = collector.poll_once(&job).await.unwrap();
        assert_matches!(poll_result, PollResult::NextAttempt(None));

        let agg_result = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(agg_result, 1);

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
        let transcript = run_vdaf(
            &vdaf,
            &random_verify_key(),
            &(),
            Nonce::generate(&RealClock::default(), Duration::from_seconds(3600)).unwrap(),
            &144,
        );
        let collector = setup_collector(vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response(&transcript, &collector.parameters, batch_interval);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mocked_collect_start_success = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let mocked_collect_complete = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create();

        let job = collector
            .start_collection(batch_interval, &())
            .await
            .unwrap();
        assert_eq!(job.collect_job_url.as_str(), collect_job_url);
        assert_eq!(job.batch_interval, batch_interval);

        let agg_result = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(agg_result, 144);

        mocked_collect_start_success.assert();
        mocked_collect_complete.assert();
    }

    #[tokio::test]
    async fn successful_collect_prio3_histogram() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_histogram(2, &[25, 50, 75, 100]).unwrap();
        let transcript = run_vdaf(
            &vdaf,
            &random_verify_key(),
            &(),
            Nonce::generate(&RealClock::default(), Duration::from_seconds(3600)).unwrap(),
            &80,
        );
        let collector = setup_collector(vdaf);

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let collect_resp =
            build_collect_response(&transcript, &collector.parameters, batch_interval);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mocked_collect_start_success = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
            .with_status(303)
            .with_header(LOCATION.as_str(), &collect_job_url)
            .expect(1)
            .create();
        let mocked_collect_complete = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
            .with_body(collect_resp.get_encoded())
            .expect(1)
            .create();

        let job = collector
            .start_collection(batch_interval, &())
            .await
            .unwrap();
        assert_eq!(job.collect_job_url.as_str(), collect_job_url);
        assert_eq!(job.batch_interval, batch_interval);

        let agg_result = collector.poll_until_complete(&job).await.unwrap();
        assert_eq!(agg_result, vec![0, 0, 0, 1, 0]);

        mocked_collect_start_success.assert();
        mocked_collect_complete.assert();
    }

    #[tokio::test]
    async fn failed_collect_start() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(vdaf);

        let mock_server_error = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
            .with_status(500)
            .expect_at_least(1)
            .create();

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let error = collector
            .start_collection(batch_interval, &())
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(StatusCode::INTERNAL_SERVER_ERROR));

        mock_server_error.assert();

        let mock_server_no_location = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
            .with_status(303)
            .expect_at_least(1)
            .create();

        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let error = collector
            .start_collection(batch_interval, &())
            .await
            .unwrap_err();
        assert_matches!(error, Error::MissingLocationHeader);

        mock_server_no_location.assert();
    }

    #[tokio::test]
    async fn failed_collect_poll() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(vdaf);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mock_collect_start = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
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
            .start_collection(batch_interval, &())
            .await
            .unwrap();
        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Http(StatusCode::INTERNAL_SERVER_ERROR));

        mock_collect_start.assert();
        mock_collect_job_server_error.assert();

        let mock_collect_job_bad_message_bytes = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
            .with_body(b"")
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Codec(_));

        mock_collect_job_bad_message_bytes.assert();

        let mock_collect_job_bad_share_count = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
            .with_body(
                CollectResp {
                    encrypted_agg_shares: vec![],
                }
                .get_encoded(),
            )
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareCount(0));

        mock_collect_job_bad_share_count.assert();

        let mock_collect_job_bad_ciphertext = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
            .with_body(
                CollectResp {
                    encrypted_agg_shares: vec![
                        HpkeCiphertext::new(collector.parameters.hpke_config.id(), vec![], vec![]),
                        HpkeCiphertext::new(collector.parameters.hpke_config.id(), vec![], vec![]),
                    ],
                }
                .get_encoded(),
            )
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::Hpke(_));

        mock_collect_job_bad_ciphertext.assert();

        let associated_data =
            associated_data_for_aggregate_share(collector.parameters.task_id, batch_interval);
        let collect_resp = CollectResp {
            encrypted_agg_shares: vec![
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Leader, Role::Collector),
                    b"bad",
                    &associated_data,
                )
                .unwrap(),
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
                    b"bad",
                    &associated_data,
                )
                .unwrap(),
            ],
        };
        let mock_collect_job_bad_shares = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
            .with_body(collect_resp.get_encoded())
            .expect_at_least(1)
            .create();

        let error = collector.poll_once(&job).await.unwrap_err();
        assert_matches!(error, Error::AggregateShareDecode);

        mock_collect_job_bad_shares.assert();

        let collect_resp = CollectResp {
            encrypted_agg_shares: vec![
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Leader, Role::Collector),
                    &<Vec<u8>>::from(&AggregateShare::from(vec![Field64::from(0)])),
                    &associated_data,
                )
                .unwrap(),
                hpke::seal(
                    &collector.parameters.hpke_config,
                    &HpkeApplicationInfo::new(Label::AggregateShare, Role::Helper, Role::Collector),
                    &<Vec<u8>>::from(&AggregateShare::from(vec![
                        Field64::from(0),
                        Field64::from(0),
                    ])),
                    &associated_data,
                )
                .unwrap(),
            ],
        };
        let mock_collect_job_unshard_failure = mock("GET", "/collect_job/1")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), CollectResp::MEDIA_TYPE)
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
        assert_matches!(error, Error::Http(StatusCode::INTERNAL_SERVER_ERROR));
        mock_collect_job_always_fail.assert();
    }

    #[tokio::test]
    async fn collect_poll_retry_after() {
        install_test_trace_subscriber();

        let vdaf = Prio3::new_aes128_count(2).unwrap();
        let collector = setup_collector(vdaf);

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let mock_collect_start = mock("POST", "/collect")
            .match_header(CONTENT_TYPE.as_str(), CollectReq::MEDIA_TYPE)
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
            .start_collection(batch_interval, &())
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
            PollResult::NextAttempt(Some(RetryAfter::Delay(duration))) => assert_eq!(duration, StdDuration::from_secs(60))
        );
        mock_collect_poll_retry_after_60s.assert();

        let mock_collect_poll_retry_after_date_time = mock("GET", "/collect_job/1")
            .with_status(202)
            .with_header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")
            .expect(1)
            .create();
        let ref_date_time = Utc.ymd(2015, 10, 21).and_hms(7, 28, 0);
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
            .max_elapsed_time = Some(StdDuration::from_secs(3));

        let collect_job_url = format!("{}/collect_job/1", mockito::server_url());
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(1_000_000),
            Duration::from_seconds(3600),
        )
        .unwrap();
        let job = CollectJob::new(collect_job_url.parse().unwrap(), batch_interval, ());

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
            Utc::now() + chrono::Duration::from_std(StdDuration::from_secs(1)).unwrap();
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
            .max_elapsed_time = Some(StdDuration::from_millis(15));
        collector
            .parameters
            .collect_poll_wait_parameters
            .initial_interval = StdDuration::from_millis(10);
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
