//! Fetch HTTP resources, honoring the `Cache-Control` header ([1]) provided by the server.
//!
//! [1]: https://datatracker.ietf.org/doc/html/rfc9111#section-5.2

use std::time::Duration;

use backon::BackoffBuilder;
use http::{
    HeaderValue,
    header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
};
use janus_messages::MediaType;
use prio::codec::Decode;
use tokio::time::Instant;
use url::Url;

use crate::{
    http::HttpErrorResponse,
    retries::{ExponentialWithTotalDelayBuilder, retry_http_request},
};

/// Errors that may arise while managing cached HTTP resources.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("decode error: {0}")]
    Decode(Box<dyn std::error::Error + 'static + Send + Sync>),
    #[error("HTTP response status {0}")]
    Http(Box<HttpErrorResponse>),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("unexpected server response {0}")]
    UnexpectedServerResponse(&'static str),
}

impl From<Result<HttpErrorResponse, reqwest::Error>> for Error {
    fn from(result: Result<HttpErrorResponse, reqwest::Error>) -> Self {
        match result {
            Ok(http_error_response) => Error::Http(Box::new(http_error_response)),
            Err(error) => error.into(),
        }
    }
}

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8])
    -> Result<Self, Box<dyn std::error::Error + 'static + Send + Sync>>;
}

impl<D: Decode> FromBytes for D {
    fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + 'static + Send + Sync>> {
        D::get_decoded(bytes).map_err(Into::into)
    }
}

/// A cached HTTP resource.
// TODO(#3159): persist the cache to storage.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CachedResource<Resource> {
    Static(Resource),
    Refreshable(Refresher<Resource>),
}

impl<Resource: FromBytes + MediaType> CachedResource<Resource> {
    /// Fetch and cache the resource at the provided URL.
    pub async fn new(
        resource_url: Url,
        http_client: reqwest::Client,
        http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
    ) -> Result<Self, Error> {
        let (resource, expires_at) =
            Refresher::refresh(&http_client, http_request_retry_parameters, &resource_url).await?;

        Ok(Self::Refreshable(Refresher {
            resource,
            expires_at,
            resource_url,
            http_client,
            http_request_retry_parameters,
        }))
    }

    /// Returns the cached resource. Refetches if it has expired.
    pub async fn resource(&mut self) -> Result<&Resource, Error> {
        match self {
            Self::Refreshable(refresher) => refresher.resource().await,
            Self::Static(resource) => Ok(resource),
        }
    }
}

/// Caches an HTTP resource based on the cache-control header provided by the server.
#[derive(Debug, Clone)]
pub struct Refresher<Resource> {
    resource: Resource,
    expires_at: Option<Instant>,
    resource_url: Url,
    http_client: reqwest::Client,
    http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
}

impl<Resource: FromBytes + MediaType> Refresher<Resource> {
    async fn resource(&mut self) -> Result<&Resource, Error> {
        // Refresh if we are past expiration.
        if self
            .expires_at
            .map(|expires_at| Instant::now() > expires_at)
            // If no expiration is provided, use cached resource forever.
            .unwrap_or(false)
        {
            (self.resource, self.expires_at) = Self::refresh(
                &self.http_client,
                self.http_request_retry_parameters,
                &self.resource_url,
            )
            .await?;
        }
        Ok(&self.resource)
    }

    async fn refresh(
        http_client: &reqwest::Client,
        http_request_retry_parameters: ExponentialWithTotalDelayBuilder,
        resource_url: &Url,
    ) -> Result<(Resource, Option<Instant>), Error> {
        let response = retry_http_request(http_request_retry_parameters.build(), || async {
            http_client
                .get(resource_url.clone())
                .header(ACCEPT, Resource::MEDIA_TYPE)
                .send()
                .await
        })
        .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Http(Box::new(HttpErrorResponse::from(status))));
        }

        let content_type =
            response
                .headers()
                .get(CONTENT_TYPE)
                .ok_or(Error::UnexpectedServerResponse(
                    "no content type in server response",
                ))?;
        if content_type != Resource::MEDIA_TYPE {
            return Err(Error::UnexpectedServerResponse(
                "unexpected content type in server response",
            ));
        }

        let expires_at = expires_at(response.headers().get_all(CACHE_CONTROL));

        Ok((
            Resource::from_bytes(response.body()).map_err(Error::Decode)?,
            expires_at,
        ))
    }
}

/// Parse the provided cache-control header values ([1]) and determine when the resource they were
/// attached to expires, or None if no maximum age is set. This function only handles the "max-age"
/// and "no-cache" response directives ([2]). If any unrecognized or malformed response directive is
/// encountered, then the resource will not be cached.
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc9111#section-5.2
/// [2]: https://datatracker.ietf.org/doc/html/rfc9111#section-5.2.2
pub(crate) fn expires_at<'a, I: IntoIterator<Item = &'a HeaderValue>>(
    cache_control_directives: I,
) -> Option<Instant> {
    let mut expires_at = None;

    for directive in cache_control_directives {
        let directive = match directive.to_str() {
            Ok(directive) => directive,
            Err(_) => return None,
        }
        .to_lowercase();

        // If we encounter no-cache, then regardless of other directives, never cache the resource
        // by indicating it expires now.
        if directive == "no-cache" {
            return Some(Instant::now());
        }

        if let Some(max_age) = directive.strip_prefix("max-age=") {
            let parsed = match max_age.parse() {
                Ok(parsed) => parsed,
                Err(_) => return None,
            };

            if expires_at.is_some() {
                return None;
            }

            expires_at = Instant::now().checked_add(Duration::from_secs(parsed));
        } else {
            return None;
        }
    }

    expires_at
}
