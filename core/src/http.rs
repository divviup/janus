use crate::auth_tokens::AuthenticationToken;
use anyhow::anyhow;
use http::{StatusCode, header::RETRY_AFTER};
use http_api_problem::{HttpApiProblem, PROBLEM_JSON_MEDIA_TYPE};
use janus_messages::problem_type::DapProblemType;
use mime::Mime;
use reqwest::{Response, header::CONTENT_TYPE};
use retry_after::RetryAfter;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;
use tracing::warn;
use trillium::{Conn, HeaderValue};

pub mod cached_resource;
#[cfg(test)]
mod cached_resource_tests;

/// This captures an HTTP status code and parsed problem details document from an HTTP response.
#[derive(Debug)]
pub struct HttpErrorResponse {
    problem_details: HttpApiProblem,
    dap_problem_type: Option<DapProblemType>,
}

impl HttpErrorResponse {
    /// Turn a [`reqwest::Response`] into a [`HttpErrorResponse`]. If applicable, a JSON problem
    /// details document is parsed from the request's body, otherwise it is solely constructed from
    /// the response's status code. (see [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807.html))
    pub async fn from_response(response: Response) -> Self {
        let status = response.status();

        if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
            if let Ok(content_type_str) = content_type.to_str() {
                if let Ok(mime) = content_type_str.parse::<Mime>() {
                    if mime.essence_str() == PROBLEM_JSON_MEDIA_TYPE {
                        match response.json::<HttpApiProblem>().await {
                            Ok(mut problem) => {
                                problem.status = Some(status);
                                // Unwrap safety: the conversion always succeeds if the status is
                                // populated.
                                return problem.try_into().unwrap();
                            }
                            Err(error) => warn!(%error, "Failed to parse problem details"),
                        }
                    }
                }
            }
        }
        status.into()
    }

    /// The HTTP status code returned by the server.
    pub fn status(&self) -> StatusCode {
        // Unwrap safety: Self::from_response(), TryFrom<HttpApiProblem>, and From<StatusCode>
        // always populate this field.
        self.problem_details.status.unwrap()
    }

    /// A URI that identifies the problem type.
    pub fn type_uri(&self) -> Option<&str> {
        self.problem_details.type_url.as_deref()
    }

    /// A short summary of the problem type.
    pub fn title(&self) -> Option<&str> {
        self.problem_details.title.as_deref()
    }

    /// Specific details about this instance of a problem.
    pub fn detail(&self) -> Option<&str> {
        self.problem_details.detail.as_deref()
    }

    /// The DAP-specific problem type, if applicable.
    pub fn dap_problem_type(&self) -> Option<&DapProblemType> {
        self.dap_problem_type.as_ref()
    }
}

/// The error type returned when converting an [`HttpApiProblem`] without a status code into an
/// [`HttpErrorResponse`].
#[derive(Debug)]
pub struct MissingStatusCodeError;

impl TryFrom<HttpApiProblem> for HttpErrorResponse {
    type Error = MissingStatusCodeError;

    fn try_from(problem_details: HttpApiProblem) -> Result<Self, Self::Error> {
        if problem_details.status.is_none() {
            return Err(MissingStatusCodeError);
        }
        let dap_problem_type = problem_details
            .type_url
            .as_ref()
            .and_then(|str| str.parse::<DapProblemType>().ok());
        Ok(Self {
            problem_details,
            dap_problem_type,
        })
    }
}

impl From<StatusCode> for HttpErrorResponse {
    fn from(value: StatusCode) -> Self {
        Self {
            problem_details: HttpApiProblem::new(value),
            dap_problem_type: None,
        }
    }
}

impl Display for HttpErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.problem_details.fmt(f)
    }
}

/// Extracts a bearer authentication token from the connection.
///
/// If the request in `conn` has an `authorization` header, returns the bearer token in the header
/// value. Returns `None` if there is no `authorization` header, and an error if there is an
/// `authorization` header whose value is not a bearer token.
pub fn extract_bearer_token(conn: &Conn) -> Result<Option<AuthenticationToken>, anyhow::Error> {
    if let Some(authorization) = conn
        .request_headers()
        .get("authorization")
        .map(HeaderValue::to_string)
    {
        let (auth_scheme, token) = authorization
            .split_once(char::is_whitespace)
            .ok_or_else(|| anyhow!("invalid authorization header"))?;

        if auth_scheme.to_lowercase() != "bearer" {
            return Err(anyhow!("authorization scheme is not bearer"));
        }

        return Ok(Some(AuthenticationToken::new_bearer_token_from_string(
            token.trim_start(),
        )?));
    }

    Ok(None)
}

/// Return OK if there is a Content-Type header and it matches the expected value.
pub fn check_content_type(
    headers: &http::HeaderMap,
    expected: &'static str,
) -> Result<(), anyhow::Error> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(anyhow!("Content-Type header not found"))?;
    let mime: Mime = content_type
        .to_str()?
        .parse()
        .map_err(|e| anyhow!("failed to parse Content-Type header: {e}"))?;
    if mime.essence_str() != expected {
        return Err(anyhow!(
            "unexpected Content-Type header {} != {}",
            mime.essence_str(),
            expected
        ));
    };
    Ok(())
}

/// Parse the HTTP Headers for a RetryAfter duration, if any. This does not handle DateTime
/// Retry-After headers, but also does not require knowledge of the current clock.
pub fn parse_retry_after_to_duration(
    headers: &http::HeaderMap,
) -> Result<Option<Duration>, anyhow::Error> {
    match parse_retry_after(headers)? {
        Some(RetryAfter::Delay(duration)) => Ok(Some(duration)),
        Some(RetryAfter::DateTime(_)) => Ok(None), // Treat as if missing. See #3943
        None => Ok(None),
    }
}

/// Parse the HTTP Headers for a RetryAfter, if any
pub fn parse_retry_after(headers: &http::HeaderMap) -> Result<Option<RetryAfter>, anyhow::Error> {
    headers
        .get(RETRY_AFTER)
        .map(RetryAfter::try_from)
        .transpose()
        .map_err(|e| anyhow!("Unable to parse Retry-After: {e}"))
}

/// Extension trait on [`reqwest::RequestBuilder`] to fluently add request authentication.
pub trait ReqwestAuthenticationToken {
    fn authentication_token(self, auth_token: &AuthenticationToken) -> Self;
}

impl ReqwestAuthenticationToken for reqwest::RequestBuilder {
    fn authentication_token(self, auth_token: &AuthenticationToken) -> Self {
        let (header, value) = auth_token.request_authentication();
        self.header(header, value)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use trillium_testing::TestConn;

    use crate::auth_tokens::AuthenticationToken;

    use super::extract_bearer_token;

    #[test]
    fn authorization_header() {
        let good_token = "gVfRUu9krhxrUgFsEo-P5w";
        let expected = AuthenticationToken::new_bearer_token_from_string(good_token).unwrap();
        assert_eq!(
            extract_bearer_token(
                &TestConn::build("get", "/", "body")
                    .with_request_header("authorization", format!("bearer {good_token}")),
            )
            .unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            extract_bearer_token(
                &TestConn::build("get", "/", "body")
                    .with_request_header("authorization", format!("BeArEr     {good_token}")),
            )
            .unwrap(),
            Some(expected)
        );

        assert_matches!(
            extract_bearer_token(
                &TestConn::build("get", "/", "body").with_request_header(
                    "Authorization",
                    "Bearer    gVfRUu9krhxrUgFsEo-P5w    asdf"
                ),
            ),
            Err(_)
        );
        assert_matches!(
            extract_bearer_token(
                &TestConn::build("get", "/", "body")
                    .with_request_header("Authorization", "BearergVfRUu9krhxrUgFsEo-P5w"),
            ),
            Err(_)
        );
        assert_matches!(
            extract_bearer_token(
                &TestConn::build("get", "/", "body")
                    .with_request_header("Authorization", "Bearer gVfRUu9krhxrUgFsEo(#@(#)*#)-P5w"),
            ),
            Err(_)
        );

        assert_matches!(
            extract_bearer_token(&TestConn::build("get", "/", "body")),
            Ok(None)
        );
    }
}
