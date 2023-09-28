use crate::auth_tokens::AuthenticationToken;
use anyhow::{anyhow, Context};
use http::StatusCode;
use http_api_problem::{HttpApiProblem, PROBLEM_JSON_MEDIA_TYPE};
use janus_messages::problem_type::DapProblemType;
use reqwest::{header::CONTENT_TYPE, Response};
use std::fmt::{self, Display, Formatter};
use tracing::warn;
use trillium::Conn;

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
            if content_type == PROBLEM_JSON_MEDIA_TYPE {
                match response.json::<HttpApiProblem>().await {
                    Ok(mut problem) => {
                        problem.status = Some(status);
                        return problem.into();
                    }
                    Err(error) => warn!(%error, "Failed to parse problem details"),
                }
            }
        }
        status.into()
    }

    /// The HTTP status code returned by the server.
    pub fn status(&self) -> Option<&StatusCode> {
        self.problem_details.status.as_ref()
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

impl From<HttpApiProblem> for HttpErrorResponse {
    fn from(problem_details: HttpApiProblem) -> Self {
        let dap_problem_type = problem_details
            .type_url
            .as_ref()
            .and_then(|str| str.parse::<DapProblemType>().ok());
        Self {
            problem_details,
            dap_problem_type,
        }
    }
}

impl From<StatusCode> for HttpErrorResponse {
    fn from(value: StatusCode) -> Self {
        HttpApiProblem::new(value).into()
    }
}

impl Display for HttpErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.problem_details.fmt(f)
    }
}

/// If the request in `conn` has an `authorization` header, returns the bearer token in the header
/// value. Returns `None` if there is no `authorization` header, and an error if there is an
/// `authorization` header whose value is not a bearer token.
pub fn extract_bearer_token(conn: &Conn) -> Result<Option<AuthenticationToken>, anyhow::Error> {
    if let Some(authorization_value) = conn.headers().get("authorization") {
        if let Some(received_token) = authorization_value.to_string().strip_prefix("Bearer ") {
            return Ok(Some(
                AuthenticationToken::new_bearer_token_from_string(received_token)
                    .context("invalid bearer token")?,
            ));
        } else {
            return Err(anyhow!("authorization header value is not a bearer token"));
        }
    }

    Ok(None)
}
