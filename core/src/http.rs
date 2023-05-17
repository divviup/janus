use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use http_api_problem::{HttpApiProblem, PROBLEM_JSON_MEDIA_TYPE};
use reqwest::{header::CONTENT_TYPE, Response};
use tracing::warn;
use trillium::Conn;

/// Turn a [`reqwest::Response`] into a [`HttpApiProblem`]. If applicable, a JSON problem details
/// document is parsed from the request's body, otherwise it is solely constructed from the
/// response's status code. (see [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807.html))
pub async fn response_to_problem_details(response: Response) -> HttpApiProblem {
    let status = response.status();
    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type == PROBLEM_JSON_MEDIA_TYPE {
            match response.json::<HttpApiProblem>().await {
                Ok(mut problem) => {
                    problem.status = Some(status);
                    return problem;
                }
                Err(error) => warn!(%error, "Failed to parse problem details"),
            }
        }
    }
    HttpApiProblem::new(status)
}

/// If the request in `conn` has an `authorization` header, returns the bearer token in the header
/// value. Returns `None` if there is no `authorization` header, and an error if there is an
/// `authorization` header whose value is not a bearer token.
pub fn extract_bearer_token(conn: &Conn) -> Result<Option<Vec<u8>>, anyhow::Error> {
    if let Some(authorization_value) = conn.headers().get("authorization") {
        if let Some(received_token) = authorization_value.as_ref().strip_prefix(b"Bearer ") {
            let decoded = STANDARD
                .decode(received_token)
                .context("bearer token cannot be decoded from Base64")?;
            return Ok(Some(decoded));
        } else {
            return Err(anyhow!("authorization header value is not a bearer token"));
        }
    }

    Ok(None)
}
