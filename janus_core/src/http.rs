use http_api_problem::{HttpApiProblem, PROBLEM_JSON_MEDIA_TYPE};
use reqwest::{header::CONTENT_TYPE, Response};
use tracing::warn;

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
