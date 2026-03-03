use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{Json, Router, body::Body, extract::State, response::IntoResponse, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use http::{Request, StatusCode};
use janus_aggregator::{
    binary_utils::{BinaryOptions, CommonBinaryOptions, janus_main},
    config::{BinaryConfig, CommonConfig},
};
use janus_aggregator_core::{
    SecretBytes,
    datastore::Datastore,
    task::{self, AggregationMode, AggregatorTask, AggregatorTaskParameters},
};
use janus_core::{
    auth_tokens::{AuthenticationToken, AuthenticationTokenHash},
    time::RealClock,
};
use janus_messages::{Duration, HpkeConfig, Time, taskprov::TimePrecision};
use prio::codec::Decode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::{
    AddTaskResponse, AggregatorAddTaskRequest, AggregatorRole,
    status::{ERROR, SUCCESS},
};

#[derive(Clone)]
struct InteropAggregatorState {
    datastore: Arc<Datastore<RealClock>>,
    proxy_url: String,
    http_client: reqwest::Client,
    dap_serving_prefix: String,
    health_check_peers: Vec<Url>,
}

#[derive(Debug, Serialize)]
struct EndpointResponse {
    status: &'static str,
    endpoint: String,
}

async fn handle_add_task(
    datastore: &Datastore<RealClock>,
    request: AggregatorAddTaskRequest,
) -> anyhow::Result<()> {
    let peer_aggregator_endpoint = match request.role {
        AggregatorRole::Leader => request.helper,
        AggregatorRole::Helper => request.leader,
    };
    let vdaf = request.vdaf.into();
    let leader_authentication_token =
        AuthenticationToken::new_dap_auth_token_from_string(request.leader_authentication_token)
            .context("invalid header value in \"leader_authentication_token\"")?;
    let vdaf_verify_key = SecretBytes::new(
        URL_SAFE_NO_PAD
            .decode(request.vdaf_verify_key)
            .context("invalid base64url content in \"vdaf_verify_key\"")?,
    );
    let time_precision = TimePrecision::from_seconds(request.time_precision);
    let collector_hpke_config_bytes = URL_SAFE_NO_PAD
        .decode(request.collector_hpke_config)
        .context("invalid base64url content in \"collector_hpke_config\"")?;
    let collector_hpke_config = HpkeConfig::get_decoded(&collector_hpke_config_bytes)
        .context("could not parse collector HPKE configuration")?;

    let aggregator_parameters = match (request.role, request.collector_authentication_token) {
        (AggregatorRole::Leader, None) => {
            return Err(anyhow::anyhow!("collector authentication token is missing"));
        }
        (AggregatorRole::Leader, Some(collector_authentication_token)) => {
            AggregatorTaskParameters::Leader {
                aggregator_auth_token: leader_authentication_token,
                collector_auth_token_hash: AuthenticationTokenHash::from(
                    &AuthenticationToken::new_dap_auth_token_from_string(
                        collector_authentication_token,
                    )
                    .context("invalid header value in \"collector_authentication_token\"")?,
                ),
                collector_hpke_config,
            }
        }
        (AggregatorRole::Helper, _) => AggregatorTaskParameters::Helper {
            aggregator_auth_token_hash: AuthenticationTokenHash::from(&leader_authentication_token),
            collector_hpke_config,
            // TODO(#3436): allow callers to specify asynchronous aggregation mode (requires
            // updated interop test design)
            aggregation_mode: AggregationMode::Synchronous,
        },
    };

    let batch_mode = match request.batch_mode {
        1 => task::BatchMode::TimeInterval,
        2 => task::BatchMode::LeaderSelected {
            batch_time_window_size: None,
        },
        _ => {
            return Err(anyhow::anyhow!(
                "invalid batch mode: {}",
                request.batch_mode
            ));
        }
    };

    let task = AggregatorTask::new(
        request.task_id,
        peer_aggregator_endpoint,
        batch_mode,
        vdaf,
        vdaf_verify_key,
        request
            .task_start
            .map(|t| Time::from_seconds_since_epoch(t, &time_precision)),
        request
            .task_end
            .map(|t| Time::from_seconds_since_epoch(t, &time_precision)),
        None,
        request.min_batch_size,
        time_precision,
        /* tolerable clock skew */
        Duration::ONE, // Since the clock skew must be a multiple of the precision, start at 1x
        aggregator_parameters,
    )
    .context("error constructing task")?;

    datastore
        .run_unnamed_tx(move |tx| {
            let task = task.clone();
            Box::pin(async move { tx.put_aggregator_task(&task).await })
        })
        .await
        .context("error adding task to database")
}

async fn add_task_endpoint(
    State(state): State<InteropAggregatorState>,
    request: Result<Json<AggregatorAddTaskRequest>, axum::extract::rejection::JsonRejection>,
) -> impl IntoResponse {
    let Json(request) = match request {
        Ok(r) => r,
        Err(err) => {
            return Json(AddTaskResponse {
                status: ERROR.to_string(),
                error: Some(format!("{err}")),
            });
        }
    };
    match handle_add_task(&state.datastore, request).await {
        Ok(()) => Json(AddTaskResponse {
            status: SUCCESS.to_string(),
            error: None,
        }),
        Err(e) => Json(AddTaskResponse {
            status: ERROR.to_string(),
            error: Some(format!("{e:?}")),
        }),
    }
}

async fn ready_endpoint(
    State(state): State<InteropAggregatorState>,
) -> impl IntoResponse {
    let client = reqwest::Client::new();
    for peer in &state.health_check_peers {
        if client.get(peer.as_str()).send().await.is_err() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    Json(json!({})).into_response()
}

async fn endpoint_for_task(
    State(state): State<InteropAggregatorState>,
) -> impl IntoResponse {
    Json(EndpointResponse {
        status: "success",
        endpoint: state.dap_serving_prefix.clone(),
    })
}

/// Simple reverse proxy handler that forwards requests to the aggregator.
async fn proxy_handler(
    State(state): State<InteropAggregatorState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let url = format!("{}{path}", state.proxy_url);

    let method = request.method().clone();
    let headers = request.headers().clone();
    let body = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let mut builder = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &url,
    );
    for (name, value) in headers.iter() {
        if name != "host" {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
    }
    builder = builder.body(body);

    let resp = match builder.send().await {
        Ok(resp) => resp,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap();
    let resp_headers = resp.headers().clone();
    let body = match resp.bytes().await {
        Ok(body) => body,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let mut response = (status, body.to_vec()).into_response();
    for (name, value) in resp_headers.iter() {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            http::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn make_handler(
    datastore: Arc<Datastore<RealClock>>,
    dap_serving_prefix: String,
    aggregator_address: SocketAddr,
    health_check_peers: Vec<Url>,
) -> Router {
    let state = InteropAggregatorState {
        datastore,
        proxy_url: format!("http://{aggregator_address}"),
        http_client: reqwest::Client::new(),
        dap_serving_prefix: dap_serving_prefix.clone(),
        health_check_peers,
    };

    // Build routes for the test API
    let test_routes = Router::new()
        .route("/internal/test/ready", post(ready_endpoint))
        .route(
            "/internal/test/endpoint_for_task",
            post(endpoint_for_task),
        )
        .route("/internal/test/add_task", post(add_task_endpoint));

    // Build the proxy fallback for DAP requests
    let proxy_routes = Router::new().fallback(proxy_handler);

    test_routes
        .merge(proxy_routes)
        .with_state(state)
}

#[derive(Debug, Parser)]
#[clap(
    name = "janus_interop_aggregator",
    about = "Janus interoperation test aggregator",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct Options {
    #[clap(flatten)]
    common: CommonBinaryOptions,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        &self.common
    }
}

fn default_dap_serving_prefix() -> String {
    "/".to_string()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    #[serde(flatten)]
    common_config: CommonConfig,

    /// Address on which this server should listen for connections and serve its
    /// API endpoints.
    listen_address: SocketAddr,

    /// Path prefix, e.g. `/dap/`, to serve DAP from.
    #[serde(default = "default_dap_serving_prefix")]
    dap_serving_prefix: String,

    /// Address on which the aggregator's HTTP server is listening. DAP requests will be proxied to
    /// this.
    aggregator_address: SocketAddr,

    /// List of URLs to health check endpoints of aggregator subprocesses. The interop aggregator
    /// will check these endpoints for readiness before considering itself ready.
    health_check_peers: Vec<Url>,
}

impl BinaryConfig for Config {
    fn common_config(&self) -> &CommonConfig {
        &self.common_config
    }

    fn common_config_mut(&mut self) -> &mut CommonConfig {
        &mut self.common_config
    }
}

impl Options {
    pub fn run(self) -> anyhow::Result<()> {
        janus_main::<_, _, Config, _, _>(
            "janus_interop_aggregator",
            self,
            RealClock::default(),
            true,
            |ctx| async move {
                ctx.datastore.put_hpke_key().await.unwrap();

                let handler = make_handler(
                    Arc::new(ctx.datastore),
                    ctx.config.dap_serving_prefix,
                    ctx.config.aggregator_address,
                    ctx.config.health_check_peers,
                );
                let listener = tokio::net::TcpListener::bind(ctx.config.listen_address).await?;
                axum::serve(listener, handler).await?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Options;

    #[test]
    fn verify_clap_app() {
        Options::command().debug_assert();
    }
}
