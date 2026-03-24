use std::{
    fmt::Display,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{State, rejection::JsonRejection},
    response::IntoResponse,
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use educe::Educe;
use janus_core::vdaf::{VdafInstance, new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128};
use janus_messages::{TaskId, Time, TimePrecision};
use prio::{
    codec::Decode,
    field::Field64,
    flp::gadgets::{Mul, ParallelSumMultithreaded},
    vdaf::prio3::Prio3,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use url::Url;

use crate::{
    NumberAsString, VdafObject, install_tracing_subscriber,
    status::{ERROR, SUCCESS},
};

/// Parse a numeric measurement from its intermediate JSON representation.
fn parse_primitive_measurement<T>(value: serde_json::Value) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: Display,
{
    Ok(serde_json::value::from_value::<NumberAsString<T>>(value)?.0)
}

/// Parse a vector measurement from its intermediate JSON representation.
fn parse_vector_measurement<T>(value: serde_json::Value) -> anyhow::Result<Vec<T>>
where
    T: FromStr,
    T::Err: Display,
{
    Ok(
        serde_json::value::from_value::<Vec<NumberAsString<T>>>(value)?
            .into_iter()
            .map(|elem| elem.0)
            .collect(),
    )
}

#[derive(Educe, Deserialize)]
#[educe(Debug)]
struct UploadRequest {
    task_id: String,
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    leader: Url,
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    helper: Url,
    vdaf: VdafObject,
    measurement: serde_json::Value,
    #[serde(default)]
    time: Option<u64>,
    time_precision: u64,
}

#[derive(Debug, Serialize)]
struct UploadResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
}

async fn handle_upload_generic<V: prio::vdaf::Client<16>>(
    http_client: &reqwest::Client,
    vdaf: V,
    request: UploadRequest,
    measurement: V::Measurement,
) -> anyhow::Result<()> {
    let task_id_bytes = URL_SAFE_NO_PAD
        .decode(request.task_id)
        .context("invalid base64url content in \"task_id\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;
    let time_precision = TimePrecision::from_seconds(request.time_precision);

    let client = janus_client::Client::builder(
        task_id,
        request.leader,
        request.helper,
        time_precision,
        vdaf,
    )
    .with_http_client(http_client.clone())
    .build()
    .await
    .context("failed to construct client")?;

    match request.time {
        Some(timestamp) => {
            client
                .upload_with_time(&[(
                    measurement,
                    Time::from_seconds_since_epoch(timestamp, &time_precision),
                )])
                .await
        }
        None => client.upload(measurement).await,
    }
    .context("report generation and upload failed")
}

async fn handle_upload(
    http_client: &reqwest::Client,
    request: UploadRequest,
) -> anyhow::Result<()> {
    let vdaf_instance = request.vdaf.clone().into();
    match vdaf_instance {
        VdafInstance::Prio3Count => {
            let measurement = parse_primitive_measurement::<u64>(request.measurement.clone())?;
            let vdaf = Prio3::new_count(2).context("failed to construct Prio3Count VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement != 0).await?;
        }

        VdafInstance::Prio3Sum { max_measurement } => {
            let measurement = parse_primitive_measurement::<u64>(request.measurement.clone())?;
            let vdaf =
                Prio3::new_sum(2, max_measurement).context("failed to construct Prio3Sum VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        VdafInstance::Prio3SumVec {
            max_measurement,
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let measurement = parse_vector_measurement::<u128>(request.measurement.clone())?;
            let vdaf =
                Prio3::new_sum_vec_multithreaded(2, max_measurement as u128, length, chunk_length)
                    .context("failed to construct Prio3SumVec VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            proofs,
            max_measurement,
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let measurement = parse_vector_measurement::<u64>(request.measurement.clone())?;
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128::<
                ParallelSumMultithreaded<Field64, Mul>,
            >(proofs, max_measurement, length, chunk_length)
            .context("failed to construct Prio3SumVecField64MultiproofHmacSha256Aes128 VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        VdafInstance::Prio3Histogram {
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let measurement = parse_primitive_measurement::<usize>(request.measurement.clone())?;
            let vdaf = Prio3::new_histogram_multithreaded(2, length, chunk_length)
                .context("failed to construct Prio3Histogram VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        _ => panic!("Unsupported VDAF: {vdaf_instance:?}"),
    }
    Ok(())
}

async fn handle_upload_endpoint(
    State(http_client): State<Arc<reqwest::Client>>,
    request: Result<Json<UploadRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(request) = match request {
        Ok(r) => r,
        Err(e) => {
            return Json(UploadResponse {
                status: ERROR,
                error: Some(format!("{e:?}")),
            });
        }
    };
    match handle_upload(&http_client, request).await {
        Ok(()) => Json(UploadResponse {
            status: SUCCESS,
            error: None,
        }),
        Err(e) => Json(UploadResponse {
            status: ERROR,
            error: Some(format!("{e:?}")),
        }),
    }
}

fn handler() -> anyhow::Result<Router> {
    let http_client = Arc::new(janus_client::default_http_client()?);

    Ok(Router::new()
        .route(
            "/internal/test/ready",
            post(|| async { Json(serde_json::json!({})) }),
        )
        .route("/internal/test/upload", post(handle_upload_endpoint))
        .with_state(http_client))
}

#[derive(Debug, Parser)]
/// Janus interoperation test client
pub struct Options {
    /// Port number to listen on.
    #[clap(long, short, default_value = "8080")]
    port: u16,
}

impl Options {
    pub fn run(self) -> anyhow::Result<()> {
        install_tracing_subscriber()?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let app = handler()?;
            let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port));
            let listener = TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        })
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
