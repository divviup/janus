use crate::{
    install_tracing_subscriber,
    status::{ERROR, SUCCESS},
    ErrorHandler, NumberAsString, VdafObject,
};
use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use educe::Educe;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{
    types::extra::{U15, U31},
    FixedI16, FixedI32,
};
#[cfg(feature = "fpvec_bounded_l2")]
use janus_core::vdaf::Prio3FixedPointBoundedL2VecSumBitSize;
use janus_core::vdaf::{new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128, VdafInstance};
use janus_messages::{Duration, TaskId, Time};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded;
use prio::{
    codec::Decode,
    field::Field64,
    flp::gadgets::{Mul, ParallelSumMultithreaded},
    vdaf::prio3::Prio3,
};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, net::Ipv4Addr, str::FromStr};
use trillium::{Conn, Handler};
use trillium_api::{api, Json, State};
use trillium_router::Router;
use url::Url;

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
    let time_precision = Duration::from_seconds(request.time_precision);

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
                .upload_with_time(vec![(
                    measurement,
                    Time::from_seconds_since_epoch(timestamp),
                )])
                .await
        }
        None => client.upload(&[measurement]).await,
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
            bits,
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let measurement = parse_vector_measurement::<u128>(request.measurement.clone())?;
            let vdaf = Prio3::new_sum_vec_multithreaded(2, bits, length, chunk_length)
                .context("failed to construct Prio3SumVec VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            proofs,
            bits,
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let measurement = parse_vector_measurement::<u64>(request.measurement.clone())?;
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128::<
                ParallelSumMultithreaded<Field64, Mul<Field64>>,
            >(proofs, bits, length, chunk_length)
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

        #[cfg(feature = "fpvec_bounded_l2")]
        VdafInstance::Prio3FixedPointBoundedL2VecSum {
            bitsize,
            dp_strategy: _,
            length,
        } => match bitsize {
            Prio3FixedPointBoundedL2VecSumBitSize::BitSize16 => {
                let measurement =
                    parse_vector_measurement::<FixedI16<U15>>(request.measurement.clone())?;
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length).context(
                        "failed to construct Prio3FixedPoint16BitBoundedL2VecSumZCdp VDAF",
                    )?;
                handle_upload_generic(http_client, vdaf, request, measurement).await?;
            }
            Prio3FixedPointBoundedL2VecSumBitSize::BitSize32 => {
                let measurement =
                    parse_vector_measurement::<FixedI32<U31>>(request.measurement.clone())?;
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length).context(
                        "failed to construct Prio3FixedPoint32BitBoundedL2VecSumZCdp VDAF",
                    )?;
                handle_upload_generic(http_client, vdaf, request, measurement).await?;
            }
        },
        _ => panic!("Unsupported VDAF: {vdaf_instance:?}"),
    }
    Ok(())
}

fn handler() -> anyhow::Result<impl Handler> {
    let http_client = janus_client::default_http_client()?;

    Ok((
        State(http_client),
        Router::new()
            .post("/internal/test/ready", Json(serde_json::json!({})))
            .post(
                "/internal/test/upload",
                api(
                    |_conn: &mut Conn, (State(http_client), Json(request))| async move {
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
                    },
                ),
            ),
        ErrorHandler,
    ))
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
        trillium_tokio::config()
            .with_host(&Ipv4Addr::UNSPECIFIED.to_string())
            .with_port(self.port)
            .run(handler()?);
        Ok(())
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
