use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{value_parser, Arg, Command};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31, U63};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32, FixedI64};
use janus_core::vdaf::VdafInstance;
use janus_interop_binaries::{
    install_tracing_subscriber,
    status::{ERROR, SUCCESS},
    ErrorHandler, NumberAsString, VdafObject,
};
use janus_messages::{Duration, TaskId, Time};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded;
use prio::{codec::Decode, vdaf::prio3::Prio3};
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

#[derive(Debug, Deserialize)]
struct UploadRequest {
    task_id: String,
    leader: Url,
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
                .upload_with_time(&measurement, Time::from_seconds_since_epoch(timestamp))
                .await
        }
        None => client.upload(&measurement).await,
    }
    .context("report generation and upload failed")
}

async fn handle_upload(
    http_client: &reqwest::Client,
    request: UploadRequest,
) -> anyhow::Result<()> {
    let vdaf_instance = request.vdaf.clone().into();
    match vdaf_instance {
        VdafInstance::Prio3Count {} => {
            let measurement = parse_primitive_measurement::<u64>(request.measurement.clone())?;
            let vdaf = Prio3::new_count(2).context("failed to construct Prio3Count VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        VdafInstance::Prio3Sum { bits } => {
            let measurement = parse_primitive_measurement::<u128>(request.measurement.clone())?;
            let vdaf = Prio3::new_sum(2, bits).context("failed to construct Prio3Sum VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        VdafInstance::Prio3SumVec {
            bits,
            length,
            chunk_length,
        } => {
            let measurement = parse_vector_measurement::<u128>(request.measurement.clone())?;
            let vdaf = Prio3::new_sum_vec_multithreaded(2, bits, length, chunk_length)
                .context("failed to construct Prio3SumVec VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        VdafInstance::Prio3Histogram {
            length,
            chunk_length,
        } => {
            let measurement = parse_primitive_measurement::<usize>(request.measurement.clone())?;
            let vdaf = Prio3::new_histogram(2, length, chunk_length)
                .context("failed to construct Prio3Histogram VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
            let measurement =
                parse_vector_measurement::<FixedI16<U15>>(request.measurement.clone())?;
            let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .context("failed to construct Prio3FixedPoint16BitBoundedL2VecSum VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
            let measurement =
                parse_vector_measurement::<FixedI32<U31>>(request.measurement.clone())?;
            let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .context("failed to construct Prio3FixedPoint32BitBoundedL2VecSum VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
            let measurement =
                parse_vector_measurement::<FixedI64<U63>>(request.measurement.clone())?;
            let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .context("failed to construct Prio3FixedPoint64BitBoundedL2VecSum VDAF")?;
            handle_upload_generic(http_client, vdaf, request, measurement).await?;
        }
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

fn app() -> clap::Command {
    Command::new("Janus interoperation test client").arg(
        Arg::new("port")
            .long("port")
            .short('p')
            .default_value("8080")
            .value_parser(value_parser!(u16))
            .help("Port number to listen on."),
    )
}

fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;
    let matches = app().get_matches();
    let port = matches
        .try_get_one::<u16>("port")?
        .ok_or_else(|| anyhow!("port argument missing"))?;
    trillium_tokio::config()
        .with_host(&Ipv4Addr::UNSPECIFIED.to_string())
        .with_port(*port)
        .run(handler()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::app;

    #[test]
    fn verify_clap_app() {
        app().debug_assert();
    }
}
