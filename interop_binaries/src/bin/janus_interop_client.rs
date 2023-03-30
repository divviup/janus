use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{value_parser, Arg, Command};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31, U63};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32, FixedI64};
use janus_client::ClientParameters;
use janus_core::{
    task::VdafInstance,
    time::{MockClock, RealClock},
};
use janus_interop_binaries::{
    install_tracing_subscriber,
    status::{ERROR, SUCCESS},
    NumberAsString, VdafObject,
};
use janus_messages::{Duration, Role, TaskId, Time};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded;
use prio::{codec::Decode, vdaf::prio3::Prio3};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};
use url::Url;
use warp::{hyper::StatusCode, reply::Response, Filter, Reply};

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
    vdaf_client: V,
    request: UploadRequest,
    measurement: V::Measurement,
) -> anyhow::Result<()> {
    let task_id_bytes = URL_SAFE_NO_PAD
        .decode(request.task_id)
        .context("invalid base64url content in \"task_id\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;
    let time_precision = Duration::from_seconds(request.time_precision);
    let client_parameters =
        ClientParameters::new(task_id, request.leader, request.helper, time_precision);

    let leader_hpke_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        &Role::Leader,
        &task_id,
        http_client,
    )
    .await
    .context("failed to fetch leader's HPKE configuration")?;
    let helper_hpke_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        &Role::Helper,
        &task_id,
        http_client,
    )
    .await
    .context("failed to fetch helper's HPKE configuration")?;

    match request.time {
        Some(timestamp) => {
            let clock = MockClock::new(Time::from_seconds_since_epoch(timestamp));
            let client = janus_client::Client::new(
                client_parameters,
                vdaf_client,
                clock,
                http_client,
                leader_hpke_config,
                helper_hpke_config,
            );
            client
                .upload(&measurement)
                .await
                .context("report generation and upload failed")
        }
        None => {
            let client = janus_client::Client::new(
                client_parameters,
                vdaf_client,
                RealClock::default(),
                http_client,
                leader_hpke_config,
                helper_hpke_config,
            );
            client
                .upload(&measurement)
                .await
                .context("report generation and upload failed")
        }
    }
}

async fn handle_upload(
    http_client: &reqwest::Client,
    request: UploadRequest,
) -> anyhow::Result<()> {
    let vdaf_instance = request.vdaf.clone().into();
    match vdaf_instance {
        VdafInstance::Prio3Count {} => {
            let measurement = parse_primitive_measurement::<u64>(request.measurement.clone())?;
            let vdaf_client = Prio3::new_count(2).context("failed to construct Prio3Count VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }

        VdafInstance::Prio3CountVec { length } => {
            let measurement = parse_vector_measurement::<u128>(request.measurement.clone())?;
            let vdaf_client = Prio3::new_sum_vec_multithreaded(2, 1, length)
                .context("failed to construct Prio3CountVec VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }

        VdafInstance::Prio3Sum { bits } => {
            let measurement = parse_primitive_measurement::<u128>(request.measurement.clone())?;
            let vdaf_client =
                Prio3::new_sum(2, bits).context("failed to construct Prio3Sum VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }

        VdafInstance::Prio3SumVec { bits, length } => {
            let measurement = parse_vector_measurement::<u128>(request.measurement.clone())?;
            let vdaf_client = Prio3::new_sum_vec_multithreaded(2, bits, length)
                .context("failed to construct Prio3SumVec VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }

        VdafInstance::Prio3Histogram { ref buckets } => {
            let measurement = parse_primitive_measurement::<u128>(request.measurement.clone())?;
            let vdaf_client = Prio3::new_histogram(2, buckets)
                .context("failed to construct Prio3Histogram VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
            let measurement =
                parse_vector_measurement::<FixedI16<U15>>(request.measurement.clone())?;
            let vdaf_client: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .context("failed to construct Prio3FixedPoint16BitBoundedL2VecSum VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
            let measurement =
                parse_vector_measurement::<FixedI32<U31>>(request.measurement.clone())?;
            let vdaf_client: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .context("failed to construct Prio3FixedPoint32BitBoundedL2VecSum VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
            let measurement =
                parse_vector_measurement::<FixedI64<U63>>(request.measurement.clone())?;
            let vdaf_client: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .context("failed to construct Prio3FixedPoint64BitBoundedL2VecSum VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }
        _ => panic!("Unsupported VDAF: {vdaf_instance:?}"),
    }
    Ok(())
}

fn make_filter() -> anyhow::Result<impl Filter<Extract = (Response,)> + Clone> {
    let http_client = janus_client::default_http_client()?;

    let ready_filter = warp::path!("ready").map(|| {
        warp::reply::with_status(warp::reply::json(&serde_json::json!({})), StatusCode::OK)
            .into_response()
    });
    let upload_filter =
        warp::path!("upload")
            .and(warp::body::json())
            .then(move |request: UploadRequest| {
                let http_client = http_client.clone();
                async move {
                    let response = match handle_upload(&http_client, request).await {
                        Ok(()) => UploadResponse {
                            status: SUCCESS,
                            error: None,
                        },
                        Err(e) => UploadResponse {
                            status: ERROR,
                            error: Some(format!("{e:?}")),
                        },
                    };
                    warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                        .into_response()
                }
            });

    Ok(warp::path!("internal" / "test" / ..)
        .and(warp::post())
        .and(ready_filter.or(upload_filter).unify()))
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;
    let matches = app().get_matches();
    let port = matches
        .try_get_one::<u16>("port")?
        .ok_or_else(|| anyhow!("port argument missing"))?;
    let filter = make_filter()?;
    let server = warp::serve(filter);
    server
        .bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port)))
        .await;
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
