use anyhow::Context;
use base64::URL_SAFE_NO_PAD;
use clap::{Arg, Command};
use interop_binaries::{
    install_tracing_subscriber,
    status::{ERROR, SUCCESS},
    VdafObject,
};
use janus_client::ClientParameters;
use janus_core::{
    message::{Duration, Role, TaskId, Time},
    time::{MockClock, RealClock},
};
use prio::{
    codec::Decode,
    vdaf::{prio3::Prio3, Vdaf},
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use url::Url;
use warp::{hyper::StatusCode, reply::Response, Filter, Reply};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadRequest {
    task_id: String,
    leader: String,
    helper: String,
    vdaf: VdafObject,
    measurement: u64,
    #[serde(default)]
    nonce_time: Option<u64>,
    min_batch_duration: u64,
}

#[derive(Debug, Serialize)]
struct UploadResponse {
    status: &'static str,
    #[serde(default)]
    error: Option<String>,
}

async fn handle_upload_generic<V: prio::vdaf::Client>(
    http_client: &reqwest::Client,
    vdaf_client: V,
    request: UploadRequest,
    measurement: V::Measurement,
) -> anyhow::Result<()>
where
    for<'a> Vec<u8>: From<&'a <V as Vdaf>::AggregateShare>,
{
    let task_id_bytes = base64::decode_config(request.task_id, URL_SAFE_NO_PAD)
        .context("invalid base64url content in \"taskId\"")?;
    let task_id = TaskId::get_decoded(&task_id_bytes).context("invalid length of TaskId")?;
    let leader_url = Url::parse(&request.leader).context("bad leader URL")?;
    let helper_url = Url::parse(&request.helper).context("bad helper URL")?;
    let min_batch_duration = Duration::from_seconds(request.min_batch_duration);
    let client_parameters =
        ClientParameters::new(task_id, vec![leader_url, helper_url], min_batch_duration);

    let leader_hpke_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        Role::Leader,
        task_id,
        http_client,
    )
    .await
    .context("failed to fetch leader's HPKE configuration")?;
    let helper_hpke_config = janus_client::aggregator_hpke_config(
        &client_parameters,
        Role::Helper,
        task_id,
        http_client,
    )
    .await
    .context("failed to fetch helper's HPKE configuration")?;

    match request.nonce_time {
        Some(nonce_time) => {
            let clock = MockClock::new(Time::from_seconds_since_epoch(nonce_time));
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
    let measurement = request.measurement;
    match request.vdaf {
        VdafObject::Prio3Aes128Count {} => {
            let vdaf_client =
                Prio3::new_aes128_count(2).context("failed to construct Prio3Aes128Count VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement).await?;
        }
        VdafObject::Prio3Aes128Sum { bits } => {
            let vdaf_client = Prio3::new_aes128_sum(2, bits)
                .context("failed to construct Prio3Aes128Sum VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement.into()).await?;
        }
        VdafObject::Prio3Aes128Histogram { ref buckets } => {
            let vdaf_client = Prio3::new_aes128_histogram(2, buckets)
                .context("failed to construct Prio3Aes128Histogram VDAF")?;
            handle_upload_generic(http_client, vdaf_client, request, measurement.into()).await?;
        }
    }
    Ok(())
}

fn make_filter() -> anyhow::Result<impl Filter<Extract = (Response,)> + Clone> {
    let http_client = janus_client::default_http_client()?;
    Ok(warp::path!("internal" / "test" / "upload")
        .and(warp::post())
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
                        error: Some(format!("{:?}", e)),
                    },
                };
                warp::reply::with_status(warp::reply::json(&response), StatusCode::OK)
                    .into_response()
            }
        }))
}

fn app() -> clap::Command<'static> {
    Command::new("Janus interoperation test client").arg(
        Arg::new("port")
            .long("port")
            .short('p')
            .default_value("8080")
            .help("Port number to listen on."),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;
    let matches = app().get_matches();
    let port = matches.value_of_t::<u16>("port")?;
    let filter = make_filter()?;
    let server = warp::serve(filter);
    server
        .bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
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
