use http::header::CONTENT_TYPE;
use janus_aggregator_core::task::test_util::Task;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label},
    http::HttpErrorResponse,
    retries::retry_http_request,
    time::TimeExt,
};
use janus_messages::{
    HpkeConfig, HpkeConfigList, InputShareAad, PlaintextInputShare, Report, ReportId,
    ReportMetadata, Role, Time,
};
use prio::{
    codec::{Decode, Encode},
    field::Field128,
    vdaf::{
        prio3::{Prio3Histogram, Prio3InputShare, Prio3PublicShare},
        Client as _,
    },
};
use rand::random;
use url::Url;

use crate::simulation::http_request_exponential_backoff;

/// Shard and upload a report, but with a fixed ReportId.
pub(super) async fn upload_replay_report(
    measurement: usize,
    task: &Task,
    vdaf: &Prio3Histogram,
    report_time: &Time,
    http_client: &reqwest::Client,
) -> Result<(), janus_client::Error> {
    // This encodes to "replayreplayreplayrepl".
    let report_id = ReportId::from([
        173, 234, 101, 107, 42, 222, 166, 86, 178, 173, 234, 101, 107, 42, 222, 166,
    ]);
    let (public_share, input_shares) = vdaf.shard(&measurement, report_id.as_ref())?;
    let rounded_time = report_time
        .to_batch_interval_start(task.time_precision())
        .unwrap();

    let report = prepare_report(
        http_client,
        task,
        public_share,
        input_shares,
        report_id,
        rounded_time,
    )
    .await?;
    upload_report(http_client, task, report).await
}

/// Shard and upload a report, but don't round the timestamp properly.
pub(super) async fn upload_report_not_rounded(
    measurement: usize,
    task: &Task,
    vdaf: &Prio3Histogram,
    report_time: &Time,
    http_client: &reqwest::Client,
) -> Result<(), janus_client::Error> {
    let report_id: ReportId = random();
    let (public_share, input_shares) = vdaf.shard(&measurement, report_id.as_ref())?;

    let report = prepare_report(
        http_client,
        task,
        public_share,
        input_shares,
        report_id,
        *report_time,
    )
    .await?;
    upload_report(http_client, task, report).await
}

async fn prepare_report(
    http_client: &reqwest::Client,
    task: &Task,
    public_share: Prio3PublicShare<16>,
    input_shares: Vec<Prio3InputShare<Field128, 16>>,
    report_id: ReportId,
    report_time: Time,
) -> Result<Report, janus_client::Error> {
    let task_id = *task.id();
    let report_metadata = ReportMetadata::new(report_id, report_time);
    let encoded_public_share = public_share.get_encoded().unwrap();

    let leader_hpke_config =
        aggregator_hpke_config(task.leader_aggregator_endpoint(), http_client).await?;
    let helper_hpke_config =
        aggregator_hpke_config(task.helper_aggregator_endpoint(), http_client).await?;

    let aad = InputShareAad::new(
        task_id,
        report_metadata.clone(),
        encoded_public_share.clone(),
    )
    .get_encoded()?;
    let leader_encrypted_input_share = hpke::seal(
        &leader_hpke_config,
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
        &PlaintextInputShare::new(Vec::new(), input_shares[0].get_encoded()?).get_encoded()?,
        &aad,
    )?;
    let helper_encrypted_input_share = hpke::seal(
        &helper_hpke_config,
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
        &PlaintextInputShare::new(Vec::new(), input_shares[1].get_encoded()?).get_encoded()?,
        &aad,
    )?;

    let report = Report::new(
        report_metadata,
        encoded_public_share,
        leader_encrypted_input_share,
        helper_encrypted_input_share,
    );
    Ok(report)
}

async fn upload_report(
    http_client: &reqwest::Client,
    task: &Task,
    report: Report,
) -> Result<(), janus_client::Error> {
    let task_id = task.id();
    let url = task
        .leader_aggregator_endpoint()
        .join(&format!("tasks/{task_id}/reports"))
        .unwrap();
    retry_http_request(http_request_exponential_backoff(), || async {
        http_client
            .put(url.clone())
            .header(CONTENT_TYPE, Report::MEDIA_TYPE)
            .body(report.get_encoded().unwrap())
            .send()
            .await
    })
    .await?;
    Ok(())
}

async fn aggregator_hpke_config(
    endpoint: &Url,
    http_client: &reqwest::Client,
) -> Result<HpkeConfig, janus_client::Error> {
    let response = retry_http_request(http_request_exponential_backoff(), || async {
        http_client
            .get(endpoint.join("hpke_config").unwrap())
            .send()
            .await
    })
    .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(janus_client::Error::Http(Box::new(
            HttpErrorResponse::from(status),
        )));
    }

    let list = HpkeConfigList::get_decoded(response.body())?;

    Ok(list.hpke_configs()[0].clone())
}
