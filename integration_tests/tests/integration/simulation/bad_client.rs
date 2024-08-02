use std::{net::Ipv4Addr, sync::Arc};

use http::header::CONTENT_TYPE;
use janus_aggregator::aggregator::http_handlers::aggregator_handler;
use janus_aggregator_core::{
    datastore::{models::HpkeKeyState, test_util::ephemeral_datastore},
    task::test_util::{Task, TaskBuilder},
    test_util::noop_meter,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    http::HttpErrorResponse,
    retries::retry_http_request,
    test_util::{install_test_trace_subscriber, runtime::TestRuntime},
    time::{Clock, RealClock, TimeExt},
    vdaf::{vdaf_dp_strategies, VdafInstance},
};
use janus_messages::{
    HpkeConfig, HpkeConfigList, InputShareAad, PlaintextInputShare, Report, ReportId,
    ReportMetadata, Role, Time,
};
use prio::{
    codec::{Decode, Encode},
    field::Field128,
    vdaf::{
        prio3::{optimal_chunk_length, Prio3, Prio3Histogram, Prio3InputShare, Prio3PublicShare},
        Client as _,
    },
};
use rand::random;
use tokio::net::TcpListener;
use trillium_tokio::Stopper;
use url::Url;

use crate::simulation::{http_request_exponential_backoff, run::MAX_REPORTS};

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

#[tokio::test(flavor = "multi_thread")]
async fn bad_client_report_validity() {
    install_test_trace_subscriber();

    let clock = RealClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock).await);
    let http_client = reqwest::Client::new();
    let keypair = HpkeKeypair::test();

    datastore
        .run_unnamed_tx(|tx| {
            let keypair = keypair.clone();
            Box::pin(async move {
                tx.put_global_hpke_keypair(&keypair).await?;
                tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                    .await
            })
        })
        .await
        .unwrap();

    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let socket_address = server.local_addr().unwrap();

    let chunk_length = optimal_chunk_length(MAX_REPORTS);
    let vdaf = Prio3::new_histogram(2, MAX_REPORTS, chunk_length).unwrap();
    let vdaf_instance = VdafInstance::Prio3Histogram {
        length: MAX_REPORTS,
        chunk_length,
        dp_strategy: vdaf_dp_strategies::Prio3Histogram::NoDifferentialPrivacy,
    };
    let task = TaskBuilder::new(
        janus_aggregator_core::task::QueryType::TimeInterval,
        vdaf_instance,
    )
    .with_leader_aggregator_endpoint(format!("http://{socket_address}/").parse().unwrap())
    .with_helper_aggregator_endpoint(format!("http://{socket_address}/").parse().unwrap())
    .build();
    datastore
        .put_aggregator_task(&task.leader_view().unwrap())
        .await
        .unwrap();

    let handler = aggregator_handler(
        Arc::clone(&datastore),
        clock,
        TestRuntime::default(),
        &noop_meter(),
        Default::default(),
    )
    .await;
    let stopper = Stopper::new();
    let server_handle = trillium_tokio::config()
        .with_stopper(stopper.clone())
        .without_signals()
        .with_prebound_server(server)
        .spawn(handler);

    let report_time = clock.now();
    upload_replay_report(0, &task, &vdaf, &report_time, &http_client)
        .await
        .unwrap();
    upload_report_not_rounded(0, &task, &vdaf, &report_time, &http_client)
        .await
        .unwrap();

    let task_id = *task.id();
    let counters = datastore
        .run_unnamed_tx(|tx| Box::pin(async move { tx.get_task_upload_counter(&task_id).await }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(counters.report_success(), 2);

    stopper.stop();
    server_handle.await;
}
