use crate::aggregator::{
    http_handlers::aggregator_handler, tests::generate_helper_report_share, Config,
};
use janus_aggregator_core::{
    datastore::{
        test_util::{ephemeral_datastore, EphemeralDatastore},
        Datastore,
    },
    task::{QueryType, Task},
    taskprov::VerifyKeyInit,
    test_util::noop_meter,
    SecretBytes,
};
use janus_core::{
    hpke::{test_util::generate_test_hpke_config_and_private_key, HpkeKeypair},
    task::{AuthenticationToken, DAP_AUTH_HEADER},
    test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf, VdafTranscript},
    time::{Clock, DurationExt, MockClock, TimeExt as _},
};
use janus_messages::{
    query_type::TimeInterval,
    taskprov::{DpConfig, DpMechanism, Query, QueryConfig, TaskConfig, VdafConfig, VdafType},
    AggregateInitializeReq, Duration, Extension, ExtensionType, HpkeConfig, PartialBatchSelector,
    ReportMetadata, ReportShare, Role, TaskId,
};
use prio::{codec::Encode, vdaf::prio3::Prio3Aes128Count};
use rand::random;
use ring::digest::{digest, SHA256};
use std::sync::Arc;
use trillium::{Handler, KnownHeaderName, Status};
use trillium_testing::{prelude::post, TestConn};

pub(super) struct ReportShareGenerator {
    clock: MockClock,
    hpke_config: HpkeConfig,
    measurement: u64,
    task_config_encoded: Vec<u8>,
    task_id: TaskId,
    time_precision: Duration,
    vdaf: Prio3Aes128Count,
    vdaf_verify_key: SecretBytes,
}

impl ReportShareGenerator {
    pub(super) fn new(
        clock: MockClock,
        hpke_config: HpkeConfig,
        task_config_encoded: Vec<u8>,
        task_id: TaskId,
        time_precision: Duration,
        vdaf_verify_key: SecretBytes,
    ) -> Self {
        Self {
            clock,
            hpke_config,
            measurement: 1u64,
            task_config_encoded,
            task_id,
            time_precision,
            vdaf: Prio3Aes128Count::new_aes128_count(2).unwrap(),
            vdaf_verify_key,
        }
    }

    pub(super) fn next(&self) -> (ReportShare, VdafTranscript<16, Prio3Aes128Count>) {
        self.next_with_metadata(ReportMetadata::new(
            random(),
            self.clock
                .now()
                .to_batch_interval_start(&self.time_precision)
                .unwrap(),
            Vec::from([Extension::new(
                ExtensionType::Taskprov,
                self.task_config_encoded.clone(),
            )]),
        ))
    }

    pub(super) fn with_measurement(mut self, measurement: u64) -> Self {
        self.measurement = measurement;
        self
    }

    pub(super) fn next_with_metadata(
        &self,
        report_metadata: ReportMetadata,
    ) -> (ReportShare, VdafTranscript<16, Prio3Aes128Count>) {
        let transcript = run_vdaf(
            &self.vdaf,
            self.vdaf_verify_key.as_ref().try_into().unwrap(),
            &(),
            report_metadata.id(),
            &self.measurement,
        );
        let report_share = generate_helper_report_share::<Prio3Aes128Count>(
            self.task_id,
            report_metadata,
            &self.hpke_config,
            &transcript.public_share,
            &transcript.input_shares[1],
        );

        (report_share, transcript)
    }
}

pub(super) struct AggregationJobInitTestCase {
    pub(super) _ephemeral_datastore: EphemeralDatastore,
    pub(super) aggregation_job_init_req: AggregateInitializeReq<TimeInterval>,
    pub(super) auth_token: AuthenticationToken,
    pub(super) clock: MockClock,
    pub(super) config: Config,
    pub(super) datastore: Arc<Datastore<MockClock>>,
    pub(super) handler: Box<dyn Handler>,
    pub(super) hpke_key: HpkeKeypair,
    pub(super) report_share_generator: ReportShareGenerator,
    pub(super) report_shares: Vec<ReportShare>,
    pub(super) task: Task,
    pub(super) task_config_encoded: Vec<u8>,
    pub(super) vdaf: Prio3Aes128Count,
    pub(super) verify_key_init: VerifyKeyInit,
}

pub(super) async fn setup_aggregate_init_test() -> AggregationJobInitTestCase {
    let test_case = setup_aggregate_init_test_without_sending_request().await;

    let response = post_aggregation_job(
        &test_case.task,
        &test_case.aggregation_job_init_req,
        &test_case.handler,
        &test_case.auth_token,
    )
    .await;
    assert_eq!(response.status(), Some(Status::Ok));

    test_case
}

pub(super) async fn setup_aggregate_init_test_without_sending_request() -> AggregationJobInitTestCase
{
    install_test_trace_subscriber();

    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    let global_hpke_key = generate_test_hpke_config_and_private_key();
    datastore
        .run_tx(|tx| {
            let global_hpke_key = global_hpke_key.clone();
            Box::pin(async move {
                tx.put_global_hpke_keypair(&global_hpke_key).await.unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

    let auth_token: AuthenticationToken = random();
    let verify_key_init: VerifyKeyInit = random();

    let tolerable_clock_skew = Duration::from_seconds(60);
    let config = Config {
        auth_tokens: vec![auth_token.clone()],
        verify_key_init,
        tolerable_clock_skew,
        ..Default::default()
    };

    let handler = aggregator_handler(
        Arc::clone(&datastore),
        clock.clone(),
        &noop_meter(),
        config.clone(),
    )
    .await
    .unwrap();

    let vdaf = Prio3Aes128Count::new_aes128_count(2).unwrap();

    let time_precision = Duration::from_seconds(1);
    let max_batch_query_count = 1;
    let min_batch_size = 1;
    let task_expiration = clock.now().add(&Duration::from_hours(24).unwrap()).unwrap();
    let task_config = TaskConfig::new(
        Vec::from("foobar".as_bytes()),
        Vec::from([
            "https://leader.example.com/".as_bytes().try_into().unwrap(),
            "https://helper.example.com/".as_bytes().try_into().unwrap(),
        ]),
        QueryConfig::new(
            time_precision,
            max_batch_query_count,
            min_batch_size,
            Query::TimeInterval,
        ),
        task_expiration,
        VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Aes128Count).unwrap(),
    )
    .unwrap();

    let task_config_encoded = task_config.get_encoded();

    let task_id = TaskId::try_from(digest(&SHA256, &task_config_encoded).as_ref()).unwrap();
    let vdaf_instance = task_config.vdaf_config().vdaf_type().try_into().unwrap();
    let vdaf_verify_key = verify_key_init.derive_vdaf_verify_key(&task_id, &vdaf_instance);

    let task = janus_aggregator_core::taskprov::Task::new(
        task_id,
        Vec::from([
            url::Url::parse("https://leader.example.com/").unwrap(),
            url::Url::parse("https://helper.example.com/").unwrap(),
        ]),
        QueryType::TimeInterval,
        vdaf_instance,
        Role::Helper,
        Vec::from([vdaf_verify_key.clone()]),
        max_batch_query_count as u64,
        Some(task_expiration),
        config.report_expiry_age,
        min_batch_size as u64,
        Duration::from_seconds(1),
        tolerable_clock_skew,
    )
    .unwrap();

    let report_share_generator = ReportShareGenerator::new(
        clock.clone(),
        global_hpke_key.config().clone(),
        task_config_encoded.clone(),
        task_id,
        *task.task().time_precision(),
        vdaf_verify_key,
    );
    let report_shares = Vec::from([
        report_share_generator.next().0,
        report_share_generator.next().0,
    ]);

    let aggregation_job_init_req = AggregateInitializeReq::new(
        task_id,
        random(),
        ().get_encoded(),
        PartialBatchSelector::new_time_interval(),
        report_shares.clone(),
    );

    AggregationJobInitTestCase {
        _ephemeral_datastore: ephemeral_datastore,
        aggregation_job_init_req,
        auth_token,
        clock,
        config,
        datastore,
        handler: Box::new(handler),
        hpke_key: global_hpke_key,
        report_share_generator,
        report_shares,
        task_config_encoded,
        task: task.into(),
        vdaf,
        verify_key_init,
    }
}

pub(crate) async fn post_aggregation_job(
    task: &Task,
    aggregation_job: &AggregateInitializeReq<TimeInterval>,
    handler: &impl Handler,
    auth_token: &AuthenticationToken,
) -> TestConn {
    let auth = auth_token.request_authentication();
    post(task.aggregation_job_uri().unwrap().path())
        .with_request_header(auth.0, auth.1)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(aggregation_job.get_encoded())
        .run_async(handler)
        .await
}

#[rstest::rstest]
#[case::not_bearer_token("wrong kind of token")]
#[case::not_base64("Bearer: ")]
#[tokio::test]
async fn aggregation_job_init_malformed_authorization_header(#[case] header_value: &'static str) {
    let test_case = setup_aggregate_init_test_without_sending_request().await;

    let response = post(test_case.task.aggregation_job_uri().unwrap().path())
        // Authenticate using a malformed "Authorization: Bearer <token>" header and a `DAP-Auth-Token`
        // header. The presence of the former should cause an error despite the latter being present and
        // well formed.
        .with_request_header(KnownHeaderName::Authorization, header_value.to_string())
        .with_request_header(
            DAP_AUTH_HEADER,
            test_case.auth_token.request_authentication().1,
        )
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(test_case.aggregation_job_init_req.get_encoded())
        .run_async(&test_case.handler)
        .await;

    assert_eq!(response.status(), Some(Status::BadRequest));
}

#[tokio::test]
#[ignore = "subscriber-01 only: since we use Prio as the test VDAF, we cannot exercise different \
    aggregation parameters"]
async fn aggregation_job_mutation_aggregation_job() {
    let test_case = setup_aggregate_init_test().await;

    // Put the aggregation job again, but with a different aggregation parameter.
    let mutated_aggregation_job_init_req = AggregateInitializeReq::new(
        *test_case.task.id(),
        *test_case.aggregation_job_init_req.job_id(),
        dummy_vdaf::AggregationParam(1).get_encoded(),
        PartialBatchSelector::new_time_interval(),
        test_case.report_shares,
    );

    let response = post_aggregation_job(
        &test_case.task,
        &mutated_aggregation_job_init_req,
        &test_case.handler,
        &test_case.auth_token,
    )
    .await;
    assert_eq!(response.status(), Some(Status::InternalServerError));
}

#[tokio::test]
async fn aggregation_job_mutation_report_shares() {
    let test_case = setup_aggregate_init_test().await;

    // Put the aggregation job again, mutating the associated report shares' metadata such that
    // uniqueness constraints on client_reports are violated
    for mutated_report_shares in [
        // Omit a report share that was included previously
        Vec::from(&test_case.report_shares[0..test_case.report_shares.len() - 1]),
        // Include a different report share than was included previously
        [
            &test_case.report_shares[0..test_case.report_shares.len() - 1],
            &[test_case.report_share_generator.next().0],
        ]
        .concat(),
        // Include an extra report share than was included previously
        [
            test_case.report_shares.as_slice(),
            &[test_case.report_share_generator.next().0],
        ]
        .concat(),
        // Reverse the order of the reports
        test_case.report_shares.into_iter().rev().collect(),
    ] {
        let mutated_aggregation_job_init_req = AggregateInitializeReq::new(
            *test_case.task.id(),
            *test_case.aggregation_job_init_req.job_id(),
            ().get_encoded(),
            PartialBatchSelector::new_time_interval(),
            mutated_report_shares,
        );
        let response = post_aggregation_job(
            &test_case.task,
            &mutated_aggregation_job_init_req,
            &test_case.handler,
            &test_case.auth_token,
        )
        .await;
        assert_eq!(response.status(), Some(Status::InternalServerError));
    }
}

#[tokio::test]
async fn aggregation_job_mutation_report_aggregations() {
    let test_case = setup_aggregate_init_test().await;

    // Generate some new reports using the existing reports' metadata, but varying the input shares
    // such that the prepare state computed during aggregation initializaton won't match the first
    // aggregation job.
    let mutated_report_shares_generator = test_case.report_share_generator.with_measurement(0);
    let mutated_report_shares = test_case
        .report_shares
        .iter()
        .map(|s| {
            mutated_report_shares_generator
                .next_with_metadata(s.metadata().clone())
                .0
        })
        .collect();

    let mutated_aggregation_job_init_req = AggregateInitializeReq::new(
        *test_case.task.id(),
        *test_case.aggregation_job_init_req.job_id(),
        ().get_encoded(),
        PartialBatchSelector::new_time_interval(),
        mutated_report_shares,
    );
    let response = post_aggregation_job(
        &test_case.task,
        &mutated_aggregation_job_init_req,
        &test_case.handler,
        &test_case.auth_token,
    )
    .await;
    assert_eq!(response.status(), Some(Status::InternalServerError));
}
