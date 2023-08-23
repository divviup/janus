use crate::aggregator::{
    http_handlers::aggregator_handler, tests::generate_helper_report_share, Config,
};
use janus_aggregator_core::{
    datastore::{
        test_util::{ephemeral_datastore, EphemeralDatastore},
        Datastore,
    },
    task::{test_util::TaskBuilder, QueryType, Task},
    test_util::noop_meter,
};
use janus_core::{
    task::{AuthenticationToken, VdafInstance, DAP_AUTH_HEADER},
    test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf, VdafTranscript},
    time::{Clock, MockClock, TimeExt as _},
};
use janus_messages::{
    query_type::TimeInterval, AggregationJobId, AggregationJobInitializeReq, PartialBatchSelector,
    PrepareInit, ReportMetadata, Role,
};
use prio::{
    codec::Encode,
    idpf::IdpfInput,
    vdaf::{
        self,
        poplar1::{Poplar1, Poplar1AggregationParam},
    },
};
use rand::random;
use std::sync::Arc;
use trillium::{Handler, KnownHeaderName, Status};
use trillium_testing::{prelude::put, TestConn};

pub(super) struct PrepareInitGenerator<const VERIFY_KEY_SIZE: usize, V>
where
    V: vdaf::Vdaf,
{
    clock: MockClock,
    task: Task,
    vdaf: V,
    aggregation_param: V::AggregationParam,
}

impl<const VERIFY_KEY_SIZE: usize, V> PrepareInitGenerator<VERIFY_KEY_SIZE, V>
where
    V: vdaf::Vdaf + vdaf::Aggregator<VERIFY_KEY_SIZE, 16> + vdaf::Client<16>,
{
    pub(super) fn new(
        clock: MockClock,
        task: Task,
        vdaf: V,
        aggregation_param: V::AggregationParam,
    ) -> Self {
        Self {
            clock,
            task,
            vdaf,
            aggregation_param,
        }
    }

    pub(super) fn next(
        &self,
        measurement: &V::Measurement,
    ) -> (PrepareInit, VdafTranscript<VERIFY_KEY_SIZE, V>) {
        self.next_with_metadata(
            ReportMetadata::new(
                random(),
                self.clock
                    .now()
                    .to_batch_interval_start(self.task.time_precision())
                    .unwrap(),
            ),
            measurement,
        )
    }

    pub(super) fn next_with_metadata(
        &self,
        report_metadata: ReportMetadata,
        measurement: &V::Measurement,
    ) -> (PrepareInit, VdafTranscript<VERIFY_KEY_SIZE, V>) {
        let transcript = run_vdaf(
            &self.vdaf,
            self.task.primary_vdaf_verify_key().unwrap().as_bytes(),
            &self.aggregation_param,
            report_metadata.id(),
            measurement,
        );
        let report_share = generate_helper_report_share::<V>(
            *self.task.id(),
            report_metadata,
            self.task.current_hpke_key().config(),
            &transcript.public_share,
            Vec::new(),
            &transcript.helper_input_share,
        );
        (
            PrepareInit::new(
                report_share,
                transcript.leader_prepare_transitions[0].2.clone(),
            ),
            transcript,
        )
    }
}

pub(super) struct AggregationJobInitTestCase<
    const VERIFY_KEY_SIZE: usize,
    V: vdaf::Aggregator<VERIFY_KEY_SIZE, 16>,
> {
    pub(super) clock: MockClock,
    pub(super) task: Task,
    pub(super) prepare_init_generator: PrepareInitGenerator<VERIFY_KEY_SIZE, V>,
    pub(super) prepare_inits: Vec<PrepareInit>,
    pub(super) aggregation_job_id: AggregationJobId,
    aggregation_job_init_req: AggregationJobInitializeReq<TimeInterval>,
    pub(super) aggregation_param: V::AggregationParam,
    pub(super) handler: Box<dyn Handler>,
    pub(super) datastore: Arc<Datastore<MockClock>>,
    _ephemeral_datastore: EphemeralDatastore,
}

pub(super) async fn setup_aggregate_init_test() -> AggregationJobInitTestCase<0, dummy_vdaf::Vdaf> {
    setup_aggregate_init_test_for_vdaf(
        dummy_vdaf::Vdaf::new(),
        VdafInstance::Fake,
        dummy_vdaf::AggregationParam(0),
        0,
    )
    .await
}

async fn setup_aggregate_init_test_for_vdaf<
    const VERIFY_KEY_SIZE: usize,
    V: vdaf::Aggregator<VERIFY_KEY_SIZE, 16> + vdaf::Client<16>,
>(
    vdaf: V,
    vdaf_instance: VdafInstance,
    aggregation_param: V::AggregationParam,
    measurement: V::Measurement,
) -> AggregationJobInitTestCase<VERIFY_KEY_SIZE, V> {
    let test_case = setup_aggregate_init_test_without_sending_request(
        vdaf,
        vdaf_instance,
        aggregation_param,
        measurement,
    )
    .await;

    let response = put_aggregation_job(
        &test_case.task,
        &test_case.aggregation_job_id,
        &test_case.aggregation_job_init_req,
        &test_case.handler,
    )
    .await;
    assert_eq!(response.status(), Some(Status::Ok));

    test_case
}

async fn setup_aggregate_init_test_without_sending_request<
    const VERIFY_KEY_SIZE: usize,
    V: vdaf::Aggregator<VERIFY_KEY_SIZE, 16> + vdaf::Client<16>,
>(
    vdaf: V,
    vdaf_instance: VdafInstance,
    aggregation_param: V::AggregationParam,
    measurement: V::Measurement,
) -> AggregationJobInitTestCase<VERIFY_KEY_SIZE, V> {
    install_test_trace_subscriber();

    let task = TaskBuilder::new(QueryType::TimeInterval, vdaf_instance, Role::Helper).build();
    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

    datastore.put_task(&task).await.unwrap();

    let handler = aggregator_handler(
        Arc::clone(&datastore),
        clock.clone(),
        &noop_meter(),
        Config::default(),
    )
    .await
    .unwrap();

    let prepare_init_generator =
        PrepareInitGenerator::new(clock.clone(), task.clone(), vdaf, aggregation_param.clone());

    let prepare_inits = Vec::from([
        prepare_init_generator.next(&measurement).0,
        prepare_init_generator.next(&measurement).0,
    ]);

    let aggregation_job_id = random();
    let aggregation_job_init_req = AggregationJobInitializeReq::new(
        aggregation_param.get_encoded(),
        PartialBatchSelector::new_time_interval(),
        prepare_inits.clone(),
    );

    AggregationJobInitTestCase {
        clock,
        task,
        prepare_inits,
        prepare_init_generator,
        aggregation_job_id,
        aggregation_job_init_req,
        aggregation_param,
        handler: Box::new(handler),
        datastore,
        _ephemeral_datastore: ephemeral_datastore,
    }
}

pub(crate) async fn put_aggregation_job(
    task: &Task,
    aggregation_job_id: &AggregationJobId,
    aggregation_job: &AggregationJobInitializeReq<TimeInterval>,
    handler: &impl Handler,
) -> TestConn {
    put(task.aggregation_job_uri(aggregation_job_id).unwrap().path())
        .with_request_header(
            DAP_AUTH_HEADER,
            task.primary_aggregator_auth_token().as_ref().to_owned(),
        )
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .with_request_body(aggregation_job.get_encoded())
        .run_async(handler)
        .await
}

#[tokio::test]
async fn aggregation_job_init_authorization_dap_auth_token() {
    let test_case = setup_aggregate_init_test_without_sending_request(
        dummy_vdaf::Vdaf::new(),
        VdafInstance::Fake,
        dummy_vdaf::AggregationParam(0),
        0,
    )
    .await;
    // Find a DapAuthToken among the task's aggregator auth tokens
    let (auth_header, auth_value) = test_case
        .task
        .aggregator_auth_tokens()
        .iter()
        .find(|auth| matches!(auth, AuthenticationToken::DapAuth(_)))
        .unwrap()
        .request_authentication();

    let response = put(test_case
        .task
        .aggregation_job_uri(&test_case.aggregation_job_id)
        .unwrap()
        .path())
    .with_request_header(auth_header, auth_value)
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
    )
    .with_request_body(test_case.aggregation_job_init_req.get_encoded())
    .run_async(&test_case.handler)
    .await;

    assert_eq!(response.status(), Some(Status::Ok));
}

#[rstest::rstest]
#[case::not_bearer_token("wrong kind of token")]
#[case::not_base64("Bearer: ")]
#[tokio::test]
async fn aggregation_job_init_malformed_authorization_header(#[case] header_value: &'static str) {
    let test_case = setup_aggregate_init_test_without_sending_request(
        dummy_vdaf::Vdaf::new(),
        VdafInstance::Fake,
        dummy_vdaf::AggregationParam(0),
        0,
    )
    .await;

    let response = put(test_case
        .task
        .aggregation_job_uri(&test_case.aggregation_job_id)
        .unwrap()
        .path())
    // Authenticate using a malformed "Authorization: Bearer <token>" header and a `DAP-Auth-Token`
    // header. The presence of the former should cause an error despite the latter being present and
    // well formed.
    .with_request_header(KnownHeaderName::Authorization, header_value.to_string())
    .with_request_header(
        DAP_AUTH_HEADER,
        test_case
            .task
            .primary_aggregator_auth_token()
            .as_ref()
            .to_owned(),
    )
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
    )
    .with_request_body(test_case.aggregation_job_init_req.get_encoded())
    .run_async(&test_case.handler)
    .await;

    assert_eq!(response.status(), Some(Status::BadRequest));
}

#[tokio::test]
async fn aggregation_job_mutation_aggregation_job() {
    let test_case = setup_aggregate_init_test().await;

    // Put the aggregation job again, but with a different aggregation parameter.
    let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
        dummy_vdaf::AggregationParam(1).get_encoded(),
        PartialBatchSelector::new_time_interval(),
        test_case.prepare_inits,
    );

    let response = put_aggregation_job(
        &test_case.task,
        &test_case.aggregation_job_id,
        &mutated_aggregation_job_init_req,
        &test_case.handler,
    )
    .await;
    assert_eq!(response.status(), Some(Status::Conflict));
}

#[tokio::test]
async fn aggregation_job_mutation_report_shares() {
    let test_case = setup_aggregate_init_test().await;

    // Put the aggregation job again, mutating the associated report shares' metadata such that
    // uniqueness constraints on client_reports are violated
    for mutated_prepare_inits in [
        // Omit a report share that was included previously
        Vec::from(&test_case.prepare_inits[0..test_case.prepare_inits.len() - 1]),
        // Include a different report share than was included previously
        [
            &test_case.prepare_inits[0..test_case.prepare_inits.len() - 1],
            &[test_case.prepare_init_generator.next(&0).0],
        ]
        .concat(),
        // Include an extra report share than was included previously
        [
            test_case.prepare_inits.as_slice(),
            &[test_case.prepare_init_generator.next(&0).0],
        ]
        .concat(),
        // Reverse the order of the reports
        test_case.prepare_inits.into_iter().rev().collect(),
    ] {
        let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
            test_case.aggregation_param.get_encoded(),
            PartialBatchSelector::new_time_interval(),
            mutated_prepare_inits,
        );
        let response = put_aggregation_job(
            &test_case.task,
            &test_case.aggregation_job_id,
            &mutated_aggregation_job_init_req,
            &test_case.handler,
        )
        .await;
        assert_eq!(response.status(), Some(Status::Conflict));
    }
}

#[tokio::test]
async fn aggregation_job_mutation_report_aggregations() {
    // We must run Poplar1 in this test so that the aggregation job won't finish on the first step

    let aggregation_param =
        Poplar1AggregationParam::try_from_prefixes(Vec::from([IdpfInput::from_bools(&[false])]))
            .unwrap();
    let test_case = setup_aggregate_init_test_for_vdaf(
        Poplar1::new_sha3(1),
        VdafInstance::Poplar1 { bits: 1 },
        aggregation_param,
        IdpfInput::from_bools(&[true]),
    )
    .await;

    // Generate some new reports using the existing reports' metadata, but varying the measurement
    // values such that the prepare state computed during aggregation initializaton won't match the
    // first aggregation job.
    let mutated_prepare_inits = test_case
        .prepare_inits
        .iter()
        .map(|s| {
            test_case
                .prepare_init_generator
                .next_with_metadata(
                    s.report_share().metadata().clone(),
                    &IdpfInput::from_bools(&[false]),
                )
                .0
        })
        .collect();

    let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
        test_case.aggregation_param.get_encoded(),
        PartialBatchSelector::new_time_interval(),
        mutated_prepare_inits,
    );

    tracing::info!("putting mutated agg job");
    let response = put_aggregation_job(
        &test_case.task,
        &test_case.aggregation_job_id,
        &mutated_aggregation_job_init_req,
        &test_case.handler,
    )
    .await;
    assert_eq!(response.status(), Some(Status::Conflict));
}
