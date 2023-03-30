use crate::aggregator::{aggregator_filter, tests::generate_helper_report_init, Config};
use http::{header::CONTENT_TYPE, StatusCode};
use janus_aggregator_core::{
    datastore::{
        test_util::{ephemeral_datastore, EphemeralDatastore},
        Datastore,
    },
    task::{test_util::TaskBuilder, QueryType, Task},
};
use janus_core::{
    task::VdafInstance,
    test_util::{dummy_vdaf, install_test_trace_subscriber, run_vdaf, VdafTranscript},
    time::{Clock, MockClock, TimeExt as _},
};
use janus_messages::{
    query_type::TimeInterval, AggregationJobId, AggregationJobInitializeReq, PartialBatchSelector,
    ReportMetadata, ReportPrepInit, Role,
};
use prio::{codec::Encode, vdaf};
use rand::random;
use std::sync::Arc;
use warp::{filters::BoxedFilter, reply::Response, Reply};

pub(super) struct ReportInitGenerator<const SEED_SIZE: usize, V>
where
    V: vdaf::Vdaf,
{
    clock: MockClock,
    task: Task,
    vdaf: V,
    aggregation_param: V::AggregationParam,
}

impl<const SEED_SIZE: usize, V> ReportInitGenerator<SEED_SIZE, V>
where
    V: vdaf::Vdaf + vdaf::Aggregator<SEED_SIZE, 16> + vdaf::Client<16>,
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
    ) -> (ReportPrepInit, VdafTranscript<SEED_SIZE, V>) {
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
    ) -> (ReportPrepInit, VdafTranscript<SEED_SIZE, V>) {
        let transcript = run_vdaf(
            &self.vdaf,
            self.task.primary_vdaf_verify_key().unwrap().as_bytes(),
            &self.aggregation_param,
            report_metadata.id(),
            measurement,
        );
        let report_init = generate_helper_report_init::<SEED_SIZE, V>(
            *self.task.id(),
            report_metadata,
            self.task.current_hpke_key().config(),
            &transcript,
            Vec::new(),
        );
        (report_init, transcript)
    }
}

pub(super) struct AggregationJobInitTestCase<const SEED_SIZE: usize, R, V: vdaf::Vdaf> {
    pub(super) clock: MockClock,
    pub(super) task: Task,
    pub(super) report_init_generator: ReportInitGenerator<SEED_SIZE, V>,
    pub(super) report_inits: Vec<ReportPrepInit>,
    pub(super) aggregation_job_id: AggregationJobId,
    pub(super) aggregation_param: V::AggregationParam,
    pub(super) filter: BoxedFilter<(R,)>,
    pub(super) datastore: Arc<Datastore<MockClock>>,
    _ephemeral_datastore: EphemeralDatastore,
}

pub(super) async fn setup_aggregate_init_test(
) -> AggregationJobInitTestCase<0, impl Reply + 'static, dummy_vdaf::Vdaf> {
    install_test_trace_subscriber();

    let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Helper).build();
    let clock = MockClock::default();
    let ephemeral_datastore = ephemeral_datastore().await;
    let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()));

    datastore.put_task(&task).await.unwrap();

    let filter =
        aggregator_filter(Arc::clone(&datastore), clock.clone(), Config::default()).unwrap();

    let aggregation_param = dummy_vdaf::AggregationParam(0);

    let report_init_generator = ReportInitGenerator::new(
        clock.clone(),
        task.clone(),
        dummy_vdaf::Vdaf::new(),
        aggregation_param,
    );

    let report_inits = Vec::from([
        report_init_generator.next(&0).0,
        report_init_generator.next(&0).0,
    ]);

    let aggregation_job_id = random();
    let aggregation_job_init_req = AggregationJobInitializeReq::new(
        aggregation_param.get_encoded(),
        PartialBatchSelector::new_time_interval(),
        report_inits.clone(),
    );

    let response = put_aggregation_job(
        &task,
        &aggregation_job_id,
        &aggregation_job_init_req,
        &filter,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    AggregationJobInitTestCase {
        clock,
        task,
        report_inits,
        report_init_generator,
        aggregation_job_id,
        aggregation_param,
        filter,
        datastore,
        _ephemeral_datastore: ephemeral_datastore,
    }
}

pub(crate) async fn put_aggregation_job(
    task: &Task,
    aggregation_job_id: &AggregationJobId,
    aggregation_job: &AggregationJobInitializeReq<TimeInterval>,
    filter: &BoxedFilter<(impl Reply + 'static,)>,
) -> Response {
    warp::test::request()
        .method("PUT")
        .path(task.aggregation_job_uri(aggregation_job_id).unwrap().path())
        .header(
            "DAP-Auth-Token",
            task.primary_aggregator_auth_token().as_bytes(),
        )
        .header(
            CONTENT_TYPE,
            AggregationJobInitializeReq::<TimeInterval>::MEDIA_TYPE,
        )
        .body(aggregation_job.get_encoded())
        .filter(filter)
        .await
        .unwrap()
        .into_response()
}

#[tokio::test]
async fn aggregation_job_mutation_aggregation_job() {
    let test_case = setup_aggregate_init_test().await;

    // Put the aggregation job again, but with a different aggregation parameter.
    let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
        dummy_vdaf::AggregationParam(1).get_encoded(),
        PartialBatchSelector::new_time_interval(),
        test_case.report_inits,
    );

    let response = put_aggregation_job(
        &test_case.task,
        &test_case.aggregation_job_id,
        &mutated_aggregation_job_init_req,
        &test_case.filter,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn aggregation_job_mutation_report_shares() {
    let test_case = setup_aggregate_init_test().await;

    // Put the aggregation job again, mutating the associated report shares' metadata such that
    // uniqueness constraints on client_reports are violated
    for mutated_report_inits in [
        // Omit a report share that was included previously
        Vec::from(&test_case.report_inits[0..test_case.report_inits.len() - 1]),
        // Include a different report share than was included previously
        [
            &test_case.report_inits[0..test_case.report_inits.len() - 1],
            &[test_case.report_init_generator.next(&0).0],
        ]
        .concat(),
        // Include an extra report share than was included previously
        [
            test_case.report_inits.as_slice(),
            &[test_case.report_init_generator.next(&0).0],
        ]
        .concat(),
        // Reverse the order of the reports
        test_case.report_inits.into_iter().rev().collect(),
    ] {
        let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
            test_case.aggregation_param.get_encoded(),
            PartialBatchSelector::new_time_interval(),
            mutated_report_inits,
        );
        let response = put_aggregation_job(
            &test_case.task,
            &test_case.aggregation_job_id,
            &mutated_aggregation_job_init_req,
            &test_case.filter,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}

#[tokio::test]
async fn aggregation_job_mutation_report_aggregations() {
    let test_case = setup_aggregate_init_test().await;

    // Generate some new reports using the existing reports' metadata, but varying the measurement
    // values such that the prepare state computed during aggregation initializaton won't match the
    // first aggregation job.
    let mutated_report_inits = test_case
        .report_inits
        .iter()
        .map(|s| {
            test_case
                .report_init_generator
                .next_with_metadata(s.report_share().metadata().clone(), &1)
                .0
        })
        .collect();

    let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
        test_case.aggregation_param.get_encoded(),
        PartialBatchSelector::new_time_interval(),
        mutated_report_inits,
    );
    let response = put_aggregation_job(
        &test_case.task,
        &test_case.aggregation_job_id,
        &mutated_aggregation_job_init_req,
        &test_case.filter,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
