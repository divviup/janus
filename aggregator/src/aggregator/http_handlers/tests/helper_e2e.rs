use assert_matches::assert_matches;
use janus_aggregator_core::task::{test_util::TaskBuilder, QueryType};
use janus_core::{report_id::ReportIdChecksumExt, vdaf::VdafInstance};
use janus_messages::{
    query_type::FixedSize, AggregateShareReq, AggregationJobInitializeReq, AggregationJobResp,
    BatchSelector, PartialBatchSelector, PrepareError, PrepareStepResult, ReportIdChecksum,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::prio3::Prio3,
};
use rand::random;
use trillium::KnownHeaderName;
use trillium_testing::{assert_status, methods::post};

use crate::aggregator::{
    aggregate_init_tests::{put_aggregation_job, PrepareInitGenerator},
    http_handlers::test_util::{setup_http_handler_test, take_response_body},
};

/// Send multiple aggregation job requests and aggregate share requests for a negative test that
/// reports cannot be aggregated with the same aggregation parameter into multiple batches.
#[tokio::test]
async fn helper_aggregation_report_share_replay() {
    let (clock, _ephemeral_datastore, datastore, handler) = setup_http_handler_test().await;

    let task = TaskBuilder::new(
        QueryType::FixedSize {
            max_batch_size: None,
            batch_time_window_size: None,
        },
        VdafInstance::Prio3SumVec {
            bits: 1,
            length: 3,
            chunk_length: 3,
        },
    )
    .with_min_batch_size(1)
    .with_max_batch_query_count(1)
    .build();
    let vdaf = Prio3::new_sum_vec(2, 1, 3, 3).unwrap();

    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    let prep_init_generator =
        PrepareInitGenerator::new(clock.clone(), helper_task.clone(), vdaf.clone(), ());
    let (replayed_report, _replayed_report_transcript) =
        prep_init_generator.next(&Vec::from([1, 0, 0]));
    let (other_report_1, _other_report_1_transcript) =
        prep_init_generator.next(&Vec::from([0, 1, 0]));
    let (other_report_2, _other_report_2_transcript) =
        prep_init_generator.next(&Vec::from([0, 0, 1]));

    let batch_id_1 = random();
    let batch_id_2 = random();
    let aggregation_job_id_1 = random();
    let aggregation_job_id_2 = random();

    let agg_init_req_1 = AggregationJobInitializeReq::new(
        Vec::new(),
        PartialBatchSelector::new_fixed_size(batch_id_1),
        Vec::from([replayed_report.clone(), other_report_1.clone()]),
    );
    let agg_init_req_2 = AggregationJobInitializeReq::new(
        Vec::new(),
        PartialBatchSelector::new_fixed_size(batch_id_2),
        Vec::from([replayed_report.clone(), other_report_2.clone()]),
    );

    let checksum_1 =
        ReportIdChecksum::for_report_id(replayed_report.report_share().metadata().id())
            .updated_with(other_report_1.report_share().metadata().id());
    let agg_share_req_1 = AggregateShareReq::<FixedSize>::new(
        BatchSelector::new(batch_id_1),
        Vec::new(),
        2,
        checksum_1,
    );
    let checksum_2 = ReportIdChecksum::for_report_id(other_report_2.report_share().metadata().id());
    let agg_share_req_2 = AggregateShareReq::<FixedSize>::new(
        BatchSelector::new(batch_id_2),
        Vec::new(),
        1,
        checksum_2,
    );

    // Make aggregation job initialization requests, and check the prepare step results.
    let mut test_conn =
        put_aggregation_job(&task, &aggregation_job_id_1, &agg_init_req_1, &handler).await;
    assert_status!(test_conn, 200);
    let agg_init_resp_1 =
        AggregationJobResp::get_decoded(take_response_body(&mut test_conn).await.as_ref()).unwrap();
    assert_matches!(
        agg_init_resp_1.prepare_resps()[0].result(),
        PrepareStepResult::Continue { .. }
    );
    assert_matches!(
        agg_init_resp_1.prepare_resps()[1].result(),
        PrepareStepResult::Continue { .. }
    );

    let mut test_conn =
        put_aggregation_job(&task, &aggregation_job_id_2, &agg_init_req_2, &handler).await;
    assert_status!(test_conn, 200);
    let agg_init_resp_2 =
        AggregationJobResp::get_decoded(take_response_body(&mut test_conn).await.as_ref()).unwrap();
    assert_matches!(
        agg_init_resp_2.prepare_resps()[0].result(),
        PrepareStepResult::Reject(PrepareError::ReportReplayed)
    );
    assert_matches!(
        agg_init_resp_2.prepare_resps()[1].result(),
        PrepareStepResult::Continue { .. }
    );

    // Make aggregate share requests. If these succeed, then the helper's report_count and checksum
    // match those in the requests.
    let (auth_header, auth_value) = task.aggregator_auth_token().request_authentication();
    let test_conn = post(task.aggregate_shares_uri().unwrap().path())
        .with_request_header(auth_header, auth_value)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateShareReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_body(agg_share_req_1.get_encoded().unwrap())
        .run_async(&handler)
        .await;
    assert_status!(test_conn, 200);

    let (auth_header, auth_value) = task.aggregator_auth_token().request_authentication();
    let test_conn = post(task.aggregate_shares_uri().unwrap().path())
        .with_request_header(auth_header, auth_value)
        .with_request_header(
            KnownHeaderName::ContentType,
            AggregateShareReq::<FixedSize>::MEDIA_TYPE,
        )
        .with_request_body(agg_share_req_2.get_encoded().unwrap())
        .run_async(&handler)
        .await;
    assert_status!(test_conn, 200);
}
