use assert_matches::assert_matches;
use http::StatusCode;
use janus_aggregator_core::task::BatchMode;
use janus_core::report_id::ReportIdChecksumExt;
use janus_messages::{
    AggregateShareReq, AggregationJobExtension, AggregationJobInitializeReq, AggregationJobResp,
    BatchSelector, CollectionJobReq, Query, ReportError, ReportIdChecksum, VerifyStepResult,
    batch_mode::LeaderSelected,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::dummy,
};
use rand::random;

use crate::aggregator::{
    aggregation_job_init::test_util::{VerifyInitGenerator, put_aggregation_job},
    http_handlers::{
        test_util::take_response_body, tests::aggregate_share::AggregateShareTestCase,
    },
};

/// Send multiple aggregation job requests and aggregate share requests for a negative test that
/// reports cannot be aggregated with the same aggregation parameter into multiple batches.
#[tokio::test]
async fn helper_aggregation_report_share_replay() {
    let test_case = AggregateShareTestCase::builder()
        .build_task(|task_builder| {
            task_builder
                .with_batch_mode(BatchMode::LeaderSelected {
                    batch_time_window_size: None,
                })
                .with_min_batch_size(1)
        })
        .build()
        .await;

    let vdaf = dummy::Vdaf::new(1);
    let agg_param = dummy::AggregationParam(0);

    let verify_init_generator = VerifyInitGenerator::new(
        test_case.test.clock.clone(),
        test_case.task.helper_view().unwrap(),
        test_case.test.hpke_keypair.config().clone(),
        vdaf.clone(),
        agg_param,
    );
    let (replayed_report, _replayed_report_transcript) = verify_init_generator.next(&7);
    let (other_report_1, _other_report_1_transcript) = verify_init_generator.next(&11);
    let (other_report_2, _other_report_2_transcript) = verify_init_generator.next(&23);

    let batch_id_1 = random();
    let batch_id_2 = random();
    let aggregation_job_id_1 = random();
    let aggregation_job_id_2 = random();

    let agg_init_req_1 = AggregationJobInitializeReq::new(
        0,
        agg_param.get_encoded().unwrap(),
        Vec::from([AggregationJobExtension::leader_selected_batch_id(
            &batch_id_1,
        )]),
        Vec::from([replayed_report.clone(), other_report_1.clone()]),
    );
    let agg_init_req_2 = AggregationJobInitializeReq::new(
        0,
        agg_param.get_encoded().unwrap(),
        Vec::from([AggregationJobExtension::leader_selected_batch_id(
            &batch_id_2,
        )]),
        Vec::from([replayed_report.clone(), other_report_2.clone()]),
    );

    let checksum_1 =
        ReportIdChecksum::for_report_id(replayed_report.report_share().metadata().id())
            .updated_with(other_report_1.report_share().metadata().id());
    let agg_share_req_1 = AggregateShareReq::<LeaderSelected>::new(
        CollectionJobReq::new(
            Query::new_leader_selected(random()),
            agg_param.get_encoded().unwrap(),
        ),
        BatchSelector::new(batch_id_1),
        2,
        checksum_1,
    );
    let checksum_2 = ReportIdChecksum::for_report_id(other_report_2.report_share().metadata().id());
    let agg_share_req_2 = AggregateShareReq::<LeaderSelected>::new(
        CollectionJobReq::new(
            Query::new_leader_selected(random()),
            agg_param.get_encoded().unwrap(),
        ),
        BatchSelector::new(batch_id_2),
        1,
        checksum_2,
    );

    // Make aggregation job initialization requests, and check the verify step results.
    let mut response = put_aggregation_job(
        &test_case.task,
        &aggregation_job_id_1,
        &agg_init_req_1,
        &test_case.test.router,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let agg_init_resp_1 =
        AggregationJobResp::get_decoded(take_response_body(&mut response).await.as_ref()).unwrap();
    let verify_resps_1 = assert_matches!(
        agg_init_resp_1,
        AggregationJobResp { verify_resps } => verify_resps
    );
    assert_matches!(
        verify_resps_1[0].result(),
        VerifyStepResult::Continue { .. }
    );
    assert_matches!(
        verify_resps_1[1].result(),
        VerifyStepResult::Continue { .. }
    );

    let mut response = put_aggregation_job(
        &test_case.task,
        &aggregation_job_id_2,
        &agg_init_req_2,
        &test_case.test.router,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let agg_init_resp_2 =
        AggregationJobResp::get_decoded(take_response_body(&mut response).await.as_ref()).unwrap();
    let verify_resps_2 = assert_matches!(
        agg_init_resp_2,
        AggregationJobResp { verify_resps } => verify_resps
    );
    assert_matches!(
        verify_resps_2[0].result(),
        VerifyStepResult::Reject(ReportError::ReportReplayed)
    );
    assert_matches!(
        verify_resps_2[1].result(),
        VerifyStepResult::Continue { .. }
    );

    // Make aggregate share requests. If these succeed, then the helper's report_count and checksum
    // match those in the requests.
    let response = test_case
        .post_aggregate_share_request(&agg_share_req_1)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = test_case
        .post_aggregate_share_request(&agg_share_req_2)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}
