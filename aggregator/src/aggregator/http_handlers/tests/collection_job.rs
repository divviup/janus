use chrono::TimeDelta;
use http::StatusCode;
use janus_aggregator_core::task::BatchMode;
use janus_core::time::{Clock, DateTimeExt, TimeExt};
use janus_messages::{
    CollectionJobExtension, CollectionJobExtensionType, CollectionJobId, CollectionJobReq,
    CollectionJobResp, Duration, Interval, MediaType, Query, Role, Time,
};
use prio::{codec::Encode, vdaf::dummy};
use rand::random;
use serde_json::json;

use crate::aggregator::{
    collection_job_tests::{CollectionJobTestCase, ids_from_collection_job_response},
    http_handlers::test_util::{decode_response_body, take_problem_details},
};

#[tokio::test]
async fn collection_job_post_request_to_helper() {
    let test_case = CollectionJobTestCase::builder()
        .with_role(Role::Helper)
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    let request = CollectionJobReq::new(
        Query::new_time_interval(
            Interval::minimal(Time::from_seconds_since_epoch(
                0,
                test_case.task.time_precision(),
            ))
            .unwrap(),
        ),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    );

    let mut response = test_case
        .post_collection_job_with_auth_token(&request, Some(&random()))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            "title": "An endpoint received a message with an unknown task ID.",
            "taskid": format!("{}", test_case.task.id()),
        })
    );
}

#[tokio::test]
async fn collection_job_post_request_invalid_batch_interval() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    let request = CollectionJobReq::new(
        Query::new_time_interval(
            Interval::new(
                Time::from_time_precision_units(0),
                // Collect request will be rejected because batch interval is too small
                Duration::from_seconds(
                    test_case.task.time_precision().as_seconds() - 1,
                    test_case.task.time_precision(),
                ),
            )
            .unwrap(),
        ),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    );

    let mut response = test_case.post_collection_job(&request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
            "title": "The batch implied by the query is invalid.",
            "taskid": format!("{}", test_case.task.id()),
        })
    );
}

#[tokio::test]
async fn collection_job_post_request_invalid_aggregation_parameter() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    let request = CollectionJobReq::new(
        Query::new_time_interval(
            Interval::minimal(Time::from_seconds_since_epoch(
                0,
                test_case.task.time_precision(),
            ))
            .unwrap(),
        ),
        // dummy::AggregationParam is a tuple struct wrapping a u8, so this is not a valid
        // encoding of an aggregation parameter.
        Vec::from([0u8, 0u8]),
    );

    let mut response = test_case.post_collection_job(&request).await;

    // Collect request will be rejected because the aggregation parameter can't be decoded
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
            "title": "The message type for a response was incorrect or the payload was malformed.",
        })
    );
}

#[tokio::test]
async fn collection_job_post_request_unsupported_extension() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    // No collection job extension types are defined, so any extension is unsupported.
    let request = CollectionJobReq::new(
        Query::new_time_interval(
            Interval::minimal(Time::from_seconds_since_epoch(
                0,
                test_case.task.time_precision(),
            ))
            .unwrap(),
        ),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    )
    .with_extensions(Vec::from([CollectionJobExtension::new(
        CollectionJobExtensionType::Unknown(0xffff),
        Vec::new(),
    )]));

    let mut response = test_case.post_collection_job(&request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:unsupportedExtension",
            "title": "The message includes an unsupported extension.",
            "detail": "collection job contains an unsupported extension type",
            "taskid": format!("{}", test_case.task.id()),
        })
    );
}

#[tokio::test]
async fn collection_job_post_request_invalid_extension_order() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    // Extension types 0x0002 then 0x0001 are not in strictly increasing order.
    let request = CollectionJobReq::new(
        Query::new_time_interval(
            Interval::minimal(Time::from_seconds_since_epoch(
                0,
                test_case.task.time_precision(),
            ))
            .unwrap(),
        ),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    )
    .with_extensions(Vec::from([
        CollectionJobExtension::new(CollectionJobExtensionType::Unknown(0x0002), Vec::new()),
        CollectionJobExtension::new(CollectionJobExtensionType::Unknown(0x0001), Vec::new()),
    ]));

    let mut response = test_case.post_collection_job(&request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:invalidExtension",
            "title": "An extensions list is out of order or contains an invalid extension encoding.",
            "detail": "collection job extensions are not in strictly increasing order of extension type",
            "taskid": format!("{}", test_case.task.id()),
        })
    );
}

#[tokio::test]
async fn collection_job_post_request_invalid_batch_size() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| {
            tb.with_min_batch_size(1)
                .with_batch_mode(BatchMode::TimeInterval)
        })
        .build()
        .await;

    let request = CollectionJobReq::new(
        Query::new_time_interval(Interval::minimal(Time::from_time_precision_units(0)).unwrap()),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    );

    let mut response = test_case.post_collection_job(&request).await;

    // Collect request will be rejected because there are no reports in the batch interval
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        take_problem_details(&mut response).await,
        json!({
            "status": StatusCode::BAD_REQUEST.as_u16(),
            "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
            "title": "The number of reports included in the batch is invalid.",
            "taskid": format!("{}", test_case.task.id()),
        })
    );
}

#[tokio::test]
async fn collection_job_post_request_unauthenticated() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    let batch_interval = Interval::minimal(Time::from_seconds_since_epoch(
        0,
        test_case.task.time_precision(),
    ))
    .unwrap();
    let req = CollectionJobReq::new(
        Query::new_time_interval(batch_interval),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    );

    // Incorrect authentication token.
    let response = test_case
        .post_collection_job_with_auth_token(&req, Some(&random()))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Aggregator authentication token.
    let response = test_case
        .post_collection_job_with_auth_token(&req, Some(test_case.task.aggregator_auth_token()))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Missing authentication token.
    let response = test_case
        .post_collection_job_with_auth_token(&req, None)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn collection_job_get_request_unauthenticated_collection_jobs() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    let batch_interval = Interval::minimal(Time::from_seconds_since_epoch(
        0,
        test_case.task.time_precision(),
    ))
    .unwrap();

    let request = CollectionJobReq::new(
        Query::new_time_interval(batch_interval),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    );

    let response = test_case.post_collection_job(&request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let (_, collection_job_id) = ids_from_collection_job_response(&response);

    // Incorrect authentication token.
    let response = test_case
        .get_collection_job_with_auth_token(&collection_job_id, Some(&random()))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Aggregator authentication token.
    let response = test_case
        .get_collection_job_with_auth_token(
            &collection_job_id,
            Some(test_case.task.aggregator_auth_token()),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Missing authentication token.
    let response = test_case
        .get_collection_job_with_auth_token(&collection_job_id, None)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn collection_job_success_time_interval() {
    let mut test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    let (request, collection_job_id) = test_case
        .simulate_successful_collection_job_time_interval(
            Time::from_time_precision_units(10),
            Interval::minimal(Time::from_time_precision_units(10)).unwrap(),
        )
        .await;

    // Re-send the very first collection job creation request. We should get the representation of
    // the completed collection job without needing a further GET.
    let mut response = test_case.post_collection_job(&request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, new_collection_job_id) = ids_from_collection_job_response(&response);
    assert_eq!(collection_job_id, new_collection_job_id);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        CollectionJobResp::MEDIA_TYPE,
    );
    decode_response_body::<CollectionJobResp>(&mut response).await;
}

#[tokio::test]
async fn collection_job_get_request_no_such_collection_job() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    let no_such_collection_job_id: CollectionJobId = random();

    let response = test_case
        .get_collection_job(&no_such_collection_job_id)
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn collection_job_post_request_batch_queried_multiple_times() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    let interval = test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    // Sending this request will consume a query for [0, time_precision).
    let request = CollectionJobReq::new(
        Query::new_time_interval(interval),
        dummy::AggregationParam(0).get_encoded().unwrap(),
    );

    let response = test_case.post_collection_job(&request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // This request will not be allowed due to the query count already being consumed.
    let invalid_request = CollectionJobReq::new(
        Query::new_time_interval(interval),
        dummy::AggregationParam(1).get_encoded().unwrap(),
    );

    let mut response = test_case.post_collection_job(&invalid_request).await;
    test_case
        .check_batch_overlap_response(response.status(), take_problem_details(&mut response).await);
}

#[tokio::test]
async fn collection_job_post_request_batch_overlap() {
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;
    let interval = test_case
        .setup_time_interval_batch(Time::from_seconds_since_epoch(
            0,
            test_case.task.time_precision(),
        ))
        .await;

    // Sending this request will consume a query for [0, 2 * time_precision).
    let request = CollectionJobReq::new(
        Query::new_time_interval(
            Interval::new(
                Time::from_time_precision_units(0),
                Duration::from_time_precision_units(2),
            )
            .unwrap(),
        ),
        dummy::AggregationParam(0).get_encoded().unwrap(),
    );

    let response = test_case.post_collection_job(&request).await;

    assert_eq!(response.status(), StatusCode::OK);

    // This request will not be allowed due to overlapping with the previous request.
    let invalid_request = CollectionJobReq::new(
        Query::new_time_interval(interval),
        dummy::AggregationParam(1).get_encoded().unwrap(),
    );

    let mut response = test_case.post_collection_job(&invalid_request).await;
    test_case
        .check_batch_overlap_response(response.status(), take_problem_details(&mut response).await);
}

#[tokio::test]
async fn recreate_deleted_collection_job_time_interval() {
    let mut test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    // Run a collection to completion, then delete the job.
    let (request, collection_job_id) = test_case
        .simulate_successful_collection_job_time_interval(
            Time::from_time_precision_units(10),
            Interval::minimal(Time::from_time_precision_units(10)).unwrap(),
        )
        .await;
    let response = test_case.delete_collection_job(&collection_job_id).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let mut response = test_case.get_collection_job(&collection_job_id).await;
    test_case.check_gone_response(
        response.status(),
        take_problem_details(&mut response).await,
        &collection_job_id,
    );

    // Re-creating the job with an identical request should be refused because it has been deleted.
    let mut response = test_case.post_collection_job(&request).await;
    test_case.check_gone_response(
        response.status(),
        take_problem_details(&mut response).await,
        &collection_job_id,
    );

    // Re-creating the job with a mutated request should fail with batchOverlap.
    let mutant_request = CollectionJobReq::new(
        request.query().clone(),
        dummy::AggregationParam(17).get_encoded().unwrap(),
    );
    let mut response = test_case.post_collection_job(&mutant_request).await;
    test_case
        .check_batch_overlap_response(response.status(), take_problem_details(&mut response).await);
}

#[tokio::test]
async fn recreate_deleted_collection_job_leader_selected() {
    let mut test_case = CollectionJobTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::leader_selected()))
        .build()
        .await;
    let (batch_id_1, batch_id_2, spanned_interval) =
        test_case.setup_leader_selected_current_batch().await;

    // Run a collection to completion, then delete the job.
    let (request, collection_job_id) = test_case
        .simulate_successful_collection_job_leader_selected(
            batch_id_1,
            batch_id_2,
            spanned_interval,
        )
        .await;

    // Put another outstanding batch in the datastore to ensure subsequent job creation requests
    // aren't failing just because there's no reports to aggregate.
    test_case
        .setup_leader_selected_batch(
            test_case
                .clock()
                .now()
                .to_time(test_case.task.time_precision()),
            test_case.task.min_batch_size() + 1,
        )
        .await;

    let response = test_case.delete_collection_job(&collection_job_id).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let mut response = test_case.get_collection_job(&collection_job_id).await;
    test_case.check_gone_response(
        response.status(),
        take_problem_details(&mut response).await,
        &collection_job_id,
    );

    // Re-creating the job with an identical request should be refused because it has been deleted.
    let mut response = test_case.post_collection_job(&request).await;
    test_case.check_gone_response(
        response.status(),
        take_problem_details(&mut response).await,
        &collection_job_id,
    );

    // Re-creating the job with a mutated request should fail with batchOverlap.
    let mutant_request = CollectionJobReq::new(
        request.query().clone(),
        dummy::AggregationParam(17).get_encoded().unwrap(),
    );
    let mut response = test_case.post_collection_job(&mutant_request).await;
    test_case
        .check_batch_overlap_response(response.status(), take_problem_details(&mut response).await);
}

#[tokio::test]
async fn create_expired_collection_job_time_interval() {
    let expiry = Duration::from_time_precision_units(20);
    let test_case = CollectionJobTestCase::builder()
        .build_task(|tb| {
            tb.with_batch_mode(BatchMode::TimeInterval)
                .with_report_expiry_age(Some(expiry))
        })
        .build()
        .await;

    let now = Time::from_seconds_since_epoch(
        test_case.clock().now().as_seconds_since_epoch(),
        test_case.task.time_precision(),
    );

    test_case
        .setup_time_interval_batch(
            now.sub_duration(&Duration::from_time_precision_units(3))
                .unwrap(),
        )
        .await;
    let queried_interval = Interval::new(
        now.sub_duration(&Duration::from_time_precision_units(10))
            .unwrap(),
        Duration::from_time_precision_units(10),
    )
    .unwrap();

    // Advance clock far enough for the batch aggregations etc. to expire.
    test_case.clock().advance(TimeDelta::seconds(
        2 * expiry.as_seconds(test_case.task.time_precision()) as i64,
    ));

    let request = CollectionJobReq::new(
        Query::new_time_interval(queried_interval),
        dummy::AggregationParam::default().get_encoded().unwrap(),
    );

    // Creating a collection job for expired data should be refused.
    let mut response = test_case.post_collection_job(&request).await;
    test_case.check_collection_job_rejection_response(
        response.status(),
        take_problem_details(&mut response).await,
    );
}

#[tokio::test]
async fn recreate_expired_collection_job_time_interval() {
    let expiry = Duration::from_time_precision_units(20);
    let mut test_case = CollectionJobTestCase::builder()
        .build_task(|tb| {
            tb.with_batch_mode(BatchMode::TimeInterval)
                .with_report_expiry_age(Some(expiry))
        })
        .build()
        .await;

    let now = Time::from_seconds_since_epoch(
        test_case.clock().now().as_seconds_since_epoch(),
        test_case.task.time_precision(),
    );

    let report_time = now
        .sub_duration(&Duration::from_time_precision_units(3))
        .unwrap();
    let queried_interval = Interval::new(
        now.sub_duration(&Duration::from_time_precision_units(10))
            .unwrap(),
        Duration::from_time_precision_units(10),
    )
    .unwrap();

    // Run a collection to completion.
    let (request, collection_job_id) = test_case
        .simulate_successful_collection_job_time_interval(report_time, queried_interval)
        .await;

    // Advance clock far enough for the collection job to expire.
    test_case.clock().advance(TimeDelta::seconds(
        2 * expiry.as_seconds(test_case.task.time_precision()) as i64,
    ));

    let response = test_case.get_collection_job(&collection_job_id).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Re-creating the job with an identical request should be refused.
    let mut response = test_case.post_collection_job(&request).await;
    test_case.check_collection_job_rejection_response(
        response.status(),
        take_problem_details(&mut response).await,
    );

    // Re-creating the job with a mutated request should also be refused.
    let mutant_request = CollectionJobReq::new(
        request.query().clone(),
        dummy::AggregationParam(17).get_encoded().unwrap(),
    );
    let mut response = test_case.post_collection_job(&mutant_request).await;
    test_case.check_collection_job_rejection_response(
        response.status(),
        take_problem_details(&mut response).await,
    );
}

#[tokio::test]
async fn recreate_expired_collection_job_leader_selected() {
    let expiry = Duration::from_time_precision_units(20);
    let mut test_case = CollectionJobTestCase::builder()
        .build_task(|tb| {
            tb.with_batch_mode(BatchMode::leader_selected())
                .with_report_expiry_age(Some(expiry))
        })
        .build()
        .await;

    let (batch_id_1, batch_id_2, spanned_interval) =
        test_case.setup_leader_selected_current_batch().await;

    let (request, collection_job_id) = test_case
        .simulate_successful_collection_job_leader_selected(
            batch_id_1,
            batch_id_2,
            spanned_interval,
        )
        .await;

    // Advance clock far enough for the collection job to expire.
    test_case.clock().advance(TimeDelta::seconds(
        2 * expiry.as_seconds(test_case.task.time_precision()) as i64,
    ));

    let response = test_case.get_collection_job(&collection_job_id).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Put another outstanding batch in the datastore to ensure subsequent job creation requests
    // aren't failing just because there's no reports to aggregate.
    test_case
        .setup_leader_selected_batch(
            test_case
                .clock()
                .now()
                .to_time(test_case.task.time_precision()),
            test_case.task.min_batch_size() + 1,
        )
        .await;

    // Re-creating the job with an identical request should be refused.
    let mut response = test_case.post_collection_job(&request).await;
    test_case.check_collection_job_rejection_response(
        response.status(),
        take_problem_details(&mut response).await,
    );

    // Re-creating the job with a mutated request should fail with batchOverlap.
    let mutant_request = CollectionJobReq::new(
        request.query().clone(),
        dummy::AggregationParam(17).get_encoded().unwrap(),
    );
    let mut response = test_case.post_collection_job(&mutant_request).await;
    test_case
        .check_batch_overlap_response(response.status(), take_problem_details(&mut response).await);
}
