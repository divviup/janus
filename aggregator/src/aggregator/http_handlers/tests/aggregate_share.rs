use crate::aggregator::{
    error::BatchMismatch,
    http_handlers::test_util::{HttpHandlerTest, decode_response_body, take_problem_details},
};
use assert_matches::assert_matches;
use futures::future::try_join_all;
use janus_aggregator_core::{
    batch_mode::CollectableBatchMode,
    datastore::models::{BatchAggregation, BatchAggregationState},
    task::{
        AggregationMode, BatchMode,
        test_util::{Task, TaskBuilder},
    },
};
use janus_core::{
    auth_tokens::test_util::WithAuthenticationToken,
    hpke::{self, HpkeApplicationInfo, Label},
    report_id::ReportIdChecksumExt,
    time::Clock,
    vdaf::VdafInstance,
};
use janus_messages::{
    AggregateShare as AggregateShareMessage, AggregateShareAad, AggregateShareId,
    AggregateShareReq, BatchSelector, Duration, Interval, MediaType, ReportIdChecksum, Role, Time,
    batch_mode::{self, TimeInterval},
    taskprov::TimePrecision,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::dummy,
};
use serde_json::json;
use trillium::{Handler, KnownHeaderName, Status};
use trillium_testing::{
    TestConn, assert_headers,
    prelude::{delete, get, put},
};

pub(crate) async fn put_aggregate_share_request<B: batch_mode::BatchMode>(
    task: &Task,
    request: &AggregateShareReq<B>,
    aggregate_share_id: &AggregateShareId,
    handler: &impl Handler,
) -> TestConn {
    put(task
        .aggregate_shares_uri(aggregate_share_id)
        .unwrap()
        .path())
    .with_authentication_token(task.aggregator_auth_token())
    .with_request_header(
        KnownHeaderName::ContentType,
        AggregateShareReq::<B>::MEDIA_TYPE,
    )
    .with_request_body(request.get_encoded().unwrap())
    .run_async(handler)
    .await
}

#[tokio::test]
async fn aggregate_share_request_to_leader() {
    let HttpHandlerTest {
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    // Prepare parameters.
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .build();
    let leader_task = task.leader_view().unwrap();
    datastore.put_aggregator_task(&leader_task).await.unwrap();

    let request = AggregateShareReq::new(
        BatchSelector::new_time_interval(
            Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
        ),
        Vec::new(),
        0,
        ReportIdChecksum::default(),
    );

    let mut test_conn = put_aggregate_share_request(
        &task,
        &request,
        &AggregateShareId::from([0u8; 16]),
        &handler,
    )
    .await;

    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            "title": "An endpoint received a message with an unknown task ID.",
            "taskid": format!("{}", task.id()),
        })
    );
}

#[tokio::test]
async fn aggregate_share_request_invalid_batch_interval() {
    let HttpHandlerTest {
        clock,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    // Prepare parameters.
    let time_precision = TimePrecision::from_hours(8);
    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_report_expiry_age(Some(Duration::from_seconds(3600, &time_precision)))
    .build();
    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    let request = AggregateShareReq::new(
        BatchSelector::new_time_interval(
            Interval::new(
                clock.now_aligned_to_precision(task.time_precision()),
                // Collect request will be rejected because batch interval is too small
                Duration::from_seconds(task.time_precision().as_seconds() - 1, &time_precision),
            )
            .unwrap(),
        ),
        Vec::new(),
        0,
        ReportIdChecksum::default(),
    );

    // Test that a request for an invalid batch fails. (Specifically, the batch interval is too
    // small.)
    let mut test_conn = put_aggregate_share_request(
        &task,
        &request,
        &AggregateShareId::from([0u8; 16]),
        &handler,
    )
    .await;

    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
            "title": "The batch implied by the query is invalid.",
            "taskid": format!("{}", task.id()),
        })
    );

    // Test that a request for a too-old batch fails.
    let test_conn = put_aggregate_share_request(
        &task,
        &AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
            ),
            Vec::new(),
            0,
            ReportIdChecksum::default(),
        ),
        &AggregateShareId::from([0u8; 16]),
        &handler,
    )
    .await;

    assert_eq!(test_conn.status(), Some(Status::BadRequest));
}

#[tokio::test]
async fn aggregate_share_request() {
    let HttpHandlerTest {
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_time_precision(TimePrecision::from_seconds(500))
    .with_min_batch_size(10)
    .build();
    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    // There are no batch aggregations in the datastore yet
    let request = AggregateShareReq::new(
        BatchSelector::new_time_interval(
            Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
        ),
        dummy::AggregationParam(0).get_encoded().unwrap(),
        0,
        ReportIdChecksum::default(),
    );

    let mut test_conn = put_aggregate_share_request(
        &task,
        &request,
        &AggregateShareId::from([0u8; 16]),
        &handler,
    )
    .await;

    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
            "title": "The number of reports included in the batch is invalid.",
            "taskid": format!("{}", task.id()),
        })
    );

    // Put some batch aggregations in the DB.
    let interval_1 =
        Interval::minimal(Time::from_seconds_since_epoch(500, task.time_precision())).unwrap();
    let interval_1_report_count = 5;
    let interval_1_checksum = ReportIdChecksum::get_decoded(&[3; 32]).unwrap();

    let interval_2 =
        Interval::minimal(Time::from_seconds_since_epoch(1500, task.time_precision())).unwrap();
    let interval_2_report_count = 5;
    let interval_2_checksum = ReportIdChecksum::get_decoded(&[2; 32]).unwrap();

    let interval_3 =
        Interval::minimal(Time::from_seconds_since_epoch(2000, task.time_precision())).unwrap();
    let interval_3_report_count = 5;
    let interval_3_checksum = ReportIdChecksum::get_decoded(&[4; 32]).unwrap();

    let interval_4 =
        Interval::minimal(Time::from_seconds_since_epoch(2500, task.time_precision())).unwrap();
    let interval_4_report_count = 5;
    let interval_4_checksum = ReportIdChecksum::get_decoded(&[8; 32]).unwrap();
    datastore
        .run_unnamed_tx(|tx| {
            let task = helper_task.clone();
            Box::pin(async move {
                for aggregation_param in [dummy::AggregationParam(0), dummy::AggregationParam(1)] {
                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                            *task.id(),
                            interval_1,
                            aggregation_param,
                            0,
                            interval_1,
                            BatchAggregationState::Aggregating {
                                aggregate_share: Some(dummy::AggregateShare(16)),
                                report_count: interval_1_report_count,
                                checksum: interval_1_checksum,
                                aggregation_jobs_created: 1,
                                aggregation_jobs_terminated: 1,
                            },
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                            *task.id(),
                            interval_2,
                            aggregation_param,
                            0,
                            interval_2,
                            BatchAggregationState::Aggregating {
                                aggregate_share: Some(dummy::AggregateShare(32)),
                                report_count: interval_2_report_count,
                                checksum: interval_2_checksum,
                                aggregation_jobs_created: 1,
                                aggregation_jobs_terminated: 1,
                            },
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                            *task.id(),
                            interval_3,
                            aggregation_param,
                            0,
                            interval_3,
                            BatchAggregationState::Aggregating {
                                aggregate_share: Some(dummy::AggregateShare(64)),
                                report_count: interval_3_report_count,
                                checksum: interval_3_checksum,
                                aggregation_jobs_created: 1,
                                aggregation_jobs_terminated: 1,
                            },
                        ),
                    )
                    .await
                    .unwrap();

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                            *task.id(),
                            interval_4,
                            aggregation_param,
                            0,
                            interval_4,
                            BatchAggregationState::Aggregating {
                                aggregate_share: Some(dummy::AggregateShare(128)),
                                report_count: interval_4_report_count,
                                checksum: interval_4_checksum,
                                aggregation_jobs_created: 1,
                                aggregation_jobs_terminated: 1,
                            },
                        ),
                    )
                    .await
                    .unwrap();
                }

                Ok(())
            })
        })
        .await
        .unwrap();

    // Specified interval includes too few reports.
    let request = AggregateShareReq::new(
        BatchSelector::new_time_interval(
            Interval::new(
                Time::from_time_precision_units(0),
                Duration::from_seconds(1000, task.time_precision()),
            )
            .unwrap(),
        ),
        dummy::AggregationParam(0).get_encoded().unwrap(),
        5,
        ReportIdChecksum::default(),
    );
    let mut test_conn = put_aggregate_share_request(
        &task,
        &request,
        &AggregateShareId::from([0u8; 16]),
        &handler,
    )
    .await;

    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
            "title": "The number of reports included in the batch is invalid.",
            "taskid": format!("{}", task.id()),
        })
    );

    // Make requests that will fail because the checksum or report counts don't match.
    struct MisalignedRequestTestCase<B: janus_messages::batch_mode::BatchMode> {
        name: &'static str,
        request: AggregateShareReq<B>,
        expected_checksum: ReportIdChecksum,
        expected_report_count: u64,
    }
    for misaligned_request in [
        MisalignedRequestTestCase {
            name: "Interval is big enough but the checksums don't match",
            request: AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_time_precision_units(0),
                        Duration::from_seconds(2000, task.time_precision()),
                    )
                    .unwrap(),
                ),
                dummy::AggregationParam(0).get_encoded().unwrap(),
                10,
                ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
            ),
            expected_checksum: interval_1_checksum.combined_with(&interval_2_checksum),
            expected_report_count: interval_1_report_count + interval_2_report_count,
        },
        MisalignedRequestTestCase {
            name: "Interval is big enough but report count doesn't match",
            request: AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000, task.time_precision()),
                        Duration::from_seconds(2000, task.time_precision()),
                    )
                    .unwrap(),
                ),
                dummy::AggregationParam(0).get_encoded().unwrap(),
                20,
                ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
            ),
            expected_checksum: interval_3_checksum.combined_with(&interval_4_checksum),
            expected_report_count: interval_3_report_count + interval_4_report_count,
        },
    ] {
        let mut test_conn = put_aggregate_share_request(
            &task,
            &misaligned_request.request,
            &AggregateShareId::from([0u8; 16]),
            &handler,
        )
        .await;

        assert_eq!(
            test_conn.status(),
            Some(Status::BadRequest),
            "{}",
            misaligned_request.name
        );

        let expected_error = BatchMismatch {
            task_id: *task.id(),
            own_checksum: misaligned_request.expected_checksum,
            own_report_count: misaligned_request.expected_report_count,
            peer_checksum: *misaligned_request.request.checksum(),
            peer_report_count: misaligned_request.request.report_count(),
        };
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:batchMismatch",
                "title": "Leader and helper disagree on reports aggregated in a batch.",
                "taskid": format!("{}", task.id()),
                "detail": expected_error.to_string(),
            }),
            "{}",
            misaligned_request.name,
        );
    }

    // Valid requests: intervals are big enough, do not overlap, checksum and report count are
    // good.
    for (label, request, expected_result) in [
        (
            "first and second batchess",
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_time_precision_units(0),
                        Duration::from_seconds(2000, task.time_precision()),
                    )
                    .unwrap(),
                ),
                dummy::AggregationParam(0).get_encoded().unwrap(),
                10,
                ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
            ),
            dummy::expected_aggregate_result(0, [16, 32]),
        ),
        (
            "third and fourth batches",
            AggregateShareReq::new(
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000, task.time_precision()),
                        Duration::from_seconds(2000, task.time_precision()),
                    )
                    .unwrap(),
                ),
                dummy::AggregationParam(0).get_encoded().unwrap(),
                10,
                ReportIdChecksum::get_decoded(&[8 ^ 4; 32]).unwrap(),
            ),
            // Should get sum over the third and fourth batches
            dummy::expected_aggregate_result(0, [64, 128]),
        ),
    ] {
        // Request the aggregate share multiple times. If the request parameters don't change,
        // then there is no query count violation and all requests should succeed.
        for iteration in 0..3 {
            let mut test_conn = put_aggregate_share_request(
                &task,
                &request,
                &AggregateShareId::from([0u8; 16]),
                &handler,
            )
            .await;

            assert_eq!(
                test_conn.status(),
                Some(Status::Ok),
                "test case: {label:?}, iteration: {iteration}"
            );
            assert_headers!(
                &test_conn,
                "content-type" => (AggregateShareMessage::MEDIA_TYPE)
            );
            let aggregate_share_resp: AggregateShareMessage =
                decode_response_body(&mut test_conn).await;

            let aggregate_share = hpke::open(
                task.collector_hpke_keypair(),
                &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
                aggregate_share_resp.encrypted_aggregate_share(),
                &AggregateShareAad::new(
                    *task.id(),
                    dummy::AggregationParam(0).get_encoded().unwrap(),
                    request.batch_selector().clone(),
                )
                .get_encoded()
                .unwrap(),
            )
            .unwrap();

            // Should get the sum over the first and second aggregate shares
            let decoded_aggregate_share =
                dummy::AggregateShare::get_decoded(aggregate_share.as_ref()).unwrap();
            assert_eq!(
                decoded_aggregate_share,
                dummy::AggregateShare(expected_result),
                "test case: {label:?}, iteration: {iteration}"
            );

            // Relevant batch aggregations should be scrubbed.
            datastore
                .run_unnamed_tx(|tx| {
                    let task = task.clone();
                    let collection_interval = *request.batch_selector().batch_interval();

                    Box::pin(async move {
                        let batch_aggregations: Vec<_> = try_join_all(
                            TimeInterval::batch_identifiers_for_collection_identifier(
                                task.time_precision(),
                                &collection_interval,
                            )
                            .map(|batch_identifier| {
                                let task_id = *task.id();

                                async move {
                                    tx.get_batch_aggregations_for_batch::<0, TimeInterval, dummy::Vdaf>(
                                        &dummy::Vdaf::new(1),
                                        &task_id,
                                        &batch_identifier,
                                        &dummy::AggregationParam(0),
                                    ).await
                                }
                            }),
                        )
                        .await
                        .unwrap()
                        .into_iter()
                        .flatten()
                        .collect();

                        assert!(!batch_aggregations.is_empty());
                        for batch_aggregation in &batch_aggregations {
                            assert_matches!(
                                batch_aggregation.state(),
                                BatchAggregationState::Scrubbed
                            );
                        }

                        Ok(())
                    })
                })
                .await
                .unwrap();
        }
    }

    // Requests for collection intervals that overlap with but are not identical to previous
    // collection intervals fail.
    let all_batch_request = AggregateShareReq::new(
        BatchSelector::new_time_interval(
            Interval::new(
                Time::from_time_precision_units(0),
                Duration::from_seconds(4000, task.time_precision()),
            )
            .unwrap(),
        ),
        dummy::AggregationParam(0).get_encoded().unwrap(),
        20,
        ReportIdChecksum::get_decoded(&[8 ^ 4 ^ 3 ^ 2; 32]).unwrap(),
    );
    let mut test_conn = put_aggregate_share_request(
        &task,
        &all_batch_request,
        &AggregateShareId::from([0u8; 16]),
        &handler,
    )
    .await;
    assert_eq!(test_conn.status(), Some(Status::BadRequest));
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::BadRequest as u16,
            "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
            "title": "The queried batch overlaps with a previously queried batch.",
            "taskid": format!("{}", task.id()),
        }),
    );

    // Previous sequence of aggregate share requests should have consumed the available queries
    // for all the batches. Further requests for any batches will cause query count violations.
    for query_count_violation_request in [
        AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_time_precision_units(0),
                    Duration::from_seconds(2000, task.time_precision()),
                )
                .unwrap(),
            ),
            dummy::AggregationParam(1).get_encoded().unwrap(),
            10,
            ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
        ),
        AggregateShareReq::new(
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(2000, task.time_precision()),
                    Duration::from_seconds(2000, task.time_precision()),
                )
                .unwrap(),
            ),
            dummy::AggregationParam(1).get_encoded().unwrap(),
            10,
            ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
        ),
    ] {
        let mut test_conn = put_aggregate_share_request(
            &task,
            &query_count_violation_request,
            &AggregateShareId::from([0u8; 16]),
            &handler,
        )
        .await;
        assert_eq!(test_conn.status(), Some(Status::BadRequest));
        assert_eq!(
            take_problem_details(&mut test_conn).await,
            json!({
                "status": Status::BadRequest as u16,
                "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "batch has already been collected with another aggregation parameter",
                "taskid": format!("{}", task.id()),
            })
        );
    }
}

#[tokio::test]
async fn aggregate_share_request_duplicate_with_different_id() {
    let HttpHandlerTest {
        clock: _,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
    .build();

    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    // Set up batch aggregations that will be used for the duplicate requests
    let batch_interval = Interval::minimal(Time::from_time_precision_units(0)).unwrap();

    let aggregation_param = dummy::AggregationParam(0);
    let report_count = 5;
    let checksum = ReportIdChecksum::get_decoded(&[3; 32]).unwrap();

    // Put batch aggregations in the database
    datastore
        .run_unnamed_tx(|tx| {
            let helper_task = helper_task.clone();

            Box::pin(async move {
                tx.put_batch_aggregation(&BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                    *helper_task.id(),
                    batch_interval,
                    aggregation_param,
                    0,
                    batch_interval,
                    BatchAggregationState::Aggregating {
                        aggregate_share: Some(dummy::AggregateShare(16)),
                        report_count,
                        checksum,
                        aggregation_jobs_created: 1,
                        aggregation_jobs_terminated: 1,
                    },
                ))
                .await
                .unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

    let request = AggregateShareReq::new(
        BatchSelector::new_time_interval(batch_interval),
        aggregation_param.get_encoded().unwrap(),
        report_count,
        checksum,
    );

    let aggregate_share_id_1 = AggregateShareId::from([1u8; 16]);
    let aggregate_share_id_2 = AggregateShareId::from([2u8; 16]);

    // First request with aggregate_share_id_1 should succeed
    let test_conn =
        put_aggregate_share_request(&task, &request, &aggregate_share_id_1, &handler).await;

    assert_eq!(test_conn.status(), Some(Status::Ok));

    // Second request with same parameters but different aggregate share ID should fail
    let test_conn =
        put_aggregate_share_request(&task, &request, &aggregate_share_id_2, &handler).await;

    assert_eq!(test_conn.status(), Some(Status::BadRequest));
}

#[tokio::test]
async fn aggregate_share_request_get_poll_after_put() {
    let HttpHandlerTest {
        clock: _,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
    .build();

    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    // Set up batch aggregations that will be used for the duplicate requests
    let batch_interval = Interval::minimal(Time::from_time_precision_units(0)).unwrap();

    let aggregation_param = dummy::AggregationParam(0);
    let report_count = 5;
    let checksum = ReportIdChecksum::get_decoded(&[3; 32]).unwrap();

    // Put batch aggregations in the database
    datastore
        .run_unnamed_tx(|tx| {
            let helper_task = helper_task.clone();

            Box::pin(async move {
                tx.put_batch_aggregation(&BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                    *helper_task.id(),
                    batch_interval,
                    aggregation_param,
                    0,
                    batch_interval,
                    BatchAggregationState::Aggregating {
                        aggregate_share: Some(dummy::AggregateShare(16)),
                        report_count,
                        checksum,
                        aggregation_jobs_created: 1,
                        aggregation_jobs_terminated: 1,
                    },
                ))
                .await
                .unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

    let request = AggregateShareReq::new(
        BatchSelector::new_time_interval(batch_interval),
        aggregation_param.get_encoded().unwrap(),
        report_count,
        checksum,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);

    // Send the request. We'll ignore the details of the response and check that polling still works.
    let test_conn =
        put_aggregate_share_request(&task, &request, &aggregate_share_id, &handler).await;

    assert_eq!(test_conn.status(), Some(Status::Ok));

    // Try to GET the first ID again. It should be OK.
    let (header, value) = task.aggregator_auth_token().request_authentication();
    let test_conn = get(task
        .aggregate_shares_uri(&aggregate_share_id)
        .unwrap()
        .path())
    .with_request_header(header, value)
    .run_async(&handler)
    .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));

    // Ensure it's idempotent.
    let (header, value) = task.aggregator_auth_token().request_authentication();
    let mut test_conn = get(task
        .aggregate_shares_uri(&aggregate_share_id)
        .unwrap()
        .path())
    .with_request_header(header, value)
    .run_async(&handler)
    .await;
    assert_eq!(test_conn.status(), Some(Status::Ok));

    assert_headers!(
        &test_conn,
        "content-type" => (AggregateShareMessage::MEDIA_TYPE)
    );
    let aggregate_share_resp: AggregateShareMessage = decode_response_body(&mut test_conn).await;

    hpke::open(
        task.collector_hpke_keypair(),
        &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
        aggregate_share_resp.encrypted_aggregate_share(),
        &AggregateShareAad::new(
            *task.id(),
            dummy::AggregationParam(0).get_encoded().unwrap(),
            request.batch_selector().clone(),
        )
        .get_encoded()
        .unwrap(),
    )
    .unwrap();

    // We should be able to delete it
    let (header, value) = task.aggregator_auth_token().request_authentication();
    let test_conn = delete(
        task.aggregate_shares_uri(&aggregate_share_id)
            .unwrap()
            .path(),
    )
    .with_request_header(header, value)
    .run_async(&handler)
    .await;
    assert_eq!(test_conn.status(), Some(Status::NoContent));
}

#[tokio::test]
async fn aggregate_share_request_get_unrecognized_id() {
    let HttpHandlerTest {
        clock: _,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
    .build();

    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    // Try to GET an aggregate share that doesn't exist
    let nonexistent_aggregate_share_id = AggregateShareId::from([99u8; 16]);

    let (header, value) = task.aggregator_auth_token().request_authentication();
    let mut test_conn = get(task
        .aggregate_shares_uri(&nonexistent_aggregate_share_id)
        .unwrap()
        .path())
    .with_request_header(header, value)
    .run_async(&handler)
    .await;

    assert_eq!(test_conn.status(), Some(Status::NotFound));

    // Verify it returns the correct problem document
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::NotFound as u16,
            "type": "https://docs.divviup.org/references/janus-errors#aggregate-share-id-unrecognized",
            "title": "The aggregate share ID is not recognized.",
            "taskid": format!("{}", task.id()),
            "aggregate_share_id": format!("{}", nonexistent_aggregate_share_id),
        })
    );
}

#[tokio::test]
async fn aggregate_share_delete_nonexistant() {
    let HttpHandlerTest {
        clock: _,
        ephemeral_datastore: _ephemeral_datastore,
        datastore,
        handler,
        ..
    } = HttpHandlerTest::new().await;

    let task = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
    .build();

    let helper_task = task.helper_view().unwrap();
    datastore.put_aggregator_task(&helper_task).await.unwrap();

    // Try to DELETE an aggregate share that doesn't exist
    let nonexistent_aggregate_share_id = AggregateShareId::from([99u8; 16]);

    let (header, value) = task.aggregator_auth_token().request_authentication();
    let mut test_conn = delete(
        task.aggregate_shares_uri(&nonexistent_aggregate_share_id)
            .unwrap()
            .path(),
    )
    .with_request_header(header, value)
    .run_async(&handler)
    .await;

    assert_eq!(test_conn.status(), Some(Status::NotFound));

    // Verify it returns the correct problem document
    assert_eq!(
        take_problem_details(&mut test_conn).await,
        json!({
            "status": Status::NotFound as u16,
            "type": "https://docs.divviup.org/references/janus-errors#aggregate-share-id-unrecognized",
            "title": "The aggregate share ID is not recognized.",
            "taskid": format!("{}", task.id()),
            "aggregate_share_id": format!("{}", nonexistent_aggregate_share_id),
        })
    );
}
