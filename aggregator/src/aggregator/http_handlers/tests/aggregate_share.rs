use assert_matches::assert_matches;
use axum::body::Body;
use chrono::TimeDelta;
use futures::future::try_join_all;
use http::{Request, StatusCode};
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
    time::{Clock, DateTimeExt, MockClock, TimeExt},
    vdaf::VdafInstance,
};
use janus_messages::{
    AggregateShare as AggregateShareMessage, AggregateShareAad, AggregateShareId,
    AggregateShareReq, BatchId, BatchSelector, CollectionJobExtension, CollectionJobExtensionType,
    CollectionJobReq, Duration, Interval, MediaType, Query, ReportIdChecksum, Role, Time,
    TimePrecision,
    batch_mode::{self, LeaderSelected, TimeInterval},
};
use prio::{
    codec::{Decode, Encode},
    vdaf::dummy,
};
use rand::random;
use serde_json::json;
use tower::ServiceExt;

use crate::aggregator::{
    error::BatchMismatch,
    http_handlers::test_util::{
        HttpHandlerTest, decode_response_body, take_problem_details, take_response_body,
    },
};

pub(super) struct AggregateShareTestCase {
    pub(super) task: Task,
    pub(super) test: HttpHandlerTest,
}

impl AggregateShareTestCase {
    const REPORT_COUNT: u64 = 5;
    const CHECKSUM: ReportIdChecksum = ReportIdChecksum::from_array([3; 32]);

    pub(super) fn builder() -> AggregateShareTestCaseBuilder {
        AggregateShareTestCaseBuilder {
            task_builder: TaskBuilder::new(
                BatchMode::TimeInterval,
                AggregationMode::Synchronous,
                VdafInstance::Fake { rounds: 1 },
            ),
            role: Role::Helper,
            time_interval_batch_aggregation: None,
            leader_selected_batch_aggregation: None,
            clock: MockClock::default(),
        }
    }

    pub(super) async fn put_aggregate_share_request<B: batch_mode::BatchMode>(
        &self,
        request: &AggregateShareReq<B>,
        aggregate_share_id: &AggregateShareId,
    ) -> http::Response<Body> {
        let req = Request::builder()
            .method("PUT")
            .uri(
                self.task
                    .aggregate_shares_uri(aggregate_share_id)
                    .unwrap()
                    .path(),
            )
            .with_authentication_token(self.task.aggregator_auth_token())
            .header(
                http::header::CONTENT_TYPE,
                AggregateShareReq::<B>::MEDIA_TYPE,
            )
            .body(Body::from(request.get_encoded().unwrap()))
            .unwrap();
        self.test.router.clone().oneshot(req).await.unwrap()
    }

    pub(super) async fn get_aggregate_share(
        &self,
        aggregate_share_id: &AggregateShareId,
    ) -> http::Response<Body> {
        let req = Request::get(
            self.task
                .aggregate_shares_uri(aggregate_share_id)
                .unwrap()
                .path(),
        )
        .with_authentication_token(self.task.aggregator_auth_token())
        .body(Body::empty())
        .unwrap();
        self.test.router.clone().oneshot(req).await.unwrap()
    }

    pub(super) async fn delete_aggregate_share(
        &self,
        aggregate_share_id: &AggregateShareId,
    ) -> http::Response<Body> {
        let req = Request::delete(
            self.task
                .aggregate_shares_uri(aggregate_share_id)
                .unwrap()
                .path(),
        )
        .with_authentication_token(self.task.aggregator_auth_token())
        .body(Body::empty())
        .unwrap();
        self.test.router.clone().oneshot(req).await.unwrap()
    }

    #[track_caller]
    pub(super) fn check_aggregate_share_rejection_response(
        &self,
        status: StatusCode,
        problem_details: serde_json::Value,
    ) {
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "detail": "aggregate share request too late",
                "type": "https://docs.divviup.org/references/janus-errors#aggregate-share-request-rejected",
                "title": "Aggregate share request rejected.",
                "taskid": format!("{}", self.task.id()),
            })
        );
    }

    #[track_caller]
    pub(super) fn check_invalid_batch_size_response(
        &self,
        status: StatusCode,
        problem_details: serde_json::Value,
    ) {
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:invalidBatchSize",
                "title": "The number of reports included in the batch is invalid.",
                "taskid": format!("{}", self.task.id()),
            })
        );
    }

    #[track_caller]
    pub(super) fn check_batch_overlap_response(
        &self,
        status: StatusCode,
        problem_details: serde_json::Value,
    ) {
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            problem_details,
            json!({
                 "status": StatusCode::BAD_REQUEST.as_u16(),
                 "type": "urn:ietf:params:ppm:dap:error:batchOverlap",
                 "title": "The queried batch overlaps with a previously queried batch.",
                 "taskid": format!("{}", self.task.id()),
            })
        );
    }

    #[track_caller]
    pub(super) fn check_forbidden_mutation_response(
        &self,
        status: StatusCode,
        problem_details: serde_json::Value,
        aggregate_share_id: &AggregateShareId,
    ) {
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::CONFLICT.as_u16(),
                "type": "https://docs.divviup.org/references/janus-errors#forbidden-mutation",
                "title": "Forbidden mutation of an immutable resource.",
                "detail": format!(
                    "The aggregate share job {aggregate_share_id} already exists and cannot be \
                     modified. Use a new identifier instead of re-sending this one with changed \
                     parameters."
                ),
            })
        );
    }

    #[track_caller]
    pub(super) fn check_batch_invalid_response(
        &self,
        status: StatusCode,
        problem_details: serde_json::Value,
    ) {
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchInvalid",
                "title": "The batch implied by the query is invalid.",
                "taskid": format!("{}", self.task.id()),
            })
        );
    }

    #[track_caller]
    pub(super) fn check_unrecognized_aggregate_share_response(
        &self,
        status: StatusCode,
        problem_details: serde_json::Value,
        aggregate_share_id: &AggregateShareId,
    ) {
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            problem_details,
            json!({
                "status": StatusCode::NOT_FOUND.as_u16(),
                "type": "https://docs.divviup.org/references/janus-errors#aggregate-share-id-unrecognized",
                "title": "The aggregate share ID is not recognized.",
                "taskid": format!("{}", self.task.id()),
                "aggregate_share_id": format!("{aggregate_share_id}"),
            })
        );
    }

    #[track_caller]
    pub(super) fn open_aggregate_share<B: batch_mode::BatchMode>(
        &self,
        req: &AggregateShareReq<B>,
        aggregate_share_resp: &AggregateShareMessage,
    ) -> Result<Vec<u8>, janus_core::hpke::Error> {
        hpke::open(
            self.task.collector_hpke_keypair(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            aggregate_share_resp.encrypted_aggregate_share(),
            &AggregateShareAad::new(
                *self.task.id(),
                self.task.task_configuration(),
                req.collection_job_req().clone(),
            )
            .get_encoded()
            .unwrap(),
        )
    }
}

struct TimeIntervalBatchAggregationSetup {
    batch_interval: Interval,
    aggregation_param: dummy::AggregationParam,
}

struct LeaderSelectedBatchAggregationSetup {
    batch_id: BatchId,
    client_timestamp_interval: Interval,
    aggregation_param: dummy::AggregationParam,
}

pub(super) struct AggregateShareTestCaseBuilder {
    task_builder: TaskBuilder,
    role: Role,
    time_interval_batch_aggregation: Option<TimeIntervalBatchAggregationSetup>,
    leader_selected_batch_aggregation: Option<LeaderSelectedBatchAggregationSetup>,
    clock: MockClock,
}

impl AggregateShareTestCaseBuilder {
    pub(super) async fn build(self) -> AggregateShareTestCase {
        let test = HttpHandlerTest::builder()
            .with_clock(self.clock)
            .build()
            .await;

        let task = self
            .task_builder
            .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
            .build();
        let role_task = match self.role {
            Role::Leader => task.leader_view().unwrap(),
            Role::Helper => task.helper_view().unwrap(),
            _ => panic!("unexpected role"),
        };
        test.datastore
            .put_aggregator_task(&role_task)
            .await
            .unwrap();

        if let Some(setup) = self.leader_selected_batch_aggregation {
            test.datastore
                .run_unnamed_tx(|tx| {
                    let task = role_task.clone();

                    Box::pin(async move {
                        tx.put_batch_aggregation(
                            &BatchAggregation::<0, LeaderSelected, dummy::Vdaf>::new(
                                *task.id(),
                                setup.batch_id,
                                setup.aggregation_param,
                                0,
                                setup.client_timestamp_interval,
                                BatchAggregationState::Aggregating {
                                    aggregate_share: Some(dummy::AggregateShare(16)),
                                    report_count: AggregateShareTestCase::REPORT_COUNT,
                                    checksum: AggregateShareTestCase::CHECKSUM,
                                    aggregation_jobs_created: 1,
                                    aggregation_jobs_terminated: 1,
                                },
                            ),
                        )
                        .await
                        .unwrap();
                        tx.put_outstanding_batch(task.id(), &setup.batch_id, &None)
                            .await
                            .unwrap();
                        Ok(())
                    })
                })
                .await
                .unwrap();
        }

        if let Some(setup) = self.time_interval_batch_aggregation {
            test.datastore
                .run_unnamed_tx(|tx| {
                    let task = role_task.clone();
                    Box::pin(async move {
                        tx.put_batch_aggregation(
                            &BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                                *task.id(),
                                setup.batch_interval,
                                setup.aggregation_param,
                                0,
                                setup.batch_interval,
                                BatchAggregationState::Aggregating {
                                    aggregate_share: Some(dummy::AggregateShare(16)),
                                    report_count: AggregateShareTestCase::REPORT_COUNT,
                                    checksum: AggregateShareTestCase::CHECKSUM,
                                    aggregation_jobs_created: 1,
                                    aggregation_jobs_terminated: 1,
                                },
                            ),
                        )
                        .await
                        .unwrap();
                        Ok(())
                    })
                })
                .await
                .unwrap();
        }

        AggregateShareTestCase { task, test }
    }

    pub(super) fn with_role(self, role: Role) -> Self {
        Self { role, ..self }
    }

    fn with_time_interval_batch_aggregation(
        self,
        setup: TimeIntervalBatchAggregationSetup,
    ) -> Self {
        Self {
            time_interval_batch_aggregation: Some(setup),
            ..self
        }
    }

    fn with_leader_selected_batch_aggregation(
        self,
        setup: LeaderSelectedBatchAggregationSetup,
    ) -> Self {
        Self {
            leader_selected_batch_aggregation: Some(setup),
            ..self
        }
    }

    fn with_clock(self, clock: MockClock) -> Self {
        Self { clock, ..self }
    }

    pub(super) fn build_task<F: FnMut(TaskBuilder) -> TaskBuilder>(self, mut f: F) -> Self {
        Self {
            task_builder: f(self.task_builder),
            ..self
        }
    }
}

#[tokio::test]
async fn aggregate_share_request_to_leader() {
    let test_case = AggregateShareTestCase::builder()
        .with_role(Role::Leader)
        .build()
        .await;

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(
                Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
            ),
            Vec::new(),
        ),
        BatchSelector::new_time_interval(
            Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
        ),
        0,
        ReportIdChecksum::default(),
    );

    let mut response = test_case
        .put_aggregate_share_request(&request, &AggregateShareId::from([0u8; 16]))
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
async fn aggregate_share_request_invalid_batch_interval() {
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| {
            tb.with_report_expiry_age(Some(Duration::from_seconds(
                3600,
                &TaskBuilder::DEFAULT_TIME_PRECISION,
            )))
        })
        .build()
        .await;

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(
                Interval::new(
                    test_case
                        .test
                        .clock
                        .now()
                        .to_time(test_case.task.time_precision()),
                    // Collect request will be rejected because the batch interval is too small.
                    Duration::ZERO,
                )
                .unwrap(),
            ),
            Vec::new(),
        ),
        BatchSelector::new_time_interval(
            Interval::new(
                test_case
                    .test
                    .clock
                    .now()
                    .to_time(test_case.task.time_precision()),
                // Collect request will be rejected because the batch interval is too small.
                Duration::ZERO,
            )
            .unwrap(),
        ),
        0,
        ReportIdChecksum::default(),
    );

    // Test that a request for an invalid batch fails. (Specifically, the batch interval is too
    // small.)
    let mut response = test_case
        .put_aggregate_share_request(&request, &AggregateShareId::from([0u8; 16]))
        .await;
    test_case
        .check_batch_invalid_response(response.status(), take_problem_details(&mut response).await);

    // Test that a request for a too-old batch fails.
    let mut response = test_case
        .put_aggregate_share_request(
            &AggregateShareReq::new(
                CollectionJobReq::new(
                    Query::new_time_interval(
                        Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
                    ),
                    Vec::new(),
                ),
                BatchSelector::new_time_interval(
                    Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
                ),
                0,
                ReportIdChecksum::default(),
            ),
            &AggregateShareId::from([0u8; 16]),
        )
        .await;
    test_case.check_aggregate_share_rejection_response(
        response.status(),
        take_problem_details(&mut response).await,
    );
}

#[tokio::test]
async fn aggregate_share_request() {
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| {
            tb.with_time_precision(TimePrecision::from_seconds(500))
                .with_min_batch_size(10)
        })
        .build()
        .await;

    // There are no batch aggregations in the datastore yet
    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(
                Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
            ),
            dummy::AggregationParam(0).get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(
            Interval::minimal(Time::from_time_precision_units(0)).unwrap(),
        ),
        0,
        ReportIdChecksum::default(),
    );

    let mut response = test_case
        .put_aggregate_share_request(&request, &AggregateShareId::from([0u8; 16]))
        .await;
    test_case.check_invalid_batch_size_response(
        response.status(),
        take_problem_details(&mut response).await,
    );

    // Put some batch aggregations in the DB.
    let interval_1 = Interval::minimal(Time::from_seconds_since_epoch(
        500,
        test_case.task.time_precision(),
    ))
    .unwrap();
    let interval_1_report_count = 5;
    let interval_1_checksum = ReportIdChecksum::get_decoded(&[3; 32]).unwrap();

    let interval_2 = Interval::minimal(Time::from_seconds_since_epoch(
        1500,
        test_case.task.time_precision(),
    ))
    .unwrap();
    let interval_2_report_count = 5;
    let interval_2_checksum = ReportIdChecksum::get_decoded(&[2; 32]).unwrap();

    let interval_3 = Interval::minimal(Time::from_seconds_since_epoch(
        2000,
        test_case.task.time_precision(),
    ))
    .unwrap();
    let interval_3_report_count = 5;
    let interval_3_checksum = ReportIdChecksum::get_decoded(&[4; 32]).unwrap();

    let interval_4 = Interval::minimal(Time::from_seconds_since_epoch(
        2500,
        test_case.task.time_precision(),
    ))
    .unwrap();
    let interval_4_report_count = 5;
    let interval_4_checksum = ReportIdChecksum::get_decoded(&[8; 32]).unwrap();
    test_case
        .test
        .datastore
        .run_unnamed_tx(|tx| {
            let task = test_case.task.clone();
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
        CollectionJobReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_time_precision_units(0),
                    Duration::from_seconds(1000, test_case.task.time_precision()),
                )
                .unwrap(),
            ),
            dummy::AggregationParam(0).get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(
            Interval::new(
                Time::from_time_precision_units(0),
                Duration::from_seconds(1000, test_case.task.time_precision()),
            )
            .unwrap(),
        ),
        5,
        ReportIdChecksum::default(),
    );
    let mut response = test_case
        .put_aggregate_share_request(&request, &AggregateShareId::from([0u8; 16]))
        .await;
    test_case.check_invalid_batch_size_response(
        response.status(),
        take_problem_details(&mut response).await,
    );

    // Make requests that will fail because the checksum or report counts don't match.
    struct MisalignedRequestTestCase<B: janus_messages::batch_mode::BatchMode> {
        name: &'static str,
        // Each case needs its own ID: a batch mismatch still persists the job, so reusing one
        // would bind a single ID to two batches.
        aggregate_share_id: AggregateShareId,
        request: AggregateShareReq<B>,
        expected_checksum: ReportIdChecksum,
        expected_report_count: u64,
    }
    for misaligned_request in [
        MisalignedRequestTestCase {
            name: "Interval is big enough but the checksums don't match",
            aggregate_share_id: AggregateShareId::from([1u8; 16]),
            request: AggregateShareReq::new(
                CollectionJobReq::new(
                    Query::new_time_interval(
                        Interval::new(
                            Time::from_time_precision_units(0),
                            Duration::from_seconds(2000, test_case.task.time_precision()),
                        )
                        .unwrap(),
                    ),
                    dummy::AggregationParam(0).get_encoded().unwrap(),
                ),
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_time_precision_units(0),
                        Duration::from_seconds(2000, test_case.task.time_precision()),
                    )
                    .unwrap(),
                ),
                10,
                ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
            ),
            expected_checksum: interval_1_checksum.combined_with(&interval_2_checksum),
            expected_report_count: interval_1_report_count + interval_2_report_count,
        },
        MisalignedRequestTestCase {
            name: "Interval is big enough but report count doesn't match",
            aggregate_share_id: AggregateShareId::from([2u8; 16]),
            request: AggregateShareReq::new(
                CollectionJobReq::new(
                    Query::new_time_interval(
                        Interval::new(
                            Time::from_seconds_since_epoch(2000, test_case.task.time_precision()),
                            Duration::from_seconds(2000, test_case.task.time_precision()),
                        )
                        .unwrap(),
                    ),
                    dummy::AggregationParam(0).get_encoded().unwrap(),
                ),
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000, test_case.task.time_precision()),
                        Duration::from_seconds(2000, test_case.task.time_precision()),
                    )
                    .unwrap(),
                ),
                20,
                ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
            ),
            expected_checksum: interval_3_checksum.combined_with(&interval_4_checksum),
            expected_report_count: interval_3_report_count + interval_4_report_count,
        },
    ] {
        let mut response = test_case
            .put_aggregate_share_request(
                &misaligned_request.request,
                &misaligned_request.aggregate_share_id,
            )
            .await;

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            misaligned_request.name
        );

        let expected_error = BatchMismatch {
            task_id: *test_case.task.id(),
            own_checksum: misaligned_request.expected_checksum,
            own_report_count: misaligned_request.expected_report_count,
            peer_checksum: *misaligned_request.request.checksum(),
            peer_report_count: misaligned_request.request.report_count(),
        };
        assert_eq!(
            take_problem_details(&mut response).await,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:batchMismatch",
                "title": "Leader and helper disagree on reports aggregated in a batch.",
                "taskid": format!("{}", test_case.task.id()),
                "detail": expected_error.to_string(),
            }),
            "{}",
            misaligned_request.name,
        );
    }

    // Valid requests: intervals are big enough, do not overlap, checksum and report count are
    // good.
    // These cover the same batches as the misaligned requests above, so they address the same
    // aggregate share resources and reuse their IDs.
    for (label, aggregate_share_id, request, expected_result) in [
        (
            "first and second batches",
            AggregateShareId::from([1u8; 16]),
            AggregateShareReq::new(
                CollectionJobReq::new(
                    Query::new_time_interval(
                        Interval::new(
                            Time::from_time_precision_units(0),
                            Duration::from_seconds(2000, test_case.task.time_precision()),
                        )
                        .unwrap(),
                    ),
                    dummy::AggregationParam(0).get_encoded().unwrap(),
                ),
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_time_precision_units(0),
                        Duration::from_seconds(2000, test_case.task.time_precision()),
                    )
                    .unwrap(),
                ),
                10,
                ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
            ),
            dummy::expected_aggregate_result(0, [16, 32]),
        ),
        (
            "third and fourth batches",
            AggregateShareId::from([2u8; 16]),
            AggregateShareReq::new(
                CollectionJobReq::new(
                    Query::new_time_interval(
                        Interval::new(
                            Time::from_seconds_since_epoch(2000, test_case.task.time_precision()),
                            Duration::from_seconds(2000, test_case.task.time_precision()),
                        )
                        .unwrap(),
                    ),
                    dummy::AggregationParam(0).get_encoded().unwrap(),
                ),
                BatchSelector::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000, test_case.task.time_precision()),
                        Duration::from_seconds(2000, test_case.task.time_precision()),
                    )
                    .unwrap(),
                ),
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
            let mut response = test_case
                .put_aggregate_share_request(&request, &aggregate_share_id)
                .await;

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "test case: {label:?}, iteration: {iteration}"
            );
            assert_eq!(
                response.headers().get(http::header::CONTENT_TYPE).unwrap(),
                AggregateShareMessage::MEDIA_TYPE,
            );
            let aggregate_share_resp: AggregateShareMessage =
                decode_response_body(&mut response).await;

            let aggregate_share = test_case
                .open_aggregate_share(&request, &aggregate_share_resp)
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
            test_case
                .test
                .datastore
                .run_unnamed_tx(|tx| {
                    let task = test_case.task.clone();
                    let collection_interval = *request.batch_selector().batch_interval();

                    Box::pin(async move {
                        let batch_aggregations: Vec<_> = try_join_all(
                            TimeInterval::batch_identifiers_for_collection_identifier(
                                &collection_interval,
                            )
                            .map(|batch_identifier| {
                                let task_id = *task.id();

                                async move {
                                    tx.get_batch_aggregations_for_batch::<
                                        0,
                                        TimeInterval,
                                        dummy::Vdaf,
                                    >(
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
        CollectionJobReq::new(
            Query::new_time_interval(
                Interval::new(
                    Time::from_time_precision_units(0),
                    Duration::from_seconds(4000, test_case.task.time_precision()),
                )
                .unwrap(),
            ),
            dummy::AggregationParam(0).get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(
            Interval::new(
                Time::from_time_precision_units(0),
                Duration::from_seconds(4000, test_case.task.time_precision()),
            )
            .unwrap(),
        ),
        20,
        ReportIdChecksum::get_decoded(&[8 ^ 4 ^ 3 ^ 2; 32]).unwrap(),
    );
    let mut response = test_case
        .put_aggregate_share_request(&all_batch_request, &AggregateShareId::from([5u8; 16]))
        .await;
    test_case
        .check_batch_overlap_response(response.status(), take_problem_details(&mut response).await);

    // Previous sequence of aggregate share requests should have consumed the available queries
    // for all the batches. Further requests for any batches will cause query count violations.
    for query_count_violation_request in [
        AggregateShareReq::new(
            CollectionJobReq::new(
                Query::new_time_interval(
                    Interval::new(
                        Time::from_time_precision_units(0),
                        Duration::from_seconds(2000, test_case.task.time_precision()),
                    )
                    .unwrap(),
                ),
                dummy::AggregationParam(1).get_encoded().unwrap(),
            ),
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_time_precision_units(0),
                    Duration::from_seconds(2000, test_case.task.time_precision()),
                )
                .unwrap(),
            ),
            10,
            ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
        ),
        AggregateShareReq::new(
            CollectionJobReq::new(
                Query::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(2000, test_case.task.time_precision()),
                        Duration::from_seconds(2000, test_case.task.time_precision()),
                    )
                    .unwrap(),
                ),
                dummy::AggregationParam(1).get_encoded().unwrap(),
            ),
            BatchSelector::new_time_interval(
                Interval::new(
                    Time::from_seconds_since_epoch(2000, test_case.task.time_precision()),
                    Duration::from_seconds(2000, test_case.task.time_precision()),
                )
                .unwrap(),
            ),
            10,
            ReportIdChecksum::get_decoded(&[4 ^ 8; 32]).unwrap(),
        ),
    ] {
        let mut response = test_case
            .put_aggregate_share_request(
                &query_count_violation_request,
                &AggregateShareId::from([6u8; 16]),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            take_problem_details(&mut response).await,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "detail": "batch has already been collected with another aggregation parameter",
                "taskid": format!("{}", test_case.task.id()),
            })
        );
    }
}

#[tokio::test]
async fn aggregate_share_request_duplicate_with_different_id() {
    // Set up batch aggregations that will be used for the duplicate requests
    let batch_interval = Interval::minimal(Time::from_time_precision_units(0)).unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let test_case = AggregateShareTestCase::builder()
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval,
            aggregation_param,
        })
        .build()
        .await;

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(batch_interval),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(batch_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id_1 = AggregateShareId::from([1u8; 16]);
    let aggregate_share_id_2 = AggregateShareId::from([2u8; 16]);

    // First request with aggregate_share_id_1 should succeed
    let response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id_1)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Second request with same parameters but different aggregate share ID should fail
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id_2)
        .await;
    test_case.check_forbidden_mutation_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id_1,
    );
}

#[tokio::test]
async fn aggregate_share_request_get_poll_after_put() {
    // Set up batch aggregations that will be used for the duplicate requests
    let batch_interval = Interval::minimal(Time::from_time_precision_units(0)).unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let test_case = AggregateShareTestCase::builder()
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval,
            aggregation_param,
        })
        .build()
        .await;

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(batch_interval),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(batch_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);

    // Send the request. We'll ignore the details of the response and check that polling still
    // works.
    let response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Try to GET the first ID again. It should be OK.
    let response = test_case.get_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Ensure it's idempotent.
    let mut response = test_case.get_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE).unwrap(),
        AggregateShareMessage::MEDIA_TYPE,
    );
    let aggregate_share_resp: AggregateShareMessage = decode_response_body(&mut response).await;
    test_case
        .open_aggregate_share(&request, &aggregate_share_resp)
        .unwrap();

    // We should be able to delete it
    let response = test_case.delete_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn aggregate_share_request_get_poll_after_put_leader_selected() {
    let batch_id = BatchId::from([9u8; 32]);
    let client_timestamp_interval = Interval::minimal(Time::from_time_precision_units(0)).unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::leader_selected()))
        .with_leader_selected_batch_aggregation(LeaderSelectedBatchAggregationSetup {
            batch_id,
            client_timestamp_interval,
            aggregation_param,
        })
        .build()
        .await;

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_leader_selected(random()),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_leader_selected(batch_id),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);

    // PUT binds the forwarded CollectionJobReq; poll (GET) reuses the stored copy.
    let response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let mut response = test_case.get_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    let aggregate_share_resp: AggregateShareMessage = decode_response_body(&mut response).await;
    test_case
        .open_aggregate_share(&request, &aggregate_share_resp)
        .unwrap();
}

// DAP-19 §4.6.4 only requires the batch selector to be contained in the collector's query, and the
// AAD binds the query, not the selector.
#[tokio::test]
async fn aggregate_share_request_narrower_selector_than_query() {
    let selected_interval = Interval::minimal(Time::from_time_precision_units(3)).unwrap();
    let queried_interval = Interval::new(
        Time::from_time_precision_units(0),
        Duration::from_time_precision_units(10),
    )
    .unwrap();
    let aggregation_param = dummy::AggregationParam(0);

    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval: selected_interval,
            aggregation_param,
        })
        .build()
        .await;

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(queried_interval),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(selected_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);
    let response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let mut response = test_case.get_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    let aggregate_share_resp: AggregateShareMessage = decode_response_body(&mut response).await;
    hpke::open(
        test_case.task.collector_hpke_keypair(),
        &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
        aggregate_share_resp.encrypted_aggregate_share(),
        &AggregateShareAad::new(
            *test_case.task.id(),
            test_case.task.task_configuration(),
            request.collection_job_req().clone(),
        )
        .get_encoded()
        .unwrap(),
    )
    .unwrap();

    // The AAD must come from the stored request, not from a query derived from the selector.
    assert!(
        hpke::open(
            test_case.task.collector_hpke_keypair(),
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            aggregate_share_resp.encrypted_aggregate_share(),
            &AggregateShareAad::new(
                *test_case.task.id(),
                test_case.task.task_configuration(),
                // selected_interval should be different than queried_interval. If it
                // isn't, then we might have "simplified" in the Helper (probably) to
                // make selected interval === queried, which isn't what DAP-19 says.
                CollectionJobReq::new(
                    Query::new_time_interval(selected_interval),
                    aggregation_param.get_encoded().unwrap(),
                ),
            )
            .get_encoded()
            .unwrap(),
        )
        .is_err()
    );
}

// Two requests to the same aggregate share resource that differ in their query are rejected
// as conflicting dupes.
#[tokio::test]
async fn aggregate_share_request_duplicate_with_different_query() {
    let selected_interval = Interval::minimal(Time::from_time_precision_units(3)).unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval: selected_interval,
            aggregation_param,
        })
        .build()
        .await;

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);
    let request_for_query = |duration| {
        AggregateShareReq::new(
            CollectionJobReq::new(
                Query::new_time_interval(
                    Interval::new(
                        Time::from_time_precision_units(0),
                        Duration::from_time_precision_units(duration),
                    )
                    .unwrap(),
                ),
                aggregation_param.get_encoded().unwrap(),
            ),
            BatchSelector::new_time_interval(selected_interval),
            AggregateShareTestCase::REPORT_COUNT,
            AggregateShareTestCase::CHECKSUM,
        )
    };

    let response = test_case
        .put_aggregate_share_request(&request_for_query(10), &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let mut response = test_case
        .put_aggregate_share_request(&request_for_query(20), &aggregate_share_id)
        .await;
    test_case.check_forbidden_mutation_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );
}

// One aggregate share ID must not be bound to two batches: the poll path looks jobs up by ID
// alone and cannot disambiguate. Narrower-than-query selectors make this easy to hit, since one
// query now admits several batches.
#[tokio::test]
async fn aggregate_share_request_same_id_different_batch() {
    let first_interval = Interval::minimal(Time::from_time_precision_units(3)).unwrap();
    let second_interval = Interval::minimal(Time::from_time_precision_units(5)).unwrap();
    let queried_interval = Interval::new(
        Time::from_time_precision_units(0),
        Duration::from_time_precision_units(10),
    )
    .unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval: first_interval,
            aggregation_param,
        })
        .build()
        .await;

    // A second batch, also contained in the collector's query.
    let helper_task = test_case.task.helper_view().unwrap();
    test_case
        .test
        .datastore
        .run_unnamed_tx(|tx| {
            let helper_task = helper_task.clone();
            Box::pin(async move {
                tx.put_batch_aggregation(&BatchAggregation::<0, TimeInterval, dummy::Vdaf>::new(
                    *helper_task.id(),
                    second_interval,
                    aggregation_param,
                    0,
                    second_interval,
                    BatchAggregationState::Aggregating {
                        aggregate_share: Some(dummy::AggregateShare(16)),
                        report_count: AggregateShareTestCase::REPORT_COUNT,
                        checksum: AggregateShareTestCase::CHECKSUM,
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

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);
    let request_for_batch = |batch_interval| {
        AggregateShareReq::new(
            CollectionJobReq::new(
                Query::new_time_interval(queried_interval),
                aggregation_param.get_encoded().unwrap(),
            ),
            BatchSelector::new_time_interval(batch_interval),
            AggregateShareTestCase::REPORT_COUNT,
            AggregateShareTestCase::CHECKSUM,
        )
    };

    let response = test_case
        .put_aggregate_share_request(&request_for_batch(first_interval), &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let mut response = test_case
        .put_aggregate_share_request(&request_for_batch(second_interval), &aggregate_share_id)
        .await;
    test_case.check_forbidden_mutation_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );
}

// Proves the TaskConfiguration in the aggregate-share AAD works: a mismatched one must not open
// the helper's share.
#[tokio::test]
async fn aggregate_share_aad_task_configuration_mismatch_fails() {
    let batch_interval = Interval::minimal(Time::from_time_precision_units(0)).unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| {
            tb.with_batch_mode(BatchMode::TimeInterval)
                .with_min_batch_size(1)
        })
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval,
            aggregation_param,
        })
        .build()
        .await;

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(batch_interval),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(batch_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let mut response = test_case
        .put_aggregate_share_request(&request, &AggregateShareId::from([7u8; 16]))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let aggregate_share_resp: AggregateShareMessage = decode_response_body(&mut response).await;

    // A task identical except for `min_batch_size` yields a different TaskConfiguration, so its AAD
    // must not open the helper's share.
    let mismatched_task_configuration = TaskBuilder::new(
        BatchMode::TimeInterval,
        AggregationMode::Synchronous,
        VdafInstance::Fake { rounds: 1 },
    )
    .with_helper_aggregator_endpoint("https://helper.example.com/".parse().unwrap())
    .with_min_batch_size(2)
    .build()
    .task_configuration();
    assert_ne!(
        mismatched_task_configuration,
        test_case.task.task_configuration(),
    );

    let result = hpke::open(
        test_case.task.collector_hpke_keypair(),
        &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
        aggregate_share_resp.encrypted_aggregate_share(),
        &AggregateShareAad::new(
            *test_case.task.id(),
            mismatched_task_configuration,
            request.collection_job_req().clone(),
        )
        .get_encoded()
        .unwrap(),
    );
    assert!(
        result.is_err(),
        "mismatched TaskConfiguration must not decrypt"
    );
}

#[tokio::test]
async fn aggregate_share_request_get_unrecognized_id() {
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    // Try to GET an aggregate share that doesn't exist
    let nonexistent_aggregate_share_id = AggregateShareId::from([99u8; 16]);

    let mut response = test_case
        .get_aggregate_share(&nonexistent_aggregate_share_id)
        .await;
    test_case.check_unrecognized_aggregate_share_response(
        response.status(),
        take_problem_details(&mut response).await,
        &nonexistent_aggregate_share_id,
    );
}

#[tokio::test]
async fn aggregate_share_delete_nonexistant() {
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    // Try to DELETE an aggregate share that doesn't exist
    let nonexistent_aggregate_share_id = AggregateShareId::from([99u8; 16]);

    let mut response = test_case
        .delete_aggregate_share(&nonexistent_aggregate_share_id)
        .await;
    test_case.check_unrecognized_aggregate_share_response(
        response.status(),
        take_problem_details(&mut response).await,
        &nonexistent_aggregate_share_id,
    );
}

#[tokio::test]
async fn aggregate_share_request_batch_selector_inconsistent_with_query() {
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    let interval = |start, duration| {
        Interval::new(
            Time::from_time_precision_units(start),
            Duration::from_time_precision_units(duration),
        )
        .unwrap()
    };
    let queried_interval = interval(10, 10);

    for selected_interval in [
        interval(30, 10), // disjoint from the queried interval
        interval(15, 10), // overruns the end of the queried interval
        interval(5, 20),  // a superset of the queried interval
    ] {
        let request = AggregateShareReq::new(
            CollectionJobReq::new(
                Query::new_time_interval(queried_interval),
                dummy::AggregationParam(0).get_encoded().unwrap(),
            ),
            BatchSelector::new_time_interval(selected_interval),
            0,
            ReportIdChecksum::default(),
        );

        let mut response = test_case
            .put_aggregate_share_request(&request, &AggregateShareId::from([0u8; 16]))
            .await;
        test_case.check_batch_invalid_response(
            response.status(),
            take_problem_details(&mut response).await,
        );
    }
}

// The helper validates the collector's extensions itself rather than trusting the leader
// (DAP-19 §4.6.4).
#[tokio::test]
async fn aggregate_share_request_unsupported_extension() {
    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::TimeInterval))
        .build()
        .await;

    let batch_interval = Interval::new(
        Time::from_time_precision_units(10),
        Duration::from_time_precision_units(10),
    )
    .unwrap();

    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(batch_interval),
            dummy::AggregationParam(0).get_encoded().unwrap(),
        )
        .with_extensions(Vec::from([CollectionJobExtension::new(
            CollectionJobExtensionType::Unknown(0xbeef),
            Vec::from([0]),
        )])),
        BatchSelector::new_time_interval(batch_interval),
        0,
        ReportIdChecksum::default(),
    );

    let mut response = test_case
        .put_aggregate_share_request(&request, &AggregateShareId::from([0u8; 16]))
        .await;

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
async fn recreate_deleted_aggregate_share_time_interval() {
    let selected_interval = Interval::minimal(Time::from_time_precision_units(3)).unwrap();
    let queried_interval = Interval::new(
        Time::from_time_precision_units(0),
        Duration::from_time_precision_units(10),
    )
    .unwrap();
    let aggregation_param = dummy::AggregationParam(0);

    let test_case = AggregateShareTestCase::builder()
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval: selected_interval,
            aggregation_param,
        })
        .build()
        .await;

    // Drive aggregate share request to successful completion.
    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(queried_interval),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(selected_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_response_body::<AggregateShareMessage>(&mut response).await;

    let mut response = test_case.delete_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(take_response_body(&mut response).await.is_empty());

    // Re-creating the aggregate share with an identical request should be refused because it has
    // been deleted.
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    test_case.check_unrecognized_aggregate_share_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );

    // Re-creating the aggregate share with a mutated request should fail with forbidden mutation.
    let mutant_request = AggregateShareReq::new(
        CollectionJobReq::new(
            request.collection_job_req().query().clone(),
            dummy::AggregationParam(17).get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(selected_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );
    let mut response = test_case
        .put_aggregate_share_request(&mutant_request, &aggregate_share_id)
        .await;
    test_case.check_forbidden_mutation_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );
}

#[tokio::test]
async fn recreate_deleted_aggregate_share_leader_selected() {
    let selected_interval = Interval::minimal(Time::from_time_precision_units(3)).unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let batch_id = random();

    let test_case = AggregateShareTestCase::builder()
        .build_task(|tb| tb.with_batch_mode(BatchMode::leader_selected()))
        .with_leader_selected_batch_aggregation(LeaderSelectedBatchAggregationSetup {
            batch_id,
            client_timestamp_interval: selected_interval,
            aggregation_param,
        })
        .build()
        .await;

    // Drive aggregate share request to successful completion.
    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_leader_selected(random()),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_leader_selected(batch_id),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_response_body::<AggregateShareMessage>(&mut response).await;

    let mut response = test_case.delete_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(take_response_body(&mut response).await.is_empty());

    // Re-creating the aggregate share with an identical request should be refused because it has
    // been deleted.
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    test_case.check_unrecognized_aggregate_share_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );

    // Re-creating the aggregate share with a mutated request should fail with forbidden mutation.
    let mutant_request = AggregateShareReq::new(
        CollectionJobReq::new(
            request.collection_job_req().query().clone(),
            dummy::AggregationParam(17).get_encoded().unwrap(),
        ),
        BatchSelector::new_leader_selected(batch_id),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );
    let mut response = test_case
        .put_aggregate_share_request(&mutant_request, &aggregate_share_id)
        .await;
    test_case.check_forbidden_mutation_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );
}

#[tokio::test]
#[ignore = "test will be fixed in #4950"]
async fn recreate_expired_aggregate_share_time_interval() {
    let clock = MockClock::default();
    let now = Time::from_seconds_since_epoch(
        clock.now().as_seconds_since_epoch(),
        &TaskBuilder::DEFAULT_TIME_PRECISION,
    );
    let expiry = Duration::from_time_precision_units(20);

    let selected_interval = Interval::minimal(
        now.sub_duration(&Duration::from_time_precision_units(3))
            .unwrap(),
    )
    .unwrap();
    let queried_interval = Interval::new(
        now.sub_duration(&Duration::from_time_precision_units(10))
            .unwrap(),
        Duration::from_time_precision_units(10),
    )
    .unwrap();
    let aggregation_param = dummy::AggregationParam(0);

    let test_case = AggregateShareTestCase::builder()
        .with_clock(clock.clone())
        .build_task(|tb| tb.with_report_expiry_age(Some(expiry)))
        .with_time_interval_batch_aggregation(TimeIntervalBatchAggregationSetup {
            batch_interval: selected_interval,
            aggregation_param,
        })
        .build()
        .await;

    assert_eq!(
        &TaskBuilder::DEFAULT_TIME_PRECISION,
        test_case.task.time_precision()
    );

    // Drive aggregate share request to successful completion.
    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_time_interval(queried_interval),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(selected_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_response_body::<AggregateShareMessage>(&mut response).await;

    let mut response = test_case.get_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_response_body::<AggregateShareMessage>(&mut response).await;

    // Advance clock far enough for the aggregate share to expire.
    clock.advance(TimeDelta::seconds(
        expiry.as_seconds(test_case.task.time_precision()) as i64,
    ));

    assert_eq!(
        test_case
            .get_aggregate_share(&aggregate_share_id)
            .await
            .status(),
        StatusCode::NOT_FOUND,
    );

    // Re-creating the aggregate share with an identical request should be refused.
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    test_case.check_aggregate_share_rejection_response(
        response.status(),
        take_problem_details(&mut response).await,
    );

    // Re-creating the aggregate share with a mutated request should fail with forbidden mutation.
    let mutant_request = AggregateShareReq::new(
        CollectionJobReq::new(
            request.collection_job_req().query().clone(),
            dummy::AggregationParam(17).get_encoded().unwrap(),
        ),
        BatchSelector::new_time_interval(selected_interval),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );
    let mut response = test_case
        .put_aggregate_share_request(&mutant_request, &aggregate_share_id)
        .await;
    test_case.check_forbidden_mutation_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );
}

#[tokio::test]
#[ignore = "test will be fixed in #4950"]
async fn recreate_expired_aggregate_share_leader_selected() {
    let clock = MockClock::default();
    let now = Time::from_seconds_since_epoch(
        clock.now().as_seconds_since_epoch(),
        &TaskBuilder::DEFAULT_TIME_PRECISION,
    );
    let selected_interval = Interval::minimal(
        now.sub_duration(&Duration::from_time_precision_units(3))
            .unwrap(),
    )
    .unwrap();
    let aggregation_param = dummy::AggregationParam(0);
    let batch_id = random();
    let expiry = Duration::from_time_precision_units(20);

    let test_case = AggregateShareTestCase::builder()
        .with_clock(clock.clone())
        .build_task(|tb| {
            tb.with_batch_mode(BatchMode::leader_selected())
                .with_report_expiry_age(Some(expiry))
        })
        .with_leader_selected_batch_aggregation(LeaderSelectedBatchAggregationSetup {
            batch_id,
            client_timestamp_interval: selected_interval,
            aggregation_param,
        })
        .build()
        .await;

    assert_eq!(
        &TaskBuilder::DEFAULT_TIME_PRECISION,
        test_case.task.time_precision()
    );

    // Drive aggregate share request to successful completion.
    let request = AggregateShareReq::new(
        CollectionJobReq::new(
            Query::new_leader_selected(random()),
            aggregation_param.get_encoded().unwrap(),
        ),
        BatchSelector::new_leader_selected(batch_id),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );

    let aggregate_share_id = AggregateShareId::from([42u8; 16]);
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_response_body::<AggregateShareMessage>(&mut response).await;

    let mut response = test_case.get_aggregate_share(&aggregate_share_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_response_body::<AggregateShareMessage>(&mut response).await;

    // Advance clock far enough for the aggregate share to expire.
    clock.advance(TimeDelta::seconds(
        expiry.as_seconds(test_case.task.time_precision()) as i64,
    ));

    assert_eq!(
        test_case
            .get_aggregate_share(&aggregate_share_id)
            .await
            .status(),
        StatusCode::NOT_FOUND,
    );

    // Re-creating the aggregate share with an identical request should be refused.
    let mut response = test_case
        .put_aggregate_share_request(&request, &aggregate_share_id)
        .await;
    test_case.check_aggregate_share_rejection_response(
        response.status(),
        take_problem_details(&mut response).await,
    );

    // Re-creating the aggregate share with a mutated request should fail with forbidden mutation.
    let mutant_request = AggregateShareReq::new(
        CollectionJobReq::new(
            request.collection_job_req().query().clone(),
            dummy::AggregationParam(17).get_encoded().unwrap(),
        ),
        BatchSelector::new_leader_selected(batch_id),
        AggregateShareTestCase::REPORT_COUNT,
        AggregateShareTestCase::CHECKSUM,
    );
    let mut response = test_case
        .put_aggregate_share_request(&mutant_request, &aggregate_share_id)
        .await;
    test_case.check_forbidden_mutation_response(
        response.status(),
        take_problem_details(&mut response).await,
        &aggregate_share_id,
    );
}
