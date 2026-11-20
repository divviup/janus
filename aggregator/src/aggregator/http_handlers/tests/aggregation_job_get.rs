use axum::body::Body;
use http::{Request, StatusCode};
use janus_aggregator_core::{
    datastore::models::{
        AggregationJobState, ReportAggregation, ReportAggregationState, UnwrittenAggregationJob,
    },
    task::{
        AggregationMode, BatchMode,
        test_util::{Task, TaskBuilder},
    },
};
use janus_core::{auth_tokens::test_util::WithAuthenticationToken, vdaf::VdafInstance};
use janus_messages::{
    AggregationJobId, AggregationJobResp, AggregationJobStep, Interval, MediaType, Role,
    VerifyInit, VerifyResp, VerifyStepResult,
};
use prio::vdaf::dummy;
use rand::random;
use tower::ServiceExt;

use crate::aggregator::{
    aggregation_job_init::test_util::VerifyInitGenerator,
    http_handlers::test_util::{HttpHandlerTest, decode_response_body, take_response_body},
};

struct AggregationJobGetTestCase {
    http_handler_test: HttpHandlerTest,
    task: Task,
    aggregation_job_id: AggregationJobId,
}

impl AggregationJobGetTestCase {
    async fn new() -> Self {
        Self::builder().build().await
    }

    fn builder() -> AggregationJobGetTestCaseBuilder {
        AggregationJobGetTestCaseBuilder {
            task_builder: TaskBuilder::new(
                BatchMode::TimeInterval,
                AggregationMode::Asynchronous,
                VdafInstance::Fake { rounds: 1 },
            ),
            role: Role::Helper,
            active_job: false,
        }
    }

    async fn get_aggregation_job(
        &self,
        aggregation_job_id: AggregationJobId,
        step: Option<AggregationJobStep>,
    ) -> http::Response<Body> {
        let uri = self
            .task
            .aggregation_job_uri(aggregation_job_id, step)
            .unwrap();
        let uri = match uri.query() {
            Some(query) => format!("{}?{}", uri.path(), query),
            None => uri.path().to_string(),
        };

        let req = Request::get(uri)
            .with_authentication_token(self.task.aggregator_auth_token())
            .body(Body::empty())
            .unwrap();
        self.http_handler_test
            .router
            .clone()
            .oneshot(req)
            .await
            .unwrap()
    }

    async fn get_aggregation_job_and_decode(
        &self,
        aggregation_job_id: AggregationJobId,
        step: Option<AggregationJobStep>,
    ) -> AggregationJobResp {
        let mut response = self.get_aggregation_job(aggregation_job_id, step).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE).unwrap(),
            AggregationJobResp::MEDIA_TYPE
        );
        decode_response_body(&mut response).await
    }
}

struct AggregationJobGetTestCaseBuilder {
    task_builder: TaskBuilder,
    role: Role,
    active_job: bool,
}

impl AggregationJobGetTestCaseBuilder {
    async fn build(self) -> AggregationJobGetTestCase {
        let http_handler_test = HttpHandlerTest::new().await;

        let task = self.task_builder.build();

        let role_task = match self.role {
            Role::Leader => task.leader_view().unwrap(),
            Role::Helper => task.helper_view().unwrap(),
            _ => panic!("unexpected role"),
        };
        http_handler_test
            .datastore
            .put_aggregator_task(&role_task)
            .await
            .unwrap();

        let aggregation_job_id: AggregationJobId = random();
        let aggregation_param = dummy::AggregationParam(7);
        let verify_init_generator = VerifyInitGenerator::new(
            http_handler_test.clock.clone(),
            role_task,
            http_handler_test.hpke_keypair.config().clone(),
            dummy::Vdaf::new(1),
            aggregation_param.clone(),
        );

        let (verify_init, transcript) = verify_init_generator.next(&13);

        http_handler_test
            .datastore
            .run_unnamed_tx(|tx| {
                let task_id = *task.id();
                let report_metadata = verify_init.report_share().metadata().clone();
                let helper_message = transcript.helper_verify_transitions[0]
                    .message()
                    .unwrap()
                    .clone();
                let leader_message = transcript.leader_verify_transitions[0]
                    .message()
                    .unwrap()
                    .clone();
                let report_share = verify_init.report_share().clone();
                let active_job = self.active_job;
                let helper_aggregation_job_id = aggregation_job_id.clone();

                Box::pin(async move {
                    tx.put_scrubbed_report(&task_id, report_metadata.id(), report_metadata.time())
                        .await
                        .unwrap();

                    let job_id = tx
                        .put_aggregation_job(&UnwrittenAggregationJob::new(
                            task_id,
                            aggregation_param,
                            (),
                            Interval::minimal(*report_metadata.time()).unwrap(),
                            if active_job {
                                AggregationJobState::Active {
                                    helper_aggregation_job_id,
                                }
                            } else {
                                AggregationJobState::AwaitingRequest {
                                    helper_aggregation_job_id,
                                }
                            },
                            AggregationJobStep::from(0),
                        ))
                        .await
                        .unwrap();

                    tx.put_report_aggregation(&ReportAggregation::<0, dummy::Vdaf>::new(
                        task_id,
                        job_id,
                        *report_metadata.id(),
                        *report_metadata.time(),
                        0,
                        if self.active_job {
                            Some(VerifyResp::new(
                                *report_metadata.id(),
                                VerifyStepResult::Continue {
                                    message: helper_message,
                                },
                            ))
                        } else {
                            None
                        },
                        if self.active_job {
                            ReportAggregationState::HelperInitProcessing {
                                verify_init: VerifyInit::new(report_share, leader_message),
                                require_taskbind_extension: false,
                            }
                        } else {
                            ReportAggregationState::Finished
                        },
                    ))
                    .await
                    .unwrap();

                    Ok(())
                })
            })
            .await
            .unwrap();

        AggregationJobGetTestCase {
            http_handler_test,
            task,
            aggregation_job_id,
        }
    }

    fn with_role(self, role: Role) -> Self {
        Self { role, ..self }
    }

    fn with_active_job(self, active_job: bool) -> Self {
        Self { active_job, ..self }
    }

    fn build_task<F: FnMut(TaskBuilder) -> TaskBuilder>(self, mut f: F) -> Self {
        Self {
            task_builder: f(self.task_builder),
            ..self
        }
    }
}

#[tokio::test]
async fn ready() {
    let test_case = AggregationJobGetTestCase::new().await;

    test_case
        .get_aggregation_job_and_decode(
            test_case.aggregation_job_id,
            Some(AggregationJobStep::from(0)),
        )
        .await;
}

#[tokio::test]
async fn unready() {
    let test_case = AggregationJobGetTestCase::builder()
        .with_active_job(false)
        .build()
        .await;

    let mut response = test_case
        .get_aggregation_job(
            test_case.aggregation_job_id,
            Some(AggregationJobStep::from(0)),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(take_response_body(&mut response).await, b"");
}

#[tokio::test]
async fn wrong_step() {
    // Job is on step 0, so getting ?step=1 should fail
    let test_case = AggregationJobGetTestCase::new().await;

    let response = test_case
        .get_aggregation_job(
            test_case.aggregation_job_id,
            Some(AggregationJobStep::from(1)),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_step() {
    // Omitting step is a bad request
    let test_case = AggregationJobGetTestCase::new().await;

    let response = test_case
        .get_aggregation_job(test_case.aggregation_job_id, None)
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sync() {
    // Getting aggregation jobs is not supported in synchronous mode
    let test_case = AggregationJobGetTestCase::builder()
        .build_task(|task_builder| {
            task_builder.with_helper_aggregation_mode(AggregationMode::Synchronous)
        })
        .build()
        .await;

    let response = test_case
        .get_aggregation_job(
            test_case.aggregation_job_id,
            Some(AggregationJobStep::from(0)),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn leader() {
    // Leader doesn't have aggregation job endpoints
    let test_case = AggregationJobGetTestCase::builder()
        .with_role(Role::Leader)
        .build()
        .await;

    let response = test_case
        .get_aggregation_job(
            test_case.aggregation_job_id,
            Some(AggregationJobStep::from(0)),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
