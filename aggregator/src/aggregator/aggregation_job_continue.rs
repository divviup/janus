//! Implements portions of aggregation job continuation for the helper.

use crate::aggregator::{accumulator::Accumulator, Error, VdafOps};
use futures::future::try_join_all;
use janus_aggregator_core::{
    datastore::{
        self,
        models::{AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState},
        Transaction,
    },
    query_type::AccumulableQueryType,
    task::Task,
};
use janus_core::time::Clock;
use janus_messages::{
    AggregateContinueReq, AggregateContinueResp, AggregateInitializeResp, PrepareStep,
    PrepareStepResult, ReportShareError,
};
use opentelemetry::{metrics::Counter, Context, KeyValue};
use prio::{
    codec::{Encode, ParameterizedDecode},
    vdaf::{self, PrepareTransition},
};
use std::{fmt::Debug, io::Cursor, sync::Arc};
use tokio::try_join;
use tracing::{info, trace_span};

impl VdafOps {
    /// Step the helper's aggregation job to the next round of VDAF preparation using the round `n`
    /// prepare state in `report_aggregations` with the round `n+1` broadcast prepare messages in
    /// `leader_aggregation_job`.
    pub(super) async fn step_aggregation_job<const SEED_SIZE: usize, C, Q, A>(
        tx: &Transaction<'_, C>,
        task: Arc<Task>,
        vdaf: Arc<A>,
        batch_aggregation_shard_count: u64,
        helper_aggregation_job: AggregationJob<SEED_SIZE, Q, A>,
        report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
        leader_aggregation_job: Arc<AggregateContinueReq>,
        aggregate_step_failure_counter: Counter<u64>,
    ) -> Result<AggregateContinueResp, datastore::Error>
    where
        C: Clock,
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE> + 'static + Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
    {
        // Handle each transition in the request.
        struct ReportAggregationData<const SEED_SIZE: usize, A>
        where
            A: vdaf::Aggregator<SEED_SIZE>,
            for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        {
            report_aggregation: ReportAggregation<SEED_SIZE, A>,
            prep_step: Option<PrepareStep>,
        }

        let mut report_aggregation_datas: Vec<_> = report_aggregations
            .into_iter()
            .map(|ra| ReportAggregationData {
                report_aggregation: ra,
                prep_step: None,
            })
            .collect();
        let mut report_aggregation_datas_iter = report_aggregation_datas.iter_mut();
        let mut accumulator = Accumulator::<SEED_SIZE, Q, A>::new(
            Arc::clone(&task),
            batch_aggregation_shard_count,
            helper_aggregation_job.aggregation_parameter().clone(),
        );

        for leader_prep_step in leader_aggregation_job.prepare_steps() {
            // Match preparation step received from leader to stored report aggregation, and extract
            // the stored preparation step.
            let report_aggregation_data = loop {
                let rad = report_aggregation_datas_iter.next().ok_or_else(|| {
                    datastore::Error::User(
                        Error::UnrecognizedMessage(
                            Some(*task.id()),
                            "leader sent unexpected, duplicate, or out-of-order prepare steps",
                        )
                        .into(),
                    )
                })?;
                if rad.report_aggregation.report_id() != leader_prep_step.report_id() {
                    // This report was omitted by the leader because of a prior failure. Note that
                    // the report was dropped (if it's not already in an error state) and continue.
                    if matches!(
                        rad.report_aggregation.state(),
                        ReportAggregationState::Waiting(_, _)
                    ) {
                        rad.report_aggregation = rad.report_aggregation.clone().with_state(
                            ReportAggregationState::Failed(ReportShareError::ReportDropped),
                        );
                        rad.prep_step = None;
                    }
                    continue;
                }
                break rad;
            };

            // Make sure this report isn't in an interval that has already started collection.
            let conflicting_aggregate_share_jobs = tx
                .get_aggregate_share_jobs_including_time::<SEED_SIZE, A>(
                    task.id(),
                    report_aggregation_data.report_aggregation.time(),
                )
                .await?;

            if !conflicting_aggregate_share_jobs.is_empty() {
                report_aggregation_data.report_aggregation = report_aggregation_data
                    .report_aggregation
                    .clone()
                    .with_state(ReportAggregationState::Failed(
                        ReportShareError::BatchCollected,
                    ));
                report_aggregation_data.prep_step = Some(PrepareStep::new(
                    *leader_prep_step.report_id(),
                    PrepareStepResult::Failed(ReportShareError::BatchCollected),
                ));
                continue;
            }

            let prep_state = match report_aggregation_data.report_aggregation.state() {
                ReportAggregationState::Waiting(prep_state, _) => prep_state,
                _ => {
                    return Err(datastore::Error::User(
                        Error::UnrecognizedMessage(
                            Some(*task.id()),
                            "leader sent prepare step for non-WAITING report aggregation",
                        )
                        .into(),
                    ));
                }
            };

            // Parse preparation message out of prepare step received from leader.
            let prep_msg = match leader_prep_step.result() {
                PrepareStepResult::Continued(payload) => A::PrepareMessage::decode_with_param(
                    prep_state,
                    &mut Cursor::new(payload.as_ref()),
                )?,
                _ => {
                    return Err(datastore::Error::User(
                        Error::UnrecognizedMessage(
                            Some(*task.id()),
                            "leader sent non-Continued prepare step",
                        )
                        .into(),
                    ));
                }
            };

            // Compute the next transition.
            let prepare_step_res = trace_span!("VDAF preparation")
                .in_scope(|| vdaf.prepare_step(prep_state.clone(), prep_msg));
            match prepare_step_res {
                Ok(PrepareTransition::Continue(prep_state, prep_share)) => {
                    report_aggregation_data.report_aggregation = report_aggregation_data
                        .report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Waiting(prep_state, None));
                    report_aggregation_data.prep_step = Some(PrepareStep::new(
                        *leader_prep_step.report_id(),
                        PrepareStepResult::Continued(prep_share.get_encoded()),
                    ));
                }

                Ok(PrepareTransition::Finish(output_share)) => {
                    accumulator.update(
                        helper_aggregation_job.partial_batch_identifier(),
                        leader_prep_step.report_id(),
                        report_aggregation_data.report_aggregation.time(),
                        &output_share,
                    )?;
                    report_aggregation_data.report_aggregation = report_aggregation_data
                        .report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Finished);
                    report_aggregation_data.prep_step = Some(PrepareStep::new(
                        *leader_prep_step.report_id(),
                        PrepareStepResult::Finished,
                    ));
                }

                Err(error) => {
                    info!(
                        task_id = %task.id(),
                        job_id = %helper_aggregation_job.id(),
                        report_id = %leader_prep_step.report_id(),
                        ?error, "Prepare step failed",
                    );
                    aggregate_step_failure_counter.add(
                        &Context::current(),
                        1,
                        &[KeyValue::new("type", "prepare_step_failure")],
                    );

                    report_aggregation_data.report_aggregation = report_aggregation_data
                        .report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Failed(
                            ReportShareError::VdafPrepError,
                        ));
                    report_aggregation_data.prep_step = Some(PrepareStep::new(
                        *leader_prep_step.report_id(),
                        PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                    ));
                }
            };
        }

        for rad in report_aggregation_datas_iter {
            // This report was omitted by the leader because of a prior failure. Note that the
            // report was dropped (if it's not already in an error state) and continue.
            if matches!(
                rad.report_aggregation.state(),
                ReportAggregationState::Waiting(_, _)
            ) {
                rad.report_aggregation =
                    rad.report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Failed(
                            ReportShareError::ReportDropped,
                        ));
                rad.prep_step = None;
            }
        }

        // Write accumulated aggregation values back to the datastore; mark any reports that can't
        // be aggregated because the batch is collected with error BatchCollected.
        let unwritable_reports = accumulator.flush_to_datastore(tx).await?;
        for rad in &mut report_aggregation_datas {
            if unwritable_reports.contains(rad.report_aggregation.report_id()) {
                rad.report_aggregation =
                    rad.report_aggregation
                        .clone()
                        .with_state(ReportAggregationState::Failed(
                            ReportShareError::BatchCollected,
                        ));
                rad.prep_step = Some(PrepareStep::new(
                    *rad.report_aggregation.report_id(),
                    PrepareStepResult::Failed(ReportShareError::BatchCollected),
                ));
            }
        }

        let saw_continue = report_aggregation_datas.iter().any(|rad| {
            matches!(
                rad.prep_step.as_ref().map(PrepareStep::result),
                Some(PrepareStepResult::Continued(_))
            )
        });
        let saw_finish = report_aggregation_datas.iter().any(|rad| {
            matches!(
                rad.prep_step.as_ref().map(PrepareStep::result),
                Some(PrepareStepResult::Finished)
            )
        });
        let helper_aggregation_job =
            helper_aggregation_job.with_state(match (saw_continue, saw_finish) {
                (false, false) => AggregationJobState::Finished, // everything failed, or there were no reports
                (true, false) => AggregationJobState::InProgress,
                (false, true) => AggregationJobState::Finished,
                (true, true) => {
                    return Err(datastore::Error::User(
                        Error::Internal(
                            "VDAF took an inconsistent number of rounds to reach Finish state"
                                .to_string(),
                        )
                        .into(),
                    ))
                }
            });

        try_join!(
            tx.update_aggregation_job(&helper_aggregation_job),
            try_join_all(
                report_aggregation_datas
                    .iter()
                    .map(|rad| tx.update_report_aggregation(&rad.report_aggregation))
            ),
        )?;

        Ok(Self::aggregate_continue_resp_for(
            report_aggregation_datas
                .into_iter()
                .map(|rad| rad.prep_step),
        ))
    }

    /// Constructs an AggregationInitialzeResp from a given set of Helper report aggregations.
    pub(super) fn aggregate_initialize_resp_for(
        prepare_steps: impl IntoIterator<Item = Option<PrepareStep>>,
    ) -> AggregateInitializeResp {
        AggregateInitializeResp::new(prepare_steps.into_iter().flatten().collect())
    }

    /// Constructs an AggregationContinueResp from a given set of Helper report aggregations.
    pub(super) fn aggregate_continue_resp_for(
        prepare_steps: impl IntoIterator<Item = Option<PrepareStep>>,
    ) -> AggregateContinueResp {
        AggregateContinueResp::new(prepare_steps.into_iter().flatten().collect())
    }
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use janus_aggregator_core::task::Task;
    use janus_messages::{AggregateContinueReq, AggregateContinueResp};
    use prio::codec::{Decode, Encode};
    use serde_json::json;
    use trillium::{Handler, KnownHeaderName, Status};
    use trillium_testing::{prelude::post, TestConn};

    async fn post_aggregation_job(
        task: &Task,
        request: &AggregateContinueReq,
        handler: &impl Handler,
    ) -> TestConn {
        post(task.aggregation_job_uri().unwrap().path())
            .with_request_header(
                "DAP-Auth-Token",
                task.primary_aggregator_auth_token().as_ref().to_owned(),
            )
            .with_request_header(
                KnownHeaderName::ContentType,
                AggregateContinueReq::MEDIA_TYPE,
            )
            .with_request_body(request.get_encoded())
            .run_async(handler)
            .await
    }

    pub async fn post_aggregation_job_and_decode(
        task: &Task,
        request: &AggregateContinueReq,
        handler: &impl Handler,
    ) -> AggregateContinueResp {
        let mut test_conn = post_aggregation_job(task, request, handler).await;

        assert_eq!(test_conn.status(), Some(Status::Ok));
        assert_eq!(
            test_conn
                .response_headers()
                .get(KnownHeaderName::ContentType)
                .unwrap(),
            AggregateContinueResp::MEDIA_TYPE
        );
        let body_bytes = test_conn
            .take_response_body()
            .unwrap()
            .into_bytes()
            .await
            .unwrap();
        AggregateContinueResp::get_decoded(&body_bytes).unwrap()
    }

    pub async fn post_aggregation_job_expecting_status(
        task: &Task,
        request: &AggregateContinueReq,
        handler: &impl Handler,
        want_status: Status,
    ) -> Option<trillium::Body> {
        let mut test_conn = post_aggregation_job(task, request, handler).await;

        assert_eq!(want_status, test_conn.status().unwrap());

        test_conn.take_response_body()
    }

    pub async fn post_aggregation_job_expecting_error(
        task: &Task,
        request: &AggregateContinueReq,
        handler: &impl Handler,
        want_status: Status,
        want_error_type: &str,
        want_error_title: &str,
    ) {
        let body = post_aggregation_job_expecting_status(task, request, handler, want_status).await;

        let problem_details: serde_json::Value =
            serde_json::from_slice(&body.unwrap().into_bytes().await.unwrap()).unwrap();
        assert_eq!(
            problem_details,
            json!({
                "status": want_status as u16,
                "type": want_error_type,
                "title": want_error_title,
                "taskid": format!("{}", task.id()),
            })
        );
    }
}
