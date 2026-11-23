//! Implements portions of aggregation job initialization for the Helper.

use std::{collections::HashMap, panic, sync::Arc};

use assert_matches::assert_matches;
use janus_aggregator_core::{
    AsyncAggregator,
    datastore::models::{ReportAggregation, ReportAggregationState},
    task::AggregatorTask,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label},
    time::{Clock, DateTimeExt as _, TimeExt as _},
    vdaf::vdaf_application_context,
};
use janus_messages::{
    ExtensionType, InputShareAad, PlaintextInputShare, ReportError, Role, VerifyResp,
    VerifyStepResult, extensions_are_strictly_increasing,
};
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram},
};
use prio::{
    codec::{Decode as _, Encode, ParameterizedDecode},
    topology::ping_pong::{Continued, PingPongState, PingPongTopology as _},
};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use tokio::sync::mpsc;
use tracing::{Span, debug, info_span, trace_span};

use crate::{
    aggregator::{
        AggregatorMetrics, Error, ExtensionTypeExt,
        aggregation_job_writer::WritableReportAggregation, error::handle_ping_pong_error,
    },
    cache::HpkeKeypairCache,
    metrics::aggregate_step_failure_types::{
        DECRYPT_FAILURE, DUPLICATE_EXTENSION, INPUT_SHARE_AAD_ENCODE_FAILURE,
        INPUT_SHARE_DECODE_FAILURE, MISSING_OR_MALFORMED_TASKBIND_EXTENSION,
        PLAINTEXT_INPUT_SHARE_DECODE_FAILURE, PUBLIC_SHARE_DECODE_FAILURE,
        UNEXPECTED_TASKBIND_EXTENSION, UNKNOWN_HPKE_CONFIG_ID, UNRECOGNIZED_EXTENSION,
        UNSORTED_EXTENSION,
    },
};

#[derive(Clone)]
pub struct AggregateInitMetrics {
    /// Counters tracking the number of failures to step client reports through the aggregation
    /// process.
    aggregate_step_failure_counter: Counter<u64>,
    /// Histogram tracking the clock skew of early reports.
    early_report_clock_skew_histogram: Histogram<u64>,
    /// Histogram tracking the clock skew of reports with timestamps in the past.
    past_report_clock_skew_histogram: Histogram<u64>,
    /// Counters tracking usage of HPKE keypairs.
    keypair_use_counter: Counter<u64>,
}

impl AggregateInitMetrics {
    pub fn new(
        aggregate_step_failure_counter: Counter<u64>,
        early_report_clock_skew_histogram: Histogram<u64>,
        past_report_clock_skew_histogram: Histogram<u64>,
        keypair_use_counter: Counter<u64>,
    ) -> Self {
        Self {
            aggregate_step_failure_counter,
            early_report_clock_skew_histogram,
            past_report_clock_skew_histogram,
            keypair_use_counter,
        }
    }
}

impl From<AggregatorMetrics> for AggregateInitMetrics {
    fn from(metrics: AggregatorMetrics) -> Self {
        Self {
            aggregate_step_failure_counter: metrics.aggregate_step_failure_counter,
            early_report_clock_skew_histogram: metrics.early_report_clock_skew_histogram,
            past_report_clock_skew_histogram: metrics.past_report_clock_skew_histogram,
            keypair_use_counter: metrics.keypair_use_counter,
        }
    }
}

/// Given report aggregations in the `HelperInitProcessing` state, this function computes the next
/// step of the aggregation; the returned [`WritableReportAggregation`]s correspond to the provided
/// report aggregations and will be in the `HelperContinue`, `Finished`, or `Failed` states.
///
/// Only report aggregations in the `HelperInitProcessing` state can be provided. The caller must
/// filter report aggregations which are in other states (e.g. `Failed`) prior to calling this
/// function.
///
/// ### Panics
///
/// Panics if a provided report aggregation is in a state other than `HelperInitProcessing`.
pub async fn compute_helper_aggregate_init<const SEED_SIZE: usize, A>(
    clock: &dyn Clock,
    hpke_keypairs: Arc<HpkeKeypairCache>,
    vdaf: &A,
    metrics: AggregateInitMetrics,
    task: &AggregatorTask,
    aggregation_parameter: &A::AggregationParam,
    report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
) -> Result<Vec<WritableReportAggregation<SEED_SIZE, A>>, Error>
where
    A: AsyncAggregator<SEED_SIZE>,
{
    let verify_key = task.vdaf_verify_key()?;
    let task_configuration = task.task_configuration();
    let report_aggregation_count = report_aggregations.len();
    let now = clock.now();
    let report_deadline = now
        .add_duration(task.tolerable_clock_skew(), task.time_precision())
        .map_err(Error::from)?;

    // Shutdown on cancellation: if this request is cancelled, the `receiver` will be dropped. This
    // will cause any attempts to send on `sender` to return a `SendError`, which will be returned
    // from the function passed to `try_for_each`; `try_for_each` will terminate early on receiving
    // an error.
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let producer_task = tokio::task::spawn_blocking({
        let parent_span = Span::current();
        let hpke_keypairs = Arc::clone(&hpke_keypairs);
        let vdaf = vdaf.clone();
        let task_id = *task.id();
        let time_precision = *task.time_precision();
        let deactivate_at = task.deactivate_at();
        let task_start = task.task_start();
        let task_end = task.task_end();
        let metrics = metrics.clone();
        let aggregation_parameter = aggregation_parameter.clone();

        move || {
            let span =
                info_span!(parent: &parent_span, "compute_helper_aggregate_init threadpool task");
            let ctx = vdaf_application_context(&task_id);

            report_aggregations
                .into_par_iter()
                .try_for_each(|report_aggregation| {
                    let _entered = span.enter();

                    // Assert safety: this function should only be called with report
                    // aggregations in the HelperInitProcessing state.
                    let (verify_init, require_taskbind_extension) = assert_matches!(
                        report_aggregation.state(),
                        ReportAggregationState::HelperInitProcessing {
                            verify_init,
                            require_taskbind_extension,
                        } => (verify_init, *require_taskbind_extension)
                    );

                    // If decryption fails, then the aggregator MUST fail with error
                    // `hpke-decrypt-error`. (§4.6.2.3 [dap-16])
                    let config_id = *verify_init
                        .report_share()
                        .encrypted_input_share()
                        .config_id();
                    let hpke_keypair = hpke_keypairs.keypair(&config_id).ok_or_else(|| {
                        debug!(
                            %config_id,
                            "Helper encrypted input share references unknown HPKE config ID"
                        );
                        metrics
                            .aggregate_step_failure_counter
                            .add(1, &[KeyValue::new("type", UNKNOWN_HPKE_CONFIG_ID)]);
                        ReportError::HpkeUnknownConfigId
                    });

                    let plaintext = hpke_keypair.and_then(|hpke_keypair| {
                        let input_share_aad = InputShareAad::new(
                            task_id,
                            task_configuration.clone(),
                            verify_init.report_share().metadata().clone(),
                            verify_init.report_share().public_share().to_vec(),
                        )
                        .get_encoded()
                        .map_err(|err| {
                            debug!(
                                task_id = %task_id,
                                report_id = ?verify_init.report_share().metadata().id(),
                                ?err,
                                "Couldn't encode input share AAD"
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", INPUT_SHARE_AAD_ENCODE_FAILURE)]);
                            // HpkeDecryptError isn't strictly accurate, but given that this
                            // fallible encoding is part of the HPKE decryption process, I think
                            // this is as close as we can get to a meaningful error signal.
                            ReportError::HpkeDecryptError
                        })?;

                        hpke::open(
                            &hpke_keypair,
                            &HpkeApplicationInfo::new(
                                &Label::InputShare,
                                &Role::Client,
                                &Role::Helper,
                            ),
                            verify_init.report_share().encrypted_input_share(),
                            &input_share_aad,
                        )
                        .inspect(|_| {
                            metrics.keypair_use_counter.add(
                                1,
                                &[KeyValue::new(
                                    "hpke_config_id",
                                    i64::from(u8::from(config_id)),
                                )],
                            )
                        })
                        .map_err(|error| {
                            debug!(
                                task_id = %task_id,
                                report_id = ?verify_init.report_share().metadata().id(),
                                ?error,
                                "Couldn't decrypt helper's report share"
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", DECRYPT_FAILURE)]);
                            ReportError::HpkeDecryptError
                        })
                    });

                    let plaintext_input_share = plaintext.and_then(|plaintext| {
                        let plaintext_input_share = PlaintextInputShare::get_decoded(&plaintext)
                            .map_err(|error| {
                                debug!(
                                    task_id = %task_id,
                                    report_id = ?verify_init.report_share().metadata().id(),
                                    ?error, "Couldn't decode helper's plaintext input share",
                                );
                                metrics.aggregate_step_failure_counter.add(
                                    1,
                                    &[KeyValue::new("type", PLAINTEXT_INPUT_SHARE_DECODE_FAILURE)],
                                );
                                ReportError::InvalidMessage
                            })?;

                        // Public extensions must be in strictly increasing order of extension
                        // type (DAP-18 §4.4.3); private extensions are validated when the
                        // plaintext input share is decoded.
                        if !extensions_are_strictly_increasing(
                            verify_init.report_share().metadata().public_extensions(),
                        ) {
                            debug!(
                                task_id = %task_id,
                                report_id = ?verify_init.report_share().metadata().id(),
                                "Received report share with unsorted public extensions",
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", UNSORTED_EXTENSION)]);
                            return Err(ReportError::InvalidMessage);
                        }

                        // Check for unrecognized extension types (§4.6.2.4 step 5 [dap-16]) and
                        // duplicate extensions (§4.6.2.4 step 6 [dap-16]) in a single pass.
                        let mut extensions = HashMap::new();
                        for extension in plaintext_input_share
                            .private_extensions()
                            .iter()
                            .chain(verify_init.report_share().metadata().public_extensions())
                        {
                            if !extension.extension_type().is_supported() {
                                debug!(
                                    task_id = %task_id,
                                    report_id = ?verify_init.report_share().metadata().id(),
                                    unrecognized_extension_type = ?extension.extension_type(),
                                    "Received report share with unrecognized extension type",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", UNRECOGNIZED_EXTENSION)]);
                                return Err(ReportError::InvalidMessage);
                            }
                            if extensions
                                .insert(*extension.extension_type(), extension.extension_data())
                                .is_some()
                            {
                                debug!(
                                    task_id = %task_id,
                                    report_id = ?verify_init.report_share().metadata().id(),
                                    "Received report share with duplicate extensions",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", DUPLICATE_EXTENSION)]);
                                return Err(ReportError::InvalidMessage);
                            }
                        }

                        if require_taskbind_extension {
                            let valid_taskbind_extension_present = extensions
                                .get(&ExtensionType::Taskbind)
                                .map(|data| data.is_empty())
                                .unwrap_or(false);
                            if !valid_taskbind_extension_present {
                                debug!(
                                    task_id = %task_id,
                                    report_id = ?verify_init.report_share().metadata().id(),
                                    "Taskprov task received report with missing or malformed \
                                    taskbind extension",
                                );
                                metrics.aggregate_step_failure_counter.add(
                                    1,
                                    &[KeyValue::new(
                                        "type",
                                        MISSING_OR_MALFORMED_TASKBIND_EXTENSION,
                                    )],
                                );
                                return Err(ReportError::InvalidMessage);
                            }
                        } else if extensions.contains_key(&ExtensionType::Taskbind) {
                            // taskprov not enabled, but the taskbind extension is present.
                            debug!(
                                task_id = %task_id,
                                report_id = ?verify_init.report_share().metadata().id(),
                                "Non-taskprov task received report with unexpected taskbind \
                                extension",
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", UNEXPECTED_TASKBIND_EXTENSION)]);
                            return Err(ReportError::InvalidMessage);
                        }

                        Ok(plaintext_input_share)
                    });

                    // Check that the input share can be decoded (§4.6.2.4 step 1 [dap-16])
                    let input_share = plaintext_input_share.and_then(|plaintext_input_share| {
                        A::InputShare::get_decoded_with_param(
                            &(&vdaf, Role::Helper.index().unwrap()),
                            plaintext_input_share.payload(),
                        )
                        .map_err(|error| {
                            debug!(
                                task_id = %task_id,
                                report_id = ?verify_init.report_share().metadata().id(),
                                ?error, "Couldn't decode helper's input share",
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", INPUT_SHARE_DECODE_FAILURE)]);
                            ReportError::InvalidMessage
                        })
                    });

                    let public_share = A::PublicShare::get_decoded_with_param(
                        &vdaf,
                        verify_init.report_share().public_share(),
                    )
                    .map_err(|error| {
                        debug!(
                            task_id = %task_id,
                            report_id = ?verify_init.report_share().metadata().id(),
                            ?error, "Couldn't decode public share",
                        );
                        metrics
                            .aggregate_step_failure_counter
                            .add(1, &[KeyValue::new("type", PUBLIC_SHARE_DECODE_FAILURE)]);
                        ReportError::InvalidMessage
                    });

                    let shares =
                        input_share.and_then(|input_share| Ok((public_share?, input_share)));

                    if let Ok(report_time_dt) = verify_init
                        .report_share()
                        .metadata()
                        .time()
                        .as_date_time(time_precision)
                    {
                        let clock_skew = report_time_dt.signed_duration_since(now);
                        let skew_seconds = clock_skew.num_seconds();

                        if skew_seconds > 0 {
                            // Early report: report time > now
                            metrics
                                .early_report_clock_skew_histogram
                                .record(skew_seconds as u64, &[]);
                        } else if skew_seconds < 0 {
                            // Past report: now > report time
                            metrics
                                .past_report_clock_skew_histogram
                                .record((-skew_seconds) as u64, &[]);
                        }
                    }

                    // Reject reports from too far in the future. (§4.6.2.4 step 2 [dap-16])
                    let shares = shares.and_then(|shares| {
                        if verify_init
                            .report_share()
                            .metadata()
                            .time()
                            .is_after(&report_deadline.to_time(&time_precision))
                        {
                            return Err(ReportError::ReportTooEarly);
                        }
                        Ok(shares)
                    });

                    // Reject reports before the task has started. (§4.6.2.4 step 3 [dap-16])
                    let shares = shares.and_then(|shares| {
                        if let Some(task_start) = task_start {
                            if verify_init
                                .report_share()
                                .metadata()
                                .time()
                                .is_before(&task_start)
                            {
                                return Err(ReportError::TaskNotStarted);
                            }
                        }
                        Ok(shares)
                    });

                    // Reject reports after the task has expired, which is inclusive
                    // of the task_end time. (§4.6.2.4 step 4 [dap-16])
                    let shares = shares.and_then(|shares| {
                        if let Some(task_end) = task_end {
                            if verify_init.report_share().metadata().time().ge(&task_end) {
                                return Err(ReportError::TaskExpired);
                            }
                        }
                        Ok(shares)
                    });

                    // Reject reports once the task has been deactivated. This is Janus-specific
                    // (not part of the task's TaskConfiguration/AAD) and is compared against
                    // the aggregator's current clock, not the report timestamp.
                    let shares = shares.and_then(|shares| {
                        if let Some(deactivate_at) = deactivate_at {
                            if now >= deactivate_at {
                                return Err(ReportError::TaskExpired);
                            }
                        }
                        Ok(shares)
                    });

                    // Next, the aggregator runs the verification-state initialization algorithm
                    // for the VDAF associated with the task and computes the first state
                    // transition. [...] If either step fails, then the aggregator MUST fail
                    // with error `vdaf-prep-error`. (§4.6.2 [dap-16])
                    let init_rslt = shares.and_then(|(public_share, input_share)| {
                        trace_span!("VDAF verification (helper initialization)").in_scope(|| {
                            vdaf.helper_initialized(
                                verify_key.as_bytes(),
                                &ctx,
                                &aggregation_parameter,
                                /* report ID is used as VDAF nonce */
                                verify_init.report_share().metadata().id().as_ref(),
                                &public_share,
                                &input_share,
                                verify_init.message(),
                            )
                            .and_then(|continuation| continuation.evaluate(&ctx, &vdaf))
                            .map_err(|error| {
                                handle_ping_pong_error(
                                    &task_id,
                                    Role::Helper,
                                    verify_init.report_share().metadata().id(),
                                    error,
                                    &metrics.aggregate_step_failure_counter,
                                )
                            })
                        })
                    });

                    let (report_aggregation_state, verify_step_result, output_share) =
                        match init_rslt {
                            // Helper is not finished. Store the new verify state, respond to
                            // the leader with the outgoing message and await the next message
                            // from the Leader to advance to the next step.
                            Ok(PingPongState::Continued(Continued {
                                verifier_state,
                                message,
                            })) => (
                                ReportAggregationState::HelperContinue {
                                    verify_state: verifier_state,
                                },
                                VerifyStepResult::Continue { message },
                                None,
                            ),

                            // Helper is finished with an outbound message. Commit to the output
                            // share and respond to the leader with the outgoing message.
                            Ok(PingPongState::FinishedWithOutbound {
                                output_share,
                                message,
                            }) => (
                                ReportAggregationState::Finished,
                                VerifyStepResult::Continue { message },
                                Some(output_share),
                            ),

                            // Helper cannot finish at this stage
                            Ok(PingPongState::Finished { .. }) => (
                                ReportAggregationState::Failed {
                                    report_error: ReportError::VdafVerifyError,
                                },
                                VerifyStepResult::Reject(ReportError::VdafVerifyError),
                                None,
                            ),

                            // Report was rejected. Respond to the leader with a rejection and
                            // abort further processing.
                            Err(report_error) => (
                                ReportAggregationState::Failed { report_error },
                                VerifyStepResult::Reject(report_error),
                                None,
                            ),
                        };

                    let report_id = *verify_init.report_share().metadata().id();
                    sender
                        .send(WritableReportAggregation::new(
                            report_aggregation
                                .with_last_verify_resp(Some(VerifyResp::new(
                                    report_id,
                                    verify_step_result,
                                )))
                                .with_state(report_aggregation_state),
                            output_share,
                        ))
                        .map_err(drop)
                })
        }
    });

    let mut report_aggregations = Vec::with_capacity(report_aggregation_count);
    while receiver.recv_many(&mut report_aggregations, 10).await > 0 {}

    // Await the producer task to resume any panics that may have occurred, and to ensure the
    // producer task is completely done (e.g. all of its memory is released). The only other errors
    // that can occur are: a `JoinError` indicating cancellation, which is impossible because we do
    // not cancel the task; and a `SendError`, which can only happen if this future is cancelled (in
    // which case we will not run this code at all).
    let _ = producer_task.await.map_err(|join_error| {
        if let Ok(reason) = join_error.try_into_panic() {
            panic::resume_unwind(reason);
        }
    });
    assert_eq!(report_aggregations.len(), report_aggregation_count);

    Ok(report_aggregations)
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use std::assert_matches;

    use axum::{Router, body::Body};
    use http::{Request, Response, StatusCode, header};
    use janus_aggregator_core::{
        AsyncAggregator,
        datastore::Datastore,
        task::{
            AggregationMode, AggregatorTask, BatchMode,
            test_util::{Task, TaskBuilder},
        },
    };
    use janus_core::{
        auth_tokens::test_util::WithAuthenticationToken,
        test_util::{VdafTranscript, run_vdaf},
        time::{Clock, DateTimeExt as _, MockClock},
        vdaf::VdafInstance,
    };
    use janus_messages::{
        AggregationJobInitializeReq, AggregationJobResp, Duration, Extension, HpkeConfig,
        MediaType, ReportMetadata, ReportShare, Role, TimePrecision, VerifyInit, VerifyStepResult,
    };
    use prio::{
        codec::Encode,
        vdaf::{self, dummy},
    };
    use rand::random;
    use tower::ServiceExt;

    use crate::aggregator::{
        http_handlers::test_util::{HttpHandlerTest, decode_response_body},
        test_util::generate_helper_report_share,
    };

    #[derive(Clone)]
    pub struct VerifyInitGenerator<const VERIFY_KEY_SIZE: usize, V>
    where
        V: vdaf::Vdaf,
    {
        clock: MockClock,
        task: AggregatorTask,
        vdaf: V,
        aggregation_param: V::AggregationParam,
        hpke_config: HpkeConfig,
        private_extensions: Vec<Extension>,
    }

    impl<const VERIFY_KEY_SIZE: usize, V> VerifyInitGenerator<VERIFY_KEY_SIZE, V>
    where
        V: AsyncAggregator<VERIFY_KEY_SIZE> + vdaf::Client<16>,
    {
        pub fn new(
            clock: MockClock,
            task: AggregatorTask,
            hpke_config: HpkeConfig,
            vdaf: V,
            aggregation_param: V::AggregationParam,
        ) -> Self {
            Self {
                clock,
                task,
                vdaf,
                aggregation_param,
                hpke_config,
                private_extensions: Vec::new(),
            }
        }

        pub fn with_private_extensions(mut self, extensions: Vec<Extension>) -> Self {
            self.private_extensions = extensions;
            self
        }

        pub fn next(
            &self,
            measurement: &V::Measurement,
        ) -> (VerifyInit, VdafTranscript<VERIFY_KEY_SIZE, V>) {
            self.next_with_metadata(
                ReportMetadata::new(
                    random(),
                    self.clock.now().to_time(self.task.time_precision()),
                    Vec::new(),
                ),
                measurement,
            )
        }

        pub fn next_with_metadata(
            &self,
            report_metadata: ReportMetadata,
            measurement: &V::Measurement,
        ) -> (VerifyInit, VdafTranscript<VERIFY_KEY_SIZE, V>) {
            let (report_share, transcript) =
                self.next_report_share_with_metadata(report_metadata, measurement);
            (
                VerifyInit::new(
                    report_share,
                    transcript.leader_verify_transitions[0]
                        .message()
                        .unwrap()
                        .clone(),
                ),
                transcript,
            )
        }

        pub fn next_report_share(
            &self,
            measurement: &V::Measurement,
        ) -> (ReportShare, VdafTranscript<VERIFY_KEY_SIZE, V>) {
            self.next_report_share_with_metadata(
                ReportMetadata::new(
                    random(),
                    self.clock.now().to_time(self.task.time_precision()),
                    Vec::new(),
                ),
                measurement,
            )
        }

        pub fn next_report_share_with_metadata(
            &self,
            report_metadata: ReportMetadata,
            measurement: &V::Measurement,
        ) -> (ReportShare, VdafTranscript<VERIFY_KEY_SIZE, V>) {
            let transcript = run_vdaf(
                &self.vdaf,
                self.task.id(),
                self.task.vdaf_verify_key().unwrap().as_bytes(),
                &self.aggregation_param,
                report_metadata.id(),
                measurement,
            );
            let report_share = generate_helper_report_share::<V>(
                *self.task.id(),
                self.task.task_configuration(),
                report_metadata,
                &self.hpke_config,
                &transcript.public_share,
                self.private_extensions.clone(),
                &transcript.helper_input_share,
            );
            (report_share, transcript)
        }
    }

    // TODO(timg) double check that this free function is useful. can it just be
    // AggregationJobInitTestCase::post_aggregation_job_init?
    pub async fn post_aggregation_job_init(
        task: &Task,
        aggregation_job: &AggregationJobInitializeReq,
        router: &Router,
    ) -> http::Response<Body> {
        let request = Request::builder()
            .method("POST")
            .uri(task.aggregation_job_creation_uri().unwrap().path())
            .with_authentication_token(task.aggregator_auth_token())
            .header(
                header::CONTENT_TYPE,
                AggregationJobInitializeReq::MEDIA_TYPE,
            )
            .body(Body::from(aggregation_job.get_encoded().unwrap()))
            .unwrap();
        router.clone().oneshot(request).await.unwrap()
    }

    pub struct AggregationJobInitTestCase {
        pub http_handler_test: HttpHandlerTest,
        pub task: Task,
        pub vdaf: dummy::Vdaf,
        pub verify_init_generator: VerifyInitGenerator<0, dummy::Vdaf>,
        pub aggregation_job_init_req: AggregationJobInitializeReq,
        pub aggregation_param: dummy::AggregationParam,
    }

    impl AggregationJobInitTestCase {
        pub async fn new() -> Self {
            Self::builder().build().await
        }

        pub fn builder() -> AggregationJobInitTestCaseBuilder {
            AggregationJobInitTestCaseBuilder {
                task_builder: TaskBuilder::new(
                    BatchMode::TimeInterval,
                    AggregationMode::Synchronous,
                    VdafInstance::Fake { rounds: 1 },
                ),
                role: Role::Helper,
                vdaf: dummy::Vdaf::new(1),
                clock: MockClock::default(),
            }
        }

        pub fn router(&self) -> Router {
            self.http_handler_test.router.clone()
        }

        pub fn clock(&self) -> &MockClock {
            &self.http_handler_test.clock
        }

        pub fn datastore(&self) -> &Datastore {
            &self.http_handler_test.datastore
        }

        pub async fn post_prepared_aggregation_job_init(&self) -> Response<Body> {
            self.post_aggregation_job_init(&self.aggregation_job_init_req)
                .await
        }

        pub async fn post_prepared_aggregation_job_init_expecting_success(
            &self,
        ) -> AggregationJobResp {
            self.post_aggregation_job_init_expecting_success(&self.aggregation_job_init_req)
                .await
        }

        pub async fn post_aggregation_job_init(
            &self,
            aggregation_job_init_req: &AggregationJobInitializeReq,
        ) -> Response<Body> {
            post_aggregation_job_init(
                &self.task,
                aggregation_job_init_req,
                &self.http_handler_test.router,
            )
            .await
        }

        pub async fn post_aggregation_job_init_expecting_success(
            &self,
            aggregation_job_init_req: &AggregationJobInitializeReq,
        ) -> AggregationJobResp {
            let mut response = self
                .post_aggregation_job_init(aggregation_job_init_req)
                .await;
            assert_eq!(response.status(), StatusCode::OK);

            let aggregation_job_resp: AggregationJobResp =
                decode_response_body(&mut response).await;
            assert_eq!(
                aggregation_job_resp.verify_resps.len(),
                aggregation_job_init_req.verify_inits().len(),
            );

            aggregation_job_resp
        }

        /// Run the first step of job preparation, returning the helper's [`AggregationJobResp`].
        pub async fn run_first_step(&self) -> AggregationJobResp {
            let aggregation_job_resp = self
                .post_aggregation_job_init_expecting_success(&self.aggregation_job_init_req)
                .await;
            assert_matches!(
                aggregation_job_resp.verify_resps[0].result(),
                &VerifyStepResult::Continue { .. }
            );

            aggregation_job_resp
        }
    }

    pub struct AggregationJobInitTestCaseBuilder {
        task_builder: TaskBuilder,
        vdaf: dummy::Vdaf,
        role: Role,
        clock: MockClock,
    }

    impl AggregationJobInitTestCaseBuilder {
        pub async fn build(self) -> AggregationJobInitTestCase {
            let http_handler_test = HttpHandlerTest::builder()
                .with_clock(self.clock)
                .build()
                .await;

            let time_precision = TimePrecision::from_seconds(100);
            let task = self
                .task_builder
                .with_time_precision(time_precision)
                .with_tolerable_clock_skew(Duration::from_seconds(500, &time_precision))
                .with_aggregator_auth_token(random())
                .build();
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

            let aggregation_param = dummy::AggregationParam(7);
            let verify_init_generator = VerifyInitGenerator::new(
                http_handler_test.clock.clone(),
                role_task,
                http_handler_test.hpke_keypair.config().clone(),
                self.vdaf.clone(),
                aggregation_param.clone(),
            );

            let verify_inits = Vec::from([
                verify_init_generator.next(&13).0,
                verify_init_generator.next(&13).0,
            ]);

            let aggregation_job_init_req = AggregationJobInitializeReq::new(
                0,
                aggregation_param.get_encoded().unwrap(),
                Vec::new(),
                verify_inits.clone(),
            );

            AggregationJobInitTestCase {
                http_handler_test,
                task,
                vdaf: self.vdaf,
                verify_init_generator,
                aggregation_job_init_req,
                aggregation_param,
            }
        }

        pub fn with_role(self, role: Role) -> Self {
            Self { role, ..self }
        }

        /// Set the VDAF to be used in the eventual test case.
        ///
        /// A `VdafInstance` corresponding to this value MUST be set on this test case's task using
        /// [`Self::build_task`].
        pub fn with_vdaf(self, vdaf: dummy::Vdaf) -> Self {
            Self { vdaf, ..self }
        }

        pub fn with_clock(self, clock: MockClock) -> Self {
            Self { clock, ..self }
        }

        pub fn build_task<F: FnMut(TaskBuilder) -> TaskBuilder>(self, mut f: F) -> Self {
            Self {
                task_builder: f(self.task_builder),
                ..self
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use axum::body::Body;
    use http::{Request, StatusCode, header};

    use janus_core::{
        auth_tokens::{AuthenticationToken, DAP_AUTH_HEADER},
        time::{Clock, DateTimeExt, MockClock, TimeExt as _},
        vdaf::VdafInstance,
    };
    use janus_messages::{
        AggregationJobExtension, AggregationJobExtensionType, AggregationJobInitializeReq,
        AggregationJobResp, Duration, Extension, ExtensionType, Interval, MediaType, ReportError,
        ReportMetadata, TimePrecision, VerifyResp, VerifyStepResult,
    };
    use prio::{codec::Encode, vdaf::dummy};
    use rand::random;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::aggregator::{
        aggregation_job_init::test_util::AggregationJobInitTestCase,
        http_handlers::test_util::{decode_response_body, take_problem_details},
    };

    #[rstest::rstest]
    #[case::not_bearer_token("wrong kind of token")]
    #[case::not_base64("Bearer: ")]
    #[tokio::test]
    async fn malformed_authorization_header(#[case] header_value: &'static str) {
        let test_case = AggregationJobInitTestCase::builder()
            .build_task(|task_builder| {
                task_builder.with_aggregator_auth_token(AuthenticationToken::DapAuth(random()))
            })
            .build()
            .await;

        // Authenticate using a malformed "Authorization: Bearer <token>" header and a
        // `DAP-Auth-Token` header. The presence of the former should cause an error despite
        // the latter being present and well formed.
        let request = Request::builder()
            .method("POST")
            .uri(
                test_case
                    .task
                    .aggregation_job_creation_uri()
                    .unwrap()
                    .path(),
            )
            .header(header::AUTHORIZATION, header_value)
            .header(
                DAP_AUTH_HEADER,
                test_case.task.aggregator_auth_token().as_ref().to_owned(),
            )
            .header(
                header::CONTENT_TYPE,
                AggregationJobInitializeReq::MEDIA_TYPE,
            )
            .body(Body::from(
                test_case.aggregation_job_init_req.get_encoded().unwrap(),
            ))
            .unwrap();
        let response = test_case.router().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn unexpected_taskbind_extension() {
        let test_case = AggregationJobInitTestCase::new().await;

        let verify_init = test_case
            .verify_init_generator
            .clone()
            .with_private_extensions(Vec::from([Extension::new(
                ExtensionType::Taskbind,
                Vec::new(),
            )]))
            .next(&0)
            .0;
        let report_id = *verify_init.report_share().metadata().id();
        let aggregation_job_init_req = AggregationJobInitializeReq::new(
            0,
            dummy::AggregationParam(1).get_encoded().unwrap(),
            Vec::new(),
            Vec::from([verify_init]),
        );

        let mut response = test_case
            .post_aggregation_job_init(&aggregation_job_init_req)
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let want_aggregation_job_resp = AggregationJobResp {
            verify_resps: Vec::from([VerifyResp::new(
                report_id,
                VerifyStepResult::Reject(ReportError::InvalidMessage),
            )]),
        };
        let got_aggregation_job_resp: AggregationJobResp =
            decode_response_body(&mut response).await;
        assert_eq!(want_aggregation_job_resp, got_aggregation_job_resp);
    }

    #[tokio::test]
    async fn mutation_aggregation_parameter() {
        let test_case = AggregationJobInitTestCase::new().await;
        test_case.run_first_step().await;

        // Put the aggregation job again, but with a different aggregation parameter. It should be
        // rejected because the reports have already been assigned to an aggregation job using a
        // different aggregation parameter.
        let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
            0,
            dummy::AggregationParam(1).get_encoded().unwrap(),
            Vec::new(),
            test_case.aggregation_job_init_req.verify_inits().to_vec(),
        );

        let response = test_case
            .post_aggregation_job_init(&mutated_aggregation_job_init_req)
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn mutation_which_verify_inits() {
        let test_case = AggregationJobInitTestCase::new().await;
        test_case.run_first_step().await;

        let verify_inits = test_case.aggregation_job_init_req.verify_inits();

        // Put the aggregation job again, mutating the associated report shares' metadata such that
        // uniqueness constraints on client_reports are violated
        for mutated_verify_inits in [
            // Omit a report share that was included previously
            Vec::from(&verify_inits[0..verify_inits.len() - 1]),
            // Include a different report share than was included previously
            [
                &verify_inits[0..verify_inits.len() - 1],
                &[test_case.verify_init_generator.next(&0).0],
            ]
            .concat(),
            // Include an extra report share than was included previously
            [verify_inits, &[test_case.verify_init_generator.next(&0).0]].concat(),
            // Reverse the order of the reports
            verify_inits.iter().rev().cloned().collect(),
        ] {
            let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
                0,
                test_case.aggregation_param.get_encoded().unwrap(),
                Vec::new(),
                mutated_verify_inits,
            );
            let response = test_case
                .post_aggregation_job_init(&mutated_aggregation_job_init_req)
                .await;
            // TODO(timg): what we have here is a bunch of aggregation jobs that overlap with a
            // previously created one. DAP says to enforce anti-replay at the time of committing
            // output shares (https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-20#section-4.5.4.3)
            // Should we allow these aggregation jobs to be created then?
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
    }

    #[tokio::test]
    async fn mutation_verify_init_contents() {
        // We set up a multi-step VDAF in this test so that the aggregation job won't finish on the
        // first step.
        let test_case = AggregationJobInitTestCase::builder()
            .build_task(|task_builder| task_builder.with_vdaf(VdafInstance::Fake { rounds: 2 }))
            .with_vdaf(dummy::Vdaf::new(2))
            .build()
            .await;
        test_case.run_first_step().await;

        // Generate some new reports using the existing reports' metadata, but varying the
        // measurement values such that the verify state computed during aggregation
        // initializaton won't match the first aggregation job.
        let mutated_verify_inits = test_case
            .aggregation_job_init_req
            .verify_inits()
            .iter()
            .map(|s| {
                test_case
                    .verify_init_generator
                    .next_with_metadata(s.report_share().metadata().clone(), &13)
                    .0
            })
            .collect();

        let mutated_aggregation_job_init_req = AggregationJobInitializeReq::new(
            0,
            test_case.aggregation_param.get_encoded().unwrap(),
            Vec::new(),
            mutated_verify_inits,
        );

        let response = test_case
            .post_aggregation_job_init(&mutated_aggregation_job_init_req)
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn intolerable_clock_skew() {
        let test_case = AggregationJobInitTestCase::new().await;

        let aggregation_job_init_req = AggregationJobInitializeReq::new(
            0,
            test_case.aggregation_param.get_encoded().unwrap(),
            Vec::new(),
            Vec::from([
                // Barely tolerable.
                test_case
                    .verify_init_generator
                    .next_with_metadata(
                        ReportMetadata::new(
                            random(),
                            test_case
                                .clock()
                                .now()
                                .to_time(test_case.task.time_precision())
                                .add_duration(test_case.task.tolerable_clock_skew())
                                .unwrap(),
                            Vec::new(),
                        ),
                        &0,
                    )
                    .0,
                // Barely intolerable.
                test_case
                    .verify_init_generator
                    .next_with_metadata(
                        ReportMetadata::new(
                            random(),
                            test_case
                                .clock()
                                .now()
                                .to_time(test_case.task.time_precision())
                                .add_duration(test_case.task.tolerable_clock_skew())
                                .unwrap()
                                .add_duration(&Duration::ONE)
                                .unwrap(),
                            Vec::new(),
                        ),
                        &0,
                    )
                    .0,
            ]),
        );

        let aggregation_job_resp = test_case
            .post_aggregation_job_init_expecting_success(&aggregation_job_init_req)
            .await;
        assert_matches!(
            aggregation_job_resp.verify_resps[0].result(),
            &VerifyStepResult::Continue { .. }
        );
        assert_matches!(
            aggregation_job_resp.verify_resps[1].result(),
            &VerifyStepResult::Reject(ReportError::ReportTooEarly)
        );
    }

    #[tokio::test]
    async fn task_expired() {
        let clock = MockClock::default();
        let time_precision = TimePrecision::from_seconds(100);
        let task_end_time = clock.now().to_time(&time_precision);

        let test_case = AggregationJobInitTestCase::builder()
            .with_clock(clock.clone())
            .build_task(|task_builder| {
                task_builder
                    .with_time_precision(time_precision)
                    .with_task_interval(Some(
                        Interval::new(
                            task_end_time
                                .sub_duration(&Duration::from_seconds(1000, &time_precision))
                                .unwrap(),
                            Duration::from_seconds(1000, &time_precision),
                        )
                        .unwrap(),
                    ))
            })
            .build()
            .await;

        let aggregation_job_init_req = AggregationJobInitializeReq::new(
            0,
            test_case.aggregation_param.get_encoded().unwrap(),
            Vec::new(),
            Vec::from([
                // Report with timestamp before task end should be accepted.
                test_case
                    .verify_init_generator
                    .next_with_metadata(
                        ReportMetadata::new(
                            random(),
                            task_end_time.sub_duration(&Duration::ONE).unwrap(),
                            Vec::new(),
                        ),
                        &0,
                    )
                    .0,
                // Report with timestamp after task end should be rejected.
                test_case
                    .verify_init_generator
                    .next_with_metadata(
                        ReportMetadata::new(
                            random(),
                            task_end_time.add_duration(&Duration::ONE).unwrap(),
                            Vec::new(),
                        ),
                        &0,
                    )
                    .0,
                // Report with timestamp exactly at task end should also be rejected.
                test_case
                    .verify_init_generator
                    .next_with_metadata(
                        ReportMetadata::new(random(), task_end_time, Vec::new()),
                        &0,
                    )
                    .0,
            ]),
        );

        let aggregation_job_resp = test_case
            .post_aggregation_job_init_expecting_success(&aggregation_job_init_req)
            .await;
        assert_matches!(
            aggregation_job_resp.verify_resps[0].result(),
            &VerifyStepResult::Continue { .. }
        );
        assert_matches!(
            aggregation_job_resp.verify_resps[1].result(),
            &VerifyStepResult::Reject(ReportError::TaskExpired)
        );
        assert_matches!(
            aggregation_job_resp.verify_resps[2].result(),
            &VerifyStepResult::Reject(ReportError::TaskExpired)
        );
    }

    #[tokio::test]
    async fn two_step_vdaf_idempotence() {
        // We set up a multi-step VDAF in this test so that the aggregation job won't finish on the
        // first step.
        let test_case = AggregationJobInitTestCase::builder()
            .build_task(|task_builder| task_builder.with_vdaf(VdafInstance::Fake { rounds: 2 }))
            .with_vdaf(dummy::Vdaf::new(2))
            .build()
            .await;
        let aggregation_job_resp = test_case.run_first_step().await;

        // Send the aggregation job init request again. We should get an identical response back.
        let aggregation_job_resp_again = test_case
            .post_aggregation_job_init_expecting_success(&test_case.aggregation_job_init_req)
            .await;
        assert_eq!(aggregation_job_resp, aggregation_job_resp_again);
    }

    #[tokio::test]
    async fn task_not_started() {
        let clock = MockClock::default();
        let time_precision = TimePrecision::from_seconds(100);
        let task_start_time = clock
            .now()
            .to_time(&time_precision)
            .sub_duration(&Duration::from_seconds(1000, &time_precision))
            .unwrap();

        let test_case = AggregationJobInitTestCase::builder()
            .with_clock(clock.clone())
            .build_task(|task_builder| {
                task_builder
                    .with_time_precision(time_precision)
                    .with_task_interval(Some(
                        Interval::new(
                            task_start_time,
                            Duration::from_seconds(2000, &time_precision),
                        )
                        .unwrap(),
                    ))
            })
            .build()
            .await;

        let aggregation_job_init_req = AggregationJobInitializeReq::new(
            0,
            test_case.aggregation_param.get_encoded().unwrap(),
            Vec::new(),
            Vec::from([
                // Report with timestamp after task start should be accepted.
                test_case
                    .verify_init_generator
                    .next_with_metadata(
                        ReportMetadata::new(
                            random(),
                            task_start_time.add_duration(&Duration::ONE).unwrap(),
                            Vec::new(),
                        ),
                        &0,
                    )
                    .0,
                // Report with timestamp before task start should be rejected.
                test_case
                    .verify_init_generator
                    .next_with_metadata(
                        ReportMetadata::new(
                            random(),
                            task_start_time.sub_duration(&Duration::ONE).unwrap(),
                            Vec::new(),
                        ),
                        &0,
                    )
                    .0,
            ]),
        );

        let aggregation_job_resp = test_case
            .post_aggregation_job_init_expecting_success(&aggregation_job_init_req)
            .await;
        assert_matches!(
            aggregation_job_resp.verify_resps[0].result(),
            &VerifyStepResult::Continue { .. }
        );
        assert_matches!(
            aggregation_job_resp.verify_resps[1].result(),
            &VerifyStepResult::Reject(ReportError::TaskNotStarted)
        );
    }

    #[tokio::test]
    async fn unexpected_batch_id_extension() {
        let test_case = AggregationJobInitTestCase::new().await;

        // A time-interval task has no use for a `leader_selected_batch_id` extension and rejects
        // it as an `invalidMessage`.
        let request = AggregationJobInitializeReq::new(
            0,
            test_case.aggregation_param.get_encoded().unwrap(),
            Vec::from([AggregationJobExtension::leader_selected_batch_id(&random())]),
            test_case.aggregation_job_init_req.verify_inits().to_vec(),
        );

        let mut response = test_case.post_aggregation_job_init(&request).await;
        assert_eq!(
            take_problem_details(&mut response).await,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "taskid": format!("{}", test_case.task.id()),
                "detail": "unexpected leader_selected_batch_id extension for time-interval batch mode",
            }),
        );
    }

    #[tokio::test]
    async fn out_of_order_extensions() {
        let test_case = AggregationJobInitTestCase::new().await;

        // Extensions must be in strictly increasing order of extension type; a decreasing pair is
        // an `invalidMessage`.
        let request = AggregationJobInitializeReq::new(
            0,
            test_case.aggregation_param.get_encoded().unwrap(),
            Vec::from([
                AggregationJobExtension::new(AggregationJobExtensionType::from(2), Vec::new()),
                AggregationJobExtension::new(AggregationJobExtensionType::from(1), Vec::new()),
            ]),
            test_case.aggregation_job_init_req.verify_inits().to_vec(),
        );

        let mut response = test_case.post_aggregation_job_init(&request).await;
        assert_eq!(
            take_problem_details(&mut response).await,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:invalidMessage",
                "title": "The message type for a response was incorrect or the payload was malformed.",
                "taskid": format!("{}", test_case.task.id()),
                "detail": "aggregation job extensions are not in strictly increasing order",
            }),
        );
    }

    #[tokio::test]
    async fn unsupported_extension() {
        let test_case = AggregationJobInitTestCase::new().await;

        // An extension type the helper does not recognize is an `unsupportedExtension`.
        let request = AggregationJobInitializeReq::new(
            0,
            test_case.aggregation_param.get_encoded().unwrap(),
            Vec::from([AggregationJobExtension::new(
                AggregationJobExtensionType::from(0xffff),
                Vec::new(),
            )]),
            test_case.aggregation_job_init_req.verify_inits().to_vec(),
        );

        let mut response = test_case.post_aggregation_job_init(&request).await;
        assert_eq!(
            take_problem_details(&mut response).await,
            json!({
                "status": StatusCode::BAD_REQUEST.as_u16(),
                "type": "urn:ietf:params:ppm:dap:error:unsupportedExtension",
                "title": "The message includes an unsupported extension.",
                "taskid": format!("{}", test_case.task.id()),
                "detail": "unrecognized aggregation job extension type",
            }),
        );
    }
}
