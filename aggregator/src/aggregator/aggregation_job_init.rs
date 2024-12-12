//! Implements portions of aggregation job initialization for the Helper.

use crate::{
    aggregator::{
        aggregation_job_writer::WritableReportAggregation, error::handle_ping_pong_error,
        AggregatorMetrics, Error,
    },
    cache::HpkeKeypairCache,
};
use assert_matches::assert_matches;
use janus_aggregator_core::{
    batch_mode::AccumulableBatchMode,
    datastore::models::{AggregationJob, ReportAggregation, ReportAggregationState},
    task::AggregatorTask,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label},
    time::{Clock, TimeExt as _},
    vdaf::vdaf_application_context,
};
use janus_messages::{
    ExtensionType, InputShareAad, PlaintextInputShare, PrepareResp, PrepareStepResult, ReportError,
    Role,
};
use opentelemetry::{metrics::Counter, KeyValue};
use prio::{
    codec::{Decode as _, Encode, ParameterizedDecode},
    topology::ping_pong::{PingPongState, PingPongTopology as _},
    vdaf,
};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use std::{collections::HashMap, panic, sync::Arc};
use tokio::sync::mpsc;
use tracing::{debug, info_span, trace_span, Span};

#[derive(Clone)]
pub struct AggregateInitMetrics {
    /// Counters tracking the number of failures to step client reports through the aggregation
    /// process.
    aggregate_step_failure_counter: Counter<u64>,
}

impl AggregateInitMetrics {
    pub fn new(aggregate_step_failure_counter: Counter<u64>) -> Self {
        Self {
            aggregate_step_failure_counter,
        }
    }
}

impl From<AggregatorMetrics> for AggregateInitMetrics {
    fn from(metrics: AggregatorMetrics) -> Self {
        Self {
            aggregate_step_failure_counter: metrics.aggregate_step_failure_counter,
        }
    }
}

// XXX: docs
pub async fn compute_helper_aggregate_init<const SEED_SIZE: usize, B, A, C>(
    clock: &C,
    hpke_keypairs: Arc<HpkeKeypairCache>,
    vdaf: Arc<A>,
    metrics: AggregateInitMetrics,
    task: Arc<AggregatorTask>,
    aggregation_job: Arc<AggregationJob<SEED_SIZE, B, A>>,
    report_aggregations: Vec<ReportAggregation<SEED_SIZE, A>>,
) -> Result<Vec<WritableReportAggregation<SEED_SIZE, A>>, Error>
where
    B: AccumulableBatchMode,
    A: vdaf::Aggregator<SEED_SIZE, 16> + 'static + Send + Sync,
    C: Clock,
    A::AggregationParam: Send + Sync + PartialEq + Eq,
    A::AggregateShare: Send + Sync,
    A::InputShare: Send + Sync,
    A::PrepareMessage: Send + Sync + PartialEq,
    A::PrepareShare: Send + Sync + PartialEq,
    for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)> + PartialEq,
    A::PublicShare: Send + Sync,
    A::OutputShare: Send + Sync + PartialEq,
{
    let verify_key = task.vdaf_verify_key()?;
    let report_aggregation_count = report_aggregations.len();
    let report_deadline = clock
        .now()
        .add(task.tolerable_clock_skew())
        .map_err(Error::from)?;

    // Shutdown on cancellation: if this request is cancelled, the `receiver` will be dropped. This
    // will cause any attempts to send on `sender` to return a `SendError`, which will be returned
    // from the function passed to `try_for_each`; `try_for_each` will terminate early on receiving
    // an error.
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let producer_task = tokio::task::spawn_blocking({
        let parent_span = Span::current();
        let hpke_keypairs = Arc::clone(&hpke_keypairs);
        let vdaf = Arc::clone(&vdaf);
        let task = Arc::clone(&task);
        let metrics = metrics.clone();
        let aggregation_job = Arc::clone(&aggregation_job);

        move || {
            let span =
                info_span!(parent: parent_span, "compute_helper_aggregate_init threadpool task");
            let ctx = vdaf_application_context(task.id());

            report_aggregations
                    .into_par_iter()
                    .try_for_each(|report_aggregation| {
                        let _entered = span.enter();

                        // Assert safety: this function should only be called with report
                        // aggregations in the HelperInitProcessing state.
                        let (prepare_init, require_taskbind_extension) = assert_matches!(
                            report_aggregation.state(),
                            ReportAggregationState::HelperInitProcessing {
                                prepare_init,
                                require_taskbind_extension,
                            } => (prepare_init, *require_taskbind_extension)
                        );

                        // If decryption fails, then the aggregator MUST fail with error `hpke-decrypt-error`. (§4.4.2.2)
                        let hpke_keypair = hpke_keypairs.keypair(
                            prepare_init
                                .report_share()
                                .encrypted_input_share()
                                .config_id(),
                        ).ok_or_else(|| {
                            debug!(
                                config_id = %prepare_init.report_share().encrypted_input_share().config_id(),
                                "Helper encrypted input share references unknown HPKE config ID"
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", "unknown_hpke_config_id")]);
                            ReportError::HpkeUnknownConfigId
                        });

                        let plaintext = hpke_keypair.and_then(|hpke_keypair| {
                            let input_share_aad = InputShareAad::new(
                                *task.id(),
                                prepare_init.report_share().metadata().clone(),
                                prepare_init.report_share().public_share().to_vec(),
                            )
                            .get_encoded()
                            .map_err(|err| {
                                debug!(
                                    task_id = %task.id(),
                                    report_id = ?prepare_init.report_share().metadata().id(),
                                    ?err,
                                    "Couldn't encode input share AAD"
                                );
                                metrics.aggregate_step_failure_counter.add(
                                    1,
                                    &[KeyValue::new("type", "input_share_aad_encode_failure")],
                                );
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
                                prepare_init.report_share().encrypted_input_share(),
                                &input_share_aad,
                            )
                            .map_err(|error| {
                                debug!(
                                    task_id = %task.id(),
                                    report_id = ?prepare_init.report_share().metadata().id(),
                                    ?error,
                                    "Couldn't decrypt helper's report share"
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "decrypt_failure")]);
                                ReportError::HpkeDecryptError
                            })
                        });

                        let plaintext_input_share = plaintext.and_then(|plaintext| {
                            let plaintext_input_share = PlaintextInputShare::get_decoded(&plaintext)
                                .map_err(|error| {
                                    debug!(
                                        task_id = %task.id(),
                                        report_id = ?prepare_init.report_share().metadata().id(),
                                        ?error, "Couldn't decode helper's plaintext input share",
                                    );
                                    metrics.aggregate_step_failure_counter.add(
                                        1,
                                        &[KeyValue::new(
                                            "type",
                                            "plaintext_input_share_decode_failure",
                                        )],
                                    );
                                    ReportError::InvalidMessage
                                })?;

                            // Build map of extension type to extension data, checking for duplicates.
                            let mut extensions = HashMap::new();
                            if !plaintext_input_share.private_extensions().iter().chain(prepare_init.report_share().metadata().public_extensions()).all(|extension| {
                                extensions
                                    .insert(*extension.extension_type(), extension.extension_data())
                                    .is_none()
                            }) {
                                debug!(
                                    task_id = %task.id(),
                                    report_id = ?prepare_init.report_share().metadata().id(),
                                    "Received report share with duplicate extensions",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "duplicate_extension")]);
                                return Err(ReportError::InvalidMessage);
                            }

                            if require_taskbind_extension {
                                let valid_taskbind_extension_present = extensions
                                    .get(&ExtensionType::Taskbind)
                                    .map(|data| data.is_empty())
                                    .unwrap_or(false);
                                if !valid_taskbind_extension_present {
                                    debug!(
                                        task_id = %task.id(),
                                        report_id = ?prepare_init.report_share().metadata().id(),
                                        "Taskprov task received report with missing or malformed \
                                        taskbind extension",
                                    );
                                    metrics.aggregate_step_failure_counter.add(
                                        1,
                                        &[KeyValue::new(
                                            "type",
                                            "missing_or_malformed_taskbind_extension",
                                        )],
                                    );
                                    return Err(ReportError::InvalidMessage);
                                }
                            } else if extensions.contains_key(&ExtensionType::Taskbind) {
                                // taskprov not enabled, but the taskbind extension is present.
                                debug!(
                                    task_id = %task.id(),
                                    report_id = ?prepare_init.report_share().metadata().id(),
                                    "Non-taskprov task received report with unexpected taskbind \
                                    extension",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "unexpected_taskbind_extension")]);
                                return Err(ReportError::InvalidMessage);
                            }

                            Ok(plaintext_input_share)
                        });

                        let input_share = plaintext_input_share.and_then(|plaintext_input_share| {
                            A::InputShare::get_decoded_with_param(
                                &(&vdaf, Role::Helper.index().unwrap()),
                                plaintext_input_share.payload(),
                            )
                            .map_err(|error| {
                                debug!(
                                    task_id = %task.id(),
                                    report_id = ?prepare_init.report_share().metadata().id(),
                                    ?error, "Couldn't decode helper's input share",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "input_share_decode_failure")]);
                                ReportError::InvalidMessage
                            })
                        });

                        let public_share = A::PublicShare::get_decoded_with_param(
                            &vdaf,
                            prepare_init.report_share().public_share(),
                        )
                        .map_err(|error| {
                            debug!(
                                task_id = %task.id(),
                                report_id = ?prepare_init.report_share().metadata().id(),
                                ?error, "Couldn't decode public share",
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", "public_share_decode_failure")]);
                            ReportError::InvalidMessage
                        });

                        let shares =
                            input_share.and_then(|input_share| Ok((public_share?, input_share)));

                        // Reject reports from too far in the future.
                        let shares = shares.and_then(|shares| {
                            if prepare_init
                                .report_share()
                                .metadata()
                                .time()
                                .is_after(&report_deadline)
                            {
                                return Err(ReportError::ReportTooEarly);
                            }
                            Ok(shares)
                        });

                        // Next, the aggregator runs the preparation-state initialization algorithm for the VDAF
                        // associated with the task and computes the first state transition. [...] If either
                        // step fails, then the aggregator MUST fail with error `vdaf-prep-error`. (§4.4.2.2)
                        let init_rslt = shares.and_then(|(public_share, input_share)| {
                            trace_span!("VDAF preparation (helper initialization)").in_scope(|| {
                                vdaf.helper_initialized(
                                    verify_key.as_bytes(),
                                    &ctx,
                                    aggregation_job.aggregation_parameter(),
                                    /* report ID is used as VDAF nonce */
                                    prepare_init.report_share().metadata().id().as_ref(),
                                    &public_share,
                                    &input_share,
                                    prepare_init.message(),
                                )
                                .and_then(|transition| transition.evaluate(&ctx, &vdaf))
                                .map_err(|error| {
                                    handle_ping_pong_error(
                                        task.id(),
                                        Role::Helper,
                                        prepare_init.report_share().metadata().id(),
                                        error,
                                        &metrics.aggregate_step_failure_counter,
                                    )
                                })
                            })
                        });

                        let (report_aggregation_state, prepare_step_result, output_share) =
                            match init_rslt {
                                Ok((PingPongState::Continued(prepare_state), outgoing_message)) => {
                                    // Helper is not finished. Await the next message from the Leader to advance to
                                    // the next step.
                                    (
                                        ReportAggregationState::HelperContinue { prepare_state },
                                        PrepareStepResult::Continue {
                                            message: outgoing_message,
                                        },
                                        None,
                                    )
                                }
                                Ok((PingPongState::Finished(output_share), outgoing_message)) => (
                                    ReportAggregationState::Finished,
                                    PrepareStepResult::Continue {
                                        message: outgoing_message,
                                    },
                                    Some(output_share),
                                ),
                                Err(report_error) => (
                                    ReportAggregationState::Failed { report_error },
                                    PrepareStepResult::Reject(report_error),
                                    None,
                                ),
                            };

                        let report_id = *prepare_init.report_share().metadata().id();
                        sender.send(WritableReportAggregation::new(
                                report_aggregation
                                    .with_last_prep_resp(
                                        Some(PrepareResp::new(
                                            report_id,
                                            prepare_step_result,
                                        ))
                                    )
                                    .with_state(report_aggregation_state),
                                output_share
                            )
                        )
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
