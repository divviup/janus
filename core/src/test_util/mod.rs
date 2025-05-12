use crate::vdaf::vdaf_application_context;
use assert_matches::assert_matches;
use janus_messages::{ReportId, Role, TaskId};
use prio::{
    topology::ping_pong::{
        Continued, PingPongContinuation, PingPongMessage, PingPongState, PingPongTopology,
    },
    vdaf,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Once};
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

pub mod kubernetes;
pub mod runtime;
pub mod testcontainers;

#[derive(Clone, Debug)]
pub struct PrepareTransition<const VERIFY_KEY_LENGTH: usize, V>
where
    V: vdaf::Aggregator<VERIFY_KEY_LENGTH, 16>,
    V::OutputShare: Eq,
{
    pub continuation: Option<PingPongContinuation<VERIFY_KEY_LENGTH, 16, V>>,
    pub state: PingPongState<V::PrepareState, V::OutputShare>,
}

impl<const VERIFY_KEY_LENGTH: usize, V> PrepareTransition<VERIFY_KEY_LENGTH, V>
where
    V: vdaf::Aggregator<VERIFY_KEY_LENGTH, 16>,
    V::OutputShare: Eq,
{
    pub fn prepare_state(&self) -> &V::PrepareState {
        assert_matches!(self.state, PingPongState::Continued(Continued{
            ref prepare_state, ..
        }) => prepare_state)
    }

    pub fn message(&self) -> Option<&PingPongMessage> {
        match self.state {
            PingPongState::Continued(Continued { ref message, .. })
            | PingPongState::FinishedWithOutbound { ref message, .. } => Some(message),
            _ => None,
        }
    }
}

/// A transcript of a VDAF run using the ping-pong VDAF topology.
#[derive(Clone, Debug)]
pub struct VdafTranscript<const VERIFY_KEY_LENGTH: usize, V>
where
    V: vdaf::Aggregator<VERIFY_KEY_LENGTH, 16>,
    V::OutputShare: Eq,
{
    /// The public share, from the sharding algorithm.
    pub public_share: V::PublicShare,
    /// The leader's input share, from the sharding algorithm.
    pub leader_input_share: V::InputShare,

    /// The helper's input share, from the sharding algorithm.
    pub helper_input_share: V::InputShare,

    /// The leader's states and messages computed throughout the protocol run. Indexed by the
    /// aggregation job step.
    #[allow(clippy::type_complexity)]
    pub leader_prepare_transitions: Vec<PrepareTransition<VERIFY_KEY_LENGTH, V>>,

    /// The helper's states and messages computed throughout the protocol run. Indexed by the
    /// aggregation job step.
    #[allow(clippy::type_complexity)]
    pub helper_prepare_transitions: Vec<PrepareTransition<VERIFY_KEY_LENGTH, V>>,

    /// The leader's computed output share.
    pub leader_output_share: V::OutputShare,

    /// The helper's computed output share.
    pub helper_output_share: V::OutputShare,

    /// The leader's aggregate share.
    pub leader_aggregate_share: V::AggregateShare,

    /// The helper's aggregate share.
    pub helper_aggregate_share: V::AggregateShare,
}

/// run_vdaf runs a VDAF state machine from sharding through to generating an output share,
/// returning a "transcript" of all states & messages.
pub fn run_vdaf<const VERIFY_KEY_LENGTH: usize, V>(
    vdaf: &V,
    task_id: &TaskId,
    verify_key: &[u8; VERIFY_KEY_LENGTH],
    aggregation_param: &V::AggregationParam,
    report_id: &ReportId,
    measurement: &V::Measurement,
) -> VdafTranscript<VERIFY_KEY_LENGTH, V>
where
    V: vdaf::Aggregator<VERIFY_KEY_LENGTH, 16> + vdaf::Client<16>,
    V::OutputShare: Eq,
{
    let ctx = vdaf_application_context(task_id);

    let mut leader_prepare_transitions = Vec::new();
    let mut helper_prepare_transitions = Vec::new();

    // Shard inputs into input shares, and initialize the initial PrepareTransitions.
    let (public_share, input_shares) = vdaf.shard(&ctx, measurement, report_id.as_ref()).unwrap();

    let leader_state = vdaf
        .leader_initialized(
            verify_key,
            &ctx,
            aggregation_param,
            report_id.as_ref(),
            &public_share,
            &input_shares[0],
        )
        .unwrap();

    leader_prepare_transitions.push(PrepareTransition {
        continuation: None,
        state: PingPongState::Continued(leader_state.clone()),
    });

    let helper_transition = vdaf
        .helper_initialized(
            verify_key,
            &ctx,
            aggregation_param,
            report_id.as_ref(),
            &public_share,
            &input_shares[1],
            &leader_state.message,
        )
        .unwrap();
    let helper_state = helper_transition.clone().evaluate(&ctx, vdaf).unwrap();

    helper_prepare_transitions.push(PrepareTransition {
        continuation: Some(helper_transition),
        state: helper_state,
    });

    // Repeatedly step the VDAF until we reach a terminal state
    let mut leader_output_share = None;
    let mut helper_output_share = None;
    loop {
        for role in [Role::Leader, Role::Helper] {
            let (curr_state, last_peer_message) = match role {
                Role::Leader => (
                    leader_prepare_transitions.last().unwrap().state.clone(),
                    helper_prepare_transitions.last().unwrap().message(),
                ),
                Role::Helper => (
                    helper_prepare_transitions.last().unwrap().state.clone(),
                    leader_prepare_transitions.last().unwrap().message(),
                ),
                _ => panic!(),
            };

            match curr_state {
                PingPongState::Continued(Continued { prepare_state, .. }) => {
                    let continuation = match role {
                        Role::Leader => vdaf
                            .leader_continued(
                                &ctx,
                                aggregation_param,
                                prepare_state,
                                last_peer_message.unwrap(),
                            )
                            .unwrap(),
                        Role::Helper => vdaf
                            .helper_continued(
                                &ctx,
                                aggregation_param,
                                prepare_state,
                                last_peer_message.unwrap(),
                            )
                            .unwrap(),
                        _ => panic!(),
                    };

                    let state = continuation.clone().evaluate(&ctx, vdaf).unwrap();

                    match role {
                        Role::Leader => leader_prepare_transitions.push(PrepareTransition {
                            continuation: Some(continuation),
                            state,
                        }),
                        Role::Helper => helper_prepare_transitions.push(PrepareTransition {
                            continuation: Some(continuation),
                            state,
                        }),
                        _ => panic!(),
                    }
                }
                PingPongState::Finished { output_share }
                | PingPongState::FinishedWithOutbound { output_share, .. } => match role {
                    Role::Leader => leader_output_share = Some(output_share.clone()),
                    Role::Helper => helper_output_share = Some(output_share.clone()),
                    _ => panic!(),
                },
            }
        }

        if leader_output_share.is_some() && helper_output_share.is_some() {
            break;
        }
    }

    let leader_aggregate_share = vdaf
        .aggregate(aggregation_param, [leader_output_share.clone().unwrap()])
        .unwrap();
    let helper_aggregate_share = vdaf
        .aggregate(aggregation_param, [helper_output_share.clone().unwrap()])
        .unwrap();

    VdafTranscript {
        public_share,
        leader_input_share: input_shares[0].clone(),
        helper_input_share: input_shares[1].clone(),
        leader_prepare_transitions,
        helper_prepare_transitions,
        leader_output_share: leader_output_share.unwrap(),
        helper_output_share: helper_output_share.unwrap(),
        leader_aggregate_share,
        helper_aggregate_share,
    }
}

/// Encodes the given value to YAML, then decodes it again, and checks that the
/// resulting value is equal to the given value.
pub fn roundtrip_encoding<T: Serialize + DeserializeOwned + Debug + PartialEq>(value: T) {
    let encoded = serde_yaml::to_string(&value).unwrap();
    let decoded = serde_yaml::from_str(&encoded).unwrap();
    assert_eq!(value, decoded);
}

/// Install a tracing subscriber for use in tests. This should be called at the beginning of any
/// test that requires a tracing subscriber.
pub fn install_test_trace_subscriber() {
    static INSTALL_TRACE_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACE_SUBSCRIBER.call_once(|| {
        let stdout_filter = EnvFilter::builder().from_env().unwrap();
        let layer = tracing_subscriber::fmt::layer()
            .with_thread_ids(true)
            .with_level(true)
            .with_target(true)
            .with_file(true)
            .with_line_number(true)
            .pretty()
            .with_test_writer()
            .with_filter(stdout_filter);
        let subscriber = Registry::default().with(layer);
        tracing::subscriber::set_global_default(subscriber).unwrap();

        LogTracer::init().unwrap();
    })
}
