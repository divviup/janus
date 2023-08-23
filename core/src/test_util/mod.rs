use janus_messages::ReportId;
use prio::{
    topology::ping_pong::{self, PingPongTopology},
    vdaf,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Once};
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

pub mod dummy_vdaf;
pub mod kubernetes;
pub mod runtime;
pub mod testcontainers;

/// A transcript of a VDAF run using the ping-pong VDAF topology.
#[derive(Clone, Debug)]
pub struct VdafTranscript<const VERIFY_KEY_LEN: usize, V: vdaf::Aggregator<VERIFY_KEY_LEN, 16>> {
    /// The public share, from the sharding algorithm.
    pub public_share: V::PublicShare,
    /// The leader's input share, from the sharding algorithm.
    pub leader_input_share: V::InputShare,

    /// The helper's input share, from the sharding algorithm.
    pub helper_input_share: V::InputShare,

    /// The leader's states and messages computed throughout the protocol run. Indexed by the
    /// aggregation job round.
    #[allow(clippy::type_complexity)]
    pub leader_prepare_transitions: Vec<(
        Option<ping_pong::Transition<VERIFY_KEY_LEN, 16, V>>,
        ping_pong::State<VERIFY_KEY_LEN, 16, V>,
        ping_pong::Message,
    )>,

    /// The helper's states and messages computed throughout the protocol run. Indexed by the
    /// aggregation job round.
    #[allow(clippy::type_complexity)]
    pub helper_prepare_transitions: Vec<(
        ping_pong::Transition<VERIFY_KEY_LEN, 16, V>,
        ping_pong::State<VERIFY_KEY_LEN, 16, V>,
        ping_pong::Message,
    )>,

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
pub fn run_vdaf<
    const VERIFY_KEY_LEN: usize,
    V: vdaf::Aggregator<VERIFY_KEY_LEN, 16> + vdaf::Client<16>,
>(
    vdaf: &V,
    verify_key: &[u8; VERIFY_KEY_LEN],
    aggregation_param: &V::AggregationParam,
    report_id: &ReportId,
    measurement: &V::Measurement,
) -> VdafTranscript<VERIFY_KEY_LEN, V> {
    let mut leader_prepare_transitions = Vec::new();
    let mut helper_prepare_transitions = Vec::new();

    // Shard inputs into input shares, and initialize the initial PrepareTransitions.
    let (public_share, input_shares) = vdaf.shard(measurement, report_id.as_ref()).unwrap();

    let (leader_state, leader_message) = vdaf
        .leader_initialize(
            verify_key,
            aggregation_param,
            report_id.as_ref(),
            &public_share,
            &input_shares[0],
        )
        .unwrap();

    leader_prepare_transitions.push((None, leader_state, leader_message.clone()));

    let helper_transition = vdaf
        .helper_initialize(
            verify_key,
            aggregation_param,
            report_id.as_ref(),
            &public_share,
            &input_shares[1],
            &leader_message,
        )
        .unwrap();
    let (helper_state, helper_message) = helper_transition.clone().evaluate(vdaf).unwrap();

    helper_prepare_transitions.push((helper_transition, helper_state, helper_message.clone()));

    // Repeatedly step the VDAF until we reach a terminal state
    let mut leader_output_share = None;
    let mut helper_output_share = None;
    loop {
        for ping_pong_role in [ping_pong::Role::Leader, ping_pong::Role::Helper] {
            let (curr_state, last_peer_message) = match ping_pong_role {
                ping_pong::Role::Leader => (
                    leader_prepare_transitions.last().unwrap().1.clone(),
                    helper_prepare_transitions.last().unwrap().2.clone(),
                ),
                ping_pong::Role::Helper => (
                    helper_prepare_transitions.last().unwrap().1.clone(),
                    leader_prepare_transitions.last().unwrap().2.clone(),
                ),
            };

            match (&curr_state, &last_peer_message) {
                (curr_state @ ping_pong::State::Continued(_), last_peer_message) => {
                    let state_and_message = vdaf
                        .continued(ping_pong_role, curr_state.clone(), last_peer_message)
                        .unwrap();

                    match state_and_message {
                        ping_pong::ContinuedValue::WithMessage { transition } => {
                            let (state, message) = transition.clone().evaluate(vdaf).unwrap();
                            match ping_pong_role {
                                ping_pong::Role::Leader => leader_prepare_transitions.push((
                                    Some(transition),
                                    state,
                                    message,
                                )),
                                ping_pong::Role::Helper => {
                                    helper_prepare_transitions.push((transition, state, message))
                                }
                            }
                        }
                        ping_pong::ContinuedValue::FinishedNoMessage { output_share } => {
                            match ping_pong_role {
                                ping_pong::Role::Leader => {
                                    leader_output_share = Some(output_share.clone())
                                }
                                ping_pong::Role::Helper => {
                                    helper_output_share = Some(output_share.clone())
                                }
                            }
                        }
                    }
                }
                (ping_pong::State::Finished(output_share), _) => match ping_pong_role {
                    ping_pong::Role::Leader => leader_output_share = Some(output_share.clone()),
                    ping_pong::Role::Helper => helper_output_share = Some(output_share.clone()),
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
pub fn roundtrip_encoding<T: Serialize + DeserializeOwned + Debug + Eq>(value: T) {
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
