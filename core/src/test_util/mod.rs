use assert_matches::assert_matches;
use janus_messages::{ReportId, Role};
use prio::vdaf::{self, PrepareTransition, VdafError};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Once};
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

pub mod dummy_vdaf;
pub mod kubernetes;
pub mod runtime;
pub mod testcontainers;

/// A transcript of a VDAF run. All fields are indexed by natural role index (i.e., index 0 =
/// leader, index 1 = helper).
#[derive(Clone, Debug)]
pub struct VdafTranscript<const SEED_SIZE: usize, V: vdaf::Aggregator<SEED_SIZE, 16>> {
    /// The public share, from the sharding algorithm.
    pub public_share: V::PublicShare,
    /// The measurement's input shares, from the sharding algorithm.
    pub input_shares: Vec<V::InputShare>,
    /// Prepare transitions sent throughout the protocol run. The outer `Vec` is indexed by
    /// aggregator, and the inner `Vec`s are indexed by VDAF round.
    prepare_transitions: Vec<Vec<PrepareTransition<V, SEED_SIZE, 16>>>,
    /// The prepare messages broadcast to all aggregators prior to each continuation round of the
    /// VDAF.
    pub prepare_messages: Vec<V::PrepareMessage>,
    /// The output shares computed by each aggregator.
    output_shares: Vec<V::OutputShare>,
    /// The aggregate shares from each aggregator.
    pub aggregate_shares: Vec<V::AggregateShare>,
}

impl<const SEED_SIZE: usize, V: vdaf::Aggregator<SEED_SIZE, 16>> VdafTranscript<SEED_SIZE, V> {
    /// Get the leader's preparation state at the requested round.
    pub fn leader_prep_state(&self, round: usize) -> &V::PrepareState {
        assert_matches!(
            &self.prepare_transitions[Role::Leader.index().unwrap()][round],
            PrepareTransition::<V, SEED_SIZE, 16>::Continue(prep_state, _) => prep_state
        )
    }

    /// Get the helper's preparation state and prepare share at the requested round.
    pub fn helper_prep_state(&self, round: usize) -> (&V::PrepareState, &V::PrepareShare) {
        assert_matches!(
            &self.prepare_transitions[Role::Helper.index().unwrap()][round],
            PrepareTransition::<V, SEED_SIZE, 16>::Continue(prep_state, prep_share) => (prep_state, prep_share)
        )
    }

    /// Get the output share for the specified aggregator.
    pub fn output_share(&self, role: Role) -> &V::OutputShare {
        &self.output_shares[role.index().unwrap()]
    }
}

/// run_vdaf runs a VDAF state machine from sharding through to generating an output share,
/// returning a "transcript" of all states & messages.
pub fn run_vdaf<const SEED_SIZE: usize, V: vdaf::Aggregator<SEED_SIZE, 16> + vdaf::Client<16>>(
    vdaf: &V,
    verify_key: &[u8; SEED_SIZE],
    aggregation_param: &V::AggregationParam,
    report_id: &ReportId,
    measurement: &V::Measurement,
) -> VdafTranscript<SEED_SIZE, V> {
    // Shard inputs into input shares, and initialize the initial PrepareTransitions.
    let (public_share, input_shares) = vdaf.shard(measurement, report_id.as_ref()).unwrap();
    let mut prep_trans: Vec<Vec<PrepareTransition<V, SEED_SIZE, 16>>> = input_shares
        .iter()
        .enumerate()
        .map(|(agg_id, input_share)| {
            let (prep_state, prep_share) = vdaf.prepare_init(
                verify_key,
                agg_id,
                aggregation_param,
                report_id.as_ref(),
                &public_share,
                input_share,
            )?;
            Ok(Vec::from([PrepareTransition::Continue(
                prep_state, prep_share,
            )]))
        })
        .collect::<Result<Vec<Vec<PrepareTransition<V, SEED_SIZE, 16>>>, VdafError>>()
        .unwrap();
    let mut prep_msgs = Vec::new();

    // Repeatedly step the VDAF until we reach a terminal state.
    loop {
        // Gather messages from last round & combine them into next round's message; if any
        // participants have reached a terminal state (Finish or Fail), we are done.
        let mut prep_shares = Vec::new();
        let mut agg_shares = Vec::new();
        let mut output_shares = Vec::new();
        for pts in &prep_trans {
            match pts.last().unwrap() {
                PrepareTransition::<V, SEED_SIZE, 16>::Continue(_, prep_share) => {
                    prep_shares.push(prep_share.clone())
                }
                PrepareTransition::Finish(output_share) => {
                    output_shares.push(output_share.clone());
                    agg_shares.push(
                        vdaf.aggregate(aggregation_param, [output_share.clone()].into_iter())
                            .unwrap(),
                    );
                }
            }
        }
        if !agg_shares.is_empty() {
            return VdafTranscript {
                public_share,
                input_shares,
                prepare_transitions: prep_trans,
                prepare_messages: prep_msgs,
                output_shares,
                aggregate_shares: agg_shares,
            };
        }
        let prep_msg = vdaf.prepare_preprocess(prep_shares).unwrap();
        prep_msgs.push(prep_msg.clone());

        // Compute each participant's next transition.
        for pts in &mut prep_trans {
            let prep_state = assert_matches!(
                pts.last().unwrap(),
                PrepareTransition::<V, SEED_SIZE, 16>::Continue(prep_state, _) => prep_state
            )
            .clone();
            pts.push(vdaf.prepare_step(prep_state, prep_msg.clone()).unwrap());
        }
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
        let stdout_filter = EnvFilter::try_from_default_env().unwrap();
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
