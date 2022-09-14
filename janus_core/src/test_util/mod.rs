use crate::message::Nonce;
use assert_matches::assert_matches;
use prio::{
    codec::Encode,
    vdaf::{self, PrepareTransition, VdafError},
};
use std::sync::Once;
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

pub mod dummy_vdaf;
pub mod kubernetes;
pub mod runtime;
pub mod testcontainers;

/// A transcript of a VDAF run. All fields are indexed by natural role index (i.e., index 0 =
/// leader, index 1 = helper).
pub struct VdafTranscript<const L: usize, V: vdaf::Aggregator<L>>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    /// The measurement's input shares, from the sharding algorithm.
    pub input_shares: Vec<V::InputShare>,
    /// Prepare transitions sent throughout the protocol run. The outer `Vec` is indexed by
    /// aggregator, and the inner `Vec`s are indexed by VDAF round.
    pub prepare_transitions: Vec<Vec<PrepareTransition<V, L>>>,
    /// The prepare messages broadcast to all aggregators prior to each continuation round of the
    /// VDAF.
    pub prepare_messages: Vec<V::PrepareMessage>,
    /// The aggregate shares from each aggregator.
    pub aggregate_shares: Vec<V::AggregateShare>,
}

/// run_vdaf runs a VDAF state machine from sharding through to generating an output share,
/// returning a "transcript" of all states & messages.
pub fn run_vdaf<const L: usize, V: vdaf::Aggregator<L> + vdaf::Client>(
    vdaf: &V,
    verify_key: &[u8; L],
    aggregation_param: &V::AggregationParam,
    nonce: Nonce,
    measurement: &V::Measurement,
) -> VdafTranscript<L, V>
where
    for<'a> &'a V::AggregateShare: Into<Vec<u8>>,
{
    // Shard inputs into input shares, and initialize the initial PrepareTransitions.
    let input_shares = vdaf.shard(measurement).unwrap();
    let encoded_nonce = nonce.get_encoded();
    let mut prep_trans: Vec<Vec<PrepareTransition<V, L>>> = input_shares
        .iter()
        .enumerate()
        .map(|(agg_id, input_share)| {
            let (prep_state, prep_share) = vdaf.prepare_init(
                verify_key,
                agg_id,
                aggregation_param,
                &encoded_nonce,
                input_share,
            )?;
            Ok(vec![PrepareTransition::Continue(prep_state, prep_share)])
        })
        .collect::<Result<Vec<Vec<PrepareTransition<V, L>>>, VdafError>>()
        .unwrap();
    let mut prep_msgs = Vec::new();

    // Repeatedly step the VDAF until we reach a terminal state.
    loop {
        // Gather messages from last round & combine them into next round's message; if any
        // participants have reached a terminal state (Finish or Fail), we are done.
        let mut prep_shares = Vec::new();
        let mut agg_shares = Vec::new();
        for pts in &prep_trans {
            match pts.last().unwrap() {
                PrepareTransition::<V, L>::Continue(_, prep_share) => {
                    prep_shares.push(prep_share.clone())
                }
                PrepareTransition::Finish(output_share) => {
                    agg_shares.push(
                        vdaf.aggregate(aggregation_param, [output_share.clone()].into_iter())
                            .unwrap(),
                    );
                }
            }
        }
        if !agg_shares.is_empty() {
            return VdafTranscript {
                input_shares,
                prepare_transitions: prep_trans,
                prepare_messages: prep_msgs,
                aggregate_shares: agg_shares,
            };
        }
        let prep_msg = vdaf.prepare_preprocess(prep_shares).unwrap();
        prep_msgs.push(prep_msg.clone());

        // Compute each participant's next transition.
        for pts in &mut prep_trans {
            let prep_state = assert_matches!(pts.last().unwrap(), PrepareTransition::<V, L>::Continue(prep_state, _) => prep_state).clone();
            pts.push(vdaf.prepare_step(prep_state, prep_msg.clone()).unwrap());
        }
    }
}

/// Install a tracing subscriber for use in tests. This should be called at the beginning of any
/// test that requires a tracing subscriber.
pub fn install_test_trace_subscriber() {
    static INSTALL_TRACE_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACE_SUBSCRIBER.call_once(|| {
        let stdout_filter = EnvFilter::from_default_env();
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
