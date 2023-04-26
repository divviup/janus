use super::VdafInstance;

impl VdafInstance {
    /// Returns the size of the public share for this VDAF, assuming there are two aggregators.
    pub fn public_share_size(&self) -> usize {
        match self {
            VdafInstance::Prio3Count => {
                // This does not use joint randomness, and thus the public share is empty.
                0
            }
            VdafInstance::Prio3CountVec { .. }
            | VdafInstance::Prio3Sum { .. }
            | VdafInstance::Prio3SumVec { .. }
            | VdafInstance::Prio3Histogram { .. } => {
                // Two seeds, for the joint randomness parts
                32
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                // Two seeds, for the joint randomness parts
                32
            }
            VdafInstance::Poplar1 { bits } => {
                // The Poplar1 public share is entirely composed of an IDPF public share. In turn,
                // this is composed of bit-packed control bits (two per level), followed by an
                // alternating sequence of seeds and field element vectors from each level's
                // correction word. The field element vectors in each correction word are of length
                // two. All but one correction word uses Field64, and the last correction word usees
                // Field255.
                let control_bits_count = bits * 2;
                let packed_control_bits_length = (control_bits_count + 7) / 8;
                let seeds_length = bits * 16;
                let values_length = 2 * ((bits - 1) * 8 + 32);
                packed_control_bits_length + seeds_length + values_length
            }
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => {
                // The dummy VDAF's public share type is `()`.
                0
            }
        }
    }

    /// Returns the size of the leader aggregator's input share for this VDAF, assuming there are two aggregators.
    pub fn leader_input_share_size(&self) -> usize {
        match self {
            // Prio3 leader shares are composed of the measurement share vector, proof share vector,
            // and a blind if joint randomness is used.
            VdafInstance::Prio3Count => {
                // Prio3Count uses Field64. The measurement share vector has one element. The proof
                // share vector has five elements.
                8 * (1 + 5)
            }
            VdafInstance::Prio3CountVec { length } => {
                // Dispatch to the calculations for Prio3SumVec, since its circuit is a generic
                // extension of Prio3CountVec.
                VdafInstance::Prio3SumVec {
                    bits: 1,
                    length: *length,
                }
                .leader_input_share_size()
            }
            VdafInstance::Prio3Sum { bits } => {
                // Prio3Sum uses Field128. The measurement share vector has as many elements as the
                // measurement has bits. The proof vector's length depends on the number of bits as
                // well, but it gets rounded up to fill out an FFT input. A blind is also included
                // for the joint randomness.
                let proof_elements = 2 * ((1 + bits).next_power_of_two() - 1) + 2;
                16 * (bits + proof_elements) + 16
            }
            VdafInstance::Prio3SumVec { bits, length } => {
                // Prio3SumVec uses Field128. The measurement share vector has as many elements as
                // there are bits in all vector elements put together. The length of the proof share
                // vector is more complicated. Input bits are divided into "chunks", such that the
                // size of the chunks and the number of chunks are both approximately equal to the
                // total number of bits. The number of gadget calls is equal to the number of
                // chunks, and the arity of each gadget call is equal to double the length of each
                // chunk. A blind is also included for the joint randomness.
                let total_bits = bits * length;
                let chunk_length = std::cmp::max(1, (total_bits as f64).sqrt() as usize);
                let gadget_calls = (total_bits + chunk_length - 1) / chunk_length;
                let proof_length =
                    (chunk_length * 2) + 3 * ((1 + gadget_calls).next_power_of_two() - 1) + 1;
                16 * (total_bits + proof_length) + 16
            }
            VdafInstance::Prio3Histogram { buckets } => {
                // Prio3Histogram uses Field128. The measurement share vector has one more element
                // than the list of bucket boundaries. The length of the proof share depends on the
                // number of bucket boundaries as well, but it gets rounded up to fill out an FFT
                // input. A blind is also included for the joint randomness.
                let proof_elements = 2 * ((1 + buckets.len() + 1).next_power_of_two() - 1) + 2;
                16 * (buckets.len() + 1 + proof_elements) + 16
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                // Dispatch to a helper function, passing the number of bits.
                fixed_point_bounded_l2_norm_leader_input_share_size(*length, 16)
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                fixed_point_bounded_l2_norm_leader_input_share_size(*length, 32)
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                fixed_point_bounded_l2_norm_leader_input_share_size(*length, 64)
            }
            VdafInstance::Poplar1 { bits } => {
                // Poplar1's input shares are symmetrical across the leader and helper. The input
                // share consists of two PRG seeds, one for the IDPF key and one for deriving the
                // correlated randomness, and two field elements per level for the remainder of the
                // correlated randomness (using Field64 for the inner node levels, and Field255 for
                // the last, leaf level).
                16 * 2 + (bits - 1) * 2 * 8 + 2 * 32
            }
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => {
                // The dummy VDAF's input share consists of a single `u8`.
                1
            }
        }
    }

    /// Returns the size of the helper aggregator's input share for this VDAF, assuming there are two aggregators.
    pub fn helper_input_share_size(&self) -> usize {
        match self {
            VdafInstance::Prio3Count => {
                // The helper share for Prio3Count consists of two PRG seeds, one for the
                // measurement share, and one for the proof share.
                2 * 16
            }
            VdafInstance::Prio3CountVec { .. }
            | VdafInstance::Prio3Sum { .. }
            | VdafInstance::Prio3SumVec { .. }
            | VdafInstance::Prio3Histogram { .. } => {
                // The helper share for any Prio3 instance using joint randomness consist of three
                // seeds, one for the measurement share, one for the proof share, and one for the
                // joint randomness part blind.
                3 * 16
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                // The helper share for any Prio3 instance using joint randomness consist of three
                // seeds, one for the measurement share, one for the proof share, and one for the
                // joint randomness part blind.
                3 * 16
            }
            VdafInstance::Poplar1 { bits } => {
                // Poplar1's input shares are symmetrical across the leader and helper. The input
                // share consists of two PRG seeds, one for the IDPF key and one for deriving the
                // correlated randomness, and two field elements per level for the remainder of the
                // correlated randomness (using Field64 for the inner node levels, and Field255 for
                // the last, leaf level).
                16 * 2 + (bits - 1) * 2 * 8 + 2 * 32
            }
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => {
                // The dummy VDAF's input share consists of a single `u8`.
                1
            }
        }
    }

    /// Returns the size of prepare message shares for a given round of this VDAF. If the `round`
    /// argument is invalid, `None` will be returned. If the VDAF instance is Poplar1, `None` will
    /// be returned, because the prepare message share size depends on the aggregation parameter as
    /// well.
    pub fn prepare_message_share_size(&self, round: usize) -> Option<usize> {
        match (self, round) {
            // Prio3 prepare message shares are composed of a verifier share vector and, if joint
            // randomness is used, a joint randomness seed.
            (VdafInstance::Prio3Count, 0) => {
                // Prio3Count uses Field64, and its verifier is four elements long. It does not use
                // joint randomness.
                Some(8 * 4)
            }
            (VdafInstance::Prio3CountVec { length }, 0) => {
                // Dispatch to the calculations for Prio3SumVec, since its circuit is a generic
                // extension of Prio3CountVec.
                VdafInstance::Prio3SumVec {
                    bits: 1,
                    length: *length,
                }
                .prepare_message_share_size(round)
            }
            (VdafInstance::Prio3Sum { .. }, 0) => {
                // Prio3Sum uses Field128, and its verifier is three elements long. It does use joint
                // randomness.
                Some(16 * 3 + 16)
            }
            (VdafInstance::Prio3SumVec { bits, length }, 0) => {
                // Prio3SumVec uses Field128, and its verifier length depends on the chunk length of
                // the parallel sum gadget. It does use joint randomness.
                let total_bits = bits * length;
                let chunk_length = std::cmp::max(1, (total_bits as f64).sqrt() as usize);
                Some(16 * (2 + chunk_length * 2) + 16)
            }
            (VdafInstance::Prio3Histogram { .. }, 0) => {
                // Prio3Histogram uses Field128, and its verifier is three elements long. It does
                // use joint randomness.
                Some(16 * 3 + 16)
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            (VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length }, 0) => {
                // Dispatch to a helper function, passing the number of bits.
                Some(fixed_point_bounded_l2_norm_prepare_message_share_size(
                    *length, 16,
                ))
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            (VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length }, 0) => Some(
                fixed_point_bounded_l2_norm_prepare_message_share_size(*length, 32),
            ),
            #[cfg(feature = "fpvec_bounded_l2")]
            (VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length }, 0) => Some(
                fixed_point_bounded_l2_norm_prepare_message_share_size(*length, 64),
            ),

            (VdafInstance::Poplar1 { .. }, _) => None,

            #[cfg(feature = "test-util")]
            (VdafInstance::Fake, 0)
            | (VdafInstance::FakeFailsPrepInit, 0)
            | (VdafInstance::FakeFailsPrepStep, 0) => Some(0),
            _ => None,
        }
    }

    /// Returns the size of prepare messages for a given round of this VDAF. If the `round` argument
    /// is invalid, `None` will be returned. If the VDAF is Poplar1, `None` will be returned,
    /// because the prepare message size depends on the aggregation parameter as well.
    pub fn prepare_message_size(&self, round: usize) -> Option<usize> {
        match (self, round) {
            // Prio3 prepare messages consist of a single PRG seed if joint randomness is used, and
            // are empty otherwise.
            (VdafInstance::Prio3Count, 0) => Some(0),
            (VdafInstance::Prio3CountVec { .. }, 0)
            | (VdafInstance::Prio3Sum { .. }, 0)
            | (VdafInstance::Prio3SumVec { .. }, 0)
            | (VdafInstance::Prio3Histogram { .. }, 0) => Some(16),
            #[cfg(feature = "fpvec_bounded_l2")]
            (VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }, 0)
            | (VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }, 0)
            | (VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. }, 0) => Some(16),

            (VdafInstance::Poplar1 { .. }, _) => None,

            // The dummy VDAF's prepare message is empty.
            #[cfg(feature = "test-util")]
            (VdafInstance::Fake, 0)
            | (VdafInstance::FakeFailsPrepInit, 0)
            | (VdafInstance::FakeFailsPrepStep, 0) => Some(0),

            // Incorrect round.
            _ => None,
        }
    }

    /// Returns the size of aggregate shares for this VDAF. If the VDAF is Poplar1, `None` will be
    /// returned, because the aggregate share size depends on the aggregation parameter as well.
    pub fn aggregate_share_size(&self) -> Option<usize> {
        match self {
            VdafInstance::Prio3Count => {
                // Prio3Count uses Field64, and its aggregate share consists of one field element.
                Some(8)
            }
            VdafInstance::Prio3CountVec { length } => {
                // Prio3CountVec uses Field128, and its aggregate share is a field element vector
                // with length equal to the `length` paramter.
                Some(16 * length)
            }
            VdafInstance::Prio3Sum { .. } => {
                // Prio3Sum uses Field128, and its aggregate share consists of one field element.
                Some(16)
            }
            VdafInstance::Prio3SumVec { bits: _, length } => {
                // Prio3SumVec uses Field128, and its aggregate share is a field element vector with
                // length equal to the `length` paramter.
                Some(16 * length)
            }
            VdafInstance::Prio3Histogram { buckets } => {
                // Prio3Histogram uses Field128, and its aggregate share is a field element vector
                // with one element per bucket (one more than the number of bucket boundaries).
                Some(16 * (buckets.len() + 1))
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                // Prio3FixedPoint__BitBoundedL2VecSum uses Field128, and its aggregate share is a
                // field element fector with length equal to the `length` parameter.
                Some(16 * length)
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => Some(16 * length),
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => Some(16 * length),
            VdafInstance::Poplar1 { .. } => None,
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => {
                // The dummy VDAF's aggregate share consists of a `u64`.
                Some(8)
            }
        }
    }
}

/// Helper function for implementation of [`VdafInstance::leader_input_share_size`] on
/// Prio3FixedPoint__BitBoundedL2VecSum instances.
#[cfg(feature = "fpvec_bounded_l2")]
fn fixed_point_bounded_l2_norm_leader_input_share_size(length: usize, bits: usize) -> usize {
    // Each Prio3FixedPoint__BitBoundedL2VecSum instance uses Field128. This family of circuits is
    // more complicated, as it feeds two different low-level gadgets into parallel sum gadgets, each
    // with different chunk lengths. The measurement share vector has one element for each bit of
    // each input vector element, plus more bits for the computed L2 norm. Lastly, a blind is also
    // included for the joint randomness.
    let bits_for_norm = 2 * bits - 2;

    let measurement_length = bits * length + bits_for_norm;

    let parallel_sum_0_length = measurement_length;
    let parallel_sum_0_chunk_length =
        std::cmp::max(1, (parallel_sum_0_length as f64).sqrt() as usize);
    let parallel_sum_0_calls =
        (parallel_sum_0_length + parallel_sum_0_chunk_length - 1) / parallel_sum_0_chunk_length;
    let parallel_sum_0_proof_length = (parallel_sum_0_chunk_length * 2)
        + 3 * ((1 + parallel_sum_0_calls).next_power_of_two() - 1)
        + 1;
    let parallel_sum_1_length = length;
    let parallel_sum_1_chunk_length =
        std::cmp::max(1, (parallel_sum_1_length as f64).sqrt() as usize);
    let parallel_sum_1_calls =
        (parallel_sum_1_length + parallel_sum_1_chunk_length - 1) / parallel_sum_1_chunk_length;
    let parallel_sum_1_proof_length =
        parallel_sum_1_chunk_length + 2 * ((1 + parallel_sum_1_calls).next_power_of_two() - 1) + 1;
    let proof_length = parallel_sum_0_proof_length + parallel_sum_1_proof_length;

    16 * (measurement_length + proof_length) + 16
}

/// Helper function for implementation of [`VdafInstance::prepare_message_share_size`] on
/// Prio3FixedPoint__BitBoundedL2VecSum instances.
#[cfg(feature = "fpvec_bounded_l2")]
fn fixed_point_bounded_l2_norm_prepare_message_share_size(length: usize, bits: usize) -> usize {
    let bits_for_norm = 2 * bits - 2;

    let measurement_length = bits * length + bits_for_norm;

    let parallel_sum_0_length = measurement_length;
    let parallel_sum_0_chunk_length =
        std::cmp::max(1, (parallel_sum_0_length as f64).sqrt() as usize);
    let parallel_sum_1_length = length;
    let parallel_sum_1_chunk_length =
        std::cmp::max(1, (parallel_sum_1_length as f64).sqrt() as usize);

    16 * (parallel_sum_0_chunk_length * 2 + parallel_sum_1_chunk_length + 3) + 16
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fpvec_bounded_l2")]
    use std::collections::BTreeSet;
    use std::{iter, num::NonZeroU8};

    #[cfg(feature = "fpvec_bounded_l2")]
    use fixed::{
        types::extra::{U15, U31, U63},
        FixedI16, FixedI32, FixedI64,
    };
    use prio::{
        codec::Encode,
        vdaf::{prio3::Prio3, Aggregator, Client, VdafError},
    };
    #[cfg(feature = "fpvec_bounded_l2")]
    use prio::{
        idpf::IdpfInput,
        vdaf::{
            poplar1::{Poplar1, Poplar1AggregationParam},
            prio3::Prio3FixedPointBoundedL2VecSumMultithreaded,
        },
    };
    use quickcheck::{empty_shrinker, Arbitrary, QuickCheck, TestResult};
    use rand::random;

    use crate::{
        task::VdafInstance,
        test_util::{dummy_vdaf, run_vdaf},
    };

    fn correct_client_message_sizes(vdaf_instance: VdafInstance) -> Result<TestResult, VdafError> {
        match &vdaf_instance {
            VdafInstance::Prio3Count => {
                let vdaf = Prio3::new_count(2)?;
                correct_client_message_sizes_generic(&vdaf_instance, &vdaf, &0)
            }
            VdafInstance::Prio3CountVec { length } => {
                let vdaf = Prio3::new_sum_vec(2, 1, *length)?;
                correct_client_message_sizes_generic(
                    &vdaf_instance,
                    &vdaf,
                    &iter::repeat(0).take(*length).collect(),
                )
            }
            VdafInstance::Prio3Sum { bits } => {
                let vdaf = Prio3::new_sum(2, *bits)?;
                correct_client_message_sizes_generic(&vdaf_instance, &vdaf, &0)
            }
            VdafInstance::Prio3SumVec { bits, length } => {
                let vdaf = Prio3::new_sum_vec_multithreaded(2, *bits, *length)?;
                correct_client_message_sizes_generic(
                    &vdaf_instance,
                    &vdaf,
                    &iter::repeat(0).take(*length).collect(),
                )
            }
            VdafInstance::Prio3Histogram { buckets } => {
                let vdaf = Prio3::new_histogram(2, buckets)?;
                correct_client_message_sizes_generic(&vdaf_instance, &vdaf, &0)
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                correct_client_message_sizes_generic(
                    &vdaf_instance,
                    &vdaf,
                    &iter::repeat(FixedI16::<U15>::from_bits(0))
                        .take(*length)
                        .collect(),
                )
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                correct_client_message_sizes_generic(
                    &vdaf_instance,
                    &vdaf,
                    &iter::repeat(FixedI32::<U31>::from_bits(0))
                        .take(*length)
                        .collect(),
                )
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                correct_client_message_sizes_generic(
                    &vdaf_instance,
                    &vdaf,
                    &iter::repeat(FixedI64::<U63>::from_bits(0))
                        .take(*length)
                        .collect(),
                )
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Poplar1 { bits } => {
                let vdaf = Poplar1::new_sha3(*bits);
                correct_client_message_sizes_generic(
                    &vdaf_instance,
                    &vdaf,
                    &IdpfInput::from_bools(&iter::repeat(false).take(*bits).collect::<Vec<bool>>()),
                )
            }
            #[cfg(not(feature = "fpvec_bounded_l2"))]
            VdafInstance::Poplar1 { .. } => {
                unreachable!("Support for Poplar1 was not enabled at compile time")
            }
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => {
                // Ignore the "fails" component, and always construct the VDAF with its default
                // closures.
                let vdaf = dummy_vdaf::Vdaf::new();
                correct_client_message_sizes_generic(&vdaf_instance, &vdaf, &())
            }
        }
    }

    fn correct_client_message_sizes_generic<V>(
        vdaf_instance: &VdafInstance,
        vdaf: &V,
        measurement: &V::Measurement,
    ) -> Result<TestResult, VdafError>
    where
        V: Client<16>,
    {
        let (public_share, input_shares) = vdaf.shard(measurement, &[0; 16])?;
        if vdaf_instance.leader_input_share_size() != input_shares[0].get_encoded().len() {
            return Ok(TestResult::failed());
        }
        if vdaf_instance.helper_input_share_size() != input_shares[1].get_encoded().len() {
            return Ok(TestResult::failed());
        }
        if vdaf_instance.public_share_size() != public_share.get_encoded().len() {
            return Ok(TestResult::failed());
        }
        Ok(TestResult::passed())
    }

    /// Arguments needed to generate a VDAF transcript, for use in testing.
    #[derive(Debug, Clone)]
    #[cfg(feature = "fpvec_bounded_l2")]
    struct TranscriptArguments {
        /// VDAF type and parameters.
        vdaf_instance: VdafInstance,

        /// Poplar1 aggregation parameter. This will be `Some` if `vdaf_instance` is Poplar1, and
        /// `None` otherwise.
        poplar1_aggregation_param: Option<Poplar1AggregationParam>,
    }

    /// Arguments needed to generate a VDAF transcript, for use in testing.
    #[derive(Debug, Clone)]
    #[cfg(not(feature = "fpvec_bounded_l2"))]
    struct TranscriptArguments {
        /// VDAF type and parameters.
        vdaf_instance: VdafInstance,

        /// Placeholder for Poplar1 aggregation parameter.
        #[allow(unused)]
        poplar1_aggregation_param: Option<()>,
    }

    fn correct_aggregator_message_sizes(
        transcript_arguments: TranscriptArguments,
    ) -> Result<TestResult, VdafError> {
        match &transcript_arguments.vdaf_instance {
            VdafInstance::Prio3Count => {
                let vdaf = Prio3::new_count(2)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &0,
                )
            }
            VdafInstance::Prio3CountVec { length } => {
                let vdaf = Prio3::new_sum_vec(2, 1, *length)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &iter::repeat(0).take(*length).collect(),
                )
            }
            VdafInstance::Prio3Sum { bits } => {
                let vdaf = Prio3::new_sum(2, *bits)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &0,
                )
            }
            VdafInstance::Prio3SumVec { bits, length } => {
                let vdaf = Prio3::new_sum_vec_multithreaded(2, *bits, *length)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &iter::repeat(0).take(*length).collect(),
                )
            }
            VdafInstance::Prio3Histogram { buckets } => {
                let vdaf = Prio3::new_histogram(2, buckets)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &0,
                )
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &iter::repeat(FixedI16::<U15>::from_bits(0))
                        .take(*length)
                        .collect(),
                )
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &iter::repeat(FixedI32::<U31>::from_bits(0))
                        .take(*length)
                        .collect(),
                )
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, *length)?;
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &(),
                    &iter::repeat(FixedI64::<U63>::from_bits(0))
                        .take(*length)
                        .collect(),
                )
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Poplar1 { bits } => {
                let vdaf = Poplar1::new_sha3(*bits);
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    transcript_arguments
                        .poplar1_aggregation_param
                        .as_ref()
                        .unwrap(),
                    &IdpfInput::from_bools(&iter::repeat(false).take(*bits).collect::<Vec<bool>>()),
                )
            }
            #[cfg(not(feature = "fpvec_bounded_l2"))]
            VdafInstance::Poplar1 { .. } => {
                unreachable!("Support for Poplar1 was not enabled at compile time")
            }
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => {
                // Ignore the "fails" component, and always construct the VDAF with its default
                // closures.
                let vdaf = dummy_vdaf::Vdaf::new();
                correct_aggregator_message_sizes_generic(
                    &transcript_arguments.vdaf_instance,
                    &vdaf,
                    &dummy_vdaf::AggregationParam(0),
                    &(),
                )
            }
        }
    }

    fn correct_aggregator_message_sizes_generic<V, const VERIFY_KEY_SIZE: usize>(
        vdaf_instance: &VdafInstance,
        vdaf: &V,
        aggregation_param: &V::AggregationParam,
        measurement: &V::Measurement,
    ) -> Result<TestResult, VdafError>
    where
        V: Client<16> + Aggregator<VERIFY_KEY_SIZE, 16>,
    {
        if let VdafInstance::Poplar1 { .. } = vdaf_instance {
            // Skip, Poplar1 message sizes depend on the aggregation parameter as well.
            return Ok(TestResult::discard());
        }

        let transcript = run_vdaf(
            vdaf,
            &[0; VERIFY_KEY_SIZE],
            aggregation_param,
            &random(),
            measurement,
        );
        for (round, prepare_message) in transcript.prepare_messages.iter().enumerate() {
            let (_, prepare_share) = transcript.helper_prep_state(round);

            let prepare_message_share_size =
                vdaf_instance.prepare_message_share_size(round).unwrap();
            let prepare_message_size = vdaf_instance.prepare_message_size(round).unwrap();

            if prepare_message_share_size != prepare_share.get_encoded().len() {
                return Ok(TestResult::failed());
            }
            if prepare_message_size != prepare_message.get_encoded().len() {
                return Ok(TestResult::failed());
            }
        }

        let aggregate_share_size = vdaf_instance.aggregate_share_size().unwrap();
        for aggregate_share in transcript.aggregate_shares.iter() {
            if aggregate_share_size != aggregate_share.get_encoded().len() {
                return Ok(TestResult::failed());
            }
        }

        Ok(TestResult::passed())
    }

    lazy_static::lazy_static! {
        static ref CHOICES_1_THROUGH_3: Vec<usize> = (1..=3).collect::<Vec<usize>>();
        static ref CHOICES_1_THROUGH_10: Vec<usize> = (1..=10).collect::<Vec<usize>>();
        static ref CHOICES_1_THROUGH_32: Vec<usize> = (1..=32).collect::<Vec<usize>>();
        static ref CHOICES_1_THROUGH_64: Vec<usize> = (1..=64).collect::<Vec<usize>>();
        static ref CHOICES_1_THROUGH_127: Vec<usize> = (1..=127).collect::<Vec<usize>>();
    }

    impl Arbitrary for VdafInstance {
        /// Return an arbitrary `VdafInstance`. Parameter choices are limited to avoid producing
        /// VDAFs that would take too long to evaluate in non-release builds.
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            #[cfg(all(feature = "fpvec_bounded_l2", feature = "test-util"))]
            let choices = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

            #[cfg(all(feature = "fpvec_bounded_l2", not(feature = "test-util")))]
            let choices = &[0, 1, 2, 3, 4, 5, 6, 7, 8];

            #[cfg(all(not(feature = "fpvec_bounded_l2"), feature = "test-util"))]
            let choices = &[0, 1, 2, 3, 4, 9];

            #[cfg(all(not(feature = "fpvec_bounded_l2"), not(feature = "test-util")))]
            let choices = &[0, 1, 2, 3, 4];

            match g.choose(choices).unwrap() {
                0 => VdafInstance::Prio3Count,
                1 => VdafInstance::Prio3CountVec {
                    length: NonZeroU8::arbitrary(g).get() as usize,
                },
                2 => {
                    // libprio-rs limits its Prio3Sum implementation to 64 bits.
                    VdafInstance::Prio3Sum {
                        bits: *g.choose(&CHOICES_1_THROUGH_64).unwrap(),
                    }
                }
                3 => {
                    // The number of bits may not exceed 127, as elements of the measurement vector
                    // get represented inside the field, and 128-bit numbers may wrap around the
                    // field's modulus.
                    VdafInstance::Prio3SumVec {
                        bits: *g.choose(&CHOICES_1_THROUGH_127).unwrap(),
                        length: *g.choose(&CHOICES_1_THROUGH_10).unwrap(),
                    }
                }
                4 => {
                    let boundary_count = NonZeroU8::arbitrary(g).get() as u64;
                    VdafInstance::Prio3Histogram {
                        buckets: (0..boundary_count).collect(),
                    }
                }
                #[cfg(feature = "fpvec_bounded_l2")]
                5 => VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum {
                    length: NonZeroU8::arbitrary(g).get() as usize,
                },
                #[cfg(feature = "fpvec_bounded_l2")]
                6 => VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum {
                    length: NonZeroU8::arbitrary(g).get() as usize,
                },
                #[cfg(feature = "fpvec_bounded_l2")]
                7 => {
                    // Note that this VDAF only supports lengths of 1, 2, or 3, as larger vectors
                    // may overflow the norm calculation. The norm is represented as a 126-bit
                    // fixed-point number, and adding four squared input elements could wrap around
                    // `Field128`'s modulus.
                    VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum {
                        length: *g.choose(&CHOICES_1_THROUGH_3).unwrap(),
                    }
                }
                8 => VdafInstance::Poplar1 {
                    bits: *g.choose(&CHOICES_1_THROUGH_32).unwrap(),
                },
                #[cfg(feature = "test-util")]
                9 => VdafInstance::Fake,
                _ => unreachable!(),
            }
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            match self {
                VdafInstance::Prio3Count => empty_shrinker(),
                VdafInstance::Prio3CountVec { length } => {
                    if *length > 1 {
                        Box::new(
                            [
                                VdafInstance::Prio3CountVec { length: length / 2 },
                                VdafInstance::Prio3CountVec { length: length - 1 },
                            ]
                            .into_iter(),
                        )
                    } else {
                        empty_shrinker()
                    }
                }
                VdafInstance::Prio3Sum { bits } => {
                    if *bits > 1 {
                        Box::new(
                            [
                                VdafInstance::Prio3Sum { bits: bits / 2 },
                                VdafInstance::Prio3Sum { bits: bits - 1 },
                            ]
                            .into_iter(),
                        )
                    } else {
                        empty_shrinker()
                    }
                }
                VdafInstance::Prio3SumVec { bits, length } => {
                    let mut v = Vec::with_capacity(4);
                    if *bits > 1 {
                        v.push(VdafInstance::Prio3SumVec {
                            bits: bits / 2,
                            length: *length,
                        });
                        v.push(VdafInstance::Prio3SumVec {
                            bits: bits - 1,
                            length: *length,
                        });
                    }
                    if *length > 1 {
                        v.push(VdafInstance::Prio3SumVec {
                            bits: *bits,
                            length: length / 2,
                        });
                        v.push(VdafInstance::Prio3SumVec {
                            bits: *bits,
                            length: length - 1,
                        });
                    }
                    Box::new(v.into_iter())
                }
                VdafInstance::Prio3Histogram { buckets } => {
                    if buckets.len() > 1 {
                        Box::new(
                            [
                                VdafInstance::Prio3Histogram {
                                    buckets: buckets[..buckets.len() / 2].to_vec(),
                                },
                                VdafInstance::Prio3Histogram {
                                    buckets: buckets[..buckets.len() - 1].to_vec(),
                                },
                            ]
                            .into_iter(),
                        )
                    } else {
                        empty_shrinker()
                    }
                }
                #[cfg(feature = "fpvec_bounded_l2")]
                VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                    if *length > 1 {
                        Box::new(
                            [
                                VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum {
                                    length: length / 2,
                                },
                                VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum {
                                    length: length - 1,
                                },
                            ]
                            .into_iter(),
                        )
                    } else {
                        empty_shrinker()
                    }
                }
                #[cfg(feature = "fpvec_bounded_l2")]
                VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                    if *length > 1 {
                        Box::new(
                            [
                                VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum {
                                    length: length / 2,
                                },
                                VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum {
                                    length: length - 1,
                                },
                            ]
                            .into_iter(),
                        )
                    } else {
                        empty_shrinker()
                    }
                }
                #[cfg(feature = "fpvec_bounded_l2")]
                VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                    if *length > 1 {
                        Box::new(
                            [
                                VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum {
                                    length: length / 2,
                                },
                                VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum {
                                    length: length - 1,
                                },
                            ]
                            .into_iter(),
                        )
                    } else {
                        empty_shrinker()
                    }
                }
                VdafInstance::Poplar1 { bits } => {
                    if *bits > 1 {
                        Box::new(
                            [
                                VdafInstance::Poplar1 { bits: bits / 2 },
                                VdafInstance::Poplar1 { bits: bits - 1 },
                            ]
                            .into_iter(),
                        )
                    } else {
                        empty_shrinker()
                    }
                }
                #[cfg(feature = "test-util")]
                VdafInstance::Fake => empty_shrinker(),
                #[cfg(feature = "test-util")]
                VdafInstance::FakeFailsPrepInit => empty_shrinker(),
                #[cfg(feature = "test-util")]
                VdafInstance::FakeFailsPrepStep => empty_shrinker(),
            }
        }
    }

    impl Arbitrary for TranscriptArguments {
        #[cfg(feature = "fpvec_bounded_l2")]
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let vdaf_instance = VdafInstance::arbitrary(g);
            if let VdafInstance::Poplar1 { bits } = &vdaf_instance {
                let max_prefix_count = if *bits > 6 { 64 } else { 1 << bits };
                let prefix_count = std::cmp::max(1, usize::arbitrary(g) % max_prefix_count);
                let mut prefixes = BTreeSet::new();
                while prefixes.len() < prefix_count {
                    prefixes.insert(IdpfInput::from_bools(
                        &iter::repeat_with(|| bool::arbitrary(g))
                            .take(*bits)
                            .collect::<Vec<bool>>(),
                    ));
                }
                let poplar1_aggregation_param =
                    Poplar1AggregationParam::try_from_prefixes(prefixes.into_iter().collect())
                        .unwrap();
                TranscriptArguments {
                    vdaf_instance,
                    poplar1_aggregation_param: Some(poplar1_aggregation_param),
                }
            } else {
                TranscriptArguments {
                    vdaf_instance,
                    poplar1_aggregation_param: None,
                }
            }
        }

        #[cfg(not(feature = "fpvec_bounded_l2"))]
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let vdaf_instance = VdafInstance::arbitrary(g);
            TranscriptArguments {
                vdaf_instance,
                poplar1_aggregation_param: None,
            }
        }

        #[cfg(feature = "fpvec_bounded_l2")]
        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            let base_iterator = self.vdaf_instance.shrink().map({
                let poplar1_aggregation_param = self.poplar1_aggregation_param.clone();
                move |vdaf_instance| TranscriptArguments {
                    vdaf_instance,
                    poplar1_aggregation_param: poplar1_aggregation_param.clone(),
                }
            });
            if let Some(poplar1_aggregation_param) = self.poplar1_aggregation_param.as_ref() {
                let prefixes = poplar1_aggregation_param.prefixes();
                Box::new(
                    base_iterator.chain(iter::once(TranscriptArguments {
                        vdaf_instance: self.vdaf_instance.clone(),
                        poplar1_aggregation_param: Some(
                            Poplar1AggregationParam::try_from_prefixes(
                                prefixes[..prefixes.len() - 1].to_vec(),
                            )
                            .unwrap(),
                        ),
                    })),
                )
            } else {
                Box::new(base_iterator)
            }
        }

        #[cfg(not(feature = "fpvec_bounded_l2"))]
        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(
                self.vdaf_instance
                    .shrink()
                    .map(|vdaf_instance| TranscriptArguments {
                        vdaf_instance,
                        poplar1_aggregation_param: None,
                    }),
            )
        }
    }

    #[test]
    fn client_prio3count() {
        let test_result = correct_client_message_sizes(VdafInstance::Prio3Count).unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn client_prio3countvec_1() {
        let test_result =
            correct_client_message_sizes(VdafInstance::Prio3CountVec { length: 1 }).unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn client_prio3sum_8() {
        let test_result = correct_client_message_sizes(VdafInstance::Prio3Sum { bits: 8 }).unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn client_prio3histogram_2_buckets() {
        let test_result = correct_client_message_sizes(VdafInstance::Prio3Histogram {
            buckets: Vec::from([1]),
        })
        .unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn client_quickcheck() {
        QuickCheck::new().quickcheck(
            correct_client_message_sizes as fn(VdafInstance) -> Result<TestResult, VdafError>,
        );
    }

    #[test]
    fn aggregator_prio3count() {
        let test_result = correct_aggregator_message_sizes(TranscriptArguments {
            vdaf_instance: VdafInstance::Prio3Count,
            poplar1_aggregation_param: None,
        })
        .unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn aggregator_prio3countvec_1() {
        let test_result = correct_aggregator_message_sizes(TranscriptArguments {
            vdaf_instance: VdafInstance::Prio3CountVec { length: 1 },
            poplar1_aggregation_param: None,
        })
        .unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn aggregator_prio3sum_8() {
        let test_result = correct_aggregator_message_sizes(TranscriptArguments {
            vdaf_instance: VdafInstance::Prio3Sum { bits: 8 },
            poplar1_aggregation_param: None,
        })
        .unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn aggregator_prio3histogram_2_buckets() {
        let test_result = correct_aggregator_message_sizes(TranscriptArguments {
            vdaf_instance: VdafInstance::Prio3Histogram {
                buckets: Vec::from([1]),
            },
            poplar1_aggregation_param: None,
        })
        .unwrap();
        assert!(!test_result.is_error());
        assert!(!test_result.is_failure());
    }

    #[test]
    fn aggregator_quickcheck() {
        QuickCheck::new().quickcheck(
            correct_aggregator_message_sizes
                as fn(TranscriptArguments) -> Result<TestResult, VdafError>,
        );
    }
}
