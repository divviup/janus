#[cfg(feature = "test-util")]
use crate::test_util::dummy_vdaf::Vdaf;
use derivative::Derivative;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::traits::Fixed;
#[cfg(feature = "fpvec_bounded_l2")]
use prio::flp::{
    gadgets::{ParallelSumGadget, PolyEval},
    types::fixedpoint_l2::{compatible_float::CompatibleFloat, FixedPointBoundedL2VecSum},
};
use prio::{
    dp::{
        DifferentialPrivacyBudget, DifferentialPrivacyDistribution, DifferentialPrivacyStrategy,
        DpError,
    },
    field::{Field128, Field64},
    flp::{
        gadgets::{Mul, ParallelSum, ParallelSumMultithreaded},
        TypeWithNoise,
    },
    vdaf::{xof::XofShake128, AggregatorWithNoise},
};
use serde::{Deserialize, Serialize};

/// An "empty" differential privacy budget type. Tasks which don't require differential privacy
/// should use this type as their `DifferentialPrivacyBudget`.
pub struct NoBudget;
impl DifferentialPrivacyBudget for NoBudget {}

/// An "empty" distribution. Tasks which don't require differential privacy should use this type
/// as their `DifferentialPrivacyDistribution`.
pub struct NoDistribution;
impl DifferentialPrivacyDistribution for NoDistribution {}

/// A "no-op" differential privacy strategy. Tasks which don't require differential privacy should
/// use this type as their `DifferentialPrivacyStrategy`.
#[derive(Debug, Derivative, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NoDifferentialPrivacy;
impl DifferentialPrivacyStrategy for NoDifferentialPrivacy {
    type Budget = NoBudget;
    type Distribution = NoDistribution;
    type Sensitivity = ();
    fn from_budget(_b: NoBudget) -> Self {
        NoDifferentialPrivacy
    }
    fn create_distribution(&self, _s: Self::Sensitivity) -> Result<Self::Distribution, DpError> {
        Ok(NoDistribution)
    }
}

// identity strategy implementations for vdafs from janus
#[cfg(feature = "test-util")]
impl AggregatorWithNoise<0, 16, NoDifferentialPrivacy> for Vdaf {
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_param: &Self::AggregationParam,
        _agg_share: &mut Self::AggregateShare,
        _num_measurements: usize,
    ) -> Result<(), prio::vdaf::VdafError> {
        Ok(())
    }
}

// identity strategy implementations for vdafs from libprio
impl TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::Sum<Field128> {
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::Count<Field64> {
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl TypeWithNoise<NoDifferentialPrivacy>
    for prio::flp::types::Histogram<Field128, ParallelSum<Field128, Mul<Field128>>>
{
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl TypeWithNoise<NoDifferentialPrivacy>
    for prio::flp::types::SumVec<Field128, ParallelSumMultithreaded<Field128, Mul<Field128>>>
{
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

#[cfg(feature = "fpvec_bounded_l2")]
impl<T, SPoly, SBlindPoly> TypeWithNoise<NoDifferentialPrivacy>
    for FixedPointBoundedL2VecSum<T, SPoly, SBlindPoly>
where
    T: Fixed + CompatibleFloat,
    SPoly: ParallelSumGadget<Field128, PolyEval<Field128>> + Eq + Clone + 'static,
    SBlindPoly: ParallelSumGadget<Field128, Mul<Field128>> + Eq + Clone + 'static,
{
    fn add_noise_to_result(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl AggregatorWithNoise<16, 16, NoDifferentialPrivacy>
    for prio::vdaf::poplar1::Poplar1<XofShake128, 16>
{
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_param: &Self::AggregationParam,
        _agg_share: &mut Self::AggregateShare,
        _num_measurements: usize,
    ) -> Result<(), prio::vdaf::VdafError> {
        Ok(())
    }
}
