#[cfg(feature = "test-util")]
use prio::vdaf::{AggregatorWithNoise, dummy};
use prio::{
    dp::{
        DifferentialPrivacyBudget, DifferentialPrivacyDistribution, DifferentialPrivacyStrategy,
        DpError,
    },
    field::{Field64, Field128},
    flp::{
        TypeWithNoise,
        gadgets::{Mul, ParallelSumGadget},
    },
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
impl AggregatorWithNoise<0, 16, NoDifferentialPrivacy> for dummy::Vdaf {
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
impl TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::Sum<Field64> {
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::Count<Field64> {
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl<PS> TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::Histogram<Field128, PS>
where
    PS: ParallelSumGadget<Field128, Mul> + Eq + 'static,
{
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl<PS> TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::SumVec<Field128, PS>
where
    PS: ParallelSumGadget<Field128, Mul> + Eq + 'static,
{
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}

impl<PS> TypeWithNoise<NoDifferentialPrivacy> for prio::flp::types::SumVec<Field64, PS>
where
    PS: ParallelSumGadget<Field64, Mul> + Eq + 'static,
{
    fn add_noise_to_agg_share(
        &self,
        _dp_strategy: &NoDifferentialPrivacy,
        _agg_result: &mut [Self::Field],
        _num_measurements: usize,
    ) -> Result<(), prio::flp::FlpError> {
        Ok(())
    }
}
