//! Implements a lightweight dummy VDAF for use in tests.

use prio::{
    codec::{Decode, Encode},
    vdaf::{self, Aggregatable, PrepareTransition, VdafError},
};
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::Arc;

pub type Vdaf = VdafWithAggregationParameter<()>;

#[derive(Clone)]
pub struct VdafWithAggregationParameter<A> {
    prep_init_fn: Arc<dyn Fn(&A) -> Result<(), VdafError> + 'static + Send + Sync>,
    prep_step_fn: Arc<dyn Fn() -> PrepareTransition<(), (), OutputShare> + 'static + Send + Sync>,
}

impl<A> Debug for VdafWithAggregationParameter<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vdaf")
            .field("prep_init_result", &"[omitted]")
            .field("prep_step_result", &"[omitted]")
            .finish()
    }
}

impl<A> VdafWithAggregationParameter<A> {
    pub fn new() -> Self {
        Self {
            prep_init_fn: Arc::new(|_| -> Result<(), VdafError> { Ok(()) }),
            prep_step_fn: Arc::new(|| -> PrepareTransition<(), (), OutputShare> {
                PrepareTransition::Finish(OutputShare())
            }),
        }
    }

    pub fn with_prep_init_fn<F: Fn(&A) -> Result<(), VdafError>>(mut self, f: F) -> Self
    where
        F: 'static + Send + Sync,
    {
        self.prep_init_fn = Arc::new(f);
        self
    }

    pub fn with_prep_step_fn<F: Fn() -> PrepareTransition<(), (), OutputShare>>(
        mut self,
        f: F,
    ) -> Self
    where
        F: 'static + Send + Sync,
    {
        self.prep_step_fn = Arc::new(f);
        self
    }
}

impl<A> Default for VdafWithAggregationParameter<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Clone + Debug + Encode + Decode> vdaf::Vdaf for VdafWithAggregationParameter<A> {
    type Measurement = ();
    type AggregateResult = ();
    type AggregationParam = A;
    type PublicParam = ();
    type VerifyParam = ();
    type InputShare = ();
    type OutputShare = OutputShare;
    type AggregateShare = AggregateShare;

    fn setup(&self) -> Result<(Self::PublicParam, Vec<Self::VerifyParam>), VdafError> {
        Ok(((), vec![(), ()]))
    }

    fn num_aggregators(&self) -> usize {
        2
    }
}

impl<A: Clone + Debug + Encode + Decode> vdaf::Aggregator for VdafWithAggregationParameter<A> {
    type PrepareStep = ();
    type PrepareMessage = ();

    fn prepare_init(
        &self,
        _: &Self::VerifyParam,
        aggregation_param: &Self::AggregationParam,
        _: &[u8],
        _: &Self::InputShare,
    ) -> Result<Self::PrepareStep, VdafError> {
        (self.prep_init_fn)(aggregation_param)
    }

    fn prepare_preprocess<M: IntoIterator<Item = Self::PrepareMessage>>(
        &self,
        _: M,
    ) -> Result<Self::PrepareMessage, VdafError> {
        Ok(())
    }

    fn prepare_step(
        &self,
        _: Self::PrepareStep,
        _: Option<Self::PrepareMessage>,
    ) -> PrepareTransition<Self::PrepareStep, Self::PrepareMessage, Self::OutputShare> {
        (self.prep_step_fn)()
    }

    fn aggregate<M: IntoIterator<Item = Self::OutputShare>>(
        &self,
        _: &Self::AggregationParam,
        _: M,
    ) -> Result<Self::AggregateShare, VdafError> {
        Ok(AggregateShare())
    }
}

impl<A: Clone + Debug + Encode + Decode> vdaf::Client for VdafWithAggregationParameter<A> {
    fn shard(
        &self,
        _: &Self::PublicParam,
        _: &Self::Measurement,
    ) -> Result<Vec<Self::InputShare>, VdafError> {
        Ok(vec![(), ()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputShare();

impl TryFrom<&[u8]> for OutputShare {
    type Error = Infallible;

    fn try_from(_: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self())
    }
}

impl From<&OutputShare> for Vec<u8> {
    fn from(_: &OutputShare) -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShare();

impl Aggregatable for AggregateShare {
    type OutputShare = OutputShare;

    fn merge(&mut self, _: &Self) -> Result<(), VdafError> {
        Ok(())
    }

    fn accumulate(&mut self, _: &Self::OutputShare) -> Result<(), VdafError> {
        Ok(())
    }
}

impl From<OutputShare> for AggregateShare {
    fn from(_: OutputShare) -> Self {
        Self()
    }
}

impl TryFrom<&[u8]> for AggregateShare {
    type Error = Infallible;

    fn try_from(_: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self())
    }
}

impl From<&AggregateShare> for Vec<u8> {
    fn from(_: &AggregateShare) -> Self {
        Self::new()
    }
}
