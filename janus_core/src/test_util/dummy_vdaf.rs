//! Implements a lightweight dummy VDAF for use in tests.

use prio::{
    codec::{CodecError, Decode, Encode},
    vdaf::{self, Aggregatable, PrepareTransition, VdafError},
};
use std::fmt::Debug;
use std::sync::Arc;
use std::{convert::Infallible, io::Cursor};

type ArcPrepInitFn =
    Arc<dyn Fn(&AggregationParam) -> Result<(), VdafError> + 'static + Send + Sync>;
type ArcPrepStepFn =
    Arc<dyn Fn() -> Result<PrepareTransition<Vdaf, 0>, VdafError> + 'static + Send + Sync>;

#[derive(Clone)]
pub struct Vdaf {
    prep_init_fn: ArcPrepInitFn,
    prep_step_fn: ArcPrepStepFn,
}

impl Debug for Vdaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vdaf")
            .field("prep_init_result", &"[omitted]")
            .field("prep_step_result", &"[omitted]")
            .finish()
    }
}

impl Vdaf {
    /// The length of the verify key parameter for fake VDAF instantiations.
    pub const VERIFY_KEY_LENGTH: usize = 0;

    pub fn new() -> Self {
        Self {
            prep_init_fn: Arc::new(|_| -> Result<(), VdafError> { Ok(()) }),
            prep_step_fn: Arc::new(|| -> Result<PrepareTransition<Self, 0>, VdafError> {
                Ok(PrepareTransition::Finish(OutputShare()))
            }),
        }
    }

    pub fn with_prep_init_fn<F: Fn(&AggregationParam) -> Result<(), VdafError>>(
        mut self,
        f: F,
    ) -> Self
    where
        F: 'static + Send + Sync,
    {
        self.prep_init_fn = Arc::new(f);
        self
    }

    pub fn with_prep_step_fn<F: Fn() -> Result<PrepareTransition<Self, 0>, VdafError>>(
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

impl Default for Vdaf {
    fn default() -> Self {
        Self::new()
    }
}

impl vdaf::Vdaf for Vdaf {
    const ID: u32 = 0xFFFF0000;

    type Measurement = ();
    type AggregateResult = ();
    type AggregationParam = AggregationParam;
    type PublicShare = ();
    type InputShare = ();
    type OutputShare = OutputShare;
    type AggregateShare = AggregateShare;

    fn num_aggregators(&self) -> usize {
        2
    }
}

impl vdaf::Aggregator<0> for Vdaf {
    type PrepareState = ();
    type PrepareShare = ();
    type PrepareMessage = ();

    fn prepare_init(
        &self,
        _: &[u8; 0],
        _: usize,
        aggregation_param: &Self::AggregationParam,
        _: &[u8],
        _: &Self::PublicShare,
        _: &Self::InputShare,
    ) -> Result<(Self::PrepareState, Self::PrepareShare), VdafError> {
        (self.prep_init_fn)(aggregation_param)?;
        Ok(((), ()))
    }

    fn prepare_preprocess<M: IntoIterator<Item = Self::PrepareMessage>>(
        &self,
        _: M,
    ) -> Result<Self::PrepareMessage, VdafError> {
        Ok(())
    }

    fn prepare_step(
        &self,
        _: Self::PrepareState,
        _: Self::PrepareMessage,
    ) -> Result<PrepareTransition<Self, 0>, VdafError> {
        (self.prep_step_fn)()
    }

    fn aggregate<M: IntoIterator<Item = Self::OutputShare>>(
        &self,
        _: &Self::AggregationParam,
        output_shares: M,
    ) -> Result<Self::AggregateShare, VdafError> {
        let mut aggregate_share = AggregateShare(0);
        for output_share in output_shares {
            aggregate_share.accumulate(&output_share)?;
        }
        Ok(aggregate_share)
    }
}

impl vdaf::Client for Vdaf {
    fn shard(
        &self,
        _: &Self::Measurement,
    ) -> Result<(Self::PublicShare, Vec<Self::InputShare>), VdafError> {
        Ok(((), Vec::from([(), ()])))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregationParam(pub u8);

impl Encode for AggregationParam {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for AggregationParam {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u8::decode(bytes)?))
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
pub struct AggregateShare(pub u64);

impl Aggregatable for AggregateShare {
    type OutputShare = OutputShare;

    fn merge(&mut self, other: &Self) -> Result<(), VdafError> {
        self.0 += other.0;
        Ok(())
    }

    fn accumulate(&mut self, _: &Self::OutputShare) -> Result<(), VdafError> {
        self.0 += 1;
        Ok(())
    }
}

impl From<OutputShare> for AggregateShare {
    fn from(_: OutputShare) -> Self {
        Self(1)
    }
}

impl TryFrom<&[u8]> for AggregateShare {
    type Error = CodecError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let val = u64::get_decoded(bytes)?;
        Ok(Self(val))
    }
}

impl From<&AggregateShare> for Vec<u8> {
    fn from(aggregate_share: &AggregateShare) -> Self {
        aggregate_share.0.get_encoded()
    }
}
