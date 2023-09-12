//! Implements a lightweight dummy VDAF for use in tests.

use prio::{
    codec::{CodecError, Decode, Encode},
    vdaf::{self, Aggregatable, PrepareTransition, VdafError},
};
use std::fmt::Debug;
use std::io::Cursor;
use std::sync::Arc;

type ArcPrepInitFn =
    Arc<dyn Fn(&AggregationParam) -> Result<(), VdafError> + 'static + Send + Sync>;
type ArcPrepStepFn =
    Arc<dyn Fn() -> Result<PrepareTransition<Vdaf, 0, 16>, VdafError> + 'static + Send + Sync>;

#[derive(Clone)]
pub struct Vdaf {
    prep_init_fn: ArcPrepInitFn,
    prep_step_fn: ArcPrepStepFn,
    input_share: InputShare,
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
            prep_step_fn: Arc::new(|| -> Result<PrepareTransition<Self, 0, 16>, VdafError> {
                Ok(PrepareTransition::Finish(OutputShare()))
            }),
            input_share: InputShare::default(),
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

    pub fn with_prep_step_fn<F: Fn() -> Result<PrepareTransition<Self, 0, 16>, VdafError>>(
        mut self,
        f: F,
    ) -> Self
    where
        F: 'static + Send + Sync,
    {
        self.prep_step_fn = Arc::new(f);
        self
    }

    pub fn with_input_share(mut self, input_share: InputShare) -> Self {
        self.input_share = input_share;
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
    type InputShare = InputShare;
    type OutputShare = OutputShare;
    type AggregateShare = AggregateShare;

    fn num_aggregators(&self) -> usize {
        2
    }
}

impl vdaf::Aggregator<0, 16> for Vdaf {
    type PrepareState = PrepareState;
    type PrepareShare = ();
    type PrepareMessage = ();

    fn prepare_init(
        &self,
        _verify_key: &[u8; 0],
        _: usize,
        aggregation_param: &Self::AggregationParam,
        _nonce: &[u8; 16],
        _: &Self::PublicShare,
        input_share: &Self::InputShare,
    ) -> Result<(Self::PrepareState, Self::PrepareShare), VdafError> {
        (self.prep_init_fn)(aggregation_param)?;
        Ok((PrepareState(input_share.0), ()))
    }

    fn prepare_shares_to_prepare_message<M: IntoIterator<Item = Self::PrepareShare>>(
        &self,
        _: &Self::AggregationParam,
        _: M,
    ) -> Result<Self::PrepareMessage, VdafError> {
        Ok(())
    }

    fn prepare_next(
        &self,
        _: Self::PrepareState,
        _: Self::PrepareMessage,
    ) -> Result<PrepareTransition<Self, 0, 16>, VdafError> {
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

impl vdaf::Client<16> for Vdaf {
    fn shard(
        &self,
        _measurement: &Self::Measurement,
        _nonce: &[u8; 16],
    ) -> Result<(Self::PublicShare, Vec<Self::InputShare>), VdafError> {
        Ok(((), Vec::from([self.input_share, self.input_share])))
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputShare(pub u8);

impl Encode for InputShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for InputShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u8::decode(bytes)?))
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregationParam(pub u8);

impl Encode for AggregationParam {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for AggregationParam {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u8::decode(bytes)?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputShare();

impl Decode for OutputShare {
    fn decode(_: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self())
    }
}

impl Encode for OutputShare {
    fn encode(&self, _: &mut Vec<u8>) {}

    fn encoded_len(&self) -> Option<usize> {
        Some(0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrepareState(pub u8);

impl Encode for PrepareState {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for PrepareState {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u8::decode(bytes)?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl Decode for AggregateShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u64::decode(bytes)?;
        Ok(Self(val))
    }
}

impl Encode for AggregateShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}
