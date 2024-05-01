use super::{BatchId, Interval};
use crate::{Collection, FixedSizeQuery, Query};
use anyhow::anyhow;
use num_enum::TryFromPrimitive;
use prio::codec::{CodecError, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    hash::Hash,
    io::Cursor,
};

/// QueryType represents a DAP query type. This is a task-level configuration setting which
/// determines how individual client reports are grouped together into batches for collection.
pub trait QueryType: Clone + Debug + PartialEq + Eq + Send + Sync + 'static {
    /// The [`Code`] associated with this query type.
    const CODE: Code;

    /// The type of a batch identifier.
    type BatchIdentifier: Display
        + Debug
        + Clone
        + Hash
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Encode
        + Decode
        + Send
        + Sync;

    /// The type of a batch identifier as it appears in a `PartialBatchSelector`. Will be either
    /// the same type as `BatchIdentifier`, or `()`.
    type PartialBatchIdentifier: Debug
        + Clone
        + Hash
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Encode
        + Decode
        + Send
        + Sync;

    /// The type of the body of a [`Query`] for this query type.
    type QueryBody: Debug + Clone + PartialEq + Eq + Encode + Decode + Send + Sync;

    /// Computes the `PartialBatchIdentifier` corresponding to the given
    /// `BatchIdentifier`.
    fn partial_batch_identifier(
        batch_identifier: &Self::BatchIdentifier,
    ) -> &Self::PartialBatchIdentifier;

    /// Retrieves the batch identifier associated with an ongoing collection.
    fn batch_identifier_for_collection(
        query: &Query<Self>,
        collect_resp: &Collection<Self>,
    ) -> Self::BatchIdentifier;
}

/// Represents a `time-interval` DAP query type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TimeInterval;

impl QueryType for TimeInterval {
    const CODE: Code = Code::TimeInterval;

    type BatchIdentifier = Interval;
    type PartialBatchIdentifier = ();
    type QueryBody = Interval;

    fn partial_batch_identifier(_: &Self::BatchIdentifier) -> &Self::PartialBatchIdentifier {
        &()
    }

    fn batch_identifier_for_collection(
        query: &Query<Self>,
        _: &Collection<Self>,
    ) -> Self::BatchIdentifier {
        *query.batch_interval()
    }
}

/// Represents a `fixed-size` DAP query type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FixedSize;

impl QueryType for FixedSize {
    const CODE: Code = Code::FixedSize;

    type BatchIdentifier = BatchId;
    type PartialBatchIdentifier = BatchId;
    type QueryBody = FixedSizeQuery;

    fn partial_batch_identifier(
        batch_identifier: &Self::BatchIdentifier,
    ) -> &Self::PartialBatchIdentifier {
        batch_identifier
    }

    fn batch_identifier_for_collection(
        _: &Query<Self>,
        collect_resp: &Collection<Self>,
    ) -> Self::BatchIdentifier {
        *collect_resp.partial_batch_selector().batch_identifier()
    }
}

/// DAP protocol message representing the type of a query.
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive, Serialize, Deserialize)]
#[repr(u8)]
#[non_exhaustive]
pub enum Code {
    Reserved = 0,
    TimeInterval = 1,
    FixedSize = 2,
}

impl Code {
    pub fn decode_expecting_value(
        bytes: &mut Cursor<&[u8]>,
        expected_code: Code,
    ) -> Result<(), CodecError> {
        let code = Self::decode(bytes)?;
        if code != expected_code {
            return Err(CodecError::Other(
                format!("unexpected query_type: {code:?} (expected {expected_code:?})").into(),
            ));
        }
        Ok(())
    }
}

impl Encode for Code {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(1)
    }
}

impl Decode for Code {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected QueryType value {}", val).into()))
    }
}
