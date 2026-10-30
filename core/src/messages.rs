//! Extensions and utilities for items from `janus_messages`.

use aws_lc_rs::digest::{Context, SHA256, digest};
use janus_messages::{
    AggregateShareId, AggregateShareReq, CollectionJobId, CollectionJobReq, batch_mode::BatchMode,
};
use prio::codec::Encode;

/// Errors from deriving IDs.
#[derive(Debug, thiserror::Error)]
pub enum DeriveIdError {
    /// Error handling a message.
    #[error("{0}")]
    Messages(#[from] janus_messages::Error),
    /// Error encoding or decoding a message.
    #[error("{0}")]
    Codec(#[from] prio::codec::CodecError),
}

/// Derive a unique identifier for the receiver.
pub trait DeriveId {
    type Identifier;

    fn derive_id(&self) -> Result<Self::Identifier, DeriveIdError>;
}

impl<B: BatchMode> DeriveId for AggregateShareReq<B> {
    type Identifier = AggregateShareId;

    fn derive_id(&self) -> Result<Self::Identifier, DeriveIdError> {
        // We don't incorporate the request's report count or checksum into the derived ID because
        // those don't identify the aggregate share.
        //
        // In particular, if an aggregate share request for a given batch selector and collection
        // job req fail because the leader's count or checksum values don't match what the helper
        // computes, we want it to be possible for a later request with corrected count and checksum
        // values to succeed.
        //
        // If the report count and checksum contributed to the aggregate share ID, then we would
        // treat the second request as being a batchOverlap with the first.
        let mut ctx = Context::new(&SHA256);
        ctx.update(&self.collection_job_req().get_encoded()?);
        ctx.update(&self.batch_selector().get_encoded()?);
        let digest = ctx.finish();

        Ok(AggregateShareId::try_from(
            &digest.as_ref()[..AggregateShareId::LEN],
        )?)
    }
}

impl<B: BatchMode> DeriveId for CollectionJobReq<B> {
    type Identifier = CollectionJobId;

    fn derive_id(&self) -> Result<Self::Identifier, DeriveIdError> {
        derive_id(self, CollectionJobId::LEN)
    }
}

fn derive_id<Request, Identifier>(
    req: &Request,
    identifier_len: usize,
) -> Result<Identifier, DeriveIdError>
where
    Request: Encode,
    Identifier: for<'a> TryFrom<&'a [u8], Error = janus_messages::Error>,
{
    let request_digest = digest(&SHA256, &req.get_encoded()?);
    Ok(Identifier::try_from(
        &request_digest.as_ref()[..identifier_len],
    )?)
}
