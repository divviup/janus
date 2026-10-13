//! Extensions and utilities for items from `janus_messages`.

use aws_lc_rs::digest::{SHA256, digest};
use janus_messages::{CollectionJobId, CollectionJobReq, batch_mode::BatchMode};
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
