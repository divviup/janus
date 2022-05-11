//! PPM protocol message definitions with serialization/deserialization support.

use anyhow::anyhow;
use janus::{
    hpke::associated_data_for_report_share,
    message::{Duration, Error, Extension, HpkeCiphertext, Nonce, TaskId, Time},
};
use num_enum::TryFromPrimitive;
use postgres_types::{FromSql, ToSql};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use rand::{thread_rng, Rng};
use ring::{
    digest::SHA256_OUTPUT_LEN,
    error::Unspecified,
    hmac::{self, HMAC_SHA256},
};
use std::{
    fmt::{Debug, Display, Formatter},
    io::{self, Cursor, ErrorKind, Read},
    marker::PhantomData,
};

/// AuthenticatedEncoder can encode messages into the format used by authenticated PPM messages. The
/// encoding format is the encoding format of the underlying message, followed by a 32-byte
/// authentication tag.
pub struct AuthenticatedEncoder<M: Encode> {
    msg: M,
}

impl<M: Encode> AuthenticatedEncoder<M> {
    /// new creates a new AuthenticatedEncoder which will encode the given message.
    pub fn new(msg: M) -> AuthenticatedEncoder<M> {
        Self { msg }
    }

    /// encode encodes the message using the given key.
    pub fn encode(&self, key: &hmac::Key) -> Vec<u8> {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let mut buf = Vec::new();
        self.msg.encode(&mut buf);
        let tag = hmac::sign(key, &buf);
        buf.extend_from_slice(tag.as_ref());
        buf
    }
}

/// AuthenticatedRequestDecoder can decode messages in the "authenticated request" format used by
/// authenticated PPM request messages. This format places the task ID as the first 32 bytes, the
/// authentication tag as the last 32 bytes, and all interior bytes as opaque message data. The
/// included message is decoded from a concatenation of the task ID & the opaque interior message
/// bytes. (This means that the task ID is aliased as both a field interpreted by the envelope, as
/// well as part of the opaque message bytes to be decoded; this allows us to save having to
/// specify the task ID twice.)
pub struct AuthenticatedRequestDecoder<B: AsRef<[u8]>, M: Decode> {
    buf: B,
    _msg_type: PhantomData<M>,
}

impl<B: AsRef<[u8]>, M: Decode> AuthenticatedRequestDecoder<B, M> {
    /// MIN_BUFFER_SIZE defines the minimum size of a decodable buffer for a request.
    pub const MIN_BUFFER_SIZE: usize = TaskId::ENCODED_LEN + SHA256_OUTPUT_LEN;

    /// new creates a new AuthenticatedRequestDecoder which will attempt to decode the given bytes.
    /// If the given buffer is not at least MIN_BUFFER_SIZE bytes large, an error will be returned.
    pub fn new(buf: B) -> Result<Self, CodecError> {
        if buf.as_ref().len() < Self::MIN_BUFFER_SIZE {
            return Err(CodecError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "buffer too small",
            )));
        }

        Ok(Self {
            buf,
            _msg_type: PhantomData,
        })
    }

    /// task_id retrieves the unauthenticated task ID associated with this message. This task ID
    /// should be used only to determine the appropriate key to use to authenticate & decode the
    /// message.
    pub fn task_id(&self) -> TaskId {
        // Retrieve task_id from the buffer bytes.
        let mut buf = [0u8; TaskId::ENCODED_LEN];
        buf.copy_from_slice(&self.buf.as_ref()[..TaskId::ENCODED_LEN]);
        TaskId::new(buf)
    }

    /// decode authenticates & decodes the message using the given key.
    pub fn decode(&self, key: &hmac::Key) -> Result<M, AuthenticatedDecodeError> {
        authenticated_decode(key, self.buf.as_ref())
    }
}

/// Errors that may occur when decoding an authenticated PPM structure. This may indicate that
/// either the authentication tag was invalid or that there was a parsing error reading the
/// envelope or the message contained within.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedDecodeError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("invalid HMAC tag")]
    InvalidHmac,
}

/// AuthenticatedResponseDecoder can decode messages in the "authenticated response" format used by
/// authenticated PPM response messages. This format places the authentication tag as the last 32
/// bytes, and all prior bytes as opaque message data.
pub struct AuthenticatedResponseDecoder<B: AsRef<[u8]>, M: Decode> {
    buf: B,
    _msg_type: PhantomData<M>,
}

impl<B: AsRef<[u8]>, M: Decode> AuthenticatedResponseDecoder<B, M> {
    // MIN_BUFFER_SIZE defines the minimum size of a decodable buffer for a response.
    pub const MIN_BUFFER_SIZE: usize = SHA256_OUTPUT_LEN;

    /// new creates a new AuthenticatedResponseDecoder which will attempt to decode the given bytes.
    /// If the given buffer is not at least MIN_BUFFER_SIZE bytes large, an error will be returned.
    pub fn new(buf: B) -> Result<Self, CodecError> {
        if buf.as_ref().len() < Self::MIN_BUFFER_SIZE {
            return Err(CodecError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "buffer too small",
            )));
        }

        Ok(Self {
            buf,
            _msg_type: PhantomData,
        })
    }

    /// decode authenticates & decodes the message using the given key.
    pub fn decode(&self, key: &hmac::Key) -> Result<M, AuthenticatedDecodeError> {
        authenticated_decode(key, self.buf.as_ref())
    }
}

fn authenticated_decode<M: Decode>(
    key: &hmac::Key,
    buf: &[u8],
) -> Result<M, AuthenticatedDecodeError> {
    let (msg_bytes, tag) = buf.split_at(buf.len() - SHA256_OUTPUT_LEN);
    hmac::verify(key, msg_bytes, tag)
        .map_err(|_: Unspecified| AuthenticatedDecodeError::InvalidHmac)?;
    M::get_decoded(msg_bytes).map_err(AuthenticatedDecodeError::from)
}

/// PPM protocol message representing a half-open interval of time with a resolution of seconds;
/// the start of the interval is included while the end of the interval is excluded.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Interval {
    /// The start of the interval.
    start: Time,
    /// The length of the interval.
    duration: Duration,
}

impl Interval {
    /// Create a new [`Interval`] from the provided start and duration. Returns an error if the end
    /// of the interval cannot be represented as a [`Time`].
    pub fn new(start: Time, duration: Duration) -> Result<Self, Error> {
        start.add(duration)?;

        Ok(Self { start, duration })
    }

    /// Returns a [`Time`] representing the included start of this interval.
    pub fn start(&self) -> Time {
        self.start
    }

    /// Get the duration of this interval.
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns a [`Time`] representing the excluded end of this interval.
    pub fn end(&self) -> Time {
        // [`Self::new`] verified that this addition doesn't overflow.
        self.start.add(self.duration).unwrap()
    }
}

impl Encode for Interval {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.start.encode(bytes);
        self.duration.encode(bytes);
    }
}

impl Decode for Interval {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let start = Time::decode(bytes)?;
        let duration = Duration::decode(bytes)?;

        Self::new(start, duration).map_err(|e| CodecError::Other(Box::new(e)))
    }
}

impl Display for Interval {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "start: {} duration: {}", self.start, self.duration)
    }
}

/// PPM protocol message representing one aggregator's share of a single client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportShare {
    pub(crate) nonce: Nonce,
    pub(crate) extensions: Vec<Extension>,
    pub(crate) encrypted_input_share: HpkeCiphertext,
}

impl ReportShare {
    pub(crate) fn associated_data(&self) -> Vec<u8> {
        associated_data_for_report_share(self.nonce, &self.extensions)
    }
}

impl Encode for ReportShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.nonce.encode(bytes);
        encode_u16_items(bytes, &(), &self.extensions);
        self.encrypted_input_share.encode(bytes);
    }
}

impl Decode for ReportShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let nonce = Nonce::decode(bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;
        let encrypted_input_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            nonce,
            extensions,
            encrypted_input_share,
        })
    }
}

/// PPM protocol message representing a transition in the state machine of a VDAF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub(crate) nonce: Nonce,
    pub(crate) trans_data: TransitionTypeSpecificData,
}

impl Encode for Transition {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.nonce.encode(bytes);
        self.trans_data.encode(bytes);
    }
}

impl Decode for Transition {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let nonce = Nonce::decode(bytes)?;
        let trans_data = TransitionTypeSpecificData::decode(bytes)?;

        Ok(Self { nonce, trans_data })
    }
}

/// PPM protocol message representing transition-type-specific data, included in a Transition
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionTypeSpecificData {
    Continued { payload: Vec<u8> },
    Finished,
    Failed { error: TransitionError },
}

impl Encode for TransitionTypeSpecificData {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Continued { payload } => {
                0u8.encode(bytes);
                encode_u16_items(bytes, &(), payload);
            }
            Self::Finished => 1u8.encode(bytes),
            Self::Failed { error } => {
                2u8.encode(bytes);
                error.encode(bytes);
            }
        }
    }
}

impl Decode for TransitionTypeSpecificData {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        let trans_data = match val {
            0 => Self::Continued {
                payload: decode_u16_items(&(), bytes)?,
            },
            1 => Self::Finished,
            2 => Self::Failed {
                error: TransitionError::decode(bytes)?,
            },
            _ => {
                return Err(CodecError::Other(
                    anyhow!("unexpected TransitionType value {}", val).into(),
                ))
            }
        };

        Ok(trans_data)
    }
}

/// PPM protocol message representing an error while transitioning a VDAF's state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, ToSql, FromSql)]
#[repr(u8)]
pub enum TransitionError {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
    UnrecognizedNonce = 6,
}

impl Encode for TransitionError {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u8).encode(bytes);
    }
}

impl Decode for TransitionError {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(anyhow!("unexpected TransitionError value {}", val).into())
        })
    }
}

/// PPM protocol message representing an identifier for an aggregation job.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregationJobId([u8; Self::ENCODED_LEN]);

impl AggregationJobId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for AggregationJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Encode for AggregationJobId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for AggregationJobId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut decoded = [0u8; 32];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl AggregationJobId {
    /// ENCODED_LEN is the length of an aggregation job ID in bytes when encoded.
    const ENCODED_LEN: usize = 32;

    /// Generate a random [`AggregationJobId`]
    pub fn random() -> Self {
        let mut buf = [0u8; Self::ENCODED_LEN];
        thread_rng().fill(&mut buf);
        Self(buf)
    }
}

/// PPM protocol message representing an aggregation request from the leader to a helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateReq {
    pub(crate) task_id: TaskId,
    pub(crate) job_id: AggregationJobId,
    pub(crate) body: AggregateReqBody,
}

impl Encode for AggregateReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);

        match &self.body {
            AggregateReqBody::AggregateInitReq { agg_param, seq } => {
                0u8.encode(bytes);
                encode_u16_items(bytes, &(), agg_param);
                encode_u16_items(bytes, &(), seq);
            }
            AggregateReqBody::AggregateContinueReq { seq } => {
                1u8.encode(bytes);
                encode_u16_items(bytes, &(), seq);
            }
        }
    }
}

impl Decode for AggregateReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;

        let msg_type = u8::decode(bytes)?;
        let body = match msg_type {
            0 => {
                let agg_param = decode_u16_items(&(), bytes)?;
                let seq = decode_u16_items(&(), bytes)?;
                AggregateReqBody::AggregateInitReq { agg_param, seq }
            }
            1 => {
                let seq = decode_u16_items(&(), bytes)?;
                AggregateReqBody::AggregateContinueReq { seq }
            }
            _ => {
                return Err(CodecError::Other(
                    anyhow!("unexpected AggregateReqType message type {}", msg_type).into(),
                ))
            }
        };

        Ok(AggregateReq {
            task_id,
            job_id,
            body,
        })
    }
}

/// PPM protocol (sub-)message indicating the "body" of an AggregateReq message, i.e. an
/// AggregateInitReq or AggregateContinueReq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AggregateReqBody {
    AggregateInitReq {
        agg_param: Vec<u8>,
        seq: Vec<ReportShare>,
    },
    AggregateContinueReq {
        seq: Vec<Transition>,
    },
}

/// PPM protocol message representing a helper's response to a request from the leader to initiate
/// or continue aggregation of a sequence of client reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateResp {
    pub(crate) seq: Vec<Transition>,
}

impl Encode for AggregateResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.seq);
    }
}

impl Decode for AggregateResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let seq = decode_u16_items(&(), bytes)?;
        Ok(Self { seq })
    }
}

/// PPM protocol message representing a request from the leader to a helper to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareReq {
    pub(crate) task_id: TaskId,
    pub(crate) batch_interval: Interval,
    pub(crate) aggregation_param: Vec<u8>,
    pub(crate) report_count: u64,
    pub(crate) checksum: [u8; 32],
}

impl Encode for AggregateShareReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
        encode_u16_items(bytes, &(), &self.aggregation_param);
        self.report_count.encode(bytes);
        bytes.extend_from_slice(&self.checksum);
    }
}

impl Decode for AggregateShareReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_interval = Interval::decode(bytes)?;
        let agg_param = decode_u16_items(&(), bytes)?;
        let report_count = u64::decode(bytes)?;
        let mut checksum = [0u8; 32];
        bytes.read_exact(&mut checksum)?;

        Ok(Self {
            task_id,
            batch_interval,
            aggregation_param: agg_param,
            report_count,
            checksum,
        })
    }
}

/// PPM protocol message representing a helper's response to the leader's request to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareResp {
    pub(crate) encrypted_aggregate_share: HpkeCiphertext,
}

impl Encode for AggregateShareResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.encrypted_aggregate_share.encode(bytes);
    }
}

impl Decode for AggregateShareResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let encrypted_aggregate_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            encrypted_aggregate_share,
        })
    }
}

/// PPM protocol message representing a request from the collector to the leader to provide
/// aggregate shares for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectReq {
    pub(crate) task_id: TaskId,
    pub(crate) batch_interval: Interval,
    pub(crate) agg_param: Vec<u8>,
}

impl Encode for CollectReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
        encode_u16_items(bytes, &(), &self.agg_param);
    }
}

impl Decode for CollectReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_interval = Interval::decode(bytes)?;
        let agg_param = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            batch_interval,
            agg_param,
        })
    }
}

/// PPM protocol message representing a leader's response to the collector's request to provide
/// aggregate shares for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectResp {
    pub(crate) encrypted_agg_shares: Vec<HpkeCiphertext>,
}

impl Encode for CollectResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.encrypted_agg_shares);
    }
}

impl Decode for CollectResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let encrypted_agg_shares = decode_u16_items(&(), bytes)?;

        Ok(Self {
            encrypted_agg_shares,
        })
    }
}

#[doc(hidden)]
pub mod test_util {
    use super::{Nonce, TaskId};
    use janus::message::{Report, Time};
    use rand::{thread_rng, Rng};

    pub fn new_dummy_report(task_id: TaskId, when: Time) -> Report {
        Report::new(
            task_id,
            Nonce::new(when, thread_rng().gen()),
            Vec::new(),
            Vec::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use janus::message::{Duration, ExtensionType, HpkeConfigId, Time};
    use lazy_static::lazy_static;

    lazy_static! {
        static ref HMAC_KEY: hmac::Key = hmac::Key::new(
            HMAC_SHA256,
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        );
    }

    fn roundtrip_encoding<T>(vals_and_encodings: &[(T, &str)])
    where
        T: Encode + Decode + core::fmt::Debug + Eq,
    {
        for (val, hex_encoding) in vals_and_encodings {
            let mut encoded_val = Vec::new();
            val.encode(&mut encoded_val);
            let encoding = hex::decode(hex_encoding).unwrap();
            assert_eq!(encoding, encoded_val);
            let decoded_val = T::decode(&mut Cursor::new(&encoded_val)).unwrap();
            assert_eq!(val, &decoded_val);
        }
    }

    #[test]
    fn roundtrip_authenticated_request_encoding() {
        let msg = AggregateReq {
            task_id: TaskId::new([
                31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ]),
            job_id: AggregationJobId([u8::MIN; 32]),
            body: AggregateReqBody::AggregateInitReq {
                agg_param: Vec::from("012345"),
                seq: vec![
                    ReportShare {
                        nonce: Nonce::new(Time::from_seconds_since_epoch(54321), [0u8; 8]),
                        extensions: vec![Extension::new(ExtensionType::Tbd, Vec::from("0123"))],
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    ReportShare {
                        nonce: Nonce::new(Time::from_seconds_since_epoch(73542), [1u8; 8]),
                        extensions: vec![Extension::new(ExtensionType::Tbd, Vec::from("3210"))],
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                ],
            },
        };

        let want_encoded_msg = msg.get_encoded();
        let want_tag = hmac::sign(&*HMAC_KEY, &want_encoded_msg);

        let encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);
        let (got_encoded_msg, got_tag) =
            encoded_bytes.split_at(encoded_bytes.len() - SHA256_OUTPUT_LEN);
        assert_eq!(want_encoded_msg, got_encoded_msg);
        assert_eq!(want_tag.as_ref(), got_tag);

        let decoder = AuthenticatedRequestDecoder::new(encoded_bytes).unwrap();
        assert_eq!(msg.task_id, decoder.task_id());
        let got_msg = decoder.decode(&*HMAC_KEY).unwrap();
        assert_eq!(msg, got_msg);
    }

    #[test]
    fn authenticated_request_bad_tag() {
        let msg = AggregateReq {
            task_id: TaskId::new([u8::MIN; 32]),
            job_id: AggregationJobId([u8::MAX; 32]),
            body: AggregateReqBody::AggregateContinueReq { seq: Vec::new() },
        };

        let mut encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);

        // Verify we can decode the unmodified bytes back to the original message.
        let got_msg = AuthenticatedRequestDecoder::new(encoded_bytes.clone())
            .unwrap()
            .decode(&*HMAC_KEY)
            .unwrap();
        assert_eq!(msg, got_msg);

        // Verify that modifying the bytes causes decoding to fail.
        let ln = encoded_bytes.len();
        encoded_bytes[ln - 1] ^= 0xFF;
        let rslt: Result<AggregateReq, AuthenticatedDecodeError> =
            AuthenticatedRequestDecoder::new(encoded_bytes.clone())
                .unwrap()
                .decode(&*HMAC_KEY);
        assert_matches!(rslt, Err(AuthenticatedDecodeError::InvalidHmac));
    }

    #[test]
    fn roundtrip_authenticated_response_encoding() {
        let msg = AggregateResp {
            seq: vec![
                Transition {
                    nonce: Nonce::new(Time::from_seconds_since_epoch(54372), [0u8; 8]),
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::from("012345"),
                    },
                },
                Transition {
                    nonce: Nonce::new(Time::from_seconds_since_epoch(12345), [1u8; 8]),
                    trans_data: TransitionTypeSpecificData::Finished,
                },
            ],
        };

        let want_encoded_msg = msg.get_encoded();
        let want_tag = hmac::sign(&*HMAC_KEY, &want_encoded_msg);

        let encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);
        let (got_encoded_msg, got_tag) =
            encoded_bytes.split_at(encoded_bytes.len() - SHA256_OUTPUT_LEN);
        assert_eq!(want_encoded_msg, got_encoded_msg);
        assert_eq!(want_tag.as_ref(), got_tag);

        let decoder = AuthenticatedResponseDecoder::new(encoded_bytes).unwrap();
        let got_msg = decoder.decode(&*HMAC_KEY).unwrap();
        assert_eq!(msg, got_msg);
    }

    #[test]
    fn authenticated_response_bad_tag() {
        let msg = AggregateResp { seq: Vec::new() };

        let mut encoded_bytes = AuthenticatedEncoder::new(msg.clone()).encode(&*HMAC_KEY);

        // Verify we can decode the unmodified bytes back to the original message.
        let got_msg = AuthenticatedResponseDecoder::new(encoded_bytes.clone())
            .unwrap()
            .decode(&*HMAC_KEY)
            .unwrap();
        assert_eq!(msg, got_msg);

        // Verify that modifying the bytes causes decoding to fail.
        let ln = encoded_bytes.len();
        encoded_bytes[ln - 1] ^= 0xFF;
        let rslt: Result<AggregateReq, AuthenticatedDecodeError> =
            AuthenticatedResponseDecoder::new(encoded_bytes.clone())
                .unwrap()
                .decode(&*HMAC_KEY);
        assert_matches!(rslt, Err(AuthenticatedDecodeError::InvalidHmac));
    }

    #[test]
    fn roundtrip_interval() {
        Interval::new(
            Time::from_seconds_since_epoch(1),
            Duration::from_seconds(u64::MAX),
        )
        .unwrap_err();

        let encoded = Interval {
            start: Time::from_seconds_since_epoch(1),
            duration: Duration::from_seconds(u64::MAX),
        }
        .get_encoded();
        assert_eq!(
            encoded,
            hex::decode(concat!(
                "0000000000000001", // start
                "FFFFFFFFFFFFFFFF", // duration))
            ))
            .unwrap()
        );

        assert_matches!(Interval::get_decoded(&encoded), Err(CodecError::Other(_)));

        roundtrip_encoding(&[
            (
                Interval {
                    start: Time::from_seconds_since_epoch(u64::MIN),
                    duration: Duration::from_seconds(u64::MAX),
                },
                concat!(
                    "0000000000000000", // start
                    "FFFFFFFFFFFFFFFF", // duration
                ),
            ),
            (
                Interval {
                    start: Time::from_seconds_since_epoch(54321),
                    duration: Duration::from_seconds(12345),
                },
                concat!(
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
            (
                Interval {
                    start: Time::from_seconds_since_epoch(u64::MAX),
                    duration: Duration::from_seconds(u64::MIN),
                },
                concat!(
                    "FFFFFFFFFFFFFFFF", // start
                    "0000000000000000", // duration
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_transition() {
        roundtrip_encoding(&[
            (
                Transition {
                    nonce: Nonce::new(
                        Time::from_seconds_since_epoch(54372),
                        [1, 2, 3, 4, 5, 6, 7, 8],
                    ),
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::from("012345"),
                    },
                },
                concat!(
                    concat!(
                        // nonce
                        "000000000000D464", // time
                        "0102030405060708", // rand
                    ),
                    "00", // trans_type
                    concat!(
                        // payload
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
            (
                Transition {
                    nonce: Nonce::new(
                        Time::from_seconds_since_epoch(12345),
                        [8, 7, 6, 5, 4, 3, 2, 1],
                    ),
                    trans_data: TransitionTypeSpecificData::Finished,
                },
                concat!(
                    concat!(
                        // nonce
                        "0000000000003039", // time
                        "0807060504030201", // rand
                    ),
                    "01", // trans_type
                ),
            ),
            (
                Transition {
                    nonce: Nonce::new(Time::from_seconds_since_epoch(345078), [255; 8]),
                    trans_data: TransitionTypeSpecificData::Failed {
                        error: TransitionError::UnrecognizedNonce,
                    },
                },
                concat!(
                    concat!(
                        // nonce
                        "00000000000543F6", // time
                        "FFFFFFFFFFFFFFFF", // rand
                    ),
                    "02", // trans_type
                    "06", // trans_error
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_transition_error() {
        roundtrip_encoding(&[
            (TransitionError::BatchCollected, "00"),
            (TransitionError::HpkeDecryptError, "04"),
            (TransitionError::HpkeUnknownConfigId, "03"),
            (TransitionError::ReportDropped, "02"),
            (TransitionError::ReportReplayed, "01"),
            (TransitionError::UnrecognizedNonce, "06"),
            (TransitionError::VdafPrepError, "05"),
        ])
    }

    #[test]
    fn roundtrip_aggregation_job_id() {
        roundtrip_encoding(&[
            (
                AggregationJobId([u8::MIN; 32]),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                AggregationJobId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                AggregationJobId([u8::MAX; 32]),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_req() {
        roundtrip_encoding(&[
            (
                AggregateReq {
                    task_id: TaskId::new([u8::MAX; 32]),
                    job_id: AggregationJobId([u8::MIN; 32]),
                    body: AggregateReqBody::AggregateInitReq {
                        agg_param: Vec::from("012345"),
                        seq: vec![
                            ReportShare {
                                nonce: Nonce::new(
                                    Time::from_seconds_since_epoch(54321),
                                    [1, 2, 3, 4, 5, 6, 7, 8],
                                ),
                                extensions: vec![Extension::new(
                                    ExtensionType::Tbd,
                                    Vec::from("0123"),
                                )],
                                encrypted_input_share: HpkeCiphertext::new(
                                    HpkeConfigId::from(42),
                                    Vec::from("012345"),
                                    Vec::from("543210"),
                                ),
                            },
                            ReportShare {
                                nonce: Nonce::new(
                                    Time::from_seconds_since_epoch(73542),
                                    [8, 7, 6, 5, 4, 3, 2, 1],
                                ),
                                extensions: vec![Extension::new(
                                    ExtensionType::Tbd,
                                    Vec::from("3210"),
                                )],
                                encrypted_input_share: HpkeCiphertext::new(
                                    HpkeConfigId::from(13),
                                    Vec::from("abce"),
                                    Vec::from("abfd"),
                                ),
                            },
                        ],
                    },
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                    "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                    "00",                                                               // msg_type
                    concat!(
                        // agg_init_req
                        concat!(
                            // agg_param
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                        concat!(
                            // seq
                            "0052", // length
                            concat!(
                                concat!(
                                    // nonce
                                    "000000000000D431", // time
                                    "0102030405060708", // rand
                                ),
                                concat!(
                                    // extensions
                                    "0008", // length
                                    concat!(
                                        "0000", // extension_type
                                        concat!(
                                            // extension_data
                                            "0004",     // length
                                            "30313233", // opaque data
                                        ),
                                    ),
                                ),
                                concat!(
                                    // encrypted_input_share
                                    "2A", // config_id
                                    concat!(
                                        // encapsulated_context
                                        "0006",         // length
                                        "303132333435", // opaque data
                                    ),
                                    concat!(
                                        // payload
                                        "0006",         // length
                                        "353433323130", // opaque data
                                    ),
                                ),
                            ),
                            concat!(
                                concat!(
                                    // nonce
                                    "0000000000011F46", // time
                                    "0807060504030201", // rand
                                ),
                                concat!(
                                    // extensions
                                    "0008", // length
                                    concat!(
                                        "0000", // extension_type
                                        concat!(
                                            // extension_data
                                            "0004",     // length
                                            "33323130", // opaque data
                                        ),
                                    ),
                                ),
                                concat!(
                                    "0D", // config_id
                                    concat!(
                                        // encapsulated_context
                                        "0004",     // length
                                        "61626365", // opaque data
                                    ),
                                    concat!(
                                        // payload
                                        "0004",     // length
                                        "61626664", // opaque data
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            (
                AggregateReq {
                    task_id: TaskId::new([u8::MIN; 32]),
                    job_id: AggregationJobId([u8::MAX; 32]),
                    body: AggregateReqBody::AggregateContinueReq {
                        seq: vec![
                            Transition {
                                nonce: Nonce::new(
                                    Time::from_seconds_since_epoch(54372),
                                    [1, 2, 3, 4, 5, 6, 7, 8],
                                ),
                                trans_data: TransitionTypeSpecificData::Continued {
                                    payload: Vec::from("012345"),
                                },
                            },
                            Transition {
                                nonce: Nonce::new(
                                    Time::from_seconds_since_epoch(12345),
                                    [8, 7, 6, 5, 4, 3, 2, 1],
                                ),
                                trans_data: TransitionTypeSpecificData::Finished,
                            },
                        ],
                    },
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                    "01",                                                               // msg_type
                    concat!(
                        // agg_continue_req
                        concat!(
                            // seq
                            "002A", // length
                            concat!(
                                concat!(
                                    // nonce
                                    "000000000000D464", // time
                                    "0102030405060708", // rand
                                ),
                                "00", // trans_type
                                concat!(
                                    // payload
                                    "0006",         // length
                                    "303132333435", // opaque data
                                ),
                            ),
                            concat!(
                                concat!(
                                    // nonce
                                    "0000000000003039", // time
                                    "0807060504030201", // rand
                                ),
                                "01", // trans_type
                            )
                        ),
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_resp() {
        roundtrip_encoding(&[
            (
                AggregateResp { seq: vec![] },
                concat!(concat!(
                    // seq
                    "0000", // length
                ),),
            ),
            (
                AggregateResp {
                    seq: vec![
                        Transition {
                            nonce: Nonce::new(
                                Time::from_seconds_since_epoch(54372),
                                [1, 2, 3, 4, 5, 6, 7, 8],
                            ),
                            trans_data: TransitionTypeSpecificData::Continued {
                                payload: Vec::from("012345"),
                            },
                        },
                        Transition {
                            nonce: Nonce::new(
                                Time::from_seconds_since_epoch(12345),
                                [8, 7, 6, 5, 4, 3, 2, 1],
                            ),
                            trans_data: TransitionTypeSpecificData::Finished,
                        },
                    ],
                },
                concat!(concat!(
                    //seq
                    "002A", // length
                    concat!(
                        concat!(
                            // nonce
                            "000000000000D464", // time
                            "0102030405060708", // rand
                        ),
                        "00", // trans_type
                        concat!(
                            // payload
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        concat!(
                            // nonce
                            "0000000000003039", // time
                            "0807060504030201", // rand
                        ),
                        "01", // trans_type
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_share_req() {
        roundtrip_encoding(&[
            (
                AggregateShareReq {
                    task_id: TaskId::new([u8::MIN; 32]),
                    batch_interval: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                    aggregation_param: vec![],
                    report_count: 439,
                    checksum: [u8::MIN; 32],
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    concat!(
                        // agg_param
                        "0000", // length
                        "",     // opaque data
                    ),
                    "00000000000001B7", // report_count
                    "0000000000000000000000000000000000000000000000000000000000000000", // checksum
                ),
            ),
            (
                AggregateShareReq {
                    task_id: TaskId::new([12u8; 32]),
                    batch_interval: Interval::new(
                        Time::from_seconds_since_epoch(50821),
                        Duration::from_seconds(84354),
                    )
                    .unwrap(),
                    aggregation_param: Vec::from("012345"),
                    report_count: 8725,
                    checksum: [u8::MAX; 32],
                },
                concat!(
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
                    concat!(
                        // batch_interval
                        "000000000000C685", // start
                        "0000000000014982", // duration
                    ),
                    concat!(
                        // agg_param
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                    "0000000000002215", // report_count
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_share_resp() {
        roundtrip_encoding(&[
            (
                AggregateShareResp {
                    encrypted_aggregate_share: HpkeCiphertext::new(
                        HpkeConfigId::from(10),
                        Vec::from("0123"),
                        Vec::from("4567"),
                    ),
                },
                concat!(concat!(
                    // encrypted_aggregate_share
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "0004",     // length
                        "34353637", // opaque data
                    ),
                )),
            ),
            (
                AggregateShareResp {
                    encrypted_aggregate_share: HpkeCiphertext::new(
                        HpkeConfigId::from(12),
                        Vec::from("01234"),
                        Vec::from("567"),
                    ),
                },
                concat!(concat!(
                    // encrypted_aggregate_share
                    "0C", // config_id
                    concat!(
                        // encapsulated_context
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        "0003",   // length
                        "353637", // opaque data
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_collect_req() {
        roundtrip_encoding(&[
            (
                CollectReq {
                    task_id: TaskId::new([u8::MIN; 32]),
                    batch_interval: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                    agg_param: Vec::new(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id,
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                    concat!(
                        // agg_param
                        "0000", // length
                        "",     // opaque data
                    ),
                ),
            ),
            (
                CollectReq {
                    task_id: TaskId::new([13u8; 32]),
                    batch_interval: Interval::new(
                        Time::from_seconds_since_epoch(48913),
                        Duration::from_seconds(44721),
                    )
                    .unwrap(),
                    agg_param: Vec::from("012345"),
                },
                concat!(
                    "0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D", // task_id
                    concat!(
                        // batch_interval
                        "000000000000BF11", // start
                        "000000000000AEB1", // duration
                    ),
                    concat!(
                        // agg_param
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_collect_resp() {
        roundtrip_encoding(&[
            (
                CollectResp {
                    encrypted_agg_shares: Vec::new(),
                },
                concat!(concat!(
                    // encrypted_agg_shares
                    "0000", // length
                )),
            ),
            (
                CollectResp {
                    encrypted_agg_shares: vec![
                        HpkeCiphertext::new(
                            HpkeConfigId::from(10),
                            Vec::from("0123"),
                            Vec::from("4567"),
                        ),
                        HpkeCiphertext::new(
                            HpkeConfigId::from(12),
                            Vec::from("01234"),
                            Vec::from("567"),
                        ),
                    ],
                },
                concat!(concat!(
                    // encrypted_agg_shares
                    "001A", // length
                    concat!(
                        "0A", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // payload
                            "0004",     // length
                            "34353637", // opaque data
                        ),
                    ),
                    concat!(
                        "0C", // config_id
                        concat!(
                            // encapsulated_context
                            "0005",       // length
                            "3031323334", // opaque data
                        ),
                        concat!(
                            // payload
                            "0003",   // length
                            "353637", // opaque data
                        ),
                    )
                )),
            ),
        ])
    }
}
