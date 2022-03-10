//! PPM protocol message definitions with serialization/deserialization support.

use anyhow::anyhow;
use num_enum::TryFromPrimitive;
use prio::codec::{
    decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode,
    ParameterizedEncode,
};
use ring::{
    digest::SHA256_OUTPUT_LEN,
    hmac::{self, HMAC_SHA256},
};
use std::io::{Cursor, Read};

// TODO(brandon): retrieve HPKE identifier values from HPKE library once one is decided upon

/// PPM protocol message representing a duration with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(pub u64);

impl Encode for Duration {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for Duration {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

/// PPM protocol message representing an instant in time with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(pub u64);

impl Encode for Time {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for Time {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

/// PPM protocol message representing a half-open interval of time with a resolution of seconds;
/// the start of the interval is included while the end of the interval is excluded.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Interval {
    /// The start of the interval.
    pub start: Time,
    /// The length of the interval.
    pub duration: Duration,
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

        Ok(Self { start, duration })
    }
}

/// PPM protocol message representing a nonce uniquely identifying a client report.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce {
    /// The time at which the report was generated.
    pub time: Time,
    /// A randomly generated value.
    pub rand: u64,
}

impl Encode for Nonce {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.time.encode(bytes);
        self.rand.encode(bytes);
    }
}

impl Decode for Nonce {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let time = Time::decode(bytes)?;
        let rand = u64::decode(bytes)?;

        Ok(Self { time, rand })
    }
}

/// PPM protocol message representing the different roles that participants can adopt.
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum Role {
    Collector = 0,
    Client = 1,
    Leader = 2,
    Helper = 3,
}

impl Encode for Role {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u8).encode(bytes);
    }
}

impl Decode for Role {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected Role value {}", val).into()))
    }
}

/// PPM protocol message representing an identifier for an HPKE config.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct HpkeConfigId(pub u8);

impl Encode for HpkeConfigId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for HpkeConfigId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u8::decode(bytes)?))
    }
}

/// PPM protocol message representing an HPKE ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HpkeCiphertext {
    /// An identifier of the HPKE configuration used to seal the message.
    pub config_id: HpkeConfigId,
    /// An encasulated HPKE context.
    pub encapsulated_context: Vec<u8>,
    /// An HPKE ciphertext.
    pub payload: Vec<u8>,
}

impl Encode for HpkeCiphertext {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.config_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.encapsulated_context);
        encode_u16_items(bytes, &(), &self.payload);
    }
}

impl Decode for HpkeCiphertext {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let config_id = HpkeConfigId::decode(bytes)?;
        let encapsulated_context = decode_u16_items(&(), bytes)?;
        let payload = decode_u16_items(&(), bytes)?;

        Ok(Self {
            config_id,
            encapsulated_context,
            payload,
        })
    }
}

/// PPM protocol message representing an identifier for a PPM task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskId(pub [u8; 32]);

impl Encode for TaskId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0)
    }
}

impl Decode for TaskId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let mut decoded = [0u8; 32];
        bytes.read_exact(&mut decoded)?;
        Ok(Self(decoded))
    }
}

impl TaskId {
    /// Get a reference to the task ID as a byte slice
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Generate a random [`TaskId`]
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();

        let mut task_id = [0u8; 32];
        rng.fill(&mut task_id);

        TaskId(task_id)
    }
}

/// PPM protocol message representing an HPKE key encapsulation mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum HpkeKemId {
    /// NIST P-256 keys and HKDF-SHA256.
    P256HkdfSha256 = 0x0010,
    /// X25519 keys and HKDF-SHA256.
    X25519HkdfSha256 = 0x0020,
}

impl Encode for HpkeKemId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for HpkeKemId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKemId value {}", val).into()))
    }
}

/// PPM protocol message representing an HPKE key derivation function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum HpkeKdfId {
    /// HMAC Key Derivation Function SHA256.
    HkdfSha256 = 0x0001,
    /// HMAC Key Derivation Function SHA384.
    HkdfSha384 = 0x0002,
    /// HMAC Key Derivation Function SHA512.
    HkdfSha512 = 0x0003,
}

impl Encode for HpkeKdfId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for HpkeKdfId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKdfId value {}", val).into()))
    }
}

/// PPM protocol message representing an HPKE AEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum HpkeAeadId {
    /// AES-128-GCM.
    Aes128Gcm = 0x0001,
    /// AES-256-GCM.
    Aes256Gcm = 0x0002,
    /// ChaCha20Poly1305.
    ChaCha20Poly1305 = 0x0003,
}

impl Encode for HpkeAeadId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for HpkeAeadId {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val)
            .map_err(|_| CodecError::Other(anyhow!("unexpected HpkeKemId value {}", val).into()))
    }
}

/// PPM protocol message representing an HPKE public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkePublicKey(pub Vec<u8>);

impl Encode for HpkePublicKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.0);
    }
}

impl Decode for HpkePublicKey {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let key = decode_u16_items(&(), bytes)?;
        Ok(Self(key))
    }
}

/// PPM protocol message representing an HPKE config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeConfig {
    pub id: HpkeConfigId,
    pub kem_id: HpkeKemId,
    pub kdf_id: HpkeKdfId,
    pub aead_id: HpkeAeadId,
    pub public_key: HpkePublicKey,
}

impl Encode for HpkeConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.id.encode(bytes);
        self.kem_id.encode(bytes);
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
        self.public_key.encode(bytes);
    }
}

impl Decode for HpkeConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let id = HpkeConfigId::decode(bytes)?;
        let kem_id = HpkeKemId::decode(bytes)?;
        let kdf_id = HpkeKdfId::decode(bytes)?;
        let aead_id = HpkeAeadId::decode(bytes)?;
        let public_key = HpkePublicKey::decode(bytes)?;

        Ok(Self {
            id,
            kem_id,
            kdf_id,
            aead_id,
            public_key,
        })
    }
}

/// PPM protocol message representing a client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub task_id: TaskId,
    pub nonce: Nonce,
    pub extensions: Vec<Extension>,
    pub encrypted_input_shares: Vec<HpkeCiphertext>,
}

impl Encode for Report {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.nonce.encode(bytes);
        encode_u16_items(bytes, &(), &self.extensions);
        encode_u16_items(bytes, &(), &self.encrypted_input_shares);
    }
}

impl Decode for Report {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let timestamp = Nonce::decode(bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;
        let encrypted_input_shares = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            nonce: timestamp,
            extensions,
            encrypted_input_shares,
        })
    }
}

/// PPM protocol message representing an arbitrary extension included in a client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: Vec<u8>,
}

impl Encode for Extension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.extension_type.encode(bytes);
        encode_u16_items(bytes, &(), &self.extension_data);
    }
}

impl Decode for Extension {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let extension_type = ExtensionType::decode(bytes)?;
        let extension_data = decode_u16_items(&(), bytes)?;

        Ok(Self {
            extension_type,
            extension_data,
        })
    }
}

/// PPM protocol message representing the type of an extension included in a client report.
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum ExtensionType {
    Tbd = 0,
}

impl Encode for ExtensionType {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes);
    }
}

impl Decode for ExtensionType {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(anyhow!("unexpected ExtensionType value {}", val).into())
        })
    }
}

/// PPM protocol message representing one aggregator's share of a single client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportShare {
    pub nonce: Nonce,
    pub extensions: Vec<Extension>,
    pub encrypted_input_share: HpkeCiphertext,
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
    pub nonce: Nonce,
    pub trans_data: TransitionTypeSpecificData,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregationJobId(pub [u8; 32]);

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

/// PPM protocol message representing an aggregation request from the leader to a helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AggregateReq {
    AggregateInitReq(AggregateInitReq),
    AggregateContinueReq(AggregateContinueReq),
}

impl ParameterizedEncode<hmac::Key> for AggregateReq {
    fn encode_with_param(&self, key: &hmac::Key, bytes: &mut Vec<u8>) {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.len();

        match self {
            Self::AggregateInitReq(req) => {
                0u8.encode(bytes);
                req.encode(bytes);
            }
            Self::AggregateContinueReq(req) => {
                1u8.encode(bytes);
                req.encode(bytes);
            }
        }

        let end_offset = bytes.len();
        let tag = hmac::sign(key, &bytes[start_offset..end_offset]);
        bytes.extend_from_slice(tag.as_ref());
    }
}

impl ParameterizedDecode<hmac::Key> for AggregateReq {
    fn decode_with_param(key: &hmac::Key, bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.position() as usize;

        let val = u8::decode(bytes)?;
        let req = match val {
            0 => Self::AggregateInitReq(AggregateInitReq::decode(bytes)?),
            1 => Self::AggregateContinueReq(AggregateContinueReq::decode(bytes)?),
            _ => {
                return Err(CodecError::Other(
                    anyhow!("unexpected AggregateReqType value {}", val).into(),
                ))
            }
        };

        let end_offset = bytes.position() as usize;
        let mut provided_tag = [0u8; SHA256_OUTPUT_LEN];
        bytes.read_exact(&mut provided_tag)?;
        hmac::verify(
            key,
            &bytes.get_ref()[start_offset..end_offset],
            &provided_tag,
        )
        .map_err(|_| CodecError::Other(anyhow!("HMAC tag verification failure").into()))?;

        Ok(req)
    }
}

/// PPM protocol message representing a request to initiate aggregation of a sequence of client
/// reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateInitReq {
    pub task_id: TaskId,
    pub job_id: AggregationJobId,
    pub agg_param: Vec<u8>,
    pub seq: Vec<ReportShare>,
}

impl Encode for AggregateInitReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.agg_param);
        encode_u16_items(bytes, &(), &self.seq);
    }
}

impl Decode for AggregateInitReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;
        let agg_param = decode_u16_items(&(), bytes)?;
        let seq = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            job_id,
            agg_param,
            seq,
        })
    }
}

/// PPM protocol message representing a request to continue aggregation of a sequence of client
/// reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueReq {
    pub task_id: TaskId,
    pub job_id: AggregationJobId,
    pub seq: Vec<Transition>,
}

impl Encode for AggregateContinueReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.seq);
    }
}

impl Decode for AggregateContinueReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;
        let seq = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            job_id,
            seq,
        })
    }
}

/// PPM protocol message representing a helper's response to a request from the leader to initiate
/// or continue aggregation of a sequence of client reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateResp {
    pub seq: Vec<Transition>,
}

impl ParameterizedEncode<hmac::Key> for AggregateResp {
    fn encode_with_param(&self, key: &hmac::Key, bytes: &mut Vec<u8>) {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.len();

        encode_u16_items(bytes, &(), &self.seq);

        let end_offset = bytes.len();
        let tag = hmac::sign(key, &bytes[start_offset..end_offset]);
        bytes.extend_from_slice(tag.as_ref());
    }
}

impl ParameterizedDecode<hmac::Key> for AggregateResp {
    fn decode_with_param(key: &hmac::Key, bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.position() as usize;

        let seq = decode_u16_items(&(), bytes)?;

        let end_offset = bytes.position() as usize;
        let mut provided_tag = [0u8; SHA256_OUTPUT_LEN];
        bytes.read_exact(&mut provided_tag)?;
        hmac::verify(
            key,
            &bytes.get_ref()[start_offset..end_offset],
            &provided_tag,
        )
        .map_err(|_| CodecError::Other(anyhow!("HMAC tag verification failure").into()))?;

        Ok(Self { seq })
    }
}

/// PPM protocol message representing a request from the leader to a helper to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareReq {
    pub task_id: TaskId,
    pub batch_interval: Interval,
    pub report_count: u64,
    pub checksum: [u8; 32],
}

impl ParameterizedEncode<hmac::Key> for AggregateShareReq {
    fn encode_with_param(&self, key: &hmac::Key, bytes: &mut Vec<u8>) {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.len();

        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
        self.report_count.encode(bytes);
        bytes.extend_from_slice(&self.checksum);

        let end_offset = bytes.len();
        let tag = hmac::sign(key, &bytes[start_offset..end_offset]);
        bytes.extend_from_slice(tag.as_ref());
    }
}

impl ParameterizedDecode<hmac::Key> for AggregateShareReq {
    fn decode_with_param(key: &hmac::Key, bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.position() as usize;

        let task_id = TaskId::decode(bytes)?;
        let batch_interval = Interval::decode(bytes)?;
        let report_count = u64::decode(bytes)?;
        let mut checksum = [0u8; 32];
        bytes.read_exact(&mut checksum)?;

        let end_offset = bytes.position() as usize;
        let mut provided_tag = [0u8; SHA256_OUTPUT_LEN];
        bytes.read_exact(&mut provided_tag)?;
        hmac::verify(
            key,
            &bytes.get_ref()[start_offset..end_offset],
            &provided_tag,
        )
        .map_err(|_| CodecError::Other(anyhow!("HMAC tag verification failure").into()))?;

        Ok(Self {
            task_id,
            batch_interval,
            report_count,
            checksum,
        })
    }
}

/// PPM protocol message representing a helper's response to the leader's request to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareResp {
    pub encrypted_aggregate_share: HpkeCiphertext,
}

impl ParameterizedEncode<hmac::Key> for AggregateShareResp {
    fn encode_with_param(&self, key: &hmac::Key, bytes: &mut Vec<u8>) {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.len();

        self.encrypted_aggregate_share.encode(bytes);

        let end_offset = bytes.len();
        let tag = hmac::sign(key, &bytes[start_offset..end_offset]);
        bytes.extend_from_slice(tag.as_ref());
    }
}

impl ParameterizedDecode<hmac::Key> for AggregateShareResp {
    fn decode_with_param(key: &hmac::Key, bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        assert_eq!(key.algorithm(), HMAC_SHA256);
        let start_offset = bytes.position() as usize;

        let encrypted_aggregate_share = HpkeCiphertext::decode(bytes)?;

        let end_offset = bytes.position() as usize;
        let mut provided_tag = [0u8; SHA256_OUTPUT_LEN];
        bytes.read_exact(&mut provided_tag)?;
        hmac::verify(
            key,
            &bytes.get_ref()[start_offset..end_offset],
            &provided_tag,
        )
        .map_err(|_| CodecError::Other(anyhow!("HMAC tag verification failure").into()))?;

        Ok(Self {
            encrypted_aggregate_share,
        })
    }
}

/// PPM protocol message representing a request from the collector to the leader to provide
/// aggregate shares for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectReq {
    pub task_id: TaskId,
    pub batch_interval: Interval,
    pub agg_param: Vec<u8>,
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
    pub encrypted_agg_shares: Vec<HpkeCiphertext>,
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

#[cfg(test)]
mod tests {
    use super::*;
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

    fn roundtrip_encoding_with_param<P, T>(param: &P, vals_and_encodings: &[(T, &str)])
    where
        T: ParameterizedEncode<P> + ParameterizedDecode<P> + core::fmt::Debug + Eq,
    {
        for (val, hex_encoding) in vals_and_encodings {
            let mut encoded_val = Vec::new();
            val.encode_with_param(param, &mut encoded_val);
            let encoding = hex::decode(hex_encoding).unwrap();
            assert_eq!(encoding, encoded_val);
            let decoded_val = T::decode_with_param(param, &mut Cursor::new(&encoded_val)).unwrap();
            assert_eq!(val, &decoded_val);
        }
    }

    #[test]
    fn roundtrip_duration() {
        roundtrip_encoding(&[
            (Duration(u64::MIN), "0000000000000000"),
            (Duration(12345), "0000000000003039"),
            (Duration(u64::MAX), "FFFFFFFFFFFFFFFF"),
        ])
    }

    #[test]
    fn roundtrip_time() {
        roundtrip_encoding(&[
            (Time(u64::MIN), "0000000000000000"),
            (Time(12345), "0000000000003039"),
            (Time(u64::MAX), "FFFFFFFFFFFFFFFF"),
        ])
    }

    #[test]
    fn roundtrip_interval() {
        roundtrip_encoding(&[
            (
                Interval {
                    start: Time(u64::MIN),
                    duration: Duration(u64::MAX),
                },
                concat!(
                    "0000000000000000", // start
                    "FFFFFFFFFFFFFFFF", // duration
                ),
            ),
            (
                Interval {
                    start: Time(54321),
                    duration: Duration(12345),
                },
                concat!(
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
            (
                Interval {
                    start: Time(u64::MAX),
                    duration: Duration(u64::MIN),
                },
                concat!(
                    "FFFFFFFFFFFFFFFF", // start
                    "0000000000000000", // duration
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_role() {
        roundtrip_encoding(&[
            (Role::Collector, "00"),
            (Role::Client, "01"),
            (Role::Leader, "02"),
            (Role::Helper, "03"),
        ]);
    }

    #[test]
    fn roundtrip_hpke_config_id() {
        roundtrip_encoding(&[
            (HpkeConfigId(u8::MIN), "00"),
            (HpkeConfigId(10), "0A"),
            (HpkeConfigId(u8::MAX), "FF"),
        ])
    }

    #[test]
    fn roundtrip_hpke_ciphertext() {
        roundtrip_encoding(&[
            (
                HpkeCiphertext {
                    config_id: HpkeConfigId(10),
                    encapsulated_context: Vec::from("0123"),
                    payload: Vec::from("4567"),
                },
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
            ),
            (
                HpkeCiphertext {
                    config_id: HpkeConfigId(12),
                    encapsulated_context: Vec::from("01234"),
                    payload: Vec::from("567"),
                },
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
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_task_id() {
        roundtrip_encoding(&[
            (
                TaskId([u8::MIN; 32]),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                TaskId([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ]),
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            (
                TaskId([u8::MAX; 32]),
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
        ])
    }

    #[test]
    fn roundtrip_hpke_kem_id() {
        roundtrip_encoding(&[
            (HpkeKemId::P256HkdfSha256, "0010"),
            (HpkeKemId::X25519HkdfSha256, "0020"),
        ])
    }

    #[test]
    fn roundtrip_hpke_kdf_id() {
        roundtrip_encoding(&[
            (HpkeKdfId::HkdfSha256, "0001"),
            (HpkeKdfId::HkdfSha384, "0002"),
            (HpkeKdfId::HkdfSha512, "0003"),
        ])
    }

    #[test]
    fn roundtrip_hpke_aead_id() {
        roundtrip_encoding(&[
            (HpkeAeadId::Aes128Gcm, "0001"),
            (HpkeAeadId::Aes256Gcm, "0002"),
            (HpkeAeadId::ChaCha20Poly1305, "0003"),
        ])
    }

    #[test]
    fn roundtrip_hpke_public_key() {
        roundtrip_encoding(&[
            (
                HpkePublicKey(Vec::new()),
                concat!(
                    "0000", // length
                    "",     // opaque data
                ),
            ),
            (
                HpkePublicKey(Vec::from("0123456789abcdef")),
                concat!(
                    "0010",                             // length
                    "30313233343536373839616263646566"  // opaque data
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_hpke_config() {
        roundtrip_encoding(&[
            (
                HpkeConfig {
                    id: HpkeConfigId(12),
                    kem_id: HpkeKemId::P256HkdfSha256,
                    kdf_id: HpkeKdfId::HkdfSha512,
                    aead_id: HpkeAeadId::Aes256Gcm,
                    public_key: HpkePublicKey(Vec::new()),
                },
                concat!(
                    "0C",   // id
                    "0010", // kem_id
                    "0003", // kdf_id
                    "0002", // aead_id
                    concat!(
                        // public_key
                        "0000", // length
                        "",     // opaque data
                    )
                ),
            ),
            (
                HpkeConfig {
                    id: HpkeConfigId(23),
                    kem_id: HpkeKemId::X25519HkdfSha256,
                    kdf_id: HpkeKdfId::HkdfSha256,
                    aead_id: HpkeAeadId::ChaCha20Poly1305,
                    public_key: HpkePublicKey(Vec::from("0123456789abcdef")),
                },
                concat!(
                    "17",   // id
                    "0020", // kem_id
                    "0001", // kdf_id
                    "0003", // aead_id
                    concat!(
                        // public_key
                        "0010",                             // length
                        "30313233343536373839616263646566", // opaque data
                    )
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report() {
        roundtrip_encoding(&[
            (
                Report {
                    task_id: TaskId([u8::MIN; 32]),
                    nonce: Nonce {
                        time: Time(12345),
                        rand: 413,
                    },
                    extensions: vec![],
                    encrypted_input_shares: vec![],
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // nonce
                        "0000000000003039", // time
                        "000000000000019D", // rand
                    ),
                    concat!(
                        // extensions
                        "0000", // length
                    ),
                    concat!(
                        // encrypted_input_shares
                        "0000", // length
                    )
                ),
            ),
            (
                Report {
                    task_id: TaskId([u8::MAX; 32]),
                    nonce: Nonce {
                        time: Time(54321),
                        rand: 314,
                    },
                    extensions: vec![Extension {
                        extension_type: ExtensionType::Tbd,
                        extension_data: Vec::from("0123"),
                    }],
                    encrypted_input_shares: vec![
                        HpkeCiphertext {
                            config_id: HpkeConfigId(42),
                            encapsulated_context: Vec::from("012345"),
                            payload: Vec::from("543210"),
                        },
                        HpkeCiphertext {
                            config_id: HpkeConfigId(13),
                            encapsulated_context: Vec::from("abce"),
                            payload: Vec::from("abfd"),
                        },
                    ],
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                    concat!(
                        "000000000000D431", // time
                        "000000000000013A", // rand
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
                        )
                    ),
                    concat!(
                        // encrypted_input_shares
                        "001E", // length
                        concat!(
                            "2A", // config_id
                            concat!(
                                // encapsulated_context
                                "0006",         // length
                                "303132333435"  // opaque data
                            ),
                            concat!(
                                // payload
                                "0006",         // length
                                "353433323130", // opaque data
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
        ])
    }

    #[test]
    fn roundtrip_extension() {
        roundtrip_encoding(&[
            (
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::new(),
                },
                concat!(
                    "0000", // extension_type
                    concat!(
                        // extension_data
                        "0000", // length
                        "",     // opaque data
                    ),
                ),
            ),
            (
                Extension {
                    extension_type: ExtensionType::Tbd,
                    extension_data: Vec::from("0123"),
                },
                concat!(
                    "0000", // extension_type
                    concat!(
                        // extension_data
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_extension_type() {
        roundtrip_encoding(&[(ExtensionType::Tbd, "0000")])
    }

    #[test]
    fn roundtrip_transition() {
        roundtrip_encoding(&[
            (
                Transition {
                    nonce: Nonce {
                        time: Time(54372),
                        rand: 53,
                    },
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: Vec::from("012345"),
                    },
                },
                concat!(
                    concat!(
                        // nonce
                        "000000000000D464", // time
                        "0000000000000035", // rand
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
                    nonce: Nonce {
                        time: Time(12345),
                        rand: 413,
                    },
                    trans_data: TransitionTypeSpecificData::Finished,
                },
                concat!(
                    concat!(
                        // nonce
                        "0000000000003039", // time
                        "000000000000019D", // rand
                    ),
                    "01", // trans_type
                ),
            ),
            (
                Transition {
                    nonce: Nonce {
                        time: Time(345078),
                        rand: 98345,
                    },
                    trans_data: TransitionTypeSpecificData::Failed {
                        error: TransitionError::UnrecognizedNonce,
                    },
                },
                concat!(
                    concat!(
                        // nonce
                        "00000000000543F6", // time
                        "0000000000018029", // rand
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
        roundtrip_encoding_with_param(
            &*HMAC_KEY,
            &[
                (
                    AggregateReq::AggregateInitReq(AggregateInitReq {
                        task_id: TaskId([u8::MAX; 32]),
                        job_id: AggregationJobId([u8::MIN; 32]),
                        agg_param: Vec::from("012345"),
                        seq: vec![
                            ReportShare {
                                nonce: Nonce {
                                    time: Time(54321),
                                    rand: 314,
                                },
                                extensions: vec![Extension {
                                    extension_type: ExtensionType::Tbd,
                                    extension_data: Vec::from("0123"),
                                }],
                                encrypted_input_share: HpkeCiphertext {
                                    config_id: HpkeConfigId(42),
                                    encapsulated_context: Vec::from("012345"),
                                    payload: Vec::from("543210"),
                                },
                            },
                            ReportShare {
                                nonce: Nonce {
                                    time: Time(73542),
                                    rand: 515,
                                },
                                extensions: vec![Extension {
                                    extension_type: ExtensionType::Tbd,
                                    extension_data: Vec::from("3210"),
                                }],
                                encrypted_input_share: HpkeCiphertext {
                                    config_id: HpkeConfigId(13),
                                    encapsulated_context: Vec::from("abce"),
                                    payload: Vec::from("abfd"),
                                },
                            },
                        ],
                    }),
                    concat!(
                        "00", // msg_type
                        concat!(
                            // agg_init_req
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                            "0000000000000000000000000000000000000000000000000000000000000000", // job_id
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
                                        "000000000000013A", // rand
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
                                        "0000000000000203", // rand
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
                        "68090A61334511E10EC2F78E1575FB26E19F29CC740F02FFB6BFEF0AA280A1B7", // tag
                    ),
                ),
                (
                    AggregateReq::AggregateContinueReq(AggregateContinueReq {
                        task_id: TaskId([u8::MAX; 32]),
                        job_id: AggregationJobId([u8::MIN; 32]),
                        seq: vec![
                            Transition {
                                nonce: Nonce {
                                    time: Time(54372),
                                    rand: 53,
                                },
                                trans_data: TransitionTypeSpecificData::Continued {
                                    payload: Vec::from("012345"),
                                },
                            },
                            Transition {
                                nonce: Nonce {
                                    time: Time(12345),
                                    rand: 413,
                                },
                                trans_data: TransitionTypeSpecificData::Finished,
                            },
                        ],
                    }),
                    concat!(
                        "01", // msg_type
                        concat!(
                            // agg_continue_req
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                            "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                            concat!(
                                // seq
                                "002A", // length
                                concat!(
                                    concat!(
                                        // nonce
                                        "000000000000D464", // time
                                        "0000000000000035", // rand
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
                                        "000000000000019D", // rand
                                    ),
                                    "01", // trans_type
                                )
                            ),
                        ),
                        "8E244B47B01EA78D8639D81F0F9377CA0D5C2F0119ACDDC17CCB1B89D042F62E", // tag
                    ),
                ),
            ],
        )
    }

    #[test]
    fn roundtrip_aggregate_init_req() {
        roundtrip_encoding(&[
            (
                AggregateInitReq {
                    task_id: TaskId([u8::MIN; 32]),
                    job_id: AggregationJobId([u8::MAX; 32]),
                    agg_param: Vec::new(),
                    seq: Vec::new(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                    concat!(
                        // agg_param
                        "0000", // length
                        "",     // opaque data
                    ),
                    concat!(
                        // seq
                        "0000", // length
                    ),
                ),
            ),
            (
                AggregateInitReq {
                    task_id: TaskId([u8::MAX; 32]),
                    job_id: AggregationJobId([u8::MIN; 32]),
                    agg_param: Vec::from("012345"),
                    seq: vec![
                        ReportShare {
                            nonce: Nonce {
                                time: Time(54321),
                                rand: 314,
                            },
                            extensions: vec![Extension {
                                extension_type: ExtensionType::Tbd,
                                extension_data: Vec::from("0123"),
                            }],
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId(42),
                                encapsulated_context: Vec::from("012345"),
                                payload: Vec::from("543210"),
                            },
                        },
                        ReportShare {
                            nonce: Nonce {
                                time: Time(73542),
                                rand: 515,
                            },
                            extensions: vec![Extension {
                                extension_type: ExtensionType::Tbd,
                                extension_data: Vec::from("3210"),
                            }],
                            encrypted_input_share: HpkeCiphertext {
                                config_id: HpkeConfigId(13),
                                encapsulated_context: Vec::from("abce"),
                                payload: Vec::from("abfd"),
                            },
                        },
                    ],
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                    "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                    concat!(
                        // agg_param
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                    concat!(
                        "0052", // length
                        concat!(
                            concat!(
                                // nonce
                                "000000000000D431", // time
                                "000000000000013A", // rand
                            ),
                            concat!(
                                // extensions
                                "0008", // length
                                "0000", // extension_type
                                concat!(
                                    // extension_data
                                    "0004",     // length
                                    "30313233", // opaque data
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
                                "0000000000000203", // rand
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
                                // encrypted_input_share
                                "0D", // config_id
                                concat!(
                                    // encapsulated_context
                                    "0004",     // length
                                    "61626365", // opaque data
                                ),
                                concat!(
                                    "0004",     // length
                                    "61626664", // opaque data
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_continue_req() {
        roundtrip_encoding(&[
            (
                AggregateContinueReq {
                    task_id: TaskId([u8::MIN; 32]),
                    job_id: AggregationJobId([u8::MAX; 32]),
                    seq: vec![],
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                    concat!(
                        // seq
                        "0000", // length
                    ),
                ),
            ),
            (
                AggregateContinueReq {
                    task_id: TaskId([u8::MAX; 32]),
                    job_id: AggregationJobId([u8::MIN; 32]),
                    seq: vec![
                        Transition {
                            nonce: Nonce {
                                time: Time(54372),
                                rand: 53,
                            },
                            trans_data: TransitionTypeSpecificData::Continued {
                                payload: Vec::from("012345"),
                            },
                        },
                        Transition {
                            nonce: Nonce {
                                time: Time(12345),
                                rand: 413,
                            },
                            trans_data: TransitionTypeSpecificData::Finished,
                        },
                    ],
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                    "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                    concat!(
                        //seq
                        "002A", // length
                        concat!(
                            concat!(
                                // nonce
                                "000000000000D464", // time
                                "0000000000000035", // rand
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
                                "000000000000019D", // rand
                            ),
                            "01", // trans_type
                        ),
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_resp() {
        roundtrip_encoding_with_param(
            &*HMAC_KEY,
            &[
                (
                    AggregateResp { seq: vec![] },
                    concat!(
                        concat!(
                            // seq
                            "0000", // length
                        ),
                        "8D460A9EB8988604F0F282887BA39AA230A73AA6254E964FD9A4352E554B38E1", // tag
                    ),
                ),
                (
                    AggregateResp {
                        seq: vec![
                            Transition {
                                nonce: Nonce {
                                    time: Time(54372),
                                    rand: 53,
                                },
                                trans_data: TransitionTypeSpecificData::Continued {
                                    payload: Vec::from("012345"),
                                },
                            },
                            Transition {
                                nonce: Nonce {
                                    time: Time(12345),
                                    rand: 413,
                                },
                                trans_data: TransitionTypeSpecificData::Finished,
                            },
                        ],
                    },
                    concat!(
                        concat!(
                            //seq
                            "002A", // length
                            concat!(
                                concat!(
                                    // nonce
                                    "000000000000D464", // time
                                    "0000000000000035", // rand
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
                                    "000000000000019D", // rand
                                ),
                                "01", // trans_type
                            ),
                        ),
                        "3F48B7D8F0AA6E2AE5677ED356D3B18FFF5318A024A25CA0BF27CE02FB770EC3",
                    ),
                ),
            ],
        )
    }

    #[test]
    fn roundtrip_aggregate_share_req() {
        roundtrip_encoding_with_param(
            &*HMAC_KEY,
            &[
                (
                    AggregateShareReq {
                        task_id: TaskId([u8::MIN; 32]),
                        batch_interval: Interval {
                            start: Time(54321),
                            duration: Duration(12345),
                        },
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
                        "00000000000001B7", // report_count
                        "0000000000000000000000000000000000000000000000000000000000000000", // checksum
                        "B19A8933DA450A49737E56643B83F3DEF530CBAF3FCD9E3E2BF09C6D8AF373A6", // tag
                    ),
                ),
                (
                    AggregateShareReq {
                        task_id: TaskId([12u8; 32]),
                        batch_interval: Interval {
                            start: Time(50821),
                            duration: Duration(84354),
                        },
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
                        "0000000000002215", // report_count
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
                        "4ADD294CF991CEB12CDE2DC5F98EAE56BC1C3D8941D3FC4C46F053AE7D3BC3CA", // tag
                    ),
                ),
            ],
        )
    }

    #[test]
    fn roundtrip_aggregate_share_resp() {
        roundtrip_encoding_with_param(
            &*HMAC_KEY,
            &[
                (
                    AggregateShareResp {
                        encrypted_aggregate_share: HpkeCiphertext {
                            config_id: HpkeConfigId(10),
                            encapsulated_context: Vec::from("0123"),
                            payload: Vec::from("4567"),
                        },
                    },
                    concat!(
                        concat!(
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
                        ),
                        "67C9AD957825E8A20F3E85B6343A4AB186927B01B16585A6F21115730C660EC7", // tag
                    ),
                ),
                (
                    AggregateShareResp {
                        encrypted_aggregate_share: HpkeCiphertext {
                            config_id: HpkeConfigId(12),
                            encapsulated_context: Vec::from("01234"),
                            payload: Vec::from("567"),
                        },
                    },
                    concat!(
                        concat!(
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
                        ),
                        "DF229D520BBB475BF17CA6DECF8EF134A6868D54D5171974340A667F5129035E", // tag
                    ),
                ),
            ],
        )
    }

    #[test]
    fn roundtrip_collect_req() {
        roundtrip_encoding(&[
            (
                CollectReq {
                    task_id: TaskId([u8::MIN; 32]),
                    batch_interval: Interval {
                        start: Time(54321),
                        duration: Duration(12345),
                    },
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
                    task_id: TaskId([13u8; 32]),
                    batch_interval: Interval {
                        start: Time(48913),
                        duration: Duration(44721),
                    },
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
                        HpkeCiphertext {
                            config_id: HpkeConfigId(10),
                            encapsulated_context: Vec::from("0123"),
                            payload: Vec::from("4567"),
                        },
                        HpkeCiphertext {
                            config_id: HpkeConfigId(12),
                            encapsulated_context: Vec::from("01234"),
                            payload: Vec::from("567"),
                        },
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
                ),),
            ),
        ])
    }
}
